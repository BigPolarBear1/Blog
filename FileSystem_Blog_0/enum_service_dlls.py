#!/usr/bin/env python3
"""
enum_service_dlls.py
────────────────────
Enumerates all Windows system services (SCM-registered), resolves the host
process for each service, and prints every DLL loaded in that process together
with its full on-disk path.

Output modes:
  • Console — pretty table grouped by service / process
  • Text file — one "dll_path" per line, deduplicated (--output)
  • JSON file — full structured data per service (--json)

Requirements:
    Windows only. Must be run as Administrator so that:
      - OpenProcess can access protected service host processes
      - EnumProcessModulesEx succeeds on all svchost.exe instances

Dependencies:
    pip install pywin32

Usage:
    python enum_service_dlls.py                          # console only
    python enum_service_dlls.py --output dlls.txt        # + flat DLL list
    python enum_service_dlls.py --json   services.json   # + structured JSON
    python enum_service_dlls.py --filter svchost         # filter by exe name
    python enum_service_dlls.py --state  all             # include stopped services
    python enum_service_dlls.py --verbose                # extra detail
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import sys
from pathlib import Path

# ── platform guard ────────────────────────────────────────────────────────────
if sys.platform != "win32":
    sys.exit("enum_service_dlls.py is Windows-only.")

# ── pywin32 ───────────────────────────────────────────────────────────────────
try:
    import win32api
    import win32con
    import win32process
    import win32security
    import win32service
    import pywintypes
except ImportError:
    sys.exit(
        "pywin32 not found — run:\n"
        "  pip install pywin32\n"
        "  python Scripts/pywin32_postinstall.py -install"
    )

# ── constants ─────────────────────────────────────────────────────────────────
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_LIMITED     = 0x1000

# State-filter values for EnumServicesStatus (NOT the same as the
# dwCurrentState values like SERVICE_RUNNING). The filter accepts only:
#   SERVICE_ACTIVE   = 0x00000001  (started/pending/paused)
#   SERVICE_INACTIVE = 0x00000002  (stopped)
#   SERVICE_STATE_ALL = 0x00000003
SERVICE_STATES = {
    "running": 0x00000001,   # SERVICE_ACTIVE
    "stopped": 0x00000002,   # SERVICE_INACTIVE
    "all":     0x00000003,   # SERVICE_STATE_ALL
}

# ── ctypes / PSAPI helpers ────────────────────────────────────────────────────
_psapi = ctypes.WinDLL("psapi", use_last_error=True)

# Declare full argtypes so ctypes uses 64-bit-safe HANDLE/HMODULE/LPVOID types
# instead of defaulting to c_int (which overflows on x64 high addresses).
_psapi.EnumProcessModulesEx.argtypes = [
    wt.HANDLE,                        # hProcess
    ctypes.POINTER(wt.HMODULE),       # lphModule
    wt.DWORD,                         # cb
    ctypes.POINTER(wt.DWORD),         # lpcbNeeded
    wt.DWORD,                         # dwFilterFlag
]
_psapi.EnumProcessModulesEx.restype = wt.BOOL

_psapi.GetModuleFileNameExW.argtypes = [
    wt.HANDLE,                        # hProcess
    wt.HMODULE,                       # hModule
    wt.LPWSTR,                        # lpFilename
    wt.DWORD,                         # nSize
]
_psapi.GetModuleFileNameExW.restype = wt.DWORD


def _enum_modules(hProcess: int) -> list[int]:
    """Return HMODULE handles for every module in hProcess."""
    LIST_MODULES_ALL = 0x03
    buf_size = 512
    while True:
        hMods     = (wt.HMODULE * buf_size)()
        cb_needed = wt.DWORD(0)
        ok = _psapi.EnumProcessModulesEx(
            hProcess,
            hMods,
            ctypes.sizeof(hMods),
            ctypes.byref(cb_needed),
            LIST_MODULES_ALL,
        )
        if not ok:
            return []
        needed_count = cb_needed.value // ctypes.sizeof(wt.HMODULE)
        if needed_count > buf_size:
            buf_size = needed_count + 64
            continue
        return list(hMods[:needed_count])


def _module_path(hProcess: int, hModule: int) -> str | None:
    """Return the full file path of hModule loaded in hProcess."""
    buf    = ctypes.create_unicode_buffer(32768)
    length = _psapi.GetModuleFileNameExW(hProcess, hModule, buf, len(buf))
    return buf.value if length else None


def get_loaded_dlls(pid: int) -> tuple[str | None, list[str]]:
    """
    Open pid and enumerate its loaded modules.
    Returns (exe_path, [dll_path, …]).
    exe_path is module index 0 (the EXE).  DLLs are indices 1+.
    """
    for flags in (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                  PROCESS_QUERY_LIMITED     | PROCESS_VM_READ):
        try:
            hProcess = win32api.OpenProcess(flags, False, pid)
            break
        except pywintypes.error:
            hProcess = None

    if hProcess is None:
        return None, []

    try:
        hMods    = _enum_modules(int(hProcess))
        exe_path = _module_path(int(hProcess), hMods[0]) if hMods else None
        dlls     = []
        for hMod in hMods[1:]:
            path = _module_path(int(hProcess), hMod)
            if path and path.lower().endswith(".dll"):
                dlls.append(path)
        return exe_path, dlls
    finally:
        hProcess.close()


# ── privilege helpers ─────────────────────────────────────────────────────────

def enable_debug_privilege() -> None:
    """Attempt to enable SeDebugPrivilege; warn but continue on failure."""
    try:
        hToken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
        )
        luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(
            hToken, False, [(luid, win32con.SE_PRIVILEGE_ENABLED)]
        )
    except pywintypes.error as exc:
        print(f"[WARN] SeDebugPrivilege: {exc}")


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ── SCM helpers ───────────────────────────────────────────────────────────────

def query_all_services(state_filter: int) -> list[dict]:
    """
    Return a list of service info dicts from the SCM.
    Each dict contains: name, display_name, status, pid, service_type, binary_path.
    """
    try:
        hSCM = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
        )
    except pywintypes.error as exc:
        sys.exit(f"OpenSCManager failed: {exc}\n(Are you running as Administrator?)")

    # Raw Win32 constants — use literals to avoid pywin32 version differences
    # in constant naming. These values are fixed by the Windows SDK.
    SERVICE_WIN32_OWN_PROCESS   = 0x00000010
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    SERVICE_WIN32_ALL           = 0x00000030  # both of the above OR'd
    SERVICE_KERNEL_DRIVER       = 0x00000001
    SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
    SERVICE_DRIVER_ALL          = 0x00000003

    def _enum(service_type):
        try:
            results = win32service.EnumServicesStatus(
                hSCM, service_type, state_filter
            )
            return results if results else []
        except pywintypes.error as exc:
            print(f"[WARN] EnumServicesStatus(type={service_type:#x}): {exc}")
            return []

    raw_entries = (
        _enum(SERVICE_WIN32_ALL) +
        _enum(SERVICE_KERNEL_DRIVER) +
        _enum(SERVICE_FILE_SYSTEM_DRIVER)
    )

    # EnumServicesStatus returns (name, display_name, status_tuple) triples.
    # Resolve PID via QueryServiceStatusEx on each service handle.
    raw = []
    for name, display_name, status in raw_entries:
        pid = 0
        try:
            hSvc = win32service.OpenService(
                hSCM, name,
                win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG,
            )
            ex = win32service.QueryServiceStatusEx(hSvc)
            pid = ex.get("ProcessId", 0)
            win32service.CloseServiceHandle(hSvc)
        except pywintypes.error:
            pass
        raw.append({
            "ServiceName": name,
            "DisplayName": display_name,
            "CurrentState": status[1],
            "ServiceType":  status[0],
            "ProcessId":    pid,
        })

    services = []
    for svc in raw:
        # Resolve the ImagePath from the registry for the binary_path field
        binary_path = "<unknown>"
        try:
            hSvc = win32service.OpenService(
                hSCM, svc["ServiceName"], win32service.SERVICE_QUERY_CONFIG
            )
            cfg          = win32service.QueryServiceConfig(hSvc)
            binary_path  = cfg[3]   # lpBinaryPathName
            win32service.CloseServiceHandle(hSvc)
        except pywintypes.error:
            pass

        services.append({
            "name":         svc["ServiceName"],
            "display_name": svc["DisplayName"],
            "pid":          svc["ProcessId"],
            "state":        svc["CurrentState"],
            "service_type": svc["ServiceType"],
            "binary_path":  binary_path,
        })

    win32service.CloseServiceHandle(hSCM)
    return services


def state_label(state: int) -> str:
    return {
        win32service.SERVICE_RUNNING:      "RUNNING",
        win32service.SERVICE_STOPPED:      "STOPPED",
        win32service.SERVICE_PAUSED:       "PAUSED",
        win32service.SERVICE_START_PENDING:"START_PENDING",
        win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
    }.get(state, f"STATE({state})")


def service_type_label(stype: int) -> str:
    labels = []
    if stype & win32service.SERVICE_KERNEL_DRIVER:       labels.append("KERNEL_DRIVER")
    if stype & win32service.SERVICE_FILE_SYSTEM_DRIVER:  labels.append("FS_DRIVER")
    if stype & win32service.SERVICE_WIN32_OWN_PROCESS:   labels.append("OWN_PROCESS")
    if stype & win32service.SERVICE_WIN32_SHARE_PROCESS: labels.append("SHARE_PROCESS")
    if stype & win32service.SERVICE_INTERACTIVE_PROCESS: labels.append("INTERACTIVE")
    return "|".join(labels) if labels else f"TYPE({stype:#x})"


# ── formatting ────────────────────────────────────────────────────────────────

SEP  = "─" * 76
SEP2 = "═" * 76


def print_service_block(svc: dict, exe_path: str | None, dlls: list[str]) -> None:
    print(f"\n{SEP2}")
    print(f"  Service     : {svc['name']}  ({svc['display_name']})")
    print(f"  State       : {state_label(svc['state'])}")
    print(f"  Type        : {service_type_label(svc['service_type'])}")
    print(f"  PID         : {svc['pid'] or '—  (not running)'}")
    print(f"  Binary path : {svc['binary_path']}")
    if exe_path:
        print(f"  Host EXE    : {exe_path}")
    print(SEP)

    if not dlls:
        print("  (no DLLs enumerated — process may be inaccessible or stopped)")
        return

    print(f"  Loaded DLLs ({len(dlls)}):")
    for dll in sorted(dlls, key=str.lower):
        print(f"    {dll}")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enumerate Windows services and their loaded DLLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write a flat, deduplicated list of DLL paths to FILE (one per line). "
             "Compatible with analyze_createfile.py --dll-list.",
    )
    parser.add_argument(
        "--json", dest="json_out", metavar="FILE",
        help="Write full structured results to FILE as JSON.",
    )
    parser.add_argument(
        "--state", choices=list(SERVICE_STATES.keys()), default="running",
        help="Which services to include (default: running).",
    )
    parser.add_argument(
        "--filter", dest="exe_filter", metavar="NAME",
        help="Only show services whose host EXE name contains NAME (case-insensitive). "
             "E.g. --filter svchost",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print extra diagnostic messages.",
    )
    args = parser.parse_args()

    # ── pre-flight ──
    if not is_admin():
        print("[WARN] Not running as Administrator — many service processes will "
              "be inaccessible. Re-run from an elevated prompt for full results.\n")

    print("[*] Enabling SeDebugPrivilege …")
    enable_debug_privilege()

    # ── query SCM ──
    state_filter = SERVICE_STATES[args.state]
    print(f"[*] Querying SCM for services (state={args.state}) …")
    services = query_all_services(state_filter)
    print(f"[+] {len(services)} service(s) found\n")

    # ── per-service DLL enumeration ──
    # Deduplicate work: many services share a svchost.exe process (same PID).
    pid_dll_cache: dict[int, tuple[str | None, list[str]]] = {}

    all_dlls:    set[str]  = set()
    json_output: list[dict] = []
    shown        = 0
    skipped      = 0

    for svc in sorted(services, key=lambda s: s["name"].lower()):
        pid = svc["pid"]

        # Resolve DLLs (use cache if we already opened this PID)
        if pid and pid not in pid_dll_cache:
            if args.verbose:
                print(f"  [*] Opening pid={pid} ({svc['name']}) …")
            pid_dll_cache[pid] = get_loaded_dlls(pid)

        exe_path, dlls = pid_dll_cache.get(pid, (None, []))

        # Apply --filter
        if args.exe_filter:
            filter_lc = args.exe_filter.lower()
            host_name = Path(exe_path).name.lower() if exe_path else ""
            if filter_lc not in host_name and filter_lc not in svc["name"].lower():
                skipped += 1
                continue

        print_service_block(svc, exe_path, dlls)
        all_dlls.update(dlls)
        shown += 1

        json_output.append({
            "service_name":  svc["name"],
            "display_name":  svc["display_name"],
            "state":         state_label(svc["state"]),
            "service_type":  service_type_label(svc["service_type"]),
            "pid":           pid,
            "binary_path":   svc["binary_path"],
            "host_exe":      exe_path,
            "loaded_dlls":   sorted(dlls, key=str.lower),
        })

    # ── summary ──
    print(f"\n{SEP2}")
    print(f"  SUMMARY")
    print(SEP)
    print(f"  Services shown   : {shown}")
    if skipped:
        print(f"  Services skipped : {skipped}  (filtered out)")
    print(f"  Unique DLL paths : {len(all_dlls)}")
    print(SEP2)

    # ── flat DLL output ──
    if args.output:
        out_path = Path(args.output)
        sorted_dlls = sorted(all_dlls, key=str.lower)
        out_path.write_text("\n".join(sorted_dlls) + "\n", encoding="utf-8")
        print(f"\n[+] Flat DLL list written to: {out_path.resolve()}")
        print(f"    Analyze with:")
        print(f"      python analyze_createfile.py --dll-list {out_path.resolve()}")

    # ── JSON output ──
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
        print(f"\n[+] JSON results written to: {json_path.resolve()}")


if __name__ == "__main__":
    main()