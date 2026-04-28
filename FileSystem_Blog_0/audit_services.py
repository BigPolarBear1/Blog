#!/usr/bin/env python3
"""
audit_services.py
─────────────────
End-to-end orchestrator: enumerates every Windows service, collects the DLLs
loaded in each service host process, and statically analyzes each unique DLL
for CreateFileW / CreateFileA call sites — all in one run.

The log file is structured by service:
  Service A
    DLL 1
      Caller foo() → CreateFileW @ 0x...
      Caller foo() → CreateFileA @ 0x...
    DLL 2
      ...
  Service B
    ...

Each unique DLL is only analyzed once (analysis results are cached and
referenced by every service that loads it), so a 200-service host shares one
analysis pass over kernel32.dll instead of 200.

Requirements:
    Windows only. Run from an elevated (Administrator) prompt.

Dependencies:
    pip install pefile capstone requests pywin32
    pip install pdbparse        # optional, for symbol resolution

Usage:
    python audit_services.py
    python audit_services.py --output-dir audit_results --verbose
    python audit_services.py --state all --no-download
    python audit_services.py --filter svchost
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# ── make companion scripts importable ────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    import enum_service_dlls as svc
    import analyze_createfile as ana
except ImportError as exc:
    sys.exit(
        f"Missing companion script: {exc}\n"
        f"Place enum_service_dlls.py and analyze_createfile.py next to this "
        f"file in:\n  {SCRIPT_DIR}"
    )

DEFAULT_OUTPUT_DIR = "audit_results"


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Service enumeration
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_services(
    state_filter: int,
    exe_filter: str | None,
    verbose: bool,
) -> tuple[list[dict], dict]:
    """
    Return a list of per-service records and a summary dict.

    Each service record contains:
        name, display_name, state, service_type, pid, binary_path,
        host_exe, dlls (list of DLL paths actually loaded in the host process)

    Services whose host PID is shared (svchost.exe) reuse one PSAPI lookup —
    we cache by PID. A summary dict reports overall counts.
    """
    print("[*] Enabling SeDebugPrivilege …")
    svc.enable_debug_privilege()

    print("[*] Querying SCM for services …")
    services = svc.query_all_services(state_filter)
    print(f"[+] {len(services)} service(s) found")

    pid_cache: dict[int, tuple[str | None, list[str]]] = {}
    examined_pids:     set[int] = set()
    inaccessible_pids: set[int] = set()
    records:  list[dict] = []
    filter_lc = exe_filter.lower() if exe_filter else None

    for s in services:
        pid       = s["pid"]
        exe_path  = None
        dlls:     list[str] = []

        if pid:
            if pid not in pid_cache:
                if verbose:
                    print(f"  [*] pid={pid:6d}  {s['name']}")
                pid_cache[pid] = svc.get_loaded_dlls(pid)
                examined_pids.add(pid)
                if not pid_cache[pid][0] and not pid_cache[pid][1]:
                    inaccessible_pids.add(pid)
            exe_path, dlls = pid_cache[pid]

        # Apply --filter: match against host EXE name OR service name
        if filter_lc:
            host = Path(exe_path).name.lower() if exe_path else ""
            if filter_lc not in host and filter_lc not in s["name"].lower():
                continue

        records.append({
            "name":         s["name"],
            "display_name": s["display_name"],
            "state":        s["state"],
            "service_type": s["service_type"],
            "pid":          pid,
            "binary_path":  s["binary_path"],
            "host_exe":     exe_path,
            "dlls":         sorted(dlls, key=str.lower),
        })

    all_dlls = {d for r in records for d in r["dlls"]}
    summary = {
        "scanned":             len(services),
        "shown":               len(records),
        "unique_pids":         len(examined_pids),
        "inaccessible_pids":   len(inaccessible_pids),
        "unique_dlls":         len(all_dlls),
    }
    return records, summary


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — DLL analysis (deduplicated)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_unique_dlls(
    service_records: list[dict],
    no_download: bool,
    verbose: bool,
) -> tuple[dict[str, list[dict]], list[tuple[str, str]]]:
    """
    Build a deduplicated list of DLL paths across all services, then run
    analyze_dll once per DLL. Returns:
        ({dll_path: [call_site_records, …]}, [(dll_path, error_msg), …])
    """
    unique_dlls = sorted(
        {d for r in service_records for d in r["dlls"]
         if Path(d).exists()},
        key=str.lower,
    )

    cache:  dict[str, list[dict]] = {}
    errors: list[tuple[str, str]] = []
    total = len(unique_dlls)

    print(f"[*] Analyzing {total} unique DLL(s) (deduplicated across services)")

    for i, dll_path in enumerate(unique_dlls, 1):
        print(f"\n[{i}/{total}] ── {Path(dll_path).name} ──")
        try:
            results, _ = ana.analyze_dll(Path(dll_path), no_download, verbose)
            cache[dll_path] = results
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            print(f"[ERROR] {msg}")
            cache[dll_path] = []
            errors.append((dll_path, msg))

    return cache, errors


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Service-centric audit log
# ─────────────────────────────────────────────────────────────────────────────

def _format_call_site(c: dict) -> list[str]:
    """Format a single call-site record as a list of indented lines."""
    return [
        f"          Target  : {c['target_function']}",
        f"          Caller  : {c['caller_function']}",
        f"          Address : 0x{c['call_va']:X}  (RVA 0x{c['call_rva']:X})",
        f"          Section : {c['section']}",
        f"          Instr   : {c['instruction']}",
        f"          Bytes   : {c['bytes']}",
        "",
    ]


def write_service_log(
    service_records: list[dict],
    analysis_cache: dict[str, list[dict]],
    log_file: Path,
    started_at: datetime,
    finished_at: datetime,
    summary: dict,
) -> None:
    """
    Write a service-centric audit log:
        Service → DLLs → call sites (grouped by caller).
    Services with zero call sites across all their DLLs get a one-line summary.
    """
    lines: list[str] = []
    add = lines.append

    sep1 = "═" * 78
    sep2 = "─" * 78

    # ── header ──
    add(sep1)
    add("  SERVICE DLL CreateFile[W/A] AUDIT REPORT")
    add(sep1)
    add(f"  Started  : {started_at.isoformat(timespec='seconds')}")
    add(f"  Finished : {finished_at.isoformat(timespec='seconds')}")
    add(f"  Duration : {(finished_at - started_at).total_seconds():.1f}s")
    add("")
    add(f"  Services scanned        : {summary['scanned']}")
    add(f"  Services in this report : {summary['shown']}")
    add(f"  Unique service host PIDs: {summary['unique_pids']}")
    add(f"  Inaccessible host PIDs  : {summary['inaccessible_pids']}")
    add(f"  Unique DLLs analyzed    : {summary['unique_dlls']}")
    add("")

    # ── overall call totals ──
    overall = Counter()
    for results in analysis_cache.values():
        for r in results:
            overall[r["target_function"]] += 1
    total_calls = sum(overall.values())

    add(sep2)
    add("  OVERALL CALL SITE TOTALS (across all unique DLLs, deduplicated)")
    add(sep2)
    for fn in sorted(overall):
        add(f"    {fn:<20} {overall[fn]} call(s)")
    add(f"    {'TOTAL':<20} {total_calls} call(s)")
    add("")

    # ── service-by-hits ranking ──
    service_totals: list[tuple[str, int, int, int]] = []
    for rec in service_records:
        w = a = 0
        for d in rec["dlls"]:
            for r in analysis_cache.get(d, []):
                if r["target_function"] == "CreateFileW":
                    w += 1
                elif r["target_function"] == "CreateFileA":
                    a += 1
        service_totals.append((rec["name"], w, a, w + a))

    service_totals.sort(key=lambda x: -x[3])

    add(sep2)
    add("  SERVICE RANKING BY CALL SITE COUNT")
    add(sep2)
    add(f"  {'Service':<40} {'CreateFileW':>12} {'CreateFileA':>12} {'Total':>8}")
    add(f"  {'─'*40} {'─'*12} {'─'*12} {'─'*8}")
    for name, w, a, tot in service_totals:
        if tot == 0:
            continue
        nm = name if len(name) <= 40 else name[:39] + "…"
        add(f"  {nm:<40} {w:>12} {a:>12} {tot:>8}")
    zero_count = sum(1 for _, _, _, t in service_totals if t == 0)
    if zero_count:
        add(f"\n  ({zero_count} service(s) had no CreateFile[W/A] call sites — "
            f"listed at end of report)")
    add("")

    # ── per-service detail blocks ──
    add(sep1)
    add("  PER-SERVICE DETAIL")
    add(sep1)

    services_with_hits    = []
    services_without_hits = []
    for rec in service_records:
        if any(analysis_cache.get(d) for d in rec["dlls"]):
            services_with_hits.append(rec)
        else:
            services_without_hits.append(rec)

    for rec in sorted(services_with_hits, key=lambda r: r["name"].lower()):
        # Per-service totals
        svc_w = svc_a = 0
        for d in rec["dlls"]:
            for r in analysis_cache.get(d, []):
                if r["target_function"] == "CreateFileW":
                    svc_w += 1
                elif r["target_function"] == "CreateFileA":
                    svc_a += 1
        if svc_w + svc_a == 0:
            continue

        add("")
        add(sep1)
        add(f"  ▓ Service : {rec['name']}  ({rec['display_name']})")
        add(f"    State        : {svc.state_label(rec['state'])}")
        add(f"    Type         : {svc.service_type_label(rec['service_type'])}")
        add(f"    PID          : {rec['pid'] or '— (not running)'}")
        add(f"    Binary path  : {rec['binary_path']}")
        if rec['host_exe']:
            add(f"    Host EXE     : {rec['host_exe']}")
        add(f"    Loaded DLLs  : {len(rec['dlls'])}")
        add(f"    Call sites   : CreateFileW={svc_w}  CreateFileA={svc_a}  "
            f"Total={svc_w + svc_a}")
        add(sep1)

        # Per-DLL blocks (only DLLs that have hits)
        for dll_path in rec["dlls"]:
            results = analysis_cache.get(dll_path, [])
            if not results:
                continue

            cnt = Counter(r["target_function"] for r in results)
            add("")
            add(f"    ─── DLL: {dll_path}")
            add(f"        CreateFileW={cnt.get('CreateFileW', 0)}  "
                f"CreateFileA={cnt.get('CreateFileA', 0)}  "
                f"Total={len(results)}")
            add(f"        {'─'*70}")

            # Group call sites by caller for readability
            by_caller: dict[str, list[dict]] = {}
            for r in results:
                by_caller.setdefault(r["caller_function"], []).append(r)

            for caller in sorted(by_caller):
                add("")
                add(f"        Caller: {caller}")
                add(f"        {'─'*60}")
                for c in by_caller[caller]:
                    lines.extend(_format_call_site(c))

    # ── services with no hits (compact list) ──
    if services_without_hits:
        add("")
        add(sep1)
        add(f"  SERVICES WITH NO CreateFile[W/A] CALL SITES "
            f"({len(services_without_hits)})")
        add(sep1)
        add("")
        for rec in sorted(services_without_hits, key=lambda r: r["name"].lower()):
            note = ""
            if not rec["pid"]:
                note = "  [no host process]"
            elif not rec["dlls"]:
                note = "  [host inaccessible / no DLLs enumerated]"
            add(f"    {rec['name']:<40} "
                f"({svc.state_label(rec['state']):<14}){note}")

    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Auxiliary outputs
# ─────────────────────────────────────────────────────────────────────────────

def write_dll_list(service_records: list[dict], out_file: Path) -> None:
    """Flat deduplicated DLL list (one path per line, sorted)."""
    paths = sorted({d for r in service_records for d in r["dlls"]},
                   key=str.lower)
    out_file.write_text("\n".join(paths) + "\n", encoding="utf-8")


def write_json(
    service_records: list[dict],
    analysis_cache: dict[str, list[dict]],
    out_file: Path,
) -> int:
    """
    Structured JSON dump with the same nesting as the log:
    service → loaded_dlls → calls.  Returns the number of call records.
    """
    payload = []
    total = 0
    for rec in service_records:
        dll_blocks = []
        for d in rec["dlls"]:
            calls = analysis_cache.get(d, [])
            dll_blocks.append({
                "dll_path":   d,
                "call_count": len(calls),
                "calls":      calls,
            })
            total += len(calls)
        payload.append({
            "service":      rec["name"],
            "display_name": rec["display_name"],
            "state":        svc.state_label(rec["state"]),
            "pid":          rec["pid"],
            "host_exe":     rec["host_exe"],
            "loaded_dlls":  dll_blocks,
        })
    out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return total


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit Windows services for CreateFile[W/A] usage. Output is a "
            "log file structured by service → DLLs → call sites."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output-dir", "-o",
                        default=DEFAULT_OUTPUT_DIR, metavar="DIR",
                        help=f"Where to write outputs (default: {DEFAULT_OUTPUT_DIR}/)")
    parser.add_argument("--state", choices=list(svc.SERVICE_STATES.keys()),
                        default="running",
                        help="Which services to enumerate (default: running)")
    parser.add_argument("--filter", dest="exe_filter", metavar="NAME",
                        help="Only include services whose host EXE or service "
                             "name contains NAME (e.g. --filter svchost)")
    parser.add_argument("--no-download", action="store_true",
                        help="Skip PDB download from the Microsoft symbol server.")
    parser.add_argument("--json", dest="json_out", action="store_true",
                        help="Also write the structured JSON output.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print extra diagnostic information.")
    args = parser.parse_args()

    if not svc.is_admin():
        print("[WARN] Not running as Administrator — many service host "
              "processes will be inaccessible.\n")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    dll_list_file = out_dir / f"dll_list_{timestamp}.txt"
    log_file      = out_dir / f"service_audit_{timestamp}.log"
    json_file     = out_dir / f"service_audit_{timestamp}.json"

    started_at = datetime.now()

    # ── PHASE 1 ──
    print("\n" + "═" * 60)
    print("  PHASE 1 — Enumerate services & loaded DLLs")
    print("═" * 60)
    state_filter = svc.SERVICE_STATES[args.state]
    service_records, summary = enumerate_services(
        state_filter, args.exe_filter, args.verbose
    )

    if not service_records:
        sys.exit("\n[-] No services matched. Try removing --filter or check "
                 "that you're running elevated.")

    write_dll_list(service_records, dll_list_file)
    print(f"\n[+] DLL list written to: {dll_list_file}")
    print(f"    {summary['unique_dlls']} unique DLL(s) across "
          f"{summary['shown']} service(s)")

    # ── PHASE 2 ──
    print("\n" + "═" * 60)
    print("  PHASE 2 — Analyze CreateFile[W/A] call sites")
    print("═" * 60)
    analysis_cache, errors = analyze_unique_dlls(
        service_records, args.no_download, args.verbose
    )

    finished_at = datetime.now()

    # ── PHASE 3 ──
    print("\n" + "═" * 60)
    print("  PHASE 3 — Write service-centric audit log")
    print("═" * 60)
    write_service_log(
        service_records, analysis_cache, log_file,
        started_at, finished_at, summary,
    )
    print(f"[+] Log file written to: {log_file}")

    if args.json_out:
        n = write_json(service_records, analysis_cache, json_file)
        print(f"[+] JSON written to:    {json_file}  ({n} call records)")

    # ── final console summary ──
    total_calls = sum(len(v) for v in analysis_cache.values())
    services_with_hits = sum(
        1 for r in service_records
        if any(analysis_cache.get(d) for d in r["dlls"])
    )
    print("\n" + "═" * 60)
    print("  AUDIT COMPLETE")
    print("═" * 60)
    print(f"  Services scanned            : {summary['scanned']}")
    print(f"  Services in report          : {summary['shown']}")
    print(f"  Services with CreateFile use: {services_with_hits}")
    print(f"  Unique DLLs analyzed        : {summary['unique_dlls']}")
    print(f"  Total call sites found      : {total_calls}")
    print(f"  Analysis errors             : {len(errors)}")
    print(f"  Duration                    : "
          f"{(finished_at - started_at).total_seconds():.1f}s")
    print(f"\n  Output directory: {out_dir.resolve()}")


if __name__ == "__main__":
    main()