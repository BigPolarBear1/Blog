#!/usr/bin/env python3
"""
analyze_createfile.py
─────────────────────
Analyzes one or more Windows DLLs to find every call site that invokes
CreateFileW or CreateFileA, then resolves the enclosing function name from a
locally-cached PDB (downloaded from the Microsoft public symbol server if
needed).

Dependencies:
    pip install pefile capstone requests

Optional (richer PDB parsing):
    pip install pdbparse          # for full PDB symbol resolution

Usage:
    # Single DLL
    python analyze_createfile.py path/to/foo.dll

    # Entire folder (all *.dll files, non-recursive)
    python analyze_createfile.py path/to/folder/

    # Entire folder tree (recursive)
    python analyze_createfile.py path/to/folder/ --recursive

    # Extra options
    python analyze_createfile.py path/to/folder/ --verbose --json results.json

Notes:
    - The script downloads the PDB from the Microsoft symbol server the first
      time it sees a DLL, caching it in ./symbols/<GUID>/<pdb_name>.
    - Symbol resolution falls back to a range-based heuristic when pdbparse is
      not installed or when a symbol is not found in the PDB.
    - DLLs with no CreateFile imports are skipped with a short notice.
    - Errors in individual DLLs are caught and reported; scanning continues.
"""

import argparse
import os
import struct
import sys
import hashlib
import json
from pathlib import Path
from typing import Optional

# ── third-party ──────────────────────────────────────────────────────────────
try:
    import pefile
except ImportError:
    sys.exit("pefile not found — run:  pip install pefile")

try:
    import capstone
except ImportError:
    sys.exit("capstone not found — run:  pip install capstone")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[WARN] requests not installed — symbol download disabled. "
          "Run:  pip install requests")

try:
    import pdbparse
    HAS_PDBPARSE = True
except ImportError:
    HAS_PDBPARSE = False
    print("[WARN] pdbparse not installed — symbol names resolved heuristically. "
          "Run:  pip install pdbparse")

# ── constants ─────────────────────────────────────────────────────────────────
MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
SYMBOL_CACHE_DIR = Path("./symbols")
TARGET_FUNCTIONS  = {"CreateFileW", "CreateFileA"}

# ── helpers ───────────────────────────────────────────────────────────────────

def get_machine_type(pe: "pefile.PE") -> str:
    """Return 'x64' or 'x86' based on the PE machine field."""
    return "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"


def build_import_map(pe: "pefile.PE") -> dict[str, int]:
    """
    Return {function_name: IAT_VA} for all imported functions.
    VA = virtual address of the IAT slot (what a CALL [mem] points at).
    """
    import_map: dict[str, int] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return import_map
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode(errors="replace")
                import_map[name] = imp.address  # absolute VA of IAT slot
    return import_map


def extract_debug_info(pe: "pefile.PE") -> Optional[tuple[str, str, str]]:
    """
    Extract (pdb_filename, guid_age_str, age) from the IMAGE_DEBUG_DIRECTORY.
    Returns None if no CodeView/PDB debug entry is found.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return None
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        # Type 2 == IMAGE_DEBUG_TYPE_CODEVIEW
        if dbg.struct.Type != 2:
            continue
        raw_off  = dbg.struct.PointerToRawData
        raw_size = dbg.struct.SizeOfData
        data = pe.__data__[raw_off: raw_off + raw_size]
        if len(data) < 24 or data[:4] not in (b"RSDS", b"NB10"):
            continue
        if data[:4] == b"RSDS":
            # RSDS format: signature(4) + GUID(16) + age(4) + pdb_name
            guid_bytes = data[4:20]
            age = struct.unpack_from("<I", data, 20)[0]
            pdb_name = data[24:].rstrip(b"\x00").decode(errors="replace")
            pdb_name = os.path.basename(pdb_name)
            # Format GUID as Microsoft expects: {AABBCCDD-EEFF-...} without dashes
            g = guid_bytes
            guid_str = (
                f"{int.from_bytes(g[0:4],'little'):08X}"
                f"{int.from_bytes(g[4:6],'little'):04X}"
                f"{int.from_bytes(g[6:8],'little'):04X}"
                + g[8:10].hex().upper()
                + g[10:16].hex().upper()
                + f"{age:X}"
            )
            return pdb_name, guid_str, age
    return None


def download_pdb(pdb_name: str, guid_age: str) -> Optional[Path]:
    """Download PDB from the Microsoft symbol server; return local path or None."""
    if not HAS_REQUESTS:
        return None
    dest_dir = SYMBOL_CACHE_DIR / guid_age
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / pdb_name
    if dest_file.exists():
        print(f"[+] PDB cache hit: {dest_file}")
        return dest_file

    url = f"{MS_SYMBOL_SERVER}/{pdb_name}/{guid_age}/{pdb_name}"
    print(f"[*] Downloading PDB from {url} …")
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            dest_file.write_bytes(resp.content)
            print(f"[+] Saved PDB → {dest_file}")
            return dest_file
        else:
            print(f"[-] Symbol server returned HTTP {resp.status_code}")
    except requests.RequestException as exc:
        print(f"[-] Download failed: {exc}")
    return None


def build_symbol_table(pdb_path: Path) -> dict[int, str]:
    """
    Parse the PDB and return {RVA: symbol_name} using pdbparse.
    Falls back to an empty dict if pdbparse is unavailable or parsing fails.
    """
    sym_table: dict[int, str] = {}
    if not HAS_PDBPARSE or pdb_path is None:
        return sym_table
    try:
        pdb = pdbparse.parse(str(pdb_path))
        # GSI / public symbols stream
        gsym = pdb.STREAM_GSYM
        for sym in gsym.globals:
            if hasattr(sym, "name") and hasattr(sym, "offset"):
                sym_table[sym.offset] = sym.name
        print(f"[+] Loaded {len(sym_table)} symbols from PDB")
    except Exception as exc:
        print(f"[WARN] PDB parse error: {exc}")
    return sym_table


def find_enclosing_symbol(rva: int, sym_table: dict[int, str]) -> str:
    """
    Find the nearest symbol whose RVA is ≤ the given RVA.
    Returns '<unknown>' if the table is empty or nothing precedes the RVA.
    """
    if not sym_table:
        return "<unknown>"
    candidates = {addr: name for addr, name in sym_table.items() if addr <= rva}
    if not candidates:
        return "<unknown>"
    best_rva = max(candidates)
    offset   = rva - best_rva
    name     = candidates[best_rva]
    return f"{name}+0x{offset:X}" if offset else name


# ── core analysis ─────────────────────────────────────────────────────────────

def disassemble_and_find_calls(
    pe: "pefile.PE",
    target_iat_vas: dict[str, int],
    sym_table: dict[int, str],
    verbose: bool = False,
) -> list[dict]:
    """
    Walk every executable section, disassemble it with Capstone, and collect
    every CALL instruction whose target resolves to one of target_iat_vas.

    Returns a list of result dicts, one per call site.
    """
    machine = get_machine_type(pe)
    if machine == "x64":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    image_base = pe.OPTIONAL_HEADER.ImageBase
    results    = []

    # Pre-build a reverse map: IAT VA → function name
    iat_va_to_name: dict[int, str] = {va: name for name, va in target_iat_vas.items()}

    for section in pe.sections:
        # Only look at executable sections
        if not (section.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        sec_name = section.Name.rstrip(b"\x00").decode(errors="replace")
        sec_va   = image_base + section.VirtualAddress
        sec_data = section.get_data()

        if verbose:
            print(f"  [section] {sec_name}  VA=0x{sec_va:X}  size={len(sec_data):#x}")

        for insn in md.disasm(sec_data, sec_va):
            # We only care about CALL instructions
            if insn.id not in (capstone.x86.X86_INS_CALL,):
                continue

            call_target_va: Optional[int] = None

            # Direct CALL rel32 — operand is an absolute VA after Capstone resolves it
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                call_target_va = insn.operands[0].imm

            # Indirect CALL [mem] — e.g. CALL QWORD PTR [rip+offset] or CALL [abs]
            elif insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
                mem = insn.operands[0].mem
                # RIP-relative (x64 typical IAT pattern)
                if mem.base == capstone.x86.X86_REG_RIP:
                    call_target_va = insn.address + insn.size + mem.disp
                elif mem.base == 0 and mem.index == 0:
                    call_target_va = mem.disp & 0xFFFFFFFFFFFFFFFF

            if call_target_va is None:
                continue

            # Check whether this VA is one of our target IAT slots
            matched_fn = iat_va_to_name.get(call_target_va)
            if matched_fn is None:
                continue

            call_rva     = insn.address - image_base
            caller_name  = find_enclosing_symbol(call_rva, sym_table)
            hex_bytes    = " ".join(f"{b:02X}" for b in insn.bytes)

            results.append({
                "target_function": matched_fn,
                "call_va":         insn.address,
                "call_rva":        call_rva,
                "section":         sec_name,
                "caller_function": caller_name,
                "instruction":     f"{insn.mnemonic} {insn.op_str}",
                "bytes":           hex_bytes,
            })

    return results


def print_report(results: list[dict], dll_path: str, sym_available: bool) -> None:
    """Pretty-print the per-DLL analysis report to stdout."""
    from collections import Counter, defaultdict

    sep = "─" * 72
    print(f"\n{'═'*72}")
    print(f"  CreateFile[W/A] Call-Site Analysis")
    print(f"  Target : {dll_path}")
    print(f"  Symbols: {'PDB (pdbparse)' if sym_available else 'heuristic / unavailable'}")
    print(f"{'═'*72}\n")

    counts = Counter(r["target_function"] for r in results)
    print("  Call counts:")
    for fn, count in sorted(counts.items()):
        print(f"    {fn:<20}  {count} call(s)")
    print(f"\n  Total: {len(results)} call site(s) across "
          f"{len(set(r['caller_function'] for r in results))} function(s)\n")
    print(sep)

    by_caller: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_caller[r["caller_function"]].append(r)

    for caller, calls in sorted(by_caller.items()):
        print(f"\n  Caller: {caller}")
        print(f"  {'─'*60}")
        for c in calls:
            print(f"    Target   : {c['target_function']}")
            print(f"    Address  : 0x{c['call_va']:X}  (RVA 0x{c['call_rva']:X})")
            print(f"    Section  : {c['section']}")
            print(f"    Instr    : {c['instruction']}")
            print(f"    Bytes    : {c['bytes']}")
            print()
    print(sep)


def print_summary(all_results: dict[str, list[dict]]) -> None:
    """Print a cross-DLL summary table after all files have been scanned."""
    from collections import Counter

    total_calls  = sum(len(v) for v in all_results.values())
    dlls_with_hits = [p for p, r in all_results.items() if r]
    dlls_skipped   = [p for p, r in all_results.items() if not r]

    print(f"\n{'╔'+'═'*70+'╗'}")
    print(f"{'║':1}{'  FOLDER SCAN SUMMARY':^70}{'║':1}")
    print(f"{'╚'+'═'*70+'╝'}")
    print(f"  DLLs scanned  : {len(all_results)}")
    print(f"  DLLs with hits: {len(dlls_with_hits)}")
    print(f"  DLLs skipped  : {len(dlls_skipped)}  (no CreateFile imports)")
    print(f"  Total calls   : {total_calls}\n")

    if not dlls_with_hits:
        print("  No CreateFile[W/A] call sites found in any DLL.")
        return

    # Per-DLL hit table
    col_dll  = 46
    col_w    = 10
    col_a    = 10
    col_tot  = 8
    header = (f"  {'DLL':<{col_dll}} {'CreateFileW':>{col_w}} "
              f"{'CreateFileA':>{col_a}} {'Total':>{col_tot}}")
    print(header)
    print(f"  {'─'*{col_dll}} {'─'*{col_w}} {'─'*{col_a}} {'─'*{col_tot}}")

    for dll_path in sorted(dlls_with_hits):
        results = all_results[dll_path]
        counts  = Counter(r["target_function"] for r in results)
        w       = counts.get("CreateFileW", 0)
        a       = counts.get("CreateFileA", 0)
        name    = Path(dll_path).name
        # Truncate long names with ellipsis
        if len(name) > col_dll:
            name = name[:col_dll - 1] + "…"
        print(f"  {name:<{col_dll}} {w:>{col_w}} {a:>{col_a}} {w+a:>{col_tot}}")

    print()


def analyze_dll(
    dll_path: Path,
    no_download: bool,
    verbose: bool,
) -> tuple[list[dict], bool]:
    """
    Run the full analysis pipeline on a single DLL.
    Returns (results, sym_available).  Raises on fatal PE errors.
    """
    print(f"\n[*] Loading PE: {dll_path}")
    pe = pefile.PE(str(dll_path), fast_load=False)
    pe.parse_data_directories()

    arch = get_machine_type(pe)
    print(f"[*] Architecture: {arch}")

    import_map = build_import_map(pe)
    target_iat = {fn: va for fn, va in import_map.items() if fn in TARGET_FUNCTIONS}

    if not target_iat:
        print(f"[-] No CreateFile imports found in {dll_path.name} — skipping.")
        return [], False

    print(f"[+] Found IAT entries: {list(target_iat.keys())}")
    for fn, va in target_iat.items():
        print(f"      {fn}  →  IAT VA 0x{va:X}")

    sym_table: dict[int, str] = {}
    dbg_info = extract_debug_info(pe)
    if dbg_info:
        pdb_name, guid_age, age = dbg_info
        print(f"[*] Debug info: {pdb_name}  GUID+Age={guid_age}")
        if not no_download:
            pdb_path = download_pdb(pdb_name, guid_age)
            if pdb_path:
                sym_table = build_symbol_table(pdb_path)
    else:
        print("[WARN] No CodeView/PDB debug directory found in the DLL")

    sym_available = bool(sym_table)

    print("[*] Disassembling executable sections …")
    results = disassemble_and_find_calls(pe, target_iat, sym_table, verbose=verbose)
    print(f"[+] Found {len(results)} call site(s)")

    return results, sym_available



def collect_dlls(target: Path, recursive: bool) -> list[Path]:
    """Return a sorted list of .dll paths under target (file or directory)."""
    if target.is_file():
        return [target]
    if not target.is_dir():
        sys.exit(f"Path is neither a file nor a directory: {target}")
    pattern = "**/*.dll" if recursive else "*.dll"
    dlls = sorted(target.glob(pattern))
    if not dlls:
        sys.exit(f"No .dll files found in {target}"
                 + (" (searched recursively)" if recursive else
                    " (use --recursive to search subdirectories)"))
    return dlls


def collect_dlls_from_list(list_file: Path) -> list[Path]:
    """
    Read a plain-text file produced by enum_system_dlls.py or
    enum_service_dlls.py (one absolute DLL path per line, # comments ignored)
    and return a sorted, deduplicated list of Path objects that exist on disk.

    Blank lines, comment lines, non-.dll extensions, and missing paths are all
    skipped with a warning so a stale list never aborts the run.
    """
    if not list_file.exists():
        sys.exit(f"DLL list file not found: {list_file}")

    raw_lines = list_file.read_text(encoding="utf-8", errors="replace").splitlines()
    seen:    set[Path] = set()
    result:  list[Path] = []
    missing: list[str]  = []

    for lineno, line in enumerate(raw_lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        p = Path(stripped)
        if p.suffix.lower() != ".dll":
            continue          # skip non-DLL entries silently
        if p in seen:
            continue          # deduplicate
        seen.add(p)
        if not p.exists():
            missing.append(f"  line {lineno}: {stripped}")
            continue
        result.append(p)

    if missing:
        print(f"[WARN] {len(missing)} path(s) in the list were not found on disk "
              f"and will be skipped:")
        for m in missing[:10]:
            print(m)
        if len(missing) > 10:
            print(f"  ... and {len(missing) - 10} more")

    if not result:
        sys.exit("No valid, existing DLL paths found in the list file.")

    return sorted(result, key=lambda p: p.name.lower())


# -- entry point ---------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze CreateFileW/A call sites in a DLL, folder, or DLL list file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Input modes (use one):\n"
            "  target               Single .dll or folder of DLLs\n"
            "  --dll-list FILE      Text file with one DLL path per line\n"
            "                       (output of enum_system_dlls.py or\n"
            "                        enum_service_dlls.py --output)\n"
            "\n"
            "Examples:\n"
            "  python analyze_createfile.py C:\\Windows\\System32\\foo.dll\n"
            "  python analyze_createfile.py C:\\Windows\\System32\\ --recursive\n"
            "  python analyze_createfile.py --dll-list system_dlls.txt\n"
            "  python enum_service_dlls.py --output svc.txt\n"
            "  python analyze_createfile.py --dll-list svc.txt"
        ),
    )

    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument(
        "target",
        nargs="?",
        help="Path to a single .dll file OR a folder containing .dll files.",
    )
    src_group.add_argument(
        "--dll-list", dest="dll_list", metavar="FILE",
        help=(
            "Plain-text file with one DLL path per line. "
            "Compatible with output from enum_system_dlls.py and "
            "enum_service_dlls.py --output."
        ),
    )

    parser.add_argument(
        "--recursive", "-r", action="store_true",
        help="Scan subdirectories recursively (folder input only).",
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print extra diagnostic information.")
    parser.add_argument("--json", dest="json_out", metavar="FILE",
                        help="Write all results as JSON to FILE.")
    parser.add_argument("--no-download", action="store_true",
                        help="Skip PDB download (use cached or skip symbols).")
    args = parser.parse_args()

    # -- resolve DLL list --
    if args.dll_list:
        list_file = Path(args.dll_list)
        print(f"[*] Reading DLL list from: {list_file}")
        dll_paths = collect_dlls_from_list(list_file)
        print(f"[+] {len(dll_paths)} valid DLL path(s) loaded from list")
        is_multi = True
    else:
        target    = Path(args.target)
        dll_paths = collect_dlls(target, args.recursive)
        is_multi  = target.is_dir()
        if is_multi:
            print(f"[*] Found {len(dll_paths)} DLL(s) in '{target}'"
                  + (" (recursive)" if args.recursive else ""))

    # -- scan each DLL --
    all_results: dict[str, list[dict]] = {}
    errors: list[tuple[str, str]] = []
    total = len(dll_paths)

    for i, dll_path in enumerate(dll_paths, 1):
        if is_multi or args.dll_list:
            print(f"\n[{i}/{total}] -- {dll_path.name} ----------------------")
        try:
            results, sym_available = analyze_dll(dll_path, args.no_download, args.verbose)
            all_results[str(dll_path)] = results
            if results:
                print_report(results, str(dll_path), sym_available)
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            print(f"[ERROR] Failed to analyze {dll_path.name}: {msg}")
            errors.append((str(dll_path), msg))
            all_results[str(dll_path)] = []

    # -- summary (shown for multi-DLL runs) --
    if is_multi or args.dll_list:
        print_summary(all_results)

    if errors:
        print(f"[!] {len(errors)} DLL(s) could not be analyzed:")
        for path, err in errors:
            print(f"      {Path(path).name}: {err}")

    # -- optional JSON output --
    if args.json_out:
        out_path = Path(args.json_out)
        flat = []
        for dll_path, results in all_results.items():
            for r in results:
                flat.append({"dll": dll_path, **r})
        out_path.write_text(json.dumps(flat, indent=2))
        print(f"\n[+] JSON results written to {out_path}  ({len(flat)} records)")


if __name__ == "__main__":
    main()
