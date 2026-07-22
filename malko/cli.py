"""Command-line interface for mal-ko.

Subcommands:
  scan-deps [path]    check dependency manifests against OSV.dev + CISA KEV
  scan-system         check installed software against NVD + CISA KEV
  scan-files <path>   hash files and look them up in MalwareBazaar
  scan-persist        check autostart/persistence entries (report only)
  kev-list            list recent CISA KEV entries
  monitor <path...>   real-time watcher: blocklist + quarantine
  blocklist-update    refresh the local malware hash blocklist
  quarantine          list / restore quarantined files
  dashboard           web UI on 127.0.0.1 (status, events, actions)
"""

import argparse
import sys

from . import blocklist, monitor, persist, quarantine, report, state, tui
from .http import SourceError
from .scanners import deps, files, system
from .sources import kev


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mal-ko",
        description=(
            "Defensive threat-intel aggregator scanner: checks dependencies, "
            "installed software and files against open vulnerability/malware "
            "databases (OSV.dev, NVD, CISA KEV, MalwareBazaar)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_deps = sub.add_parser(
        "scan-deps", help="scan dependency manifests (requirements.txt, package.json)"
    )
    p_deps.add_argument("path", nargs="?", default=".", help="directory to scan (default: cwd)")
    p_deps.add_argument("--json", metavar="FILE", help="save machine-readable results to FILE")
    p_deps.set_defaults(func=cmd_scan_deps)

    p_sys = sub.add_parser("scan-system", help="scan installed software (NVD + CISA KEV)")
    p_sys.add_argument(
        "--max-products",
        type=int,
        default=30,
        help="max number of installed products to check (default: 30)",
    )
    p_sys.add_argument("--json", metavar="FILE", help="save machine-readable results to FILE")
    p_sys.set_defaults(func=cmd_scan_system)

    p_files = sub.add_parser("scan-files", help="hash files and check them in MalwareBazaar")
    p_files.add_argument("paths", nargs="+", help="files or directories (recursive)")
    p_files.add_argument("--json", metavar="FILE", help="save machine-readable results to FILE")
    p_files.add_argument(
        "--quarantine",
        action="store_true",
        help="move confirmed malware hits into quarantine",
    )
    p_files.add_argument(
        "--no-heuristics",
        action="store_true",
        help="disable heuristic static analysis (hash lookup only)",
    )
    p_files.set_defaults(func=cmd_scan_files)

    p_persist = sub.add_parser(
        "scan-persist",
        help="check autostart/persistence entries (Run keys, startup, tasks)",
    )
    p_persist.add_argument("--json", metavar="FILE", help="save machine-readable results to FILE")
    p_persist.set_defaults(func=cmd_scan_persist)

    p_kev = sub.add_parser("kev-list", help="list recent CISA KEV entries")
    p_kev.add_argument(
        "--since", metavar="YYYY-MM-DD", help="only entries added on/after this date"
    )
    p_kev.add_argument(
        "--limit", type=int, default=20, help="max entries to show (default: 20)"
    )
    p_kev.set_defaults(func=cmd_kev_list)

    p_mon = sub.add_parser(
        "monitor", help="real-time watcher: hash new/changed files, quarantine malware"
    )
    p_mon.add_argument("paths", nargs="+", help="directories to watch (recursive)")
    p_mon.add_argument(
        "--interval", type=float, default=monitor.DEFAULT_INTERVAL,
        help="seconds between snapshots (default: %(default)s)",
    )
    p_mon.add_argument(
        "--max-size", type=int, default=monitor.DEFAULT_MAX_SIZE_MB, metavar="MB",
        help="skip files larger than this many MB (default: %(default)s)",
    )
    p_mon.add_argument(
        "--live-api", action="store_true",
        help="also query the MalwareBazaar live API for unknown files "
             "(requires MB_AUTH_KEY; default: off)",
    )
    p_mon.add_argument("--verbose", action="store_true", help="report clean files too")
    p_mon.add_argument(
        "--no-heuristics",
        action="store_true",
        help="disable heuristic static analysis (blocklist only)",
    )
    p_mon.add_argument(
        "--proc", action="store_true",
        help="also check executables of newly started processes (alert only, never kill)",
    )
    p_mon.set_defaults(func=cmd_monitor)

    p_bl = sub.add_parser(
        "blocklist-update", help="download/refresh the local malware hash blocklist"
    )
    p_bl.set_defaults(func=cmd_blocklist_update)

    p_q = sub.add_parser("quarantine", help="manage quarantined files")
    q_sub = p_q.add_subparsers(dest="quarantine_command", required=True)
    q_list = q_sub.add_parser("list", help="list quarantined files")
    q_list.set_defaults(func=cmd_quarantine_list)
    q_restore = q_sub.add_parser("restore", help="restore a quarantined file by id")
    q_restore.add_argument("id", help="quarantine entry id (see 'quarantine list')")
    q_restore.add_argument(
        "--force", action="store_true", help="overwrite the destination if it exists"
    )
    q_restore.set_defaults(func=cmd_quarantine_restore)

    p_dash = sub.add_parser(
        "dashboard", help="web dashboard on 127.0.0.1 (status, events, quarantine)"
    )
    p_dash.add_argument(
        "--port", type=int, default=8888, help="port to bind (default: 8888)"
    )
    p_dash.add_argument(
        "--no-browser", action="store_true", help="do not open the browser"
    )
    p_dash.set_defaults(func=cmd_dashboard)
    return parser


def cmd_scan_deps(args):
    tui.print_banner()
    result = deps.scan(args.path)
    packages = result["packages"]
    state.add_findings(result["findings"], source="scan-deps")
    state.set_last_scan(
        "scan-deps",
        f"{len(packages)} package(s), {len(result['findings'])} finding(s)",
    )
    state.event(
        "info",
        f"scan-deps {args.path}: {len(packages)} package(s), "
        f"{len(result['findings'])} finding(s)",
        "scan",
    )
    extra = [f"Scanned {len(packages)} pinned package(s) under {args.path}."]
    report.print_report("Dependency scan (OSV.dev + CISA KEV)", result["findings"], extra)
    if args.json:
        report.save_json(
            args.json,
            {
                "scan": "deps",
                "path": args.path,
                "packages": [
                    {"name": n, "ecosystem": e, "version": v, "manifest": m}
                    for n, e, v, m in packages
                ],
                "findings": result["findings"],
                "warnings": result["warnings"],
            },
        )
    return 1 if result["findings"] else 0


def cmd_scan_system(args):
    tui.print_banner()
    result = system.scan(max_products=args.max_products)
    if result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 2
    state.add_findings(result["findings"], source="scan-system")
    state.set_last_scan(
        "scan-system",
        f"{len(result['products'])} product(s), {len(result['findings'])} finding(s)",
    )
    state.event(
        "info",
        f"scan-system: {len(result['products'])} product(s), "
        f"{len(result['findings'])} finding(s)",
        "scan",
    )
    extra = [f"Checked {len(result['products'])} installed product(s)."]
    if result.get("note"):
        extra.append(result["note"])
    report.print_report("System scan (NVD + CISA KEV)", result["findings"], extra)
    if args.json:
        report.save_json(
            args.json,
            {
                "scan": "system",
                "products": result["products"],
                "findings": result["findings"],
            },
        )
    return 1 if result["findings"] else 0


def cmd_scan_files(args):
    tui.print_banner()
    result = files.scan(args.paths, use_heuristics=not args.no_heuristics)
    state.bump("files_scanned", len(result["files"]))
    if args.quarantine:
        for finding in result["findings"]:
            # Only confirmed hits (known malware / EICAR) are quarantined;
            # heuristic SUSPICIOUS findings are warnings, not proof.
            if finding["severity"] != "CRITICAL":
                continue
            details = finding["details"]
            record = quarantine.quarantine_file(
                details["path"], details["sha256"], source="scan-files"
            )
            details["quarantine_id"] = record["id"]
            print(f"quarantined as {record['id']}: {details['path']}")
    state.add_findings(result["findings"], source="scan-files")
    state.set_last_scan(
        "scan-files",
        f"{len(result['files'])} file(s), {len(result['findings'])} finding(s)",
    )
    state.event(
        "info",
        f"scan-files: {len(result['files'])} file(s), "
        f"{len(result['findings'])} finding(s)",
        "scan",
    )
    extra = [f"Hashed and checked {len(result['files'])} file(s)."]
    report.print_report("File scan (MalwareBazaar)", result["findings"], extra)
    if args.json:
        report.save_json(
            args.json,
            {"scan": "files", "files": result["files"], "findings": result["findings"]},
        )
    return 1 if result["findings"] else 0


def cmd_scan_persist(args):
    tui.print_banner()
    result = persist.scan()
    state.add_findings(result["findings"], source="scan-persist")
    state.set_last_scan(
        "scan-persist",
        f"{len(result['entries'])} entries, {len(result['findings'])} finding(s)",
    )
    state.event(
        "info",
        f"scan-persist: {len(result['entries'])} entries, "
        f"{len(result['findings'])} finding(s)",
        "scan",
    )
    extra = [f"Checked {len(result['entries'])} persistence entries."]
    extra.extend(f"note: {note}" for note in result["notes"])
    report.print_report(
        "Persistence scan (autoruns, detection only)", result["findings"], extra
    )
    if args.json:
        report.save_json(
            args.json,
            {
                "scan": "persist",
                "entries": result["entries"],
                "findings": result["findings"],
                "notes": result["notes"],
            },
        )
    return 1 if result["findings"] else 0


def cmd_monitor(args):
    tui.print_banner()
    hashes, refreshed = blocklist.ensure_fresh()
    if refreshed:
        print(f"blocklist refreshed: {len(hashes)} hashes.")
        state.blocklist_updated(len(hashes))
    mon = monitor.Monitor(
        args.paths,
        interval=args.interval,
        max_size_mb=args.max_size,
        live_api=args.live_api,
        verbose=args.verbose,
        use_proc=args.proc,
        use_heuristics=not args.no_heuristics,
        hashes=hashes,
    )
    mon.run()
    return 0


def cmd_blocklist_update(args):
    count = blocklist.update()
    state.blocklist_updated(count)
    state.event("info", f"blocklist updated: {count} hashes", "blocklist")
    print(f"blocklist updated: {count} SHA-256 hashes -> {blocklist.blocklist_path()}")
    return 0


def cmd_quarantine_list(args):
    entries = quarantine.list_entries()
    if not entries:
        print("quarantine is empty.")
        return 0
    print(f"\n=== Quarantine ({len(entries)} entr{'y' if len(entries) == 1 else 'ies'}) ===\n")
    for record in entries:
        missing = "" if record.get("quarantined_file_exists") else "  [FILE MISSING]"
        print(f"{record['id']}{missing}")
        print(f"    original: {record.get('original_path', '?')}")
        print(
            f"    sha256: {record.get('sha256', '?')}  "
            f"source: {record.get('source', '?')}  time: {record.get('timestamp', '?')}"
        )
    print()
    return 0


def cmd_quarantine_restore(args):
    dest = quarantine.restore(args.id, force=args.force)
    print(f"restored: {dest}")
    return 0


def cmd_dashboard(args):
    from . import web

    print("Запуск веб-панели mal-ko. Командная строка: mal-ko --help")
    print("Starting the mal-ko web dashboard. For CLI usage: mal-ko --help",
          flush=True)
    return web.serve(port=args.port, open_browser=not args.no_browser)


def cmd_kev_list(args):
    entries = kev.load_catalog()
    if args.since:
        entries = kev.entries_since(entries, args.since)
    entries = sorted(entries, key=lambda e: e.get("dateAdded", ""), reverse=True)
    shown = entries[: args.limit]
    print(f"\n=== CISA KEV entries ({len(entries)} matching, showing {len(shown)}) ===\n")
    for entry in shown:
        print(
            f"{entry.get('dateAdded', '?')}  {entry.get('cveID', '?')}  "
            f"{entry.get('vendorProject', '')} {entry.get('product', '')}"
        )
        print(f"    {entry.get('vulnerabilityName', '')}")
        if entry.get("dueDate"):
            print(f"    remediation due: {entry['dueDate']}")
    print()
    return 0


def _default_to_dashboard():
    """No-args launches default to the dashboard for frozen exes
    (double-click) and interactive consoles; piped invocations keep the
    classic argparse error."""
    if getattr(sys, "frozen", False):
        return True
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (ValueError, OSError):
        return False


def resolve_argv(argv):
    """Apply the no-arguments default (launch the dashboard)."""
    if argv:
        return argv
    return ["dashboard"] if _default_to_dashboard() else argv


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = resolve_argv(list(argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except quarantine.QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
