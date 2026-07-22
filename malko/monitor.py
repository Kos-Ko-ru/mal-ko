"""Real-time filesystem monitor (polling-based, stdlib only).

Takes recursive snapshots of the watched directories
({path: (mtime_ns, size)}) and diffs them every `interval` seconds.
Created/modified files are hashed (streamed SHA-256) and checked
against the local blocklist. Malicious files are quarantined
immediately, alerted loudly and logged to ~/.malko/monitor.log.

This is hash-reputation protection only: no heuristics, no kernel
driver. Unknown malware is NOT detected.
"""

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import blocklist, heuristics, quarantine, state
from .scanners.files import sha256_file
from .sources import malwarebazaar

DEFAULT_INTERVAL = 2.0
DEFAULT_MAX_SIZE_MB = 100


def monitor_log_path():
    override = os.environ.get("MALKO_MONITOR_LOG")
    if override:
        return Path(override)
    return Path.home() / ".malko" / "monitor.log"


def log_line(message, log_path=None):
    """Append a timestamped line to the monitor log file."""
    log_path = log_path or monitor_log_path()
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"{stamp} {message}\n")
    except OSError:
        pass


def snapshot(paths, skip_dirs=()):
    """Recursive {str(path): (mtime_ns, size)} map of all files.

    Unreadable entries and anything under skip_dirs are ignored.
    """
    skip = tuple(str(Path(d).resolve()) for d in skip_dirs)
    state = {}
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            print(f"warning: path not found, skipped: {raw}", file=sys.stderr)
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for item in candidates:
            try:
                resolved = str(item.resolve())
                if skip and resolved.startswith(skip):
                    continue
                if not item.is_file():
                    continue
                st = item.stat()
                state[resolved] = (st.st_mtime_ns, st.st_size)
            except OSError:
                continue
    return state


def diff(old, new):
    """Compare two snapshots -> (created, modified, deleted) path lists."""
    created = [p for p in new if p not in old]
    deleted = [p for p in old if p not in new]
    modified = [p for p in new if p in old and new[p] != old[p]]
    return created, modified, deleted


class Monitor:
    """Polling watcher with blocklist verdicts and quarantine."""

    def __init__(self, paths, *, interval=DEFAULT_INTERVAL,
                 max_size_mb=DEFAULT_MAX_SIZE_MB, live_api=False,
                 verbose=False, use_proc=False, use_heuristics=True,
                 hashes=None, log_path=None):
        self.paths = paths
        self.interval = interval
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.live_api = live_api
        self.verbose = verbose
        self.use_proc = use_proc
        self.use_heuristics = use_heuristics
        self.hashes = hashes if hashes is not None else blocklist.load()
        self.log_path = log_path or monitor_log_path()
        self.skip_dirs = (quarantine.quarantine_dir(),)
        self.stats = {"scanned": 0, "malicious": 0, "quarantined": 0,
                      "suspicious": 0, "deleted": 0}

    def alert(self, message, level="critical"):
        """Prominent alert: stdout banner + log file + dashboard event."""
        banner = f"!!! {message}"
        print(f"\n{'=' * 70}\n{banner}\n{'=' * 70}", flush=True)
        log_line(message, self.log_path)
        state.event(level, message, "alert")

    def check_file(self, path):
        """Hash one file and act on the verdict."""
        try:
            size = os.path.getsize(path)
        except OSError:
            return  # vanished between snapshot and check
        if size > self.max_size_bytes:
            if self.verbose:
                print(f"skipped (too large): {path}")
            return
        try:
            digest = sha256_file(path)
        except OSError as exc:
            if self.verbose:
                print(f"skipped (unreadable: {exc}): {path}")
            return
        self.stats["scanned"] += 1
        state.bump("files_scanned")

        malicious = digest in self.hashes
        signature = "blocklist"
        if not malicious and self.live_api and os.environ.get("MB_AUTH_KEY"):
            try:
                result = malwarebazaar.lookup_hash(digest)
                malicious = result["status"] == "ok"
                signature = result.get("signature", "MalwareBazaar")
            except Exception as exc:  # noqa: BLE001 - live lookup is best-effort
                if self.verbose:
                    print(f"warning: live API lookup failed for {path}: {exc}",
                          file=sys.stderr)

        # Heuristic layer: EICAR counts as confirmed; SUSPICIOUS(+)
        # raises a loud warning but is NOT quarantined (false positives
        # are normal for static heuristics).
        if not malicious and self.use_heuristics and heuristics.should_analyze(path):
            result = heuristics.analyze(path)
            if result["verdict"] == "EICAR-TEST":
                malicious = True
                signature = "EICAR-TEST"
            elif result["verdict"] in ("SUSPICIOUS", "SUSPICIOUS+"):
                self.stats["suspicious"] += 1
                rules = ", ".join(h["id"] for h in result["rules"])
                state.add_findings(
                    [
                        {
                            "id": f"HEUR-{digest[:12]}",
                            "severity": "SUSPICIOUS",
                            "title": (
                                f"{result['verdict']} file (score "
                                f"{result['score']}): {path} - {rules}"
                            ),
                            "details": {
                                "path": path,
                                "sha256": digest,
                                "score": result["score"],
                                "heuristics": result["rules"],
                            },
                        }
                    ],
                    source="monitor",
                )
                self.alert(
                    f"SUSPICIOUS FILE ({result['verdict']}, score "
                    f"{result['score']}): {path} sha256={digest} rules: {rules} "
                    f"(heuristic warning - NOT quarantined)",
                    level="warning",
                )

        if malicious:
            self.stats["malicious"] += 1
            state.add_findings(
                [
                    {
                        "id": digest,
                        "severity": "CRITICAL",
                        "title": f"malicious file ({signature}): {path}",
                        "details": {"path": path, "sha256": digest},
                    }
                ],
                source="monitor",
            )
            try:
                record = quarantine.quarantine_file(path, digest, source="monitor")
                self.stats["quarantined"] += 1
                self.alert(
                    f"MALICIOUS FILE ({signature}): {path} sha256={digest} "
                    f"-> quarantined as {record['id']}"
                )
            except quarantine.QuarantineError as exc:
                self.alert(
                    f"MALICIOUS FILE ({signature}): {path} sha256={digest} "
                    f"-> QUARANTINE FAILED: {exc}"
                )
        elif self.verbose:
            print(f"clean: {path}")

    def run(self):
        """Watch until Ctrl+C. Prints stats on shutdown."""
        from . import procmon  # local import: only needed when running

        print(f"monitoring {len(self.paths)} path(s), "
              f"blocklist: {len(self.hashes)} hashes, "
              f"interval: {self.interval}s. Press Ctrl+C to stop.")
        state.event(
            "info",
            f"monitor started on {len(self.paths)} path(s), "
            f"blocklist {len(self.hashes)} hashes",
            "monitor",
        )
        prev = snapshot(self.paths, self.skip_dirs)
        print(f"initial snapshot: {len(prev)} file(s).", flush=True)
        seen_processes = procmon.snapshot_processes() if self.use_proc else {}
        try:
            while True:
                time.sleep(self.interval)
                current = snapshot(self.paths, self.skip_dirs)
                created, modified, deleted = diff(prev, current)
                prev = current
                self.stats["deleted"] += len(deleted)
                for path in created + modified:
                    self.check_file(path)
                if self.use_proc:
                    procmon.check_new_processes(
                        seen_processes, self.hashes, self.alert, self.verbose
                    )
        except KeyboardInterrupt:
            state.event(
                "info",
                f"monitor stopped: scanned={self.stats['scanned']}, "
                f"malicious={self.stats['malicious']}, "
                f"quarantined={self.stats['quarantined']}",
                "monitor",
            )
            print(
                f"\nmonitor stopped. stats: scanned={self.stats['scanned']}, "
                f"malicious={self.stats['malicious']}, "
                f"suspicious={self.stats['suspicious']}, "
                f"quarantined={self.stats['quarantined']}, "
                f"deleted={self.stats['deleted']}. "
                f"log: {self.log_path}"
            )
