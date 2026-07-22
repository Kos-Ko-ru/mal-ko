"""Optional process monitor for mal-ko (enabled with --proc).

Polls running processes (Windows: tasklist + wmic/PowerShell; Linux:
/proc). For newly seen PIDs it resolves the executable path, hashes it
and checks the local blocklist. Malicious executables trigger a loud
alert and a log line — processes are NEVER killed automatically.

Everything here is best-effort: unresolvable paths (permissions,
short-lived processes) are skipped quietly.
"""

import csv
import io
import os
import platform
import shutil
import subprocess
from pathlib import Path

from .scanners.files import sha256_file


def _snapshot_windows():
    """{pid: exe_path_or_None} from tasklist; paths resolved lazily later."""
    pids = {}
    try:
        out = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        for row in csv.reader(io.StringIO(out.stdout)):
            if len(row) >= 2:
                try:
                    pids[int(row[1])] = None
                except ValueError:
                    continue
    except (OSError, subprocess.SubprocessError):
        pass
    return pids


def _snapshot_linux():
    """{pid: exe_path} from /proc (exe resolved via readlink)."""
    pids = {}
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pids[int(entry.name)] = os.readlink(entry / "exe")
        except OSError:
            pids[int(entry.name)] = None
    return pids


def snapshot_processes():
    """Return {pid: exe_path_or_None} for the current OS."""
    system = platform.system()
    if system == "Windows":
        return _snapshot_windows()
    if system == "Linux":
        return _snapshot_linux()
    return {}


def _exe_path_windows(pid):
    """Resolve the executable path of a Windows PID (wmic, else PowerShell)."""
    if shutil.which("wmic"):
        try:
            out = subprocess.run(
                ["wmic", "process", "where", f"processid={pid}",
                 "get", "ExecutablePath", "/format:list"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("ExecutablePath="):
                    return line.split("=", 1)[1] or None
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Path"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        path = out.stdout.strip()
        return path or None
    except (OSError, subprocess.SubprocessError):
        return None


def resolve_exe_path(pid):
    """Best-effort executable path for a PID; None when unresolvable."""
    if platform.system() == "Windows":
        return _exe_path_windows(pid)
    if platform.system() == "Linux":
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
    return None


def check_new_processes(seen, hashes, alert, verbose=False):
    """Check PIDs that appeared since the last call.

    `seen` is a {pid: path} dict updated in place. Malicious executables
    are reported via `alert(message)`; they are not killed.
    """
    current = snapshot_processes()
    for pid in list(seen):
        if pid not in current:
            del seen[pid]  # process exited; forget it
    for pid in current:
        if pid in seen:
            continue
        exe = current[pid] or resolve_exe_path(pid)
        seen[pid] = exe
        if not exe:
            if verbose:
                print(f"proc: pid {pid}: executable path not resolvable, skipped")
            continue
        try:
            digest = sha256_file(exe)
        except OSError:
            continue
        if digest in hashes:
            alert(
                f"MALICIOUS PROCESS: pid={pid} exe={exe} sha256={digest} "
                f"(blocklist match; NOT killed - inspect and stop it manually)"
            )
        elif verbose:
            print(f"proc: pid {pid} clean: {exe}")
