"""Persistence/autorun scanner (detection and reporting ONLY).

Enumerates common autostart locations and checks each entry's target
against the blocklist and the heuristic engine. Nothing is modified or
deleted.

Windows: HKCU/HKLM ...\\CurrentVersion\\Run(+RunOnce), the user Startup
folder, scheduled tasks via `schtasks /query /fo csv /v` (parsed
defensively; localized Windows may use non-English column names — then
tasks are skipped with a note).
Linux: ~/.config/autostart/*.desktop + `crontab -l` (best effort).
"""

import csv
import io
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import blocklist, heuristics
from .scanners.files import sha256_file

_EXEC_RE = re.compile(
    r"(?i)^(.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|com|msi))\b"
)


def resolve_target(command):
    """Extract the executable path from an autorun command line.

    Strips quotes and arguments, expands environment variables. Returns
    None when nothing usable can be extracted.
    """
    if not command:
        return None
    expanded = os.path.expandvars(str(command).strip())
    if not expanded:
        return None
    if expanded.startswith('"'):
        end = expanded.find('"', 1)
        if end > 1:
            return expanded[1:end]
        expanded = expanded.strip('"')
    match = _EXEC_RE.match(expanded)
    if match:
        return match.group(1).strip()
    tokens = expanded.split()
    return tokens[0] if tokens else None


def parse_schtasks_csv(text):
    """Parse `schtasks /query /fo csv /v` output into entries.

    Looks for the 'TaskName' and 'Task To Run' columns (English locale);
    returns ([entries], note_or_None).
    """
    entries = []
    try:
        reader = csv.reader(io.StringIO(text))
        header = [c.strip().lower() for c in next(reader, [])]
    except csv.Error:
        return [], "schtasks output could not be parsed"
    try:
        name_idx = header.index("taskname")
        run_idx = header.index("task to run")
    except ValueError:
        return [], (
            "schtasks CSV has no 'TaskName'/'Task To Run' columns "
            "(non-English Windows locale?); scheduled tasks skipped"
        )
    for row in reader:
        if len(row) <= max(name_idx, run_idx):
            continue
        command = row[run_idx].strip()
        if not command or command.upper() == "N/A":
            continue
        entries.append(
            {"source": "scheduled task", "name": row[name_idx], "command": command}
        )
    return entries, None


def parse_desktop(text):
    """Extract the Exec= command from a .desktop file, or None."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Exec="):
            return line.split("=", 1)[1].strip()
    return None


def _run_key_entries():
    """Windows Run/RunOnce registry values (HKCU + HKLM)."""
    import winreg

    entries = []
    hives = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    subkeys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for hive, hive_name in hives:
        for subkey in subkeys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            continue
                        entries.append(
                            {
                                "source": f"registry {hive_name} ...\\{subkey.rsplit(chr(92), 1)[-1]}",
                                "name": str(name),
                                "command": str(value),
                            }
                        )
            except OSError:
                continue
    return entries


def _startup_folder_entries():
    """Files in the per-user Startup folder."""
    entries = []
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return entries
    startup = (
        Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    )
    try:
        for item in sorted(startup.iterdir()):
            if item.is_file():
                entries.append(
                    # The command IS the file path; quote it so target
                    # resolution keeps paths containing spaces intact.
                    {"source": "startup folder", "name": item.name,
                     "command": f'"{item}"'}
                )
    except OSError:
        pass
    return entries


def _schtasks_entries():
    """Scheduled tasks (Windows). Skips quietly when unavailable."""
    if not shutil.which("schtasks"):
        return [], "schtasks not found; scheduled tasks skipped"
    try:
        out = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"schtasks query failed ({exc}); scheduled tasks skipped"
    return parse_schtasks_csv(out.stdout)


def _autostart_entries_linux():
    entries = []
    autostart = Path.home() / ".config" / "autostart"
    try:
        for item in sorted(autostart.glob("*.desktop")):
            try:
                command = parse_desktop(item.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if command:
                entries.append(
                    {"source": f"autostart {item.name}", "name": item.stem,
                     "command": command}
                )
    except OSError:
        pass
    return entries


def _crontab_entries_linux():
    if not shutil.which("crontab"):
        return [], "crontab not found; cron entries skipped"
    try:
        out = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"crontab -l failed ({exc}); cron entries skipped"
    entries = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append({"source": "crontab", "name": line[:60], "command": line})
    return entries, None


def collect_entries():
    """Gather all persistence entries for the current OS.

    Returns (entries, notes).
    """
    notes = []
    system = platform.system()
    if system == "Windows":
        entries = _run_key_entries() + _startup_folder_entries()
        tasks, note = _schtasks_entries()
        if note:
            notes.append(note)
        entries += tasks
        return entries, notes
    if system == "Linux":
        entries = _autostart_entries_linux()
        cron, note = _crontab_entries_linux()
        if note:
            notes.append(note)
        entries += cron
        return entries, notes
    return [], f"unsupported system: {system or 'unknown'} (persistence scan)"


def _looks_like_path(target):
    return bool(target) and (os.sep in target or "/" in target or ":" in target)


def _load_blocklist_quietly(notes):
    try:
        return blocklist.load()
    except Exception:  # noqa: BLE001 - hash check is optional here
        notes.append("blocklist not available locally; hash check skipped "
                     "(run 'python -m malko blocklist-update')")
        return set()


def scan():
    """Check all persistence entries. Never modifies anything.

    Returns {"entries": [...], "findings": [...], "notes": [...]}.
    """
    entries, notes = collect_entries()
    hashes = _load_blocklist_quietly(notes)
    findings = []

    def add(finding_id, severity, title, details):
        findings.append(
            {"id": finding_id, "severity": severity, "title": title,
             "details": details}
        )

    for entry in entries:
        target = resolve_target(entry["command"])
        entry["target"] = target
        label = f"{entry['source']}: {entry['name']}"
        details = dict(entry)

        if not target:
            add("PERSIST-NO-TARGET", "LOW",
                f"{label}: could not resolve target from "
                f"{entry['command']!r}", details)
            continue
        if _looks_like_path(target) and not Path(target).exists():
            add("PERSIST-MISSING", "LOW",
                f"{label}: target not found: {target}", details)
            continue
        if not Path(target).is_file():
            continue  # bare command name resolved via PATH; nothing to hash

        if heuristics.is_risky_location(target):
            add("PERSIST-RISKY-LOCATION", "MEDIUM",
                f"{label}: autorun target in a temporary/user-writable "
                f"location: {target}", details)

        if not heuristics.should_analyze(target):
            continue
        try:
            digest = sha256_file(target)
        except OSError:
            continue
        details["sha256"] = digest
        if digest in hashes:
            add("PERSIST-BLOCKLIST", "CRITICAL",
                f"{label}: autorun target is BLOCKLISTED malware: {target}",
                details)
            continue
        result = heuristics.analyze(target)
        if result["verdict"] == "EICAR-TEST":
            add("EICAR-TEST", "CRITICAL",
                f"{label}: EICAR test file in autorun: {target}", details)
        elif result["verdict"] in ("SUSPICIOUS", "SUSPICIOUS+"):
            rules = ", ".join(h["id"] for h in result["rules"])
            add(f"PERSIST-HEUR-{digest[:12]}", "SUSPICIOUS",
                f"{label}: suspicious autorun target {target} "
                f"(score {result['score']}: {rules})",
                {**details, "heuristics": result["rules"],
                 "score": result["score"]})
    return {"entries": entries, "findings": findings, "notes": notes}
