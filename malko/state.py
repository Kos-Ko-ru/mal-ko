"""Shared on-disk state for the mal-ko dashboard.

Two files in the state dir (~/.malko by default, MALKO_STATE_DIR override):

- state.json   — counters, blocklist info, last scan, recent findings.
                 Merged on load; a missing or corrupt file yields defaults.
- events.jsonl — one structured JSON event per line (append-only feed
                 for the dashboard: timestamp, level, kind, message).

All writers are best-effort: state bookkeeping must never break a scan.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()
MAX_FINDINGS = 200

DEFAULT_STATE = {
    "counters": {"files_scanned": 0, "threats_found": 0, "quarantined": 0},
    "blocklist": {"hashes": 0, "updated": None},
    "last_scan": None,
    "findings": [],
}


def state_dir():
    override = os.environ.get("MALKO_STATE_DIR")
    return Path(override) if override else Path.home() / ".malko"


def state_path():
    return state_dir() / "state.json"


def events_path():
    return state_dir() / "events.jsonl"


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(path=None):
    """Load state, merged over defaults. Tolerates missing/corrupt files."""
    path = Path(path) if path else state_path()
    data = None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    state = json.loads(json.dumps(DEFAULT_STATE))  # deep copy of defaults
    if not isinstance(data, dict):
        return state
    counters = data.get("counters")
    if isinstance(counters, dict):
        for key, value in counters.items():
            if isinstance(value, int) and not isinstance(value, bool):
                state["counters"][key] = value
    for key in ("blocklist", "last_scan", "findings"):
        if key in data and type(data[key]) is type(state[key]):
            state[key] = data[key]
    return state


def save(state, path=None):
    """Persist state atomically (best-effort)."""
    path = Path(path) if path else state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _mutate(fn):
    with _LOCK:
        state = load()
        fn(state)
        save(state)


def bump(counter, n=1):
    """Increment a numeric counter (files_scanned, threats_found, ...)."""

    def fn(state):
        state["counters"][counter] = state["counters"].get(counter, 0) + n

    _mutate(fn)


def add_findings(findings, source):
    """Append findings (newest last, capped) and count them as threats."""

    def fn(state):
        for finding in findings:
            entry = dict(finding)
            entry["source"] = source
            entry["ts"] = now_iso()
            state["findings"].append(entry)
        state["findings"] = state["findings"][-MAX_FINDINGS:]
        state["counters"]["threats_found"] += len(findings)

    if findings:
        _mutate(fn)


def set_last_scan(scan_type, summary):
    def fn(state):
        state["last_scan"] = {"type": scan_type, "time": now_iso(), "summary": summary}

    _mutate(fn)


def blocklist_updated(count):
    def fn(state):
        state["blocklist"] = {"hashes": count, "updated": now_iso()}

    _mutate(fn)


def event(level, message, kind="info", path=None):
    """Append one structured event to events.jsonl (best-effort)."""
    record = {"ts": now_iso(), "level": level, "kind": kind, "message": message}
    path = Path(path) if path else events_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return record


def read_events(limit=200, path=None):
    """Return the newest `limit` events (oldest first). Tolerant of junk."""
    path = Path(path) if path else events_path()
    events = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and "message" in record:
            events.append(record)
    return events
