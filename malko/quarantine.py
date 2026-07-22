"""Quarantine: move malicious files out of harm's way.

A quarantined file is moved to ~/.malko/quarantine/ under a generated
id, with a sidecar <id>.json recording the original path, SHA-256,
timestamp and source ("monitor" or "scan-files").

The quarantine dir can be overridden with MALKO_QUARANTINE_DIR (tests).
"""

import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import state


class QuarantineError(Exception):
    """Raised for unknown ids, missing files, or unsafe restores."""


def quarantine_dir():
    override = os.environ.get("MALKO_QUARANTINE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".malko" / "quarantine"


def _new_id():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def quarantine_file(path, sha256, source):
    """Move `path` into quarantine and write its sidecar metadata.

    Returns the record dict (includes the generated "id").
    """
    path = Path(path)
    if not path.is_file():
        raise QuarantineError(f"file not found: {path}")
    qdir = quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)
    entry_id = _new_id()
    record = {
        "id": entry_id,
        "original_path": str(path.resolve()),
        "sha256": sha256,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
    }
    shutil.move(str(path), str(qdir / entry_id))
    (qdir / f"{entry_id}.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    state.bump("quarantined")
    state.event(
        "warning", f"quarantined {path} as {entry_id} (source: {source})", "quarantine"
    )
    return record


def list_entries():
    """Return all quarantine records (newest first)."""
    qdir = quarantine_dir()
    entries = []
    if not qdir.is_dir():
        return entries
    for sidecar in sorted(qdir.glob("*.json"), reverse=True):
        try:
            record = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        record["quarantined_file_exists"] = (qdir / record.get("id", "")).is_file()
        entries.append(record)
    return entries


def get_entry(entry_id):
    """Load one record by id. Raises QuarantineError when unknown."""
    for record in list_entries():
        if record.get("id") == entry_id:
            return record
    raise QuarantineError(f"no quarantine entry with id: {entry_id}")


def restore(entry_id, force=False):
    """Move a quarantined file back to its original path.

    Refuses to overwrite an existing file unless force=True.
    Returns the restored path.
    """
    record = get_entry(entry_id)
    qfile = quarantine_dir() / entry_id
    if not qfile.is_file():
        raise QuarantineError(f"quarantined file is missing for id: {entry_id}")
    dest = Path(record["original_path"])
    if dest.exists() and not force:
        raise QuarantineError(
            f"destination already exists: {dest} (use --force to overwrite)"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(qfile), str(dest))
    sidecar = quarantine_dir() / f"{entry_id}.json"
    if sidecar.exists():
        sidecar.unlink()
    state.event("info", f"restored {entry_id} to {dest}", "quarantine")
    return dest
