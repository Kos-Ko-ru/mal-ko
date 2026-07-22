"""Local malware SHA-256 blocklist (MalwareBazaar text export).

Source: https://bazaar.abuse.ch/export/txt/sha256/recent/
The export is a plain text list, one hash per line, `#` comment lines.
It is cached in the mal-ko cache dir (default TTL 24 h) and loaded into
a set for O(1) membership checks.

The blocklist path can be overridden with the MALKO_BLOCKLIST_PATH
environment variable (useful for tests and offline simulations).
"""

import os
import time
from pathlib import Path

from . import http
from .cache import default_cache_dir
from .http import SourceError

EXPORT_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
DEFAULT_TTL = 24 * 3600  # 24 hours
_FILENAME = "sha256-blocklist.txt"


def blocklist_path():
    """Resolve the blocklist file path (env override wins)."""
    override = os.environ.get("MALKO_BLOCKLIST_PATH")
    if override:
        return Path(override)
    return default_cache_dir() / _FILENAME


def parse_blocklist(text):
    """Parse the export text into a set of lowercase SHA-256 hashes.

    Skips `#` comment lines, blank lines and anything that is not a
    64-char hex string.
    """
    hashes = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
            hashes.add(line)
    return hashes


def load(path=None):
    """Load hashes from the local blocklist file into a set."""
    path = Path(path) if path else blocklist_path()
    if not path.exists():
        raise SourceError(
            f"blocklist not found at {path}. Run 'python -m malko blocklist-update' first."
        )
    return parse_blocklist(path.read_text(encoding="utf-8", errors="replace"))


def is_stale(path=None, ttl=DEFAULT_TTL):
    """True when the blocklist file is missing or older than ttl seconds."""
    path = Path(path) if path else blocklist_path()
    try:
        return (time.time() - path.stat().st_mtime) > ttl
    except OSError:
        return True


def update(path=None):
    """Download the export and store it. Returns the number of hashes."""
    path = Path(path) if path else blocklist_path()
    text = http.request_text(EXPORT_URL, timeout=120)
    hashes = parse_blocklist(text)
    if not hashes:
        raise SourceError(f"no hashes parsed from {EXPORT_URL} (unexpected format)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return len(hashes)


def ensure_fresh(path=None, ttl=DEFAULT_TTL):
    """Return (hashes, refreshed). Downloads when missing/stale.

    If the download fails but an old copy exists, it is used with a
    warning. If there is no local copy at all, SourceError propagates.
    """
    path = Path(path) if path else blocklist_path()
    refreshed = False
    if is_stale(path, ttl):
        try:
            update(path)
            refreshed = True
        except SourceError:
            if not path.exists():
                raise
            import sys

            print(
                f"warning: blocklist refresh failed, using stale copy at {path}",
                file=sys.stderr,
            )
    return load(path), refreshed
