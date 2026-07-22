"""Tiny JSON file cache with TTL.

Used mainly for the CISA KEV feed (~1 MB) so it is not re-downloaded
on every run. Cache lives in ~/.malko/cache/ by default.
"""

import json
import os
import time
from pathlib import Path

DEFAULT_TTL = 24 * 3600  # 24 hours


def default_cache_dir():
    """Return the default cache directory (~/.malko/cache)."""
    override = os.environ.get("MALKO_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".malko" / "cache"


class FileCache:
    """A single cached JSON document at a fixed path with a TTL."""

    def __init__(self, path, ttl=DEFAULT_TTL):
        self.path = Path(path)
        self.ttl = ttl

    def get(self):
        """Return the cached JSON value, or None if missing/stale/corrupt."""
        try:
            if not self.path.exists():
                return None
            age = time.time() - self.path.stat().st_mtime
            if age > self.ttl:
                return None
            with self.path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, data):
        """Store a JSON-serializable value. Creates parent dirs."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(data, fh)
            tmp.replace(self.path)
        except OSError:
            # Caching is best-effort; never break a scan over it.
            pass
