"""CISA Known Exploited Vulnerabilities (KEV) catalog source.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
The feed is ~1 MB, so it is cached locally (TTL 24 h by default).
"""

from .. import http
from ..cache import FileCache, default_cache_dir

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def load_catalog(cache=None):
    """Return the list of KEV vulnerability entries.

    Uses `cache` (a FileCache) if given, otherwise the default
    ~/.malko/cache/kev.json with a 24 h TTL. Raises SourceError if the
    feed cannot be fetched and there is no usable cache.
    """
    if cache is None:
        cache = FileCache(default_cache_dir() / "kev.json")
    cached = cache.get()
    if cached is not None:
        return cached.get("vulnerabilities", [])
    data = http.request_json(FEED_URL, timeout=60)
    cache.set(data)
    return data.get("vulnerabilities", [])


def entries_since(entries, since):
    """Filter entries with dateAdded >= since ('YYYY-MM-DD' string)."""
    return [e for e in entries if e.get("dateAdded", "") >= since]


def match_cve(entries, cve_id):
    """Return the KEV entry for a CVE id, or None."""
    cve_id = (cve_id or "").upper()
    for entry in entries:
        if entry.get("cveID", "").upper() == cve_id:
            return entry
    return None


def match_product(entries, product_name):
    """Return KEV entries whose vendor/product matches a software name.

    Case-insensitive word-substring match against vendorProject and
    product fields. Very short names (< 4 chars) are skipped to avoid
    false positives.
    """
    name = (product_name or "").strip().lower()
    if len(name) < 4:
        return []
    matches = []
    for entry in entries:
        vendor = entry.get("vendorProject", "").lower()
        product = entry.get("product", "").lower()
        if name in vendor or name in product or product in name or vendor in name:
            matches.append(entry)
    return matches
