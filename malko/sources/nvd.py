"""NVD source: keyword search over the CVE 2.0 API.

GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<name>
Without an API key NVD rate-limits aggressively; callers must sleep
~1.5 s between requests (see malko.scanners.system).
"""

import urllib.parse

from .. import http

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 5


def _extract_severity(cve):
    """Severity from CVSS v3.1/v3.0/v2 metrics, else UNKNOWN."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            sev = entries[0].get("cvssData", {}).get("baseSeverity")
            if sev:
                return sev.upper()
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        sev = entries[0].get("baseSeverity")
        if sev:
            return sev.upper()
    return "UNKNOWN"


def _extract_description(cve):
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def keyword_search(keyword):
    """Search NVD for CVEs mentioning `keyword`.

    Returns a list of {"id", "severity", "description"} (max 5).
    """
    params = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": RESULTS_PER_PAGE}
    )
    data = http.request_json(f"{API_URL}?{params}", timeout=40)
    results = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        results.append(
            {
                "id": cve_id,
                "severity": _extract_severity(cve),
                "description": _extract_description(cve)[:200],
            }
        )
    return results
