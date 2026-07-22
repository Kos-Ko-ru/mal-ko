"""OSV.dev source: batch vulnerability queries for package@version.

API: POST https://api.osv.dev/v1/querybatch
Each query: {"package": {"name": ..., "ecosystem": "PyPI"|"npm"},
             "version": ...}
The batch endpoint returns vulnerability IDs only; details are fetched
per ID from GET /v1/vulns/<id> (summary + severity).
"""

from .. import http

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"


def query_batch(packages):
    """Query OSV for a list of (name, ecosystem, version) tuples.

    Returns a list of result dicts aligned with `packages`:
    {"name", "ecosystem", "version", "ids": [...]}.
    """
    queries = [
        {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        for name, ecosystem, version in packages
    ]
    if not queries:
        return []
    data = http.request_json(QUERYBATCH_URL, json_body={"queries": queries})
    results = []
    for (name, ecosystem, version), item in zip(packages, data.get("results", [])):
        vulns = item.get("vulns") or []
        results.append(
            {
                "name": name,
                "ecosystem": ecosystem,
                "version": version,
                "ids": [v.get("id", "") for v in vulns if v.get("id")],
            }
        )
    return results


def _extract_severity(vuln):
    """Best-effort severity string from an OSV vuln record."""
    db_specific = vuln.get("database_specific") or {}
    sev = db_specific.get("severity")
    if isinstance(sev, str) and sev:
        sev = sev.upper()
        # GitHub advisories use MODERATE; normalize to CVSS-style MEDIUM.
        return {"MODERATE": "MEDIUM"}.get(sev, sev)
    # Fall back to the highest CVSS base score we can find.
    best = None
    for entry in vuln.get("severity") or []:
        score = entry.get("score", "")
        # CVSS vector strings are not scores; skip parsing them deeply.
        if isinstance(score, (int, float)):
            best = max(best or 0.0, float(score))
    if best is None:
        return "UNKNOWN"
    if best >= 9.0:
        return "CRITICAL"
    if best >= 7.0:
        return "HIGH"
    if best >= 4.0:
        return "MEDIUM"
    return "LOW"


def _related_cves(vuln):
    """Collect CVE aliases of an OSV record (for KEV cross-check)."""
    cves = [a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")]
    if vuln.get("id", "").startswith("CVE-"):
        cves.append(vuln["id"])
    return sorted(set(cves))


def vuln_details(vuln_id):
    """Fetch one vulnerability record. Returns {id, summary, severity, cves}."""
    data = http.request_json(VULN_URL + vuln_id)
    return {
        "id": data.get("id", vuln_id),
        "summary": data.get("summary") or "(no summary)",
        "severity": _extract_severity(data),
        "cves": _related_cves(data),
    }
