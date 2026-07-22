"""Dependency-manifest scanner.

Finds requirements.txt (PyPI) and package.json (npm) files under a
path, resolves pinned versions, and checks them against OSV.dev.
Found CVE ids are cross-checked against the CISA KEV catalog and
flagged as ACTIVELY EXPLOITED.
"""

import json
import re
import sys
from pathlib import Path

from ..sources import kev, osv

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", ".venv", "venv"}

# name==1.2.3, name[extra]==1.2.3, name == 1.2.3
_REQ_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._*!+-]+)"
)
# First plain version token inside an npm range string.
_NPM_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-]+)?")


def _warn(message):
    print(f"warning: {message}", file=sys.stderr)


def find_manifests(path):
    """Return {"requirements.txt": [...], "package.json": [...]} of paths."""
    root = Path(path)
    found = {"requirements.txt": [], "package.json": []}
    if root.is_file():
        if root.name in found:
            found[root.name].append(root)
        return found
    for item in sorted(root.rglob("*")):
        if not item.is_file() or item.name not in found:
            continue
        if any(part in SKIP_DIRS for part in item.parts):
            continue
        found[item.name].append(item)
    return found


def parse_requirements(path):
    """Parse requirements.txt -> list of (name, version).

    Only `==` pins are resolvable; anything else is skipped with a
    warning. Returns (packages, warnings).
    """
    packages, warnings = [], []
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            if line.startswith("-r") or line.startswith("--requirement"):
                warnings.append(f"{path}:{lineno}: include files are not followed: {line!r}")
            continue
        match = _REQ_PIN_RE.match(line)
        if match:
            packages.append((match.group(1), match.group(3)))
        else:
            warnings.append(
                f"{path}:{lineno}: not a pinned '==' requirement, skipped: {line!r}"
            )
    return packages, warnings


def _resolve_npm_range(spec):
    """Strip a semver range (^, ~, >=, ...) to a concrete version.

    Returns the version string, or None when unresolvable
    (e.g. 'latest', '*', urls, '||' ranges).
    """
    spec = (spec or "").strip()
    if not spec or spec in ("*", "latest", "x", "X"):
        return None
    if "||" in spec or "://" in spec or spec.startswith(("git", "file:", "link:", "workspace:")):
        return None
    match = _NPM_VERSION_RE.search(spec)
    return match.group(0) if match else None


def parse_package_json(path):
    """Parse package.json dependencies+devDependencies -> (name, version).

    Returns (packages, warnings).
    """
    packages, warnings = [], []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        warnings.append(f"{path}: invalid JSON ({exc}), skipped")
        return packages, warnings
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in sorted(deps.items()):
            version = _resolve_npm_range(str(spec))
            if version is None:
                warnings.append(
                    f"{path}: cannot resolve version for {name!r} ({spec!r}), skipped"
                )
            else:
                packages.append((name, version))
    return packages, warnings


def scan(path):
    """Scan a path for dependency manifests.

    Returns {"packages": [...], "findings": [...], "warnings": [...]}.
    """
    manifests = find_manifests(path)
    packages, warnings = [], []
    for req in manifests["requirements.txt"]:
        pkgs, warns = parse_requirements(req)
        packages.extend((n, "PyPI", v, str(req)) for n, v in pkgs)
        warnings.extend(warns)
    for pkg_json in manifests["package.json"]:
        pkgs, warns = parse_package_json(pkg_json)
        packages.extend((n, "npm", v, str(pkg_json)) for n, v in pkgs)
        warnings.extend(warns)

    for warning in warnings:
        _warn(warning)

    findings = []
    if packages:
        results = osv.query_batch([(n, eco, v) for n, eco, v, _ in packages])
        kev_entries = _load_kev_safe()
        for (name, eco, version, manifest), result in zip(packages, results):
            for vuln_id in result["ids"]:
                details = osv.vuln_details(vuln_id)
                kev_hit = None
                for cve in details["cves"]:
                    kev_hit = kev.match_cve(kev_entries, cve)
                    if kev_hit:
                        break
                title = f"{name} {version} ({eco}): {details['summary']}"
                if kev_hit:
                    title = f"ACTIVELY EXPLOITED (CISA KEV {kev_hit['cveID']}): " + title
                findings.append(
                    {
                        "id": details["id"],
                        "severity": details["severity"],
                        "title": title,
                        "details": {
                            "package": name,
                            "version": version,
                            "ecosystem": eco,
                            "manifest": manifest,
                            "cves": details["cves"],
                            "kev": bool(kev_hit),
                        },
                    }
                )
    return {"packages": packages, "findings": findings, "warnings": warnings}


def _load_kev_safe():
    """KEV cross-check is best-effort: offline scans still report OSV hits."""
    try:
        return kev.load_catalog()
    except Exception as exc:  # noqa: BLE001 - any failure just skips KEV flagging
        _warn(f"KEV catalog unavailable, skipping KEV cross-check ({exc})")
        return []
