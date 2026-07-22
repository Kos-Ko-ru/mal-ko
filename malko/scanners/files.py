"""File scanner: SHA-256 hashing + MalwareBazaar lookups + heuristics.

Hashes every file under the given paths (directories are walked
recursively) and asks MalwareBazaar whether each hash is known malware.
Files not present in the database are then run through the heuristic
engine (unless disabled). Files absent from the database are reported
as clean/unknown; lookup failures (offline, missing API key) degrade
to per-file warnings without aborting the scan.
"""

import hashlib
import sys
from pathlib import Path

from .. import heuristics
from ..http import SourceError
from ..sources import malwarebazaar

_CHUNK = 1024 * 1024


def sha256_file(path):
    """Compute the SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(paths):
    """Yield files from a list of files/directories (dirs recursive)."""
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
        elif path.is_dir():
            for item in sorted(path.rglob("*")):
                if item.is_file():
                    yield item
        else:
            print(f"warning: path not found, skipped: {raw}", file=sys.stderr)


def heuristic_finding(path, digest, result):
    """Build a finding dict from a heuristic verdict (None when clean)."""
    verdict = result["verdict"]
    if verdict == "EICAR-TEST":
        return {
            "id": "EICAR-TEST",
            "severity": "CRITICAL",
            "title": f"EICAR antivirus test file: {path}",
            "details": {"path": str(path), "sha256": digest, "status": "eicar"},
        }
    if verdict in ("SUSPICIOUS", "SUSPICIOUS+"):
        rules = ", ".join(h["id"] for h in result["rules"])
        return {
            "id": f"HEUR-{digest[:12]}",
            "severity": "SUSPICIOUS",
            "title": f"{verdict} file (score {result['score']}): {path} - {rules}",
            "details": {
                "path": str(path),
                "sha256": digest,
                "status": "suspicious",
                "score": result["score"],
                "heuristics": result["rules"],
            },
        }
    return None


def scan(paths, progress=True, use_heuristics=True):
    """Hash files and look them up in MalwareBazaar (+ heuristics).

    Returns {"files": [...], "findings": [...]} where findings contains
    confirmed malware hits and suspicious (heuristic) hits.
    """
    files, findings = [], []
    lookup_warned = False
    for path in iter_files(paths):
        try:
            digest = sha256_file(path)
        except OSError as exc:
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
            continue
        if progress:
            print(f"checking: {path}", file=sys.stderr)
        try:
            result = malwarebazaar.lookup_hash(digest)
        except SourceError as exc:
            if not lookup_warned:
                print(
                    f"warning: MalwareBazaar lookup unavailable ({exc}); "
                    "continuing with heuristics only",
                    file=sys.stderr,
                )
                lookup_warned = True
            result = {"status": "lookup_error"}
        record = {"path": str(path), "sha256": digest, "status": result["status"]}
        files.append(record)
        if result["status"] == "ok":
            findings.append(
                {
                    "id": result["signature"],
                    "severity": "CRITICAL",
                    "title": (
                        f"KNOWN MALWARE: {path} (signature: {result['signature']}, "
                        f"type: {result['file_type']}, first seen: {result['first_seen']})"
                    ),
                    "details": record,
                }
            )
        elif use_heuristics and heuristics.should_analyze(path):
            hit = heuristic_finding(path, digest, heuristics.analyze(path))
            if hit:
                findings.append(hit)
    return {"files": files, "findings": findings}
