"""Console and JSON reporting.

Findings are dicts with keys: id, severity, title, details (dict).
The console report prints counts by severity, then the findings sorted
by severity (CRITICAL first). Every scan subcommand can also dump the
full machine-readable result with --json <file>.
"""

import json
from pathlib import Path

from . import tui

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "SUSPICIOUS": 3, "LOW": 4, "UNKNOWN": 5,
}


def severity_rank(severity):
    """Numeric rank for sorting; unknown severities sort last."""
    return SEVERITY_ORDER.get((severity or "").upper(), SEVERITY_ORDER["UNKNOWN"])


def sort_findings(findings):
    """Sort findings by severity (CRITICAL first), then by id."""
    return sorted(findings, key=lambda f: (severity_rank(f.get("severity")), f.get("id", "")))


def severity_counts(findings):
    """Return {severity: count} in display order (only present levels)."""
    counts = {}
    for finding in findings:
        sev = (finding.get("severity") or "UNKNOWN").upper()
        if sev not in SEVERITY_ORDER:
            sev = "UNKNOWN"
        counts[sev] = counts.get(sev, 0) + 1
    ordered = [s for s in SEVERITY_ORDER if s in counts]
    return {s: counts[s] for s in ordered}


def print_report(title, findings, extra_lines=None):
    """Print a readable console summary to stdout (colored on TTYs)."""
    print(tui.paint(f"\n=== {title} ===", tui.BOLD, tui.CYAN))
    if not findings:
        print(tui.paint("No findings. Nothing matched the threat-intel sources.",
                        tui.GREEN))
    else:
        counts = severity_counts(findings)
        worst = min(counts, key=lambda s: SEVERITY_ORDER[s])
        summary = ", ".join(f"{sev}: {n}" for sev, n in counts.items())
        line = f"Findings: {len(findings)} ({summary})\n"
        print(tui.paint(line, tui.SEVERITY_COLORS.get(worst, tui.GRAY), tui.BOLD))
        for finding in sort_findings(findings):
            sev = (finding.get("severity") or "UNKNOWN").upper()
            print(f"{tui.badge(sev)} {finding.get('id', '?')}")
            print(f"  {finding.get('title', '')}")
    for line in extra_lines or []:
        print(line)
    print()


def save_json(path, payload):
    """Save a machine-readable result as pretty JSON."""
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"JSON report written to {path}")
