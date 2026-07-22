"""Offline tests for severity ordering in the report module."""

import io
import unittest
from contextlib import redirect_stdout

from malko import report

FINDINGS = [
    {"id": "CVE-1", "severity": "LOW", "title": "low"},
    {"id": "CVE-2", "severity": "CRITICAL", "title": "critical"},
    {"id": "CVE-3", "severity": "MEDIUM", "title": "medium"},
    {"id": "CVE-4", "severity": "HIGH", "title": "high"},
    {"id": "GHSA-5", "severity": "UNKNOWN", "title": "unknown"},
    {"id": "CVE-6", "severity": "nonsense", "title": "garbage severity"},
]


class TestSeveritySorting(unittest.TestCase):
    def test_sort_order(self):
        ordered = [f["id"] for f in report.sort_findings(FINDINGS)]
        self.assertEqual(
            ordered, ["CVE-2", "CVE-4", "CVE-3", "CVE-1", "CVE-6", "GHSA-5"]
        )

    def test_severity_rank(self):
        self.assertLess(report.severity_rank("CRITICAL"), report.severity_rank("LOW"))
        self.assertEqual(report.severity_rank("nonsense"), report.severity_rank(None))
        # case-insensitive
        self.assertEqual(report.severity_rank("high"), report.severity_rank("HIGH"))

    def test_severity_counts(self):
        counts = report.severity_counts(FINDINGS)
        self.assertEqual(
            counts, {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 2}
        )

    def test_print_report_empty(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            report.print_report("Test", [])
        self.assertIn("No findings", buf.getvalue())

    def test_print_report_lists_findings(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            report.print_report("Test", FINDINGS)
        out = buf.getvalue()
        self.assertIn("Findings: 6", out)
        # CRITICAL line appears before LOW line in the output.
        self.assertLess(out.index("[CRITICAL]"), out.index("[LOW]"))


if __name__ == "__main__":
    unittest.main()
