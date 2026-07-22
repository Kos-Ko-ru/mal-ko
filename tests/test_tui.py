"""Offline tests for terminal color handling."""

import os
import re
import unittest

from malko import tui

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def reset_cache():
    tui._enabled = None


class TuiTestCase(unittest.TestCase):
    def setUp(self):
        self._old_no_color = os.environ.get("NO_COLOR")
        self.addCleanup(self._restore)
        reset_cache()

    def _restore(self):
        if self._old_no_color is None:
            os.environ.pop("NO_COLOR", None)
        else:
            os.environ["NO_COLOR"] = self._old_no_color
        reset_cache()

    def force(self, enabled):
        tui._enabled = enabled


class TestNoColor(TuiTestCase):
    def test_no_color_env_disables(self):
        os.environ["NO_COLOR"] = "1"
        reset_cache()
        self.assertFalse(tui.colors_enabled())

    def test_not_a_tty_disables(self):
        # unittest stdout is typically not a TTY (captured); force-detect.
        os.environ.pop("NO_COLOR", None)
        reset_cache()
        import sys

        if not sys.stdout.isatty():
            self.assertFalse(tui.colors_enabled())

    def test_paint_passthrough_when_disabled(self):
        self.force(False)
        self.assertEqual(tui.paint("hello", tui.RED, tui.BOLD), "hello")
        self.assertEqual(tui.badge("CRITICAL"), "[CRITICAL]")

    def test_banner_plain_when_disabled(self):
        self.force(False)
        self.assertNotIn("\x1b[", tui.banner())


class TestColors(TuiTestCase):
    def test_paint_wraps_and_strips_back(self):
        self.force(True)
        colored = tui.paint("alert", tui.RED, tui.BOLD)
        self.assertIn("\x1b[", colored)
        self.assertEqual(ANSI_RE.sub("", colored), "alert")

    def test_badge_content(self):
        self.force(True)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            self.assertEqual(ANSI_RE.sub("", tui.badge(sev)), f"[{sev}]")

    def test_badge_unknown_severity_falls_back(self):
        self.force(True)
        self.assertEqual(ANSI_RE.sub("", tui.badge("nonsense")), "[NONSENSE]")

    def test_banner_contains_name_and_tagline(self):
        self.force(False)
        text = tui.banner()
        self.assertIn("threat intelligence scanner", text)
        self.assertGreater(len(text.strip().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
