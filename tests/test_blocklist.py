"""Offline tests for the blocklist parser and loader."""

import os
import tempfile
import unittest
from pathlib import Path

from malko import blocklist
from malko.http import SourceError

SAMPLE = """# MalwareBazaar Recent SHA256 Hashes
# Generated on 2026-07-22 00:00:00 UTC

5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592
  7d793037a0760186574b0282f2f435e77d793037a0760186574b0282f2f435E7
not-a-hash
1234
"""


class TestParseBlocklist(unittest.TestCase):
    def test_skips_comments_blanks_and_garbage(self):
        hashes = blocklist.parse_blocklist(SAMPLE)
        self.assertEqual(len(hashes), 2)
        self.assertIn(
            "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592",
            hashes,
        )

    def test_membership_is_case_insensitive(self):
        hashes = blocklist.parse_blocklist(SAMPLE)
        # The second sample line has mixed case; stored lowercase.
        self.assertIn(
            "7d793037a0760186574b0282f2f435e77d793037a0760186574b0282f2f435e7",
            hashes,
        )

    def test_empty_input(self):
        self.assertEqual(blocklist.parse_blocklist(""), set())
        self.assertEqual(blocklist.parse_blocklist("# only comments\n"), set())


class TestLoadBlocklist(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = Path(self.tmpdir.name) / "blocklist.txt"

    def test_load_from_explicit_path(self):
        self.path.write_text(SAMPLE, encoding="utf-8")
        hashes = blocklist.load(self.path)
        self.assertEqual(len(hashes), 2)

    def test_load_missing_raises(self):
        with self.assertRaises(SourceError):
            blocklist.load(self.path)

    def test_env_override_path(self):
        self.path.write_text(SAMPLE, encoding="utf-8")
        old = os.environ.get("MALKO_BLOCKLIST_PATH")
        os.environ["MALKO_BLOCKLIST_PATH"] = str(self.path)
        try:
            self.assertEqual(blocklist.blocklist_path(), self.path)
            self.assertEqual(len(blocklist.load()), 2)
        finally:
            if old is None:
                del os.environ["MALKO_BLOCKLIST_PATH"]
            else:
                os.environ["MALKO_BLOCKLIST_PATH"] = old

    def test_is_stale(self):
        self.assertTrue(blocklist.is_stale(self.path, ttl=60))
        self.path.write_text(SAMPLE, encoding="utf-8")
        self.assertFalse(blocklist.is_stale(self.path, ttl=3600))
        # Negative TTL means "always stale" regardless of clock granularity.
        self.assertTrue(blocklist.is_stale(self.path, ttl=-1))


if __name__ == "__main__":
    unittest.main()
