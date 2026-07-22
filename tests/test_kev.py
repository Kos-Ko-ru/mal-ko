"""Offline tests for the KEV cache and matching logic."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from malko.cache import FileCache
from malko.sources import kev

FIXTURE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
        },
        {
            "cveID": "CVE-2023-4863",
            "vendorProject": "Google",
            "product": "Chrome",
            "vulnerabilityName": "Google Chrome Skia Heap Buffer Overflow Vulnerability",
            "dateAdded": "2023-09-13",
            "dueDate": "2023-10-04",
        },
    ]
}


class TestFileCache(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = Path(self.tmpdir.name) / "kev.json"

    def test_roundtrip(self):
        cache = FileCache(self.path, ttl=3600)
        self.assertIsNone(cache.get())
        cache.set(FIXTURE)
        self.assertEqual(cache.get(), FIXTURE)

    def test_expired_returns_none(self):
        cache = FileCache(self.path, ttl=3600)
        cache.set(FIXTURE)
        # Make the file look older than the TTL.
        old = time.time() - 7200
        import os

        os.utime(self.path, (old, old))
        stale = FileCache(self.path, ttl=3600)
        self.assertIsNone(stale.get())

    def test_corrupt_returns_none(self):
        self.path.write_text("{broken", encoding="utf-8")
        cache = FileCache(self.path, ttl=3600)
        self.assertIsNone(cache.get())

    def test_load_catalog_from_cache(self):
        cache = FileCache(self.path, ttl=3600)
        cache.set(FIXTURE)
        entries = kev.load_catalog(cache=cache)
        self.assertEqual(len(entries), 2)


class TestKevMatching(unittest.TestCase):
    def setUp(self):
        self.entries = FIXTURE["vulnerabilities"]

    def test_match_cve(self):
        hit = kev.match_cve(self.entries, "CVE-2021-44228")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["vendorProject"], "Apache")
        self.assertIsNone(kev.match_cve(self.entries, "CVE-1999-0001"))
        # case-insensitive
        self.assertIsNotNone(kev.match_cve(self.entries, "cve-2023-4863"))

    def test_match_product(self):
        hits = kev.match_product(self.entries, "Google Chrome")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["cveID"], "CVE-2023-4863")
        hits = kev.match_product(self.entries, "log4j2")
        self.assertEqual(len(hits), 1)
        self.assertEqual(kev.match_product(self.entries, "NotInstalledThing"), [])
        # short names are skipped to avoid false positives
        self.assertEqual(kev.match_product(self.entries, "go"), [])

    def test_entries_since(self):
        self.assertEqual(len(kev.entries_since(self.entries, "2023-01-01")), 1)
        self.assertEqual(len(kev.entries_since(self.entries, "2021-01-01")), 2)
        self.assertEqual(len(kev.entries_since(self.entries, "2024-01-01")), 0)


if __name__ == "__main__":
    unittest.main()
