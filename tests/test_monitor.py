"""Offline tests for the monitor snapshot/diff logic and file verdicts."""

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path

from malko import monitor, quarantine


class TestSnapshotDiff(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)

    def test_created_modified_deleted(self):
        keep = self.root / "keep.txt"
        keep.write_text("v1", encoding="utf-8")
        old = monitor.snapshot([self.root])
        self.assertEqual(len(old), 1)

        new_file = self.root / "new.txt"
        new_file.write_text("hello", encoding="utf-8")
        keep.write_text("v1-modified-longer", encoding="utf-8")

        mid = monitor.snapshot([self.root])
        created, modified, deleted = monitor.diff(old, mid)
        self.assertEqual(created, [str(new_file.resolve())])
        self.assertEqual(modified, [str(keep.resolve())])
        self.assertEqual(deleted, [])

        keep.unlink()
        final = monitor.snapshot([self.root])
        created, modified, deleted = monitor.diff(mid, final)
        self.assertEqual(created, [])
        self.assertEqual(modified, [])
        self.assertEqual(deleted, [str(keep.resolve())])

    def test_no_changes(self):
        (self.root / "a.txt").write_text("a", encoding="utf-8")
        snap = monitor.snapshot([self.root])
        created, modified, deleted = monitor.diff(snap, snap)
        self.assertEqual((created, modified, deleted), ([], [], []))

    def test_recursive_and_skip_dirs(self):
        sub = self.root / "sub"
        sub.mkdir()
        (sub / "deep.txt").write_text("x", encoding="utf-8")
        qdir = self.root / "quarantine"
        qdir.mkdir()
        (qdir / "held.bin").write_text("y", encoding="utf-8")
        snap = monitor.snapshot([self.root], skip_dirs=(qdir,))
        self.assertEqual(len(snap), 1)
        self.assertIn(str((sub / "deep.txt").resolve()), snap)

    def test_missing_path_warns_not_raises(self):
        snap = monitor.snapshot([self.root / "does-not-exist"])
        self.assertEqual(snap, {})


class TestCheckFileVerdict(unittest.TestCase):
    """check_file against a fake in-memory blocklist (no network)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self._env = {}
        for var in ("MALKO_QUARANTINE_DIR", "MALKO_MONITOR_LOG", "MALKO_STATE_DIR"):
            self._env[var] = os.environ.get(var)
        os.environ["MALKO_QUARANTINE_DIR"] = str(self.root / "quarantine")
        os.environ["MALKO_MONITOR_LOG"] = str(self.root / "monitor.log")
        os.environ["MALKO_STATE_DIR"] = str(self.root / "state")
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for var, value in self._env.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value

    def _make_monitor(self, hashes):
        return monitor.Monitor([self.root], hashes=hashes, verbose=False)

    def test_malicious_file_quarantined_and_logged(self):
        evil = self.root / "evil.exe"
        evil.write_bytes(b"MZ payload")
        digest = hashlib.sha256(b"MZ payload").hexdigest()
        mon = self._make_monitor({digest})
        mon.check_file(str(evil))
        self.assertFalse(evil.exists())
        self.assertEqual(mon.stats["scanned"], 1)
        self.assertEqual(mon.stats["malicious"], 1)
        self.assertEqual(mon.stats["quarantined"], 1)
        entries = quarantine.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source"], "monitor")
        log = (self.root / "monitor.log").read_text(encoding="utf-8")
        self.assertIn("MALICIOUS FILE", log)
        self.assertIn(digest, log)

    def test_clean_file_left_alone(self):
        good = self.root / "good.txt"
        good.write_text("harmless", encoding="utf-8")
        mon = self._make_monitor(set())
        mon.check_file(str(good))
        self.assertTrue(good.exists())
        self.assertEqual(mon.stats["scanned"], 1)
        self.assertEqual(mon.stats["malicious"], 0)

    def test_oversize_file_skipped(self):
        big = self.root / "big.bin"
        big.write_bytes(b"x" * 2048)
        mon = self._make_monitor(set())
        mon.max_size_bytes = 1024
        mon.check_file(str(big))
        self.assertEqual(mon.stats["scanned"], 0)


if __name__ == "__main__":
    unittest.main()
