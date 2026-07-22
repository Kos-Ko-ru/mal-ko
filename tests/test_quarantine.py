"""Offline tests for quarantine: move, metadata, list, restore."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from malko import quarantine


class QuarantineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.old_env = os.environ.get("MALKO_QUARANTINE_DIR")
        self.old_state_env = os.environ.get("MALKO_STATE_DIR")
        os.environ["MALKO_QUARANTINE_DIR"] = str(self.root / "quarantine")
        os.environ["MALKO_STATE_DIR"] = str(self.root / "state")
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self.old_env is None:
            os.environ.pop("MALKO_QUARANTINE_DIR", None)
        else:
            os.environ["MALKO_QUARANTINE_DIR"] = self.old_env
        if self.old_state_env is None:
            os.environ.pop("MALKO_STATE_DIR", None)
        else:
            os.environ["MALKO_STATE_DIR"] = self.old_state_env

    def _make_file(self, name="evil.exe", content=b"MZ fake malware"):
        path = self.root / name
        path.write_bytes(content)
        return path


class TestQuarantineFile(QuarantineTestCase):
    def test_move_and_sidecar(self):
        path = self._make_file()
        record = quarantine.quarantine_file(path, "a" * 64, source="monitor")
        # Original is gone, quarantined copy exists under the generated id.
        self.assertFalse(path.exists())
        qfile = self.root / "quarantine" / record["id"]
        self.assertTrue(qfile.is_file())
        self.assertEqual(qfile.read_bytes(), b"MZ fake malware")
        sidecar = json.loads(
            (self.root / "quarantine" / f"{record['id']}.json").read_text("utf-8")
        )
        self.assertEqual(sidecar["original_path"], str(path.resolve()))
        self.assertEqual(sidecar["sha256"], "a" * 64)
        self.assertEqual(sidecar["source"], "monitor")
        self.assertIn("timestamp", sidecar)

    def test_missing_file_raises(self):
        with self.assertRaises(quarantine.QuarantineError):
            quarantine.quarantine_file(self.root / "nope.bin", "b" * 64, source="monitor")

    def test_list_entries(self):
        self.assertEqual(quarantine.list_entries(), [])
        path = self._make_file()
        record = quarantine.quarantine_file(path, "c" * 64, source="scan-files")
        entries = quarantine.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], record["id"])
        self.assertTrue(entries[0]["quarantined_file_exists"])


class TestRestore(QuarantineTestCase):
    def test_restore_to_original_path(self):
        path = self._make_file()
        record = quarantine.quarantine_file(path, "d" * 64, source="monitor")
        dest = quarantine.restore(record["id"])
        self.assertEqual(dest, path.resolve())
        self.assertEqual(path.read_bytes(), b"MZ fake malware")
        # Entry is consumed by the restore.
        self.assertEqual(quarantine.list_entries(), [])

    def test_restore_refuses_overwrite(self):
        path = self._make_file()
        record = quarantine.quarantine_file(path, "e" * 64, source="monitor")
        path.write_bytes(b"new occupant")
        with self.assertRaises(quarantine.QuarantineError):
            quarantine.restore(record["id"])
        # Force overwrites.
        dest = quarantine.restore(record["id"], force=True)
        self.assertEqual(dest.read_bytes(), b"MZ fake malware")

    def test_restore_unknown_id(self):
        with self.assertRaises(quarantine.QuarantineError):
            quarantine.restore("no-such-id")


if __name__ == "__main__":
    unittest.main()
