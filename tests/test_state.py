"""Offline tests for the dashboard state plumbing (state.json/events.jsonl)."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from malko import state


class StateTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.old_env = os.environ.get("MALKO_STATE_DIR")
        os.environ["MALKO_STATE_DIR"] = str(self.root)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self.old_env is None:
            os.environ.pop("MALKO_STATE_DIR", None)
        else:
            os.environ["MALKO_STATE_DIR"] = self.old_env


class TestLoadMerge(StateTestCase):
    def test_missing_file_yields_defaults(self):
        loaded = state.load()
        self.assertEqual(
            loaded["counters"],
            {"files_scanned": 0, "threats_found": 0, "quarantined": 0},
        )
        self.assertEqual(loaded["findings"], [])

    def test_corrupt_file_yields_defaults(self):
        state.state_path().write_text("{broken json", encoding="utf-8")
        loaded = state.load()
        self.assertEqual(loaded["counters"]["files_scanned"], 0)

    def test_merge_keeps_known_fields(self):
        state.state_path().write_text(
            json.dumps(
                {
                    "counters": {"files_scanned": 7, "bogus": "x"},
                    "findings": [{"id": "CVE-1"}],
                    "unknown_top_level": 1,
                }
            ),
            encoding="utf-8",
        )
        loaded = state.load()
        self.assertEqual(loaded["counters"]["files_scanned"], 7)
        self.assertEqual(loaded["counters"]["threats_found"], 0)  # default filled
        self.assertNotIn("bogus", loaded["counters"])
        self.assertEqual(len(loaded["findings"]), 1)
        self.assertNotIn("unknown_top_level", loaded)

    def test_wrong_types_fall_back_to_defaults(self):
        state.state_path().write_text(
            json.dumps({"counters": "nope", "findings": {"a": 1}}), encoding="utf-8"
        )
        loaded = state.load()
        self.assertIsInstance(loaded["counters"], dict)
        self.assertEqual(loaded["findings"], [])


class TestMutations(StateTestCase):
    def test_bump_and_roundtrip(self):
        state.bump("files_scanned", 3)
        state.bump("files_scanned")
        self.assertEqual(state.load()["counters"]["files_scanned"], 4)

    def test_add_findings_counts_and_caps(self):
        findings = [
            {"id": f"ID-{i}", "severity": "LOW", "title": "t", "details": {}}
            for i in range(state.MAX_FINDINGS + 10)
        ]
        state.add_findings(findings, source="test")
        loaded = state.load()
        self.assertEqual(len(loaded["findings"]), state.MAX_FINDINGS)
        self.assertEqual(
            loaded["counters"]["threats_found"], state.MAX_FINDINGS + 10
        )
        # Newest entries survive the cap; source/ts are attached.
        self.assertEqual(loaded["findings"][-1]["id"], f"ID-{state.MAX_FINDINGS + 9}")
        self.assertEqual(loaded["findings"][0]["source"], "test")
        self.assertIn("ts", loaded["findings"][0])

    def test_add_findings_empty_is_noop(self):
        state.add_findings([], source="test")
        self.assertFalse(state.state_path().exists())

    def test_blocklist_updated(self):
        state.blocklist_updated(760)
        bl = state.load()["blocklist"]
        self.assertEqual(bl["hashes"], 760)
        self.assertIsNotNone(bl["updated"])


class TestEvents(StateTestCase):
    def test_event_roundtrip(self):
        state.event("info", "first", "scan")
        state.event("critical", "second", "alert")
        events = state.read_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["message"], "first")
        self.assertEqual(events[1]["level"], "critical")
        self.assertEqual(events[1]["kind"], "alert")
        self.assertIn("ts", events[0])

    def test_read_events_tolerates_junk_lines(self):
        with state.events_path().open("a", encoding="utf-8") as fh:
            fh.write("not json\n")
            fh.write('{"no_message": true}\n')
            fh.write(json.dumps({"ts": "t", "level": "info", "kind": "k",
                                 "message": "ok"}) + "\n")
        events = state.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["message"], "ok")

    def test_read_events_missing_file(self):
        self.assertEqual(state.read_events(), [])

    def test_read_events_limit(self):
        for i in range(10):
            state.event("info", f"e{i}")
        events = state.read_events(limit=3)
        self.assertEqual([e["message"] for e in events], ["e7", "e8", "e9"])


if __name__ == "__main__":
    unittest.main()
