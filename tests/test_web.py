"""Offline tests for the web dashboard API.

Starts the real server on an ephemeral port in a thread and talks to it
with urllib. No external network involved (127.0.0.1 only).
"""

import hashlib
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from malko import quarantine, state, web


class WebTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = web.make_server(port=0)  # ephemeral port
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self._env = {}
        for var, sub in (
            ("MALKO_STATE_DIR", "state"),
            ("MALKO_QUARANTINE_DIR", "quarantine"),
        ):
            self._env[var] = os.environ.get(var)
            os.environ[var] = str(self.root / sub)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for var, value in self._env.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path):
        with urllib.request.urlopen(self.url(path), timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def get_raw(self, path):
        with urllib.request.urlopen(self.url(path), timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")

    def post(self, path, body):
        req = urllib.request.Request(
            self.url(path),
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class TestGetEndpoints(WebTestCase):
    def test_index_page_served(self):
        code, html = self.get_raw("/")
        self.assertEqual(code, 200)
        self.assertIn("MAL-KO", html)
        self.assertIn("<svg", html)  # inline shield logo

    def test_status_shape(self):
        code, data = self.get("/api/status")
        self.assertEqual(code, 200)
        for key in ("state", "blocklist_path", "server_time"):
            self.assertIn(key, data)
        self.assertIn("counters", data["state"])
        self.assertIn("files_scanned", data["state"]["counters"])

    def test_events_shape(self):
        state.event("info", "test-event", "test")
        code, data = self.get("/api/events")
        self.assertEqual(code, 200)
        self.assertIn("events", data)
        self.assertTrue(any(e["message"] == "test-event" for e in data["events"]))

    def test_findings_shape(self):
        code, data = self.get("/api/findings")
        self.assertEqual(code, 200)
        self.assertEqual(data, {"findings": []})

    def test_quarantine_empty(self):
        code, data = self.get("/api/quarantine")
        self.assertEqual(code, 200)
        self.assertEqual(data, {"entries": []})

    def test_unknown_route_404(self):
        req = urllib.request.Request(self.url("/api/nope"))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 404)


class TestRestoreEndpoint(WebTestCase):
    def _quarantine_something(self):
        payload = self.root / "evil.bin"
        payload.write_bytes(b"MZ fake")
        digest = hashlib.sha256(b"MZ fake").hexdigest()
        return payload, quarantine.quarantine_file(payload, digest, source="test")

    def test_restore_happy_path(self):
        payload, record = self._quarantine_something()
        code, data = self.post("/api/quarantine/restore", {"id": record["id"]})
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(payload.read_bytes(), b"MZ fake")

    def test_restore_unknown_id_404(self):
        code, data = self.post("/api/quarantine/restore", {"id": "no-such-id"})
        self.assertEqual(code, 404)
        self.assertIn("error", data)

    def test_restore_refuses_overwrite_400(self):
        payload, record = self._quarantine_something()
        payload.write_bytes(b"occupant")
        code, data = self.post("/api/quarantine/restore", {"id": record["id"]})
        self.assertEqual(code, 400)
        code, data = self.post(
            "/api/quarantine/restore", {"id": record["id"], "force": True}
        )
        self.assertEqual(code, 200)


class TestScanEndpoint(WebTestCase):
    def test_rejects_relative_path(self):
        code, data = self.post("/api/scan", {"type": "deps", "path": "some/rel/dir"})
        self.assertEqual(code, 400)
        self.assertIn("absolute", data["error"])

    def test_rejects_nonexistent_path(self):
        missing = str(self.root / "does-not-exist")
        code, data = self.post("/api/scan", {"type": "files", "path": missing})
        self.assertEqual(code, 400)
        self.assertIn("does not exist", data["error"])

    def test_rejects_unknown_type(self):
        code, data = self.post("/api/scan", {"type": "everything", "path": str(self.root)})
        self.assertEqual(code, 400)

    def test_rejects_missing_path_for_files(self):
        code, data = self.post("/api/scan", {"type": "files", "path": ""})
        self.assertEqual(code, 400)

    def test_accepts_valid_target(self):
        code, data = self.post("/api/scan", {"type": "deps", "path": str(self.root)})
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "started")
        # Wait for the background scan thread to finish before teardown,
        # otherwise it writes state files into the removed temp dir.
        import time

        deadline = time.time() + 10
        while time.time() < deadline:
            events = state.read_events()
            if any("finished" in e["message"] for e in events):
                break
            time.sleep(0.05)
        else:
            self.fail("background scan did not finish in time")


if __name__ == "__main__":
    unittest.main()
