"""Offline tests for the no-arguments dashboard default in the CLI."""

import sys
import unittest
from unittest import mock

from malko import cli


class TestResolveArgv(unittest.TestCase):
    def test_explicit_args_pass_through(self):
        self.assertEqual(cli.resolve_argv(["scan-files", "x"]), ["scan-files", "x"])
        self.assertEqual(cli.resolve_argv(["--help"]), ["--help"])

    def test_no_args_frozen_defaults_to_dashboard(self):
        with mock.patch.object(cli, "_default_to_dashboard", return_value=True):
            self.assertEqual(cli.resolve_argv([]), ["dashboard"])

    def test_no_args_non_interactive_keeps_empty(self):
        with mock.patch.object(cli, "_default_to_dashboard", return_value=False):
            self.assertEqual(cli.resolve_argv([]), [])


class TestDefaultToDashboard(unittest.TestCase):
    def test_frozen_always_defaults(self):
        with mock.patch.object(sys, "frozen", True, create=True):
            self.assertTrue(cli._default_to_dashboard())

    def test_interactive_console_defaults(self):
        with mock.patch.object(sys, "frozen", False, create=True), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch.object(sys.stdout, "isatty", return_value=True):
            self.assertTrue(cli._default_to_dashboard())

    def test_piped_stdout_does_not_default(self):
        with mock.patch.object(sys, "frozen", False, create=True), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch.object(sys.stdout, "isatty", return_value=False):
            self.assertFalse(cli._default_to_dashboard())


class TestPortFallback(unittest.TestCase):
    def test_serve_falls_back_to_nearby_port(self):
        from malko import web
        import threading
        import urllib.request

        blocker = web.make_server(port=0)
        port = blocker.server_address[1]
        blocking_thread = threading.Thread(target=blocker.serve_forever, daemon=True)
        blocking_thread.start()
        try:
            server = None
            for candidate in range(port, port + 10):
                try:
                    server = web.make_server(candidate)
                    break
                except OSError:
                    continue
            self.assertIsNotNone(server)
            self.assertNotEqual(server.server_address[1], port)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_address[1]}/api/events"
                with urllib.request.urlopen(url, timeout=10) as resp:
                    self.assertEqual(resp.status, 200)
            finally:
                server.shutdown()
                server.server_close()
        finally:
            blocker.shutdown()
            blocker.server_close()


if __name__ == "__main__":
    unittest.main()
