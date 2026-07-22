"""Local web dashboard for mal-ko.

A ThreadingHTTPServer bound to 127.0.0.1 only, serving a self-contained
single-page UI (malko.webui.PAGE) and a small JSON API. Scans and the
blocklist update run in background threads; their progress appears in
the event feed (events.jsonl via malko.state).

API:
  GET  /api/status            state + blocklist file info
  GET  /api/events            recent events
  GET  /api/findings          recorded findings
  GET  /api/quarantine        quarantine entries
  POST /api/quarantine/restore  {id, force?}   404 unknown id
  POST /api/update-blocklist  {}               starts refresh thread
  POST /api/scan              {type, path?}    type: deps|system|files
"""

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import blocklist, quarantine, state
from .scanners import deps, files, system
from .webui import PAGE

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
_SCAN_TYPES = ("deps", "system", "files")


def _validate_scan_target(scan_type, path):
    """Return an error string, or None when the target is acceptable."""
    if scan_type not in _SCAN_TYPES:
        return f"unknown scan type: {scan_type!r} (expected one of {_SCAN_TYPES})"
    if scan_type == "system":
        return None  # no path needed
    if not path:
        return "path is required for this scan type"
    p = Path(path)
    if not p.is_absolute():
        return f"path must be absolute: {path!r}"
    if not p.exists():
        return f"path does not exist: {path!r}"
    return None


def _run_scan(scan_type, path):
    """Background scan worker; reports through the event feed/state."""
    label = f"scan-{scan_type}"
    state.event("info", f"{label} started" + (f" on {path}" if path else ""), "scan")
    try:
        if scan_type == "deps":
            result = deps.scan(path)
            findings = result["findings"]
            summary = f"{len(result['packages'])} package(s), {len(findings)} finding(s)"
        elif scan_type == "files":
            result = files.scan([path], progress=False)
            findings = result["findings"]
            state.bump("files_scanned", len(result["files"]))
            summary = f"{len(result['files'])} file(s), {len(findings)} finding(s)"
        else:
            result = system.scan(max_products=10, progress=False)
            if result.get("error"):
                state.event("warning", f"{label}: {result['error']}", "scan")
                return
            findings = result["findings"]
            summary = f"{len(result['products'])} product(s), {len(findings)} finding(s)"
        state.add_findings(findings, source=label)
        state.set_last_scan(label, summary)
        level = "warning" if findings else "info"
        state.event(level, f"{label} finished: {summary}", "scan")
    except Exception as exc:  # noqa: BLE001 - report any scan failure to the feed
        state.event("critical", f"{label} failed: {exc}", "scan")


def _run_blocklist_update():
    state.event("info", "blocklist update started", "blocklist")
    try:
        count = blocklist.update()
        state.blocklist_updated(count)
        state.event("info", f"blocklist updated: {count} hashes", "blocklist")
    except Exception as exc:  # noqa: BLE001
        state.event("critical", f"blocklist update failed: {exc}", "blocklist")


class DashboardServer(ThreadingHTTPServer):
    """Threaded server that refuses to rebind an occupied port.

    (On Windows SO_REUSEADDR would otherwise let two dashboards share a
    port unpredictably, which would silently break the port fallback.)
    """

    allow_reuse_address = False
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "mal-ko-dashboard/0.1"

    def log_message(self, fmt, *args):  # keep the console clean
        pass

    # -- helpers ---------------------------------------------------------
    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}

    # -- GET -------------------------------------------------------------
    def do_GET(self):
        route = self.path.split("?", 1)[0].rstrip("/") or "/"
        if route == "/" or route == "/index.html":
            self._send_html(PAGE)
        elif route == "/api/status":
            self._send_json(self._status())
        elif route == "/api/events":
            self._send_json({"events": state.read_events(limit=200)})
        elif route == "/api/findings":
            self._send_json({"findings": state.load().get("findings", [])})
        elif route == "/api/quarantine":
            self._send_json({"entries": quarantine.list_entries()})
        else:
            self._send_json({"error": "not found"}, code=404)

    def _status(self):
        bl_path = blocklist.blocklist_path()
        bl_mtime = None
        try:
            from datetime import datetime, timezone

            bl_mtime = datetime.fromtimestamp(
                bl_path.stat().st_mtime, tz=timezone.utc
            ).isoformat(timespec="seconds")
        except OSError:
            pass
        return {
            "state": state.load(),
            "blocklist_path": str(bl_path),
            "blocklist_mtime": bl_mtime,
            "server_time": state.now_iso(),
        }

    # -- POST ------------------------------------------------------------
    def do_POST(self):
        route = self.path.split("?", 1)[0].rstrip("/")
        body = self._read_body()
        if route == "/api/quarantine/restore":
            self._post_restore(body)
        elif route == "/api/update-blocklist":
            threading.Thread(target=_run_blocklist_update, daemon=True).start()
            self._send_json({"ok": True, "status": "started"})
        elif route == "/api/scan":
            self._post_scan(body)
        else:
            self._send_json({"error": "not found"}, code=404)

    def _post_restore(self, body):
        entry_id = str(body.get("id") or "")
        if not entry_id:
            self._send_json({"error": "id is required"}, code=400)
            return
        try:
            quarantine.get_entry(entry_id)
        except quarantine.QuarantineError:
            self._send_json({"error": f"unknown id: {entry_id}"}, code=404)
            return
        try:
            dest = quarantine.restore(entry_id, force=bool(body.get("force")))
        except quarantine.QuarantineError as exc:
            self._send_json({"error": str(exc)}, code=400)
            return
        self._send_json({"ok": True, "path": str(dest)})

    def _post_scan(self, body):
        scan_type = str(body.get("type") or "")
        path = str(body.get("path") or "").strip()
        error = _validate_scan_target(scan_type, path)
        if error:
            self._send_json({"error": error}, code=400)
            return
        threading.Thread(
            target=_run_scan, args=(scan_type, path or None), daemon=True
        ).start()
        self._send_json({"ok": True, "status": "started", "type": scan_type})


def make_server(port=DEFAULT_PORT):
    """Create the dashboard server (does not start serving)."""
    return DashboardServer((BIND_HOST, port), Handler)


def serve(port=DEFAULT_PORT, open_browser=True, max_attempts=10):
    """Run the dashboard until Ctrl+C.

    If the requested port is occupied, nearby ports are tried so a
    double-clicked exe still ends up with a working dashboard.
    """
    server = None
    for candidate in range(port, port + max_attempts):
        try:
            server = make_server(candidate)
            break
        except OSError:
            continue
    if server is None:
        print(
            f"error: no free port in range {port}-{port + max_attempts - 1}",
            file=sys.stderr,
        )
        return 2
    actual_port = server.server_address[1]
    if actual_port != port:
        print(f"port {port} is busy, using port {actual_port} instead.",
              flush=True)
    url = f"http://{BIND_HOST}:{actual_port}/"
    state.event("info", f"dashboard started at {url}", "dashboard")
    print(f"mal-ko dashboard: {url}  (Ctrl+C to stop / Ctrl+C для остановки)",
          flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\ndashboard stopped.")
    finally:
        server.server_close()
    return 0
