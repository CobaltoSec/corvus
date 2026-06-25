"""
Minimal HTTP wrapper around mock_server.handle() for HttpTransport tests.
Runs the MCP JSON-RPC handler over HTTP POST on a random port.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from tests.mock_server import handle


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        # Capture headers (lowercased keys) so tests can verify custom headers were forwarded
        self.server.last_headers = {k.lower(): v for k, v in self.headers.items()}  # type: ignore[attr-defined]

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Bad JSON")
            return

        resp = handle(req)
        if resp is not None:
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(204)
            self.end_headers()

    def log_message(self, *args) -> None:
        pass  # silence request logs during tests


class MockHTTPServer:
    def __init__(self) -> None:
        # Port 0 lets the OS pick a free port
        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._server.last_headers: dict[str, str] = {}  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def last_headers(self) -> dict[str, str]:
        return self._server.last_headers  # type: ignore[attr-defined]

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()


class _HTMLHandler(BaseHTTPRequestHandler):
    """MCP server that returns HTML catch-all for tools/call — simulates an SPA server.

    initialize and tools/list behave normally; tools/call returns an HTML page
    that embeds sensitive-looking strings to verify they are NOT flagged (A6 FP fix).
    """

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Bad JSON")
            return

        if req.get("method") == "tools/call":
            # Return HTML instead of JSON-RPC — simulates SPA catch-all
            html = (
                "<!DOCTYPE html><html><body>"
                "<p>Not found. Path /etc/passwd not available.</p>"
                "<p>API_KEY=not-a-real-key</p>"
                "</body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        else:
            resp = handle(req)
            if resp is not None:
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(204)
                self.end_headers()

    def log_message(self, *args) -> None:
        pass


class MockHTMLHTTPServer:
    """HTTP server that returns HTML catch-all for tools/call — used to test A6 FP fix."""

    def __init__(self) -> None:
        self._server = HTTPServer(("127.0.0.1", 0), _HTMLHandler)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
