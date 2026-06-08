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
