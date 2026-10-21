"""HTTP callback listener: records inbound requests (SSRF evidence)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.callback_hits.append({"path": self.path, "method": "GET"})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        self.server.callback_hits.append({"path": self.path, "method": "POST"})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


class CallbackListener:
    """A threaded HTTP server that records all incoming requests."""

    def __init__(self, port: int = 9091, host: str = "127.0.0.1"):
        self.port = port
        self.host = host
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._server = HTTPServer((self.host, self.port), _CallbackHandler)
        self._server.callback_hits = []
        self.port = self._server.server_address[1]  # update if ephemeral
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def get_hits(self) -> list[dict]:
        if self._server:
            return list(self._server.callback_hits)
        return []

    def clear_hits(self) -> None:
        if self._server:
            self._server.callback_hits = []

    @property
    def hit_count(self) -> int:
        return len(self.get_hits())
