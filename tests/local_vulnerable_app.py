"""Controlled local application used by authorized Phase 4 integration tests."""
from __future__ import annotations

import html
import sqlite3
import tempfile
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class LocalVulnerableApp(BaseHTTPRequestHandler):
    db_path = None
    def log_message(self, format, *args):
        pass

    def _send(self, status, body, headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path
        value = query.get("input", [""])[0]

        if path == "/reflect":
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/reflect-safe":
            return self._send(200, f"<html><body>{html.escape(value, quote=True)}</body></html>")
        if path == "/large":
            return self._send(200, "A" * 10000)
        if path in ("/sqli/sqlite-vulnerable", "/sqli/sqlite-safe"):
            value = query.get("id", ["1"])[0]
            connection = sqlite3.connect(self.db_path)
            try:
                if path.endswith("vulnerable"):
                    # Deliberately vulnerable fixture: the controlled test value
                    # is concatenated into a real SQLite query.
                    rows = connection.execute(
                        f"SELECT name FROM users WHERE id = {value}"
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT name FROM users WHERE id = ?", (value,)
                    ).fetchall()
                return self._send(200, repr(rows))
            except sqlite3.Error as exc:
                return self._send(500, f"sqlite3.OperationalError: {exc}")
            finally:
                connection.close()
        if path == "/waf/block":
            if "<script" in value or "'" in value:
                return self._send(403, "Access Denied by AWS WAF", {"x-amzn-waf": "1"})
            return self._send(200, "<html><body>ok</body></html>")
        if path == "/waf/observed":
            return self._send(403, "AWS WAF request blocked", {"x-amzn-waf": "1"})
        if path == "/csp-strict":
            return self._send(
                200, f"<html><body>{value}</body></html>",
                {"Content-Security-Policy": "default-src 'self'; script-src 'self'"},
            )
        return self._send(404, "not found")


def start_server():
    database = tempfile.NamedTemporaryFile(prefix="ailook-sqli-", suffix=".sqlite", delete=False)
    database.close()
    with sqlite3.connect(database.name) as connection:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        connection.execute("INSERT INTO users(id, name) VALUES (1, 'fixture-user')")
    handler = type("FixtureHandler", (LocalVulnerableApp,), {"db_path": database.name})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.db_path = database.name
    return server
