"""Controlled local application used by authorized integration tests."""
from __future__ import annotations

import html
import json
import re
import sqlite3
import tempfile
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse


class LocalVulnerableApp(BaseHTTPRequestHandler):
    db_path = None
    state = None
    def log_message(self, format, *args):
        pass

    def _send(self, status, body, headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        supplied_headers = headers or {}
        content_type = next(
            (value for key, value in supplied_headers.items()
             if key.lower() == "content-type"),
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in supplied_headers.items():
            if key.lower() == "content-type":
                continue
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def do_GET(self):
        with self.state["lock"]:
            self.state["request_count"] += 1
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path
        value = query.get("input", [""])[0]
        recorded_value = next(iter(query.values()), [""])[0]
        with self.state["lock"]:
            self.state["request_values"].append(recorded_value)

        if path == "/reflect":
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/reflect-safe":
            return self._send(200, f"<html><body>{html.escape(value, quote=True)}</body></html>")
        if path == "/reflect-encoded":
            encoded = html.escape(value, quote=True).replace("&#x27;", "&#39;")
            return self._send(200, f"<html><body>{encoded}</body></html>")
        if path == "/xss/json":
            return self._send(
                200, json.dumps({"value": value}),
                {"Content-Type": "application/json; charset=utf-8"},
            )
        if path == "/xss/attribute":
            return self._send(200, f'<html><body><input value="{value}"></body></html>')
        if path == "/xss/script-string":
            return self._send(200, f'<html><body><script>const q="{value}";</script></body></html>')
        if path == "/xss/escaped":
            return self._send(200, f"<html><body>{html.escape(value, quote=True)}</body></html>")
        if path == "/xss/mismatch":
            if "__AI_LOOK_PHASE6_PROOF__" in value:
                value = value.replace("__AI_LOOK_PHASE6_PROOF__", "__AI_LOOK_WRONG_PROOF__")
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/xss/stale-token":
            if value.startswith("AILOOKREFLECT"):
                stale = self.state.get("previous_xss_token")
                prefix = (
                    f'<script>window.__AI_LOOK_PHASE6_PROOF__="{stale}";</script>'
                    if stale else ""
                )
                return self._send(200, f"<html><body>{prefix}{value}</body></html>")
            token_match = re.search(
                r'__AI_LOOK_PHASE6_PROOF__ = "([0-9a-f]{48})"', value,
            )
            current = token_match.group(1) if token_match else ""
            stale = self.state.get("previous_xss_token")
            self.state["previous_xss_token"] = current
            if stale:
                old_proof = f'<script>window.__AI_LOOK_PHASE6_PROOF__ = "{stale}";</script>'
                return self._send(200, f"<html><body>{old_proof}{html.escape(value, quote=True)}</body></html>")
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/xss/resources":
            return self._send(
                200,
                "<html><body><script>"
                "fetch('http://outside.invalid/xss-fetch').catch(()=>{});"
                "new WebSocket('ws://outside.invalid/xss-socket');"
                "window.open('http://outside.invalid/xss-popup');"
                "</script>" + value + "</body></html>",
            )
        if path == "/xss/non-http":
            return self._send(
                200,
                '<html><body><iframe src="data:text/html,%3Cscript%3Ewindow.__data_frame_loaded=true%3C/script%3E"></iframe>'
                + value + "</body></html>",
            )
        if path == "/xss/worker":
            return self._send(
                200,
                "<html><body><script>"
                "const w=new Worker('/xss/worker-script');"
                "w.onmessage=()=>window.__worker_done=true;"
                "</script>" + value + "</body></html>",
            )
        if path == "/xss/worker-script":
            return self._send(
                200,
                "fetch('http://outside.invalid/xss-worker').catch(()=>{});postMessage('done');",
                {"Content-Type": "application/javascript; charset=utf-8"},
            )
        if path == "/xss/same-origin-resource":
            return self._send(
                200,
                "<html><body><script src='/xss/resource-script'></script>" + value + "</body></html>",
            )
        if path == "/xss/resource-script":
            return self._send(
                200, "window.__same_origin_resource_loaded = true;",
                {"Content-Type": "application/javascript; charset=utf-8"},
            )
        if path == "/xss/slow":
            time.sleep(4)
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/xss/slow-proof":
            if not value.startswith("AILOOKREFLECT"):
                time.sleep(4)
            return self._send(200, f"<html><body>{value}</body></html>")
        if path == "/xss/concurrent-slow":
            with self.state["lock"]:
                self.state["active_slow"] += 1
                self.state["max_active_slow"] = max(
                    self.state["max_active_slow"], self.state["active_slow"],
                )
            try:
                time.sleep(0.05)
                return self._send(200, f"<html><body>{value}</body></html>")
            finally:
                with self.state["lock"]:
                    self.state["active_slow"] -= 1
        if path == "/xss/large-proof":
            if value.startswith("AILOOKREFLECT"):
                return self._send(200, f"<html><body>{value}</body></html>")
            return self._send(200, f"<html><body>{value}{'A' * 1_200_000}</body></html>")
        if path == "/xss/redirect-outside":
            if value.startswith("AILOOKREFLECT"):
                return self._send(200, f"<html><body>{value}</body></html>")
            self.send_response(302)
            self.send_header("Location", "http://outside.invalid/xss-redirect")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/xss/redirect-authorized":
            if value.startswith("AILOOKREFLECT"):
                return self._send(200, f"<html><body>{value}</body></html>")
            self.send_response(302)
            self.send_header("Location", "/reflect?" + urlencode({"input": value}))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/reflect-false-only":
            value = query.get("id", query.get("input", [""]))[0]
            if "1=2" in value or "'1'='2" in value:
                return self._send(200, f"<html><body>reflected {value}</body></html>")
            return self._send(200, "<html><body>normal</body></html>")
        if path == "/large":
            return self._send(200, "A" * 10000)
        if path == "/undecodable":
            return self._send(200, "stable body", {"Content-Encoding": "x-unknown-coding"})
        if path == "/dynamic":
            return self._send(200, f"stable-prefix-{uuid.uuid4()}")
        if path == "/slow":
            with self.state["lock"]:
                self.state["active_slow"] += 1
                self.state["max_active_slow"] = max(
                    self.state["max_active_slow"], self.state["active_slow"]
                )
            try:
                time.sleep(0.05)
                return self._send(200, "stable slow response")
            finally:
                with self.state["lock"]:
                    self.state["active_slow"] -= 1
        if path == "/status-404":
            return self._send(404, "not found")
        if path == "/status-500":
            return self._send(500, "server error")
        if path == "/redirect-untrusted":
            self.send_response(302)
            self.send_header("Location", "http://outside.invalid/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/redirect-authorized":
            self.send_response(302)
            self.send_header("Location", "/reflect?" + urlencode({"input": value}))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/sqli/one-empty":
            with self.state["lock"]:
                send_empty = not self.state["empty_sent"]
                self.state["empty_sent"] = True
            if send_empty:
                return self._send(200, "")
            return self._send(200, "[]" if "1=2" in value else "fixture")
        if path == "/sqli/empty-all":
            return self._send(200, "")
        if path == "/sqli/status-variation":
            value = query.get("id", query.get("input", [""]))[0]
            return self._send(201 if "1=1" in value else 200, "stable")
        if path == "/sqli/candidate-only":
            value = query.get("id", [""])[0]
            if value.endswith("'") or " OR " in value.upper():
                return self._send(500, "sqlite3.OperationalError: near quote fixture-secret")
            return self._send(200, "[('fixture-user',)]")
        if path in ("/sqli/sqlite-vulnerable", "/sqli/sqlite-safe", "/sqli/sqlite-toggle"):
            value = query.get("id", ["1"])[0]
            if path.endswith("toggle") and self.state["sqli_mode"] == "incomplete":
                if value == "1":
                    self.state["toggle_baseline_count"] += 1
                    if self.state["toggle_baseline_count"] == 5:
                        return self._send(200, "")
                if value.endswith("'") or " OR " in value.upper():
                    return self._send(500, "sqlite3.OperationalError: near quote")
                if "1=2" in value:
                    return self._send(200, "[]")
                return self._send(200, "[('fixture-user',)]")
            connection = sqlite3.connect(self.db_path)
            try:
                if path.endswith("vulnerable") or (path.endswith("toggle") and not self.state["sqli_safe"]):
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
        if path in ("/sqli/sqlite-string-vulnerable", "/sqli/sqlite-string-safe"):
            value = query.get("name", ["fixtureuser"])[0]
            connection = sqlite3.connect(self.db_path)
            try:
                if path.endswith("vulnerable"):
                    rows = connection.execute(
                        f"SELECT name FROM users WHERE name = '{value}'"
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT name FROM users WHERE name = ?", (value,)
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
        connection.execute("INSERT INTO users(id, name) VALUES (2, 'fixtureuser')")
    state = {
        "lock": threading.Lock(),
        "empty_sent": False,
        "request_count": 0,
        "request_values": [],
        "resolver_calls": [],
        "active_slow": 0,
        "max_active_slow": 0,
        "sqli_safe": False,
        "sqli_mode": "normal",
        "toggle_baseline_count": 0,
    }
    handler = type("FixtureHandler", (LocalVulnerableApp,), {"db_path": database.name, "state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.db_path = database.name
    return server
