#!/usr/bin/env python3
"""Honeypot status relay on kan-pi.

kan-pi sits on both the tailnet and the office LAN, so it bridges
the tailnet-only status endpoint on the Sakura VPS to the office
display (which has no Tailscale). Serves the last fetched snapshot
on the LAN interface; refreshes every 10 seconds in the background
and serves stale data (with its age) when the VPS is unreachable.
"""
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("RELAY_UPSTREAM", "http://100.124.133.46:8901/status.json")
BIND = os.environ.get("RELAY_BIND", "192.168.80.123")
PORT = int(os.environ.get("RELAY_PORT", "8902"))
REFRESH = 10

state = {"body": None, "fetched_at": 0.0, "error": "not fetched yet"}
lock = threading.Lock()


def refresh_loop():
    while True:
        try:
            req = urllib.request.Request(UPSTREAM, headers={"User-Agent": "honeypot-relay/1.0"})
            with urllib.request.urlopen(req, timeout=4) as r:
                body = r.read()
            json.loads(body)  # validate before caching
            with lock:
                state["body"] = body
                state["fetched_at"] = time.time()
                state["error"] = None
        except Exception as e:  # keep serving the stale snapshot
            with lock:
                state["error"] = f"{type(e).__name__}: {e}"
        time.sleep(REFRESH)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        with lock:
            body, fetched_at, error = state["body"], state["fetched_at"], state["error"]
        age = time.time() - fetched_at if fetched_at else None
        if self.path.startswith("/status.json"):
            if body is None:
                self.send_error(503, "no snapshot yet")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Relay-Age", f"{age:.0f}" if age is not None else "-1")
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/health"):
            payload = json.dumps({
                "ok": body is not None,
                "age_s": round(age, 1) if age is not None else None,
                "error": error,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(404)


if __name__ == "__main__":
    threading.Thread(target=refresh_loop, daemon=True).start()
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
