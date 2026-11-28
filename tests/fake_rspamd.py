#!/usr/bin/env python3
"""Local Rspamd protocol fixture for the QEMU submission tests."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Scanner(BaseHTTPRequestHandler):
    def do_POST(self):
        message = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path != "/checkv2" or self.headers.get("Password") != "ci-only-rspamd-password":
            self.send_error(403)
            return
        action = "reject" if b"guard-scan-reject@example.net" in message else "no action"
        body = json.dumps({"action": action}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Scanner).serve_forever()
