#!/usr/bin/env python3

#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

# A minimal in-memory OpenBao/Vault KV v2 server for the CI, on 127.0.0.1:
#   fake_openbao.py PORT TOKEN
# GET/POST /v1/<mount>/data/<path> with X-Vault-Token. Nothing else.

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TOKEN = int(sys.argv[1]), sys.argv[2]
STORE = {}


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, body=None):
        data = json.dumps(body if body is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _key(self):
        parts = self.path.split("?", 1)[0].split("/")
        # ['', 'v1', mount, 'data', path...]
        if len(parts) < 5 or parts[1] != "v1" or parts[3] != "data":
            return None
        return parts[2] + ":" + "/".join(parts[4:])

    def _authorized(self):
        if self.headers.get("X-Vault-Token") != TOKEN:
            self._reply(403, {"errors": ["permission denied"]})
            return False
        return True

    def do_GET(self):
        if not self._authorized():
            return
        key = self._key()
        if key is None or key not in STORE:
            self._reply(404, {"errors": []})
            return
        self._reply(200, {"data": {"data": STORE[key], "metadata": {"version": 1}}})

    def do_POST(self):
        if not self._authorized():
            return
        key = self._key()
        if key is None:
            self._reply(404, {"errors": []})
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        STORE[key] = body.get("data") or {}
        self._reply(200, {"data": {"version": 1}})

    def log_message(self, fmt, *args):
        print(fmt % args, file=sys.stderr)


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
