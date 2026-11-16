#!/usr/bin/env python3

#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Webhook receiver of the CI, on 127.0.0.1:
#   fake_webhook.py serve PORT FILE
#       append each POST as a JSON line {"headers": {...}, "body": "..."}
#   fake_webhook.py check FILE RECIPIENT SECRET TOKEN
#       find the record of RECIPIENT, verify X-KumoMTA-Signature and the
#       bearer token, print the record; exit 1 if missing or invalid

import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def serve(port, path):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode(errors="replace")
            with open(path, "a") as fp:
                fp.write(json.dumps({"headers": dict(self.headers.items()), "body": body}) + "\n")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *args):
            print(fmt % args, file=sys.stderr)

    ThreadingHTTPServer(("127.0.0.1", int(port)), Handler).serve_forever()


def check(path, recipient, secret, token):
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        req = json.loads(line)
        record = json.loads(req["body"])
        if record.get("recipient") != recipient:
            continue
        headers = {k.lower(): v for k, v in req["headers"].items()}
        fields = dict(f.split("=", 1) for f in headers.get("x-kumomta-signature", "").split(",") if "=" in f)
        expected = hmac.new(secret.encode(), (fields.get("t", "") + "." + req["body"]).encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, fields.get("v1", "")):
            print("bad signature", headers.get("x-kumomta-signature"))
            sys.exit(1)
        if headers.get("authorization") != "Bearer " + token:
            print("bad token")
            sys.exit(1)
        print(json.dumps(record))
        sys.exit(0)
    print("no record for", recipient)
    sys.exit(1)


if sys.argv[1] == "serve":
    serve(sys.argv[2], sys.argv[3])
else:
    check(*sys.argv[2:6])
