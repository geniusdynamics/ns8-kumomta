#!/usr/bin/env python3

#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

# SMTP checks run on the test node:
#   smtp_check.py banner HOST PORT
#   smtp_check.py submit HOST PORT USER PASSWORD FROM TO
#   smtp_check.py badauth HOST PORT USER
#   smtp_check.py relay HOST PORT FROM TO     (expects relaying denied)

import smtplib
import socket
import ssl
import sys

cmd, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

if cmd == "banner":
    with socket.create_connection((host, port), timeout=15) as sock:
        banner = sock.recv(512).decode(errors="replace").strip()
        sock.sendall(b"QUIT\r\n")
    print(banner)
    sys.exit(0 if banner.startswith("220 ") else 1)

if cmd == "submit":
    user, password, mfrom, rcpt = sys.argv[4:8]
    msg = (f"From: {mfrom}\r\nTo: {rcpt}\r\nSubject: ns8-kumomta CI\r\n"
           f"Message-ID: <ci-{port}@ns8-ci.test>\r\n\r\nTest message\r\n")
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo("ci.ns8-ci.test")
        smtp.starttls(context=ctx)
        smtp.ehlo("ci.ns8-ci.test")
        print(smtp.login(user, password))
        refused = smtp.sendmail(mfrom, [rcpt], msg)
    print("accepted", refused)
    sys.exit(0 if not refused else 1)

if cmd == "badauth":
    user = sys.argv[4]
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.starttls(context=ctx)
        try:
            smtp.login(user, "wrong-password-123")
        except smtplib.SMTPAuthenticationError as ex:
            print("rejected", ex.smtp_code)
            sys.exit(0)
    print("login accepted with a wrong password")
    sys.exit(1)

if cmd == "relay":
    mfrom, rcpt = sys.argv[4:6]
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo("ci.ns8-ci.test")
        try:
            smtp.sendmail(mfrom, [rcpt], "Subject: relay test\r\n\r\nx\r\n")
        except smtplib.SMTPRecipientsRefused as ex:
            print("denied", ex.recipients)
            sys.exit(0)
    print("relaying was accepted")
    sys.exit(1)

sys.exit(2)
