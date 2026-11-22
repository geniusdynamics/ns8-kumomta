#!/usr/bin/env python3
#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Robot helper, run inside the module (runagent -m <id> python3 ...):
drive provisioned mode with the module's own Python and pypkg against the
in-process fake of tests/fake_bao_api.py, in a scratch state directory
(the instance state is not touched). Prints a JSON summary."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fake_bao_api import FakeBao  # noqa: E402
import openbao_client  # noqa: E402
import kumomta_ns8 as kumo  # noqa: E402

module = os.environ["MODULE_ID"]
os.chdir(tempfile.mkdtemp())
os.environ["AGENT_STATE_DIR"] = os.getcwd()
bao = FakeBao()
bao.start()
run = bao.runner(module)
settings = dict(kumo.DEFAULTS, domains=[], vault_enabled=True, vault_auth="provisioned", vault_provider="openbao1")
out = {"first": kumo.provisioned_client_step(settings, run=run)[0]}
bao.approved[module] = {}
out["approved"] = kumo.provisioned_client_step(settings, run=run)[0]
view = kumo.vault_view(settings) or {}
out["source"] = view.get("source", "")
out["path"] = view.get("path", "")
out["token_hidden"] = openbao_client.read_token() not in json.dumps(openbao_client.public_state())
out["dir_mode"] = oct(os.stat(openbao_client._dir()).st_mode & 0o777)
bao.revoke(module)
openbao_client.mark_reprovision()
out["revoked"] = kumo.provisioned_client_step(settings, run=run)[0]
out["fallback_local"] = kumo.vault_view(settings) is None
bao.stop()
json.dump(out, sys.stdout)
