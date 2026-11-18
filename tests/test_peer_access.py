# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "imageroot/pypkg"))
with patch.dict(sys.modules, {"agent": MagicMock()}):
    import kumomta_peer_access as access


class PeerAccessTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(temp.name)
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.dict(os.environ, {"MODULE_ID": "kumomta1"}))
        self.registry = {"kumomta2": "uuid2"}
        patches.enter_context(patch.object(access, "registered_uuid", side_effect=self.registry.get))

    def assert_denied(self, user):
        with patch.dict(os.environ, {"AGENT_TASK_USER": user}), contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exc:
                with access.authorized_peer():
                    self.fail("Unexpected access")
        self.assertEqual(exc.exception.code, 3)
        self.assertEqual(json.loads(output.getvalue())[0]["error"], "peer_not_authorized")

    def test_grants_bind_authenticated_id_and_current_uuid(self):
        self.assert_denied("module/kumomta2")
        access.set_peer_access("kumomta2", True)
        for user in ("", "admin", "node/2", "module/kumomta2/other", "module/kumomta3"):
            with self.subTest(user=user):
                self.assert_denied(user)
        with patch.dict(os.environ, {"AGENT_TASK_USER": "module/kumomta2"}):
            with access.authorized_peer() as peer:
                self.assertEqual(peer, "kumomta2")
        self.assertEqual(Path(access.GRANTS).stat().st_mode & 0o777, 0o600)
        self.registry["kumomta2"] = "replacement-uuid"
        self.assert_denied("module/kumomta2")

    def test_revocation_idempotent_after_peer_removal(self):
        access.set_peer_access("kumomta2", True)
        del self.registry["kumomta2"]
        access.set_peer_access("kumomta2", False)
        access.set_peer_access("kumomta2", False)
        self.assertEqual(access.read_grants(), {})
        self.registry["kumomta2"] = "uuid2"
        self.assert_denied("module/kumomta2")
