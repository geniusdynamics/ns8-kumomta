#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Regression tests for DKIM provisioning at one shared selector."""

import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import types
import unittest
import urllib.request  # noqa: F401 (imported before the agent stub below)
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "imageroot/pypkg"))
# Production loads this SDK from the NS8 core image.


def read_envfile(path):
    with open(path) as fp:
        return dict(line.split("=", 1) for line in fp.read().splitlines() if "=" in line)


with patch.dict(sys.modules, {"agent": types.SimpleNamespace(SD_ERR="", SD_WARNING="", read_envfile=read_envfile)}):
    import kumomta_ns8 as kumo

DOMAIN = "customer.example"
SELECTOR = "s1"


class ClusterDkimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first, cls.first_public = kumo.generate_dkim_key()
        cls.other, cls.other_public = kumo.generate_dkim_key()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(temp.name)
        self.settings = dict(kumo.DEFAULTS, cluster_store="manual", domains=[])
        self.key, self.pub = map(Path, kumo.dkim_paths(DOMAIN, SELECTOR))

    def enable_vault(self):
        self.settings["vault_enabled"] = True
        kumo.write_openbao_env("http://vault.example", "test")

    def install(self, **kwargs):
        return kumo.install_dkim_key(self.settings, DOMAIN, SELECTOR, **kwargs)

    def test_local_explicit_generation_retry_import_and_rotation(self):
        with self.assertRaisesRegex(kumo.DomainError, "cluster_key_required"):
            kumo.add_domain(self.settings, DOMAIN, SELECTOR)
        self.assertEqual(self.settings["domains"], [])
        self.install(source="generate")
        original = self.key.read_text()
        self.install(source="generate")
        self.install(source="peer", pem=original)
        with self.assertRaisesRegex(kumo.DomainError, "local_key_conflict"):
            self.install(source="import", pem=self.other)
        with self.assertRaisesRegex(kumo.DomainError, "cluster_rotation_refused"):
            self.install(source="generate", rotate=True)
        self.assertEqual(self.key.read_text(), original)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.settings["cluster_store"] = "none"
        self.install(source="generate", rotate=True)
        self.assertNotEqual(self.key.read_text(), original)

    def test_public_only_state_requires_matching_private_key(self):
        kumo.store_dkim_public(DOMAIN, SELECTOR, self.first_public)
        with self.assertRaisesRegex(kumo.DomainError, "cluster_key_required"):
            self.install(source="generate")
        with self.assertRaisesRegex(kumo.DomainError, "local_key_conflict"):
            self.install(source="peer", pem=self.other)
        self.assertFalse(self.key.exists())
        self.assertEqual(self.pub.read_text().strip(), self.first_public)
        self.assertEqual(self.install(source="peer", pem=self.first), "local")

    def test_existing_local_key_migrates_to_vault_with_create_only(self):
        self.install(source="import", pem=self.first)
        self.enable_vault()
        with patch.object(kumo, "read_shared_dkim_key", return_value=None), patch.object(kumo, "openbao_write") as write:
            self.assertEqual(self.install(source="generate"), "openbao")
        write.assert_called_once()
        self.assertEqual(write.call_args.args[1:], ("kumomta/dkim/customer.example/s1", self.first))
        self.assertTrue(write.call_args.kwargs["create_only"])
        self.assertFalse(self.key.exists())
        self.assertEqual(self.pub.read_text().strip(), self.first_public)

    def test_generated_keys_converge_on_winner_of_concurrent_vault_create(self):
        self.enable_vault()
        conflict = kumo.OpenBaoHTTPError(400, "selector")
        # Another peer commits its key between our read and our create-only write.
        with patch.object(kumo, "read_shared_dkim_key", side_effect=[None, self.other]) as read, \
             patch.object(kumo, "openbao_write", side_effect=conflict) as write:
            entry = kumo.add_domain(self.settings, DOMAIN, SELECTOR)
        self.assertEqual(entry["status"], "pending")
        self.assertTrue(write.call_args.kwargs["create_only"])
        self.assertEqual(read.call_count, 2)
        self.assertFalse(self.key.exists())
        self.assertEqual(self.pub.read_text().strip(), self.other_public)
        with patch.object(kumo, "read_shared_dkim_key", return_value=self.other), patch.object(kumo, "openbao_write") as write:
            self.assertEqual(self.install(source="generate"), "openbao")
            write.assert_not_called()

    def test_racing_existing_or_explicit_key_is_never_replaced(self):
        self.enable_vault()
        conflict = kumo.OpenBaoHTTPError(400, "selector")
        for existing in [False, True]:
            with self.subTest(existing=existing):
                if existing:
                    kumo.store_dkim_private(DOMAIN, SELECTOR, self.first)
                    kumo.store_dkim_public(DOMAIN, SELECTOR, self.first_public)
                with patch.object(kumo, "read_shared_dkim_key", side_effect=[None, self.other]), \
                     patch.object(kumo, "openbao_write", side_effect=conflict):
                    with self.assertRaisesRegex(kumo.DomainError, "local_key_conflict" if existing else "shared_key_exists"):
                        self.install(source="import", pem=self.first)
                self.assertEqual(self.key.exists(), existing)
                self.assertEqual(self.pub.exists(), existing)
                if existing:
                    self.assertEqual(self.key.read_text(), self.first)
                    self.assertEqual(self.pub.read_text().strip(), self.first_public)

    def test_vault_write_serializes_kv2_cas_and_denial_is_fatal(self):
        env = {"VAULT_ADDR": "http://vault.example", "VAULT_TOKEN": "test"}
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"{}")) as send:
            kumo.openbao_write(self.settings, "test-path", "test-value", env, create_only=True)
        request = send.call_args.args[0]
        self.assertEqual(json.loads(request.data), {"options": {"cas": 0}, "data": {"key": "test-value"}})
        denied = kumo.OpenBaoHTTPError(403, "secret")
        self.enable_vault()
        with patch.object(kumo, "openbao_read", side_effect=denied), patch.object(kumo, "openbao_write") as write:
            with self.assertRaisesRegex(kumo.DomainError, "openbao_read_failed"):
                self.install()
            write.assert_not_called()

    def test_domain_api_requires_an_existing_or_imported_key(self):
        kumo.save_settings(self.settings)
        with patch.dict(sys.modules, {"kumomta_ns8": kumo}):
            handler_type = runpy.run_path(str(ROOT / "imageroot/bin/kumomta-api"))["Handler"]
        handler = object.__new__(handler_type)
        handler.path = "/api/v1/domains"
        handler.authenticate = Mock(return_value={"name": "platform"})
        handler.reply = Mock()
        data = {"domain": DOMAIN, "selector": SELECTOR}
        handler.body = Mock(return_value=data)
        handler.handle_any("POST")
        handler.reply.assert_called_with(422, {"error": "cluster_key_required", "detail": DOMAIN})
        self.assertEqual(kumo.load_settings()["domains"], [])
        with self.assertRaisesRegex(kumo.DomainError, "invalid_private_key"):
            self.install(source="import", pem="invalid")
        self.install(source="import", pem=self.first)
        data["dkim_private_key"] = self.other
        handler.handle_any("POST")
        handler.reply.assert_called_with(409, {"error": "local_key_conflict", "detail": DOMAIN})
        data["dkim_private_key"] = self.first
        with patch.object(kumo, "apply_policy"):
            handler.handle_any("POST")
        status, body = handler.reply.call_args.args
        self.assertEqual(status, 201)
        self.assertEqual(body["owner"], "platform")
        self.assertEqual(body["dkim_record"]["value"], f"v=DKIM1; k=rsa; p={self.first_public}")


if __name__ == "__main__":
    unittest.main()
