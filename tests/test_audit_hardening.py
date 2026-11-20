#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

import base64
from contextlib import nullcontext
import hashlib
from pathlib import Path
import runpy
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "imageroot/pypkg"))
with patch.dict(sys.modules, {"agent": types.SimpleNamespace(SD_WARNING="", SD_ERR="")}):
    import kumomta_ns8 as kumo


class CredentialsTest(unittest.TestCase):
    def test_legacy_upgrade_preserves_password_without_retaining_fast_hash(self):
        password = "example-fixture-password"
        salt = "example-legacy-salt"
        old = {"salt": salt, "sha256": hashlib.sha256((salt + password).encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, patch.object(kumo, "SECRETS_DIR", directory):
            self.assertTrue(kumo.write_smtp_users({"alice": old}))
            upgraded = kumo.read_smtp_users()["alice"]
            self.assertNotIn("sha256", upgraded)
            self.assertTrue(kumo.check_password(upgraded, password))
            self.assertFalse(kumo.check_password(upgraded, "other-password"))
            self.assertFalse(kumo.write_smtp_users({"alice": upgraded}))
            rotated = kumo.hash_password("other-password")
            self.assertFalse(kumo.check_password(rotated, password))
            self.assertTrue(kumo.check_password(rotated, "other-password"))
            self.assertNotIn(password, (Path(directory) / "smtp_users.json").read_text())
            self.assertNotIn(upgraded["scrypt"], (Path(directory) / "smtp_users.toml").read_text())

    def test_domain_auth_and_local_verifier_apply_independent_scope_checks(self):
        with patch.dict(sys.modules, {"kumomta_ns8": kumo}):
            handler_type = runpy.run_path(str(ROOT / "imageroot/bin/kumomta-api"))["Handler"]
        handler = object.__new__(handler_type)
        password = "fixture-example-password"
        auth = base64.b64encode(f"platform:{password}".encode()).decode()
        handler.headers = {"Authorization": f"Basic {auth}"}
        handler.error = Mock()
        handler.reply = Mock()
        credential = {"salt": "old", "sha256": hashlib.sha256(("old" + password).encode()).hexdigest()}
        integration = {"name": "platform", "scopes": ["inject"]}
        with patch.object(kumo, "load_settings", return_value={"integrations": [integration]}), \
                patch.object(kumo, "read_integrations_secrets", return_value={"platform": credential}), \
                patch.object(kumo, "read_smtp_users", return_value={}), \
                patch.object(kumo, "read_secret", return_value="fixture-token"):
            self.assertIsNone(handler.authenticate())
            self.assertEqual(handler.error.call_args.args[:2], (403, "forbidden"))
            handler.headers["X-Kumo-Local-Token"] = "fixture-token"
            handler.body = Mock(return_value={"name": "platform", "password": password, "scope": "inject"})
            handler.verify_local_auth()
            handler.reply.assert_called_with(200, {})
            handler.body.return_value["scope"] = "smtp"
            handler.verify_local_auth()
            handler.reply.assert_called_with(401, {})
            del handler.headers["X-Kumo-Local-Token"]
            handler.verify_local_auth()
            handler.error.assert_called_with(401, "unauthorized")

    def test_domain_mutation_limits_are_applied_together(self):
        with patch.dict(sys.modules, {"kumomta_ns8": kumo}):
            api = runpy.run_path(str(ROOT / "imageroot/bin/kumomta-api"))
        limit = api["_rate_limit"]
        with patch("time.monotonic", return_value=300) as now:
            self.assertTrue(limit(("one", 1), ("global", 2)))
            self.assertFalse(limit(("one", 1), ("global", 2)))
            self.assertTrue(limit(("two", 1), ("global", 2)))
            self.assertFalse(limit(("three", 1), ("global", 2)))
            now.return_value = 360
            self.assertTrue(limit(("three", 1), ("global", 2)))


class RelayTrustTest(unittest.TestCase):
    def test_cluster_relay_is_opt_in_and_requires_vpn_endpoint(self):
        with patch.object(kumo, "cluster_info", return_value=("192.0.2.0/24", "192.0.2.10")):
            self.assertEqual(kumo.cluster_relay_policy(kumo.DEFAULTS), {})
            settings = dict(kumo.DEFAULTS, cluster_relay=True)
            self.assertEqual(kumo.cluster_relay_policy(settings), {
                "cluster_network": "192.0.2.0/24", "cluster_address": "192.0.2.10",
            })
            self.assertEqual(kumo.cluster_relay_policy(dict(settings, inbound_port=2525)), {})
        with patch.object(kumo, "cluster_info", return_value=("192.0.2.0/24", "198.51.100.10")):
            self.assertEqual(kumo.cluster_relay_policy(settings), {})

    def test_tsa_trusts_registered_kumomta_addresses_for_same_store(self):
        modules = {"kumomta1": "11", "kumomta2": "12", "kumomta3": "13", "other1": "14"}
        records = {
            "kumomta1": {"module_uuid": "one", "store": "same", "host": "192.0.2.11", "tsa": "1", "port": "8001"},
            "kumomta2": {"module_uuid": "two", "store": "same", "host": "192.0.2.12"},
            "kumomta3": {"module_uuid": "three", "store": "different", "host": "192.0.2.13"},
            "other1": {"module_uuid": "four", "store": "same", "host": "192.0.2.14"},
            "kumomta4": {"module_uuid": "five", "store": "same", "host": "192.0.2.15"},
        }
        rdb = Mock()
        rdb.hget.side_effect = lambda key, _: f"192.0.2.{key.split('/')[1]}"
        connection = types.SimpleNamespace(redis_connect=Mock(return_value=nullcontext(rdb)))
        with patch.object(kumo, "kumomta_modules", return_value=modules), \
                patch.object(kumo, "service_records", return_value=records), \
                patch.object(kumo, "agent", connection):
            self.assertEqual(kumo.tsa_peers("same", "192.0.2.0/24"),
                             ({"192.0.2.11", "192.0.2.12"}, ["http://192.0.2.11:8001"]))
            records["kumomta2"]["host"] = "192.0.2.19"
            self.assertEqual(kumo.tsa_peers("same", "192.0.2.0/24"),
                             ({"192.0.2.11"}, ["http://192.0.2.11:8001"]))
