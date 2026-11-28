# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later

# Multi-tenant integrations, loopback trust and the tsa-daemon peer list

import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "imageroot/pypkg"))
with patch.dict(sys.modules, {"agent": MagicMock()}):
    import kumomta_ns8 as kumo

TEMPLATES = Path(__file__).resolve().parents[1] / "imageroot/templates"


class TenantRulesTest(unittest.TestCase):
    def test_multi_tenant_credential_without_prefix_allows_any_label(self):
        integ = {"name": "bonga", "tenant": "", "tenant_prefix": ""}
        self.assertTrue(kumo.integration_tenant_allowed(integ, "bonga-42"))
        self.assertTrue(kumo.integration_tenant_allowed(integ, "customer.7"))

    def test_prefix_limits_the_labels(self):
        integ = {"name": "bonga", "tenant": "", "tenant_prefix": "bonga-"}
        self.assertTrue(kumo.integration_tenant_allowed(integ, "bonga-42"))
        self.assertFalse(kumo.integration_tenant_allowed(integ, "other-42"))

    def test_fixed_tenant_allows_only_itself(self):
        integ = {"name": "shop", "tenant": "shop1", "tenant_prefix": ""}
        self.assertTrue(kumo.integration_tenant_allowed(integ, "shop1"))
        self.assertFalse(kumo.integration_tenant_allowed(integ, "shop2"))

    def test_invalid_labels_are_refused(self):
        integ = {"name": "bonga", "tenant": ""}
        for label in ("", "with space", "a/b", "x" * 65):
            with self.subTest(label=label):
                self.assertFalse(kumo.integration_tenant_allowed(integ, label))


class RenderTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(temp.name)
        self.settings = kumo.load_settings()
        self.settings["hostname"] = "mta.example.org"

    def relay_networks(self):
        with patch.object(kumo, "cluster_info", return_value=(None, None)), \
                patch.object(kumo, "read_cluster_state", return_value={}):
            files = kumo.render(self.settings, str(TEMPLATES / "init.lua"))
        return tomllib.loads(files["relay_hosts.toml"]).get("networks", [])

    def test_loopback_trusted_by_default(self):
        self.assertTrue(self.settings["trust_loopback"])
        self.assertEqual(self.relay_networks()[:2], ["127.0.0.0/8", "::1/128"])

    def test_loopback_trust_can_be_turned_off(self):
        self.settings["trust_loopback"] = False
        self.settings["relay_networks"] = ["192.168.1.0/24"]
        self.assertEqual(self.relay_networks(), ["192.168.1.0/24"])

    def test_integration_policy_carries_prefix(self):
        self.settings["integrations"] = [{"name": "bonga", "tenant": "", "tenant_prefix": "bonga-",
                                          "scopes": ["inject", "domains"], "max_message_rate": "100/h",
                                          "max_domains": 0}]
        salt, digest = kumo.hash_password("0123456789abcdef")
        kumo.write_integrations(self.settings, {"bonga": {"salt": salt, "sha256": digest}})
        with open(os.path.join(kumo.SECRETS_DIR, "integrations.toml"), "rb") as fp:
            table = tomllib.load(fp)["integration"]["bonga"]
        self.assertEqual(table["tenant_prefix"], "bonga-")
        self.assertEqual(table["tenant"], "")
        self.assertEqual(table["max_message_rate"], "100/h")


    def test_guard_policy_and_isolated_sandbox_pool(self):
        self.settings.update({
            "sending_ips": [{"address": "192.0.2.10"}, {"address": "192.0.2.11"}],
            "sandbox_ips": ["192.0.2.11"],
            "tenant_policies": {"ci.customer": {"admission_per_hour": 25, "pool": "sandbox", "paused": True}},
        })
        self.assertEqual(list(kumo.submission_guard_errors(self.settings)), [])
        with patch.object(kumo, "cluster_info", return_value=(None, None)):
            files = kumo.render(self.settings, str(TEMPLATES / "init.lua"))
        pools = tomllib.loads(files["sources.toml"])["pool"]
        self.assertEqual(set(pools["default"]), {kumo.source_name(self.settings, "192.0.2.10")})
        self.assertEqual(set(pools["sandbox"]), {kumo.source_name(self.settings, "192.0.2.11")})
        self.assertEqual(pools["ns8-paused"], {})
        policy = tomllib.loads(files["submission-guard.toml"])
        self.assertEqual(policy["tenant"]["ci.customer"], self.settings["tenant_policies"]["ci.customer"])
        headers = tomllib.loads(files["dkim_data.toml"])["base"]["headers"]
        self.assertIn("List-Unsubscribe", headers)
        self.assertIn("List-Unsubscribe-Post", headers)

    def test_shared_pool_and_unsafe_credential_settings_are_refused(self):
        self.settings.update({
            "sending_ips": [{"address": ""}, {"address": "192.0.2.11"}],
            "sandbox_ips": ["192.0.2.11"], "smarthost_enabled": True,
            "integrations": [{"name": "bonga", "scopes": ["smtp"]}],
            "guarded_integrations": ["bonga", "unknown"],
        })
        errors = {error[2] for error in kumo.submission_guard_errors(self.settings)}
        self.assertEqual(errors, {"sandbox_requires_separate_explicit_ips", "sandbox_requires_direct_delivery",
                                  "tenant_or_prefix_required", "submission_integration_required"})


    def test_same_ipv6_address_cannot_be_in_both_pools(self):
        self.settings["sending_ips"] = [{"address": "2001:db8::1"}, {"address": "2001:db8:0:0:0:0:0:1"}]
        self.settings["sandbox_ips"] = ["2001:db8::1"]
        errors = [error[2] for error in kumo.submission_guard_errors(self.settings)]
        self.assertEqual(errors, ["sandbox_requires_unique_addresses"])


class MetricsAllowlistTest(unittest.TestCase):
    def setUp(self):
        self.settings = kumo.load_settings()
        p = patch.object(kumo, "cluster_info", return_value=("10.5.4.0/24", "10.5.4.1"))
        p.start()
        self.addCleanup(p.stop)

    def test_public_without_allowlist_is_open(self):
        self.assertTrue(self.settings["metrics_public"])
        self.assertEqual(kumo.metrics_allowlist(self.settings), [])

    def test_public_with_allowlist_keeps_it(self):
        self.settings["metrics_allowlist"] = ["203.0.113.7/32"]
        self.assertEqual(kumo.metrics_allowlist(self.settings), ["203.0.113.7/32"])

    def test_private_adds_private_and_cluster_networks(self):
        self.settings["metrics_public"] = False
        self.settings["metrics_allowlist"] = ["203.0.113.7/32"]
        allow = kumo.metrics_allowlist(self.settings)
        for net in ("192.168.0.0/16", "10.0.0.0/8", "10.5.4.0/24", "203.0.113.7/32"):
            self.assertIn(net, allow)
        self.assertEqual(len(allow), len(set(allow)))


class TsaTrustTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(temp.name)
        self.settings = kumo.load_settings()
        state = {"tsa_listen": "10.5.4.1:20003"}
        for target, value in ((kumo, "read_cluster_state"),):
            p = patch.object(target, value, return_value=state)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(kumo, "clustered", return_value=True)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(kumo, "cluster_info", return_value=("10.5.4.0/24", "10.5.4.1"))
        p.start()
        self.addCleanup(p.stop)

    def test_trusts_the_peers_of_the_store_only(self):
        with patch.object(kumo, "store_peer_addresses", return_value=["10.5.4.1", "10.5.4.2"]):
            policy = kumo.render_tsa_init(self.settings, str(TEMPLATES))
        self.assertIn('"10.5.4.2"', policy)
        self.assertNotIn("10.5.4.0/24", policy)

    def test_falls_back_to_the_cluster_network(self):
        with patch.object(kumo, "store_peer_addresses", side_effect=RuntimeError("redis down")):
            policy = kumo.render_tsa_init(self.settings, str(TEMPLATES))
        self.assertIn("10.5.4.0/24", policy)

    def test_peer_records_need_a_matching_node_address(self):
        rdb = MagicMock()
        rdb.hget.side_effect = lambda key, field: {"node/1/vpn": "10.5.4.1", "node/2/vpn": "10.5.4.2"}.get(key)
        records = {
            "kumomta1": {"store": "s1", "host": "10.5.4.1"},
            "kumomta2": {"store": "s1", "host": "10.5.4.9"},   # forged host
            "kumomta3": {"store": "s2", "host": "10.5.4.2"},   # other store
            "other1": {"store": "s1", "host": "10.5.4.2"},     # not kumomta
        }
        with patch.object(kumo.agent, "redis_connect", return_value=rdb), \
                patch.object(kumo, "kumomta_modules", return_value={"kumomta1": "1", "kumomta2": "2",
                                                                    "kumomta3": "2"}), \
                patch.object(kumo, "service_records", return_value=records):
            self.assertEqual(kumo.store_peer_addresses("s1"), ["10.5.4.1"])


if __name__ == "__main__":
    unittest.main()
