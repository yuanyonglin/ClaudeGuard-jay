import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import gate

NODE = {
    "name": "Example-A", "server": "203.0.113.10", "port": 443, "type": "vless",
    "uuid": "11111111-2222-3333-4444-555555555555", "tls": True,
    "network": "tcp", "flow": "xtls-rprx-vision",
    "servername": "example.com", "client-fingerprint": "chrome",
    "reality-opts": {"public-key": "PUB", "short-id": "0123456789abcdef"},
}

OPTIONS = {"expected_ip": "198.51.100.7", "proxy_port": 27899, "probe_port": 27898,
           "redir_port": 27897, "controller_port": 29099}


class SettingsTests(unittest.TestCase):
    def test_defaults_apply_when_nothing_is_configured(self):
        result = gate.settings({})
        for key, value in gate.DEFAULTS.items():
            self.assertEqual(result[key], value)

    def test_ports_must_be_integers_in_range(self):
        for value in (0, 80, 70000, True, "17899", 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.settings({"proxy_port": value})

    def test_duplicate_ports_are_rejected(self):
        with self.assertRaises(ValueError):
            gate.settings({"proxy_port": 20000, "probe_port": 20000})

    def test_interval_and_timeout_bounds(self):
        for value in (4, 3601, True, "30"):
            with self.subTest(field="verify_interval", value=value), self.assertRaises(ValueError):
                gate.settings({"verify_interval": value})
        for value in (0, 61, True):
            with self.subTest(field="verify_timeout", value=value), self.assertRaises(ValueError):
                gate.settings({"verify_timeout": value})

    def test_expected_ip_is_trimmed(self):
        self.assertEqual(gate.settings({"expected_ip": "  198.51.100.7 "})["expected_ip"], "198.51.100.7")


class NodeTests(unittest.TestCase):
    def test_valid_vless_node(self):
        result = gate.validate_node(NODE)
        self.assertEqual(result["type"], "vless")
        self.assertEqual(result["reality-opts"]["public-key"], "PUB")

    def test_ss_node_needs_cipher_and_password(self):
        result = gate.validate_node({"server": "203.0.113.10", "port": 8388,
                                     "type": "ss", "cipher": "aes-256-gcm", "password": "x"})
        self.assertEqual(result["cipher"], "aes-256-gcm")
        with self.assertRaises(ValueError):
            gate.validate_node({"server": "203.0.113.10", "port": 8388, "type": "ss", "password": "x"})

    def test_rejects_unknown_type_and_bad_port(self):
        with self.assertRaises(ValueError):
            gate.validate_node({**NODE, "type": "wireguard"})
        for value in (0, 65536, True, "443"):
            with self.subTest(port=value), self.assertRaises(ValueError):
                gate.validate_node({**NODE, "port": value})

    def test_missing_uuid_and_incomplete_reality_are_rejected(self):
        with self.assertRaises(ValueError):
            gate.validate_node({k: v for k, v in NODE.items() if k != "uuid"})
        with self.assertRaises(ValueError):
            gate.validate_node({**NODE, "reality-opts": {"public-key": "PUB"}})

    def test_default_name_is_derived(self):
        result = gate.validate_node({k: v for k, v in NODE.items() if k != "name"})
        self.assertEqual(result["name"], "vless-203.0.113.10:443")


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.config = gate.render_config(gate.validate_node(NODE), gate.settings(OPTIONS), "tok")

    def test_ports_and_controller(self):
        self.assertEqual(self.config["mixed-port"], 27899)
        self.assertEqual(self.config["redir-port"], 27897)
        self.assertEqual(self.config["external-controller"], "127.0.0.1:29099")
        self.assertEqual(self.config["secret"], "tok")

    def test_gate_group_holds_pinned_and_reject(self):
        group = self.config["proxy-groups"][0]
        self.assertEqual(group["name"], gate.GATE_GROUP)
        self.assertEqual(group["proxies"], [gate.PINNED, gate.REJECT])
        self.assertEqual(self.config["rules"], [f"MATCH,{gate.GATE_GROUP}"])

    def test_probe_listener_is_wired_to_the_pinned_node(self):
        listener = self.config["listeners"][0]
        self.assertEqual(listener["port"], 27898)
        self.assertEqual(listener["proxy"], gate.PINNED)

    def test_interface_is_optional(self):
        self.assertNotIn("interface-name", self.config)
        with_iface = gate.render_config(gate.validate_node(NODE),
                                        gate.settings({**OPTIONS, "interface_name": "en0"}), "tok")
        self.assertEqual(with_iface["interface-name"], "en0")

    def test_ss_node_renders_cipher_not_uuid(self):
        node = gate.validate_node({"server": "203.0.113.10", "port": 8388, "type": "ss",
                                   "cipher": "aes-256-gcm", "password": "secret"})
        proxy = gate.render_config(node, gate.settings(OPTIONS), "tok")["proxies"][0]
        self.assertEqual(proxy["cipher"], "aes-256-gcm")
        self.assertNotIn("uuid", proxy)


class YamlTests(unittest.TestCase):
    def test_scalars_and_quoting(self):
        self.assertEqual(gate._yaml_scalar(True), "true")
        self.assertEqual(gate._yaml_scalar(False), "false")
        self.assertEqual(gate._yaml_scalar(None), "null")
        self.assertEqual(gate._yaml_scalar(17899), "17899")
        self.assertEqual(gate._yaml_scalar("plain"), "plain")
        self.assertEqual(gate._yaml_scalar("127.0.0.1:19099"), '"127.0.0.1:19099"')
        self.assertEqual(gate._yaml_scalar("MATCH,GATE"), '"MATCH,GATE"')

    def test_nested_output(self):
        text = gate.yaml_dump({"a": {"b": [1, 2]}, "c": True})
        self.assertIn("a:", text)
        self.assertIn("b:", text)
        self.assertIn("- 1", text)
        self.assertIn("c: true", text)


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.gate = gate.Gate(directory=self.temp.name, options=OPTIONS)

    def test_token_is_created_private_and_stable(self):
        first = self.gate.token()
        self.assertEqual(len(first), 64)
        mode = stat.S_IMODE(os.stat(self.gate.token_path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(self.gate.token(), first)

    def test_write_config_is_private_and_contains_secret(self):
        node_path = Path(self.temp.name) / "node.json"
        node_path.write_text(json.dumps(NODE), encoding="utf-8")
        path = self.gate.write_config()
        text = path.read_text(encoding="utf-8")
        self.assertIn("mixed-port: 27899", text)
        self.assertIn(self.gate.token(), text)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.gate = gate.Gate(directory=self.temp.name, options=OPTIONS)
        self.switched = []
        self.gate.set_gate = self.switched.append

    def probe(self, **values):
        self.gate.probe = lambda: (values, {})

    def test_matching_exit_ip_is_ready_and_opens_the_path(self):
        self.probe(http="198.51.100.7", cloudflare="198.51.100.7")
        status = self.gate.verify()
        self.assertEqual(status["state"], "READY")
        self.assertEqual(self.switched[-1], gate.PINNED)
        self.assertTrue(self.gate.fresh())

    def test_mismatch_blocks_and_rejects(self):
        self.probe(http="198.51.100.7", cloudflare="203.0.113.99")
        status = self.gate.verify()
        self.assertEqual(status["state"], "BLOCKED")
        self.assertEqual(self.switched[-1], gate.REJECT)
        self.assertIn("203.0.113.99", status["reason"])

    def test_missing_provider_blocks_even_when_the_other_matches(self):
        self.probe(http="198.51.100.7")
        status = self.gate.verify()
        self.assertEqual(status["state"], "BLOCKED")
        self.assertEqual(self.switched[-1], gate.REJECT)

    def test_empty_answer_blocks(self):
        self.probe(http="", cloudflare="")
        self.assertEqual(self.gate.verify()["state"], "BLOCKED")

    def test_unconfigured_expected_ip_blocks(self):
        self.gate.options["expected_ip"] = ""
        self.probe(http="198.51.100.7", cloudflare="198.51.100.7")
        status = self.gate.verify()
        self.assertEqual(status["state"], "BLOCKED")
        self.assertEqual(self.switched[-1], gate.REJECT)

    def test_fresh_expires(self):
        self.probe(http="198.51.100.7", cloudflare="198.51.100.7")
        self.gate.verify()
        self.gate.options["verify_interval"] = 0
        self.assertFalse(self.gate.fresh(interval=0))

    def test_fresh_is_false_before_any_success(self):
        self.assertFalse(self.gate.fresh())


class DiscoveryTests(unittest.TestCase):
    def test_explicit_path_wins_and_missing_falls_through(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "mihomo"
            binary.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(binary, 0o755)
            self.assertEqual(gate.find_mihomo(str(binary)), str(binary))
            self.assertNotEqual(gate.find_mihomo(str(Path(temp) / "nope")), str(Path(temp) / "nope"))

    def test_no_candidate_returns_none(self):
        with patch.object(gate, "MIHOMO_CANDIDATES", ()):
            self.assertIsNone(gate.find_mihomo())


if __name__ == "__main__":
    unittest.main()
