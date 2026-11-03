import json
import os
import stat
import tempfile
import time
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

    def test_tun_settings_validation(self):
        self.assertFalse(gate.settings({})["tun_enabled"])
        self.assertTrue(gate.settings({"tun_enabled": True})["tun_enabled"])
        for value in ("yes", 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.settings({"tun_enabled": value})
        with self.assertRaises(ValueError):
            gate.settings({"tun_stack": "lwip"})

    def test_main_proxy_normalisation(self):
        self.assertEqual(gate.parse_main_proxy(""), "")
        self.assertEqual(gate.parse_main_proxy("direct"), "")
        self.assertEqual(gate.parse_main_proxy("http://127.0.0.1:7897"), "127.0.0.1:7897")
        self.assertEqual(gate.parse_main_proxy(" 127.0.0.1:7897 "), "127.0.0.1:7897")
        for value in ("127.0.0.1", "http://user:pass@127.0.0.1:7897", "127.0.0.1:abc", 7897):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.parse_main_proxy(value)


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

    def test_telemetry_is_rejected_before_the_proxy_port(self):
        rules = self.config["rules"]
        in_port = rules.index("IN-PORT,27899,GATE")
        for domain in gate.TELEMETRY_DOMAINS:
            rule = f"DOMAIN-SUFFIX,{domain},REJECT"
            self.assertIn(rule, rules)
            self.assertLess(rules.index(rule), in_port)

    def test_anthropic_domains_use_the_gate_and_the_rest_use_main(self):
        rules = self.config["rules"]
        for domain in gate.CLAUDE_DOMAINS:
            self.assertIn(f"DOMAIN-SUFFIX,{domain},GATE", rules)
        self.assertEqual(rules[-1], "MATCH,MAIN")

    def test_main_defaults_to_direct(self):
        main = self.config["proxy-groups"][1]
        self.assertEqual(main["name"], gate.MAIN_GROUP)
        self.assertEqual(main["proxies"], ["DIRECT"])
        self.assertEqual(len(self.config["proxies"]), 1)

    def test_main_proxy_is_chained_as_an_http_upstream(self):
        config = gate.render_config(gate.validate_node(NODE),
                                    gate.settings({**OPTIONS, "main_proxy": "http://127.0.0.1:7897"}), "tok")
        upstream = config["proxies"][1]
        self.assertEqual(upstream["type"], "http")
        self.assertEqual(upstream["server"], "127.0.0.1")
        self.assertEqual(upstream["port"], 7897)
        self.assertEqual(config["proxy-groups"][1]["proxies"], [gate.MAIN_PROXY, "DIRECT"])

    def test_probe_listener_is_wired_to_the_pinned_node(self):
        listener = self.config["listeners"][0]
        self.assertEqual(listener["port"], 27898)
        self.assertEqual(listener["proxy"], gate.PINNED)

    def test_interface_is_optional(self):
        self.assertNotIn("interface-name", self.config)
        with_iface = gate.render_config(gate.validate_node(NODE),
                                        gate.settings({**OPTIONS, "interface_name": "en0"}), "tok")
        self.assertEqual(with_iface["interface-name"], "en0")

    def test_redir_port_is_dropped_when_tun_is_used(self):
        config = gate.render_config(gate.validate_node(NODE),
                                    gate.settings({**OPTIONS, "tun_enabled": True}), "tok")
        self.assertNotIn("redir-port", config)

    def test_tun_is_absent_by_default(self):
        self.assertNotIn("tun", self.config)

    def test_tun_enabled_adds_kernel_capture(self):
        config = gate.render_config(gate.validate_node(NODE),
                                    gate.settings({**OPTIONS, "tun_enabled": True}), "tok")
        self.assertTrue(config["tun"]["enable"])
        self.assertTrue(config["tun"]["auto-route"])
        self.assertEqual(config["tun"]["stack"], "gvisor")
        self.assertEqual(config["tun"]["dns-hijack"], ["any:53"])

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

    def test_missing_provider_is_degraded_when_the_other_matches(self):
        # A single provider timing out must not close Claude: the reachable
        # provider still proves the expected exit, and a mismatch is fatal.
        self.probe(http="198.51.100.7")
        status = self.gate.verify()
        self.assertEqual(status["state"], "READY")
        self.assertIn("cloudflare", status["reason"])
        self.assertEqual(self.switched[-1], gate.PINNED)

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


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.gate = gate.Gate(directory=self.temp.name, options=OPTIONS)

    def test_publish_writes_a_private_state_file(self):
        data = self.gate.publish()
        path = gate.state_path(self.temp.name)
        self.assertTrue(path.exists())
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn("updated_at", data)
        self.assertEqual(gate.read_state(self.temp.name)["state"], data["state"])

    def test_missing_state_reads_as_none(self):
        self.assertIsNone(gate.read_state(self.temp.name))

    def test_stale_state_reads_as_none(self):
        self.gate.publish()
        later = time.time() + 1000
        self.assertIsNone(gate.read_state(self.temp.name, max_age=45, now=lambda: later))
        self.assertIsNotNone(gate.read_state(self.temp.name, max_age=45))

    def test_watch_publishes_each_iteration(self):
        self.gate.running = lambda: True

        def fake_verify():
            self.gate.state = "READY"
            self.gate.reason = "ok"
            self.gate.last_verified = time.time()
            return self.gate.status()

        self.gate.verify = fake_verify
        results = gate.run_watch(self.gate, iterations=2, sleep=lambda _: None)
        self.assertEqual([item["state"] for item in results], ["READY", "READY"])
        self.assertEqual(gate.read_state(self.temp.name)["state"], "READY")

    def test_watch_publishes_blocked_instead_of_raising(self):
        self.gate.running = lambda: True

        def boom():
            raise RuntimeError("upstream gone")

        self.gate.verify = boom
        result = gate.run_watch(self.gate, iterations=1)[0]
        self.assertEqual(result["state"], "BLOCKED")
        self.assertIn("upstream gone", result["reason"])
        self.assertEqual(gate.read_state(self.temp.name)["state"], "BLOCKED")


class StartCommandTests(unittest.TestCase):
    def test_plain_start_has_no_sudo(self):
        argv = gate.start_command("/bin/mihomo", "/d", "/d/config.yaml")
        self.assertEqual(argv, ["/bin/mihomo", "-d", "/d", "-f", "/d/config.yaml"])

    def test_tun_start_goes_through_the_validated_wrapper(self):
        argv = gate.start_command("/bin/mihomo", "/d", "/d/config.yaml",
                                  tun_enabled=True, use_sudo=True)
        self.assertEqual(argv, ["sudo", "-n", gate.GATE_WRAPPER, "/d", "/bin/mihomo"])
        self.assertNotIn("-f", argv)

    def test_tun_start_without_sudo_when_already_root(self):
        argv = gate.start_command("/bin/mihomo", "/d", "/d/config.yaml",
                                  tun_enabled=True, use_sudo=False)
        self.assertNotIn("sudo", argv)


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
