import base64
import json
import os
import sqlite3
import tempfile
import unittest

from src import gate, gate_nodes

UUID = "11111111-2222-3333-4444-555555555555"

VLESS = (f"vless://{UUID}@203.0.113.10:443?encryption=none&security=reality"
         "&sni=example.com&fp=chrome&pbk=PUBLICKEY&sid=0123abcd"
         "&type=tcp&flow=xtls-rprx-vision#Example-A")

SS_USERINFO = base64.b64encode(b"aes-256-gcm:pass123").decode()
SS = f"ss://{SS_USERINFO}@203.0.113.11:8388#Example-B"

VMESS_JSON = {
    "v": "2", "ps": "Example-C", "add": "203.0.113.12", "port": "443",
    "id": UUID, "aid": "0", "net": "ws", "host": "example.com",
    "path": "/ws", "tls": "tls", "scy": "auto",
}
VMESS = "vmess://" + base64.b64encode(json.dumps(VMESS_JSON).encode()).decode()

TROJAN = "trojan://secretpass@203.0.113.13:443?sni=example.com&type=tcp#Example-D"


class VlessTests(unittest.TestCase):
    def test_reality_link_maps_every_field(self):
        node = gate_nodes.parse_vless(VLESS)
        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["server"], "203.0.113.10")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["uuid"], UUID)
        self.assertEqual(node["name"], "Example-A")
        self.assertEqual(node["network"], "tcp")
        self.assertTrue(node["tls"])
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["servername"], "example.com")
        self.assertEqual(node["client-fingerprint"], "chrome")
        self.assertEqual(node["reality-opts"], {"public-key": "PUBLICKEY", "short-id": "0123abcd"})

    def test_ws_link_gets_ws_opts(self):
        node = gate_nodes.parse_vless(
            f"vless://{UUID}@203.0.113.10:443?type=ws&security=tls&path=%2Fws&host=example.com#W")
        self.assertEqual(node["network"], "ws")
        self.assertEqual(node["ws-opts"], {"path": "/ws", "headers": {"Host": "example.com"}})

    def test_missing_uuid_is_rejected(self):
        with self.assertRaises(ValueError):
            gate_nodes.parse_vless("vless://@203.0.113.10:443?security=tls#x")

    def test_reality_without_public_key_is_rejected(self):
        with self.assertRaises(ValueError):
            gate_nodes.parse_vless(
                f"vless://{UUID}@203.0.113.10:443?security=reality&sni=example.com#x")


class SsTests(unittest.TestCase):
    def test_sip002_userinfo(self):
        node = gate_nodes.parse_ss(SS)
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "pass123")
        self.assertEqual(node["server"], "203.0.113.11")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["name"], "Example-B")

    def test_legacy_whole_body_base64(self):
        body = base64.b64encode(b"aes-128-gcm:legacy@203.0.113.14:8389").decode()
        node = gate_nodes.parse_ss(f"ss://{body}#Legacy")
        self.assertEqual(node["cipher"], "aes-128-gcm")
        self.assertEqual(node["password"], "legacy")
        self.assertEqual(node["server"], "203.0.113.14")
        self.assertEqual(node["port"], 8389)


class VmessTests(unittest.TestCase):
    def test_json_link(self):
        node = gate_nodes.parse_vmess(VMESS)
        self.assertEqual(node["type"], "vmess")
        self.assertEqual(node["server"], "203.0.113.12")
        self.assertEqual(node["uuid"], UUID)
        self.assertEqual(node["network"], "ws")
        self.assertTrue(node["tls"])
        self.assertEqual(node["ws-opts"]["path"], "/ws")

    def test_bad_payload_is_rejected(self):
        with self.assertRaises(ValueError):
            gate_nodes.parse_vmess("vmess://" + base64.b64encode(b"not json").decode())


class TrojanTests(unittest.TestCase):
    def test_password_and_sni(self):
        node = gate_nodes.parse_trojan(TROJAN)
        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["password"], "secretpass")
        self.assertEqual(node["servername"], "example.com")
        self.assertTrue(node["tls"])
        self.assertEqual(node["name"], "Example-D")


class SubscriptionTests(unittest.TestCase):
    def test_plain_body(self):
        nodes, skipped = gate_nodes.nodes_from_text(f"{VLESS}\n{SS}\n")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(skipped, [])

    def test_base64_body(self):
        body = base64.b64encode(f"{VLESS}\n{SS}\n".encode()).decode()
        nodes, skipped = gate_nodes.nodes_from_text(body)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(skipped, [])

    def test_unsupported_and_broken_lines_are_reported_not_fatal(self):
        text = "\n".join([VLESS, "hysteria2://x@203.0.113.20:443#H", "garbage", SS])
        nodes, skipped = gate_nodes.nodes_from_text(text)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(len(skipped), 2)
        self.assertTrue(any("hysteria2" in reason for _, reason in skipped))

    def test_every_parsed_node_passes_gate_validation(self):
        nodes, _ = gate_nodes.nodes_from_text("\n".join([VLESS, SS, VMESS, TROJAN]))
        self.assertEqual(len(nodes), 4)
        for node in nodes:
            self.assertEqual(gate.validate_node(node)["type"], node["type"])

    def test_parsed_nodes_render_a_config(self):
        nodes, _ = gate_nodes.nodes_from_text("\n".join([VLESS, SS, VMESS, TROJAN]))
        options = gate.settings({"expected_ip": "198.51.100.7"})
        for node in nodes:
            config = gate.render_config(node, options, "tok")
            self.assertEqual(config["proxies"][0]["name"], gate.PINNED)


class V2rayNTests(unittest.TestCase):
    def make_db(self, directory, url="https://example.com/sub?token=x"):
        path = os.path.join(directory, "guiNDB.db")
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE SubItem (Id TEXT, Remarks TEXT, Url TEXT, UpdateTime INTEGER)")
        connection.execute("INSERT INTO SubItem VALUES ('1', 'test', ?, 0)", (url,))
        connection.commit()
        connection.close()
        return path

    def test_reads_subscription_url(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.make_db(temp)
            self.assertEqual(gate_nodes.subscription_url_from_v2rayn(path),
                             "https://example.com/sub?token=x")

    def test_missing_database_is_reported(self):
        with self.assertRaises(ValueError):
            gate_nodes.subscription_url_from_v2rayn("/nonexistent/guiNDB.db")

    def test_empty_subscription_table_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.make_db(temp, url="")
            with self.assertRaises(ValueError):
                gate_nodes.subscription_url_from_v2rayn(path)


class FileTests(unittest.TestCase):
    def test_reads_links_from_a_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "sub.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"{VLESS}\n{SS}\n")
            nodes, skipped = gate_nodes.nodes_from_file(path)
            self.assertEqual(len(nodes), 2)
            self.assertEqual(skipped, [])


if __name__ == "__main__":
    unittest.main()
