import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from src import brain


class StubConfig:
    """Minimal ConfigManager stand-in: only what get_verdict touches."""

    def __init__(self, path, gate_enabled=True, protection=True):
        self.path = path
        self.config = {}
        self.gate_enabled = gate_enabled
        self.protection_enabled = protection

    allowed_ips = ()
    ip_check_mode = "both"

    @property
    def gate_dir(self):
        return os.path.join(os.path.dirname(self.path), "gate")


class GateVerdictTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = StubConfig(os.path.join(self.temp.name, "config.json"))

    def publish(self, state, reason="", expected="198.51.100.7", age=0):
        directory = self.config.gate_dir
        os.makedirs(directory, exist_ok=True)
        payload = {"state": state, "reason": reason, "expected_ip": expected,
                   "updated_at": time.time() - age}
        with open(os.path.join(directory, "state.json"), "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    def test_ready_is_allowed(self):
        self.publish("READY", expected="198.51.100.7")
        verdict, ip, err = brain.get_verdict(self.config)
        self.assertEqual(verdict, "allowed")
        self.assertEqual(ip, "198.51.100.7")
        self.assertIsNone(err)

    def test_blocked_carries_the_gate_reason(self):
        self.publish("BLOCKED", reason="出口与预期不符", expected="198.51.100.7")
        verdict, _, err = brain.get_verdict(self.config)
        self.assertEqual(verdict, "blocked")
        self.assertIn("出口与预期不符", err)

    def test_missing_state_is_offline_not_allowed(self):
        verdict, _, err = brain.get_verdict(self.config)
        self.assertEqual(verdict, "offline")
        self.assertIn("门卫状态未发布", err)

    def test_stale_state_is_offline(self):
        self.publish("READY", age=1000)
        verdict, _, _ = brain.get_verdict(self.config)
        self.assertEqual(verdict, "offline")

    def test_protection_off_ignores_the_gate(self):
        self.publish("BLOCKED", reason="x")
        self.config.protection_enabled = False
        self.assertEqual(brain.get_verdict(self.config)[0], "allowed")

    def test_gate_disabled_uses_the_whitelist_path(self):
        """With gate mode off, a READY gate must not influence the verdict."""
        self.config.gate_enabled = False
        self.publish("READY", expected="198.51.100.7")
        with patch.object(brain.policy, "advanced", return_value=False), \
                patch.object(brain, "read_daemon_state", return_value=None), \
                patch.object(brain, "perform_ip_check",
                             return_value=("203.0.113.9", False, None)):
            verdict, ip, _ = brain.get_verdict(self.config)
        self.assertEqual(verdict, "blocked")
        self.assertEqual(ip, "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
