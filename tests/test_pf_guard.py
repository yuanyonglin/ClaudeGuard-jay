import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from src import pf_guard

NODE = {"server": "203.0.113.10", "port": 443, "type": "vless"}
OPTIONS = {"redir_port": 17897, "main_proxy": "127.0.0.1:7897", "rollback_after": 20}

STOCK = """scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
"""


class SettingsTests(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(pf_guard.settings({})["rollback_after"], 20)
        for value in (4, 601, True, "20"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pf_guard.settings({"rollback_after": value})


class RenderTests(unittest.TestCase):
    def test_anchor_redirects_80_and_443(self):
        text = pf_guard.render_anchor(OPTIONS, NODE)
        self.assertIn("rdr pass on lo0 inet proto tcp", text)
        self.assertIn("port 443 -> 127.0.0.1 port 17897", text)
        self.assertIn("port 80 -> 127.0.0.1 port 17897", text)
        # The UDP drop is a filter rule: it belongs in the main ruleset, not in
        # an anchor referenced by rdr-anchor.
        self.assertNotIn("block", text)

    def test_exclusions_cover_loopback_node_and_upstream(self):
        exclude = pf_guard.exclusions(OPTIONS, NODE)
        self.assertIn("127.0.0.0/8", exclude)
        self.assertIn("203.0.113.10", exclude)
        self.assertIn("127.0.0.1", exclude)

    def test_node_address_is_excluded_from_the_redirect(self):
        """A missing exclusion makes the gate redirect its own upstream into itself."""
        text = pf_guard.render_anchor(OPTIONS, NODE)
        redirect = [line for line in text.splitlines() if line.startswith("rdr ")][0]
        self.assertIn(pf_guard.SKIP_TABLE, redirect)

    def test_exclusions_use_a_table_not_a_negated_list(self):
        """macOS pf rejects `to ! { a, b }`; the exclusions have to be a table."""
        text = pf_guard.render_anchor(OPTIONS, NODE)
        self.assertIn(f"table <{pf_guard.SKIP_TABLE}>", text)
        self.assertNotIn("! {", text)
        self.assertIn(f"! <{pf_guard.SKIP_TABLE}>", text)

    def test_ruleset_drops_quic_in_the_filter_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            stock = os.path.join(temp, "pf.conf")
            with open(stock, "w", encoding="utf-8") as handle:
                handle.write(STOCK)
            text = pf_guard.render_ruleset(stock_path=stock)
        self.assertIn("block drop out quick proto udp to any port 443", text)

    def test_rdr_anchor_is_declared_before_any_filter_statement(self):
        """pf rejects a file that interleaves translation and filter stages."""
        with tempfile.TemporaryDirectory() as temp:
            stock = os.path.join(temp, "pf.conf")
            with open(stock, "w", encoding="utf-8") as handle:
                handle.write(STOCK)
            text = pf_guard.render_ruleset(stock_path=stock)
        lines = [line.strip() for line in text.splitlines()]
        rdr_index = lines.index('rdr-anchor "com.claudeguard.gate"')
        anchor_index = lines.index('anchor "com.apple/*"')
        block_index = next(i for i, line in enumerate(lines) if line.startswith("block "))
        self.assertLess(rdr_index, anchor_index)
        self.assertLess(anchor_index, block_index)

    def test_ruleset_keeps_stock_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            stock = os.path.join(temp, "pf.conf")
            with open(stock, "w", encoding="utf-8") as handle:
                handle.write(STOCK)
            text = pf_guard.render_ruleset(stock_path=stock)
        self.assertIn('anchor "com.apple/*"', text)
        self.assertIn('anchor "com.claudeguard.gate"', text)
        self.assertIn('load anchor "com.claudeguard.gate"', text)


class ValidateTests(unittest.TestCase):
    def test_generated_ruleset_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            stock = os.path.join(temp, "pf.conf")
            with open(stock, "w", encoding="utf-8") as handle:
                handle.write(STOCK)
            pf_guard.validate_ruleset(pf_guard.render_ruleset(stock_path=stock))
        pf_guard.validate_anchor(pf_guard.render_anchor(OPTIONS, NODE))

    def test_anchor_rejects_wide_open_rules(self):
        with self.assertRaises(ValueError):
            pf_guard.validate_anchor('pass in all\nrdr pass on lo0 proto tcp to any port 1 -> 127.0.0.1 port 2\n')

    def test_wide_open_rules_are_rejected(self):
        for text in ('pass in all\nanchor "com.claudeguard.gate"\n',
                     'nat on en0 from any to any -> 1.2.3.4\n',
                     'rdr pass on lo0 proto tcp to any port 443 -> 127.0.0.1 port 1\n'):
            with self.subTest(text=text.splitlines()[0]), self.assertRaises(ValueError):
                pf_guard.validate_ruleset(text)

    def test_unrecognised_statement_is_rejected(self):
        with self.assertRaises(ValueError):
            pf_guard.validate_ruleset(
                'rdr pass on lo0 proto tcp to any port 443 -> 127.0.0.1 port 1\n'
                'anchor "com.claudeguard.gate"\n'
                'some unknown directive\n')


class FakeRunner:
    def __init__(self, results=None):
        self.calls = []
        self.results = results or {}

    def __call__(self, argv):
        self.calls.append(argv)
        return self.results.get(tuple(argv[:2]), (0, "", ""))

    def actions(self):
        return [argv[1] for argv in self.calls if len(argv) > 1]


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = self.temp.name
        self.patch = patch.multiple(
            pf_guard,
            PENDING_DIR=os.path.join(root, "pending"),
            ANCHOR_PATH=os.path.join(root, "pending", "gate.anchor"),
            RULESET_PATH=os.path.join(root, "pending", "gate.ruleset"),
            REQUEST_PATH=os.path.join(root, "pending", "gate.request"),
            APPLIED_PATH=os.path.join(root, "pending", "gate.applied"),
            CONFIRM_PATH=os.path.join(root, "pending", "gate.confirm"),
            HELPER=os.path.join(root, "gate-helper"),
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.runner = FakeRunner()
        self.guard = pf_guard.PfGuard(OPTIONS, NODE, runner=self.runner)

    def test_stage_writes_private_files_and_a_deadline(self):
        staged = self.guard.stage()
        self.assertTrue(os.path.exists(pf_guard.ANCHOR_PATH))
        self.assertTrue(os.path.exists(pf_guard.RULESET_PATH))
        self.assertEqual(stat.S_IMODE(os.stat(pf_guard.ANCHOR_PATH).st_mode), 0o600)
        with open(pf_guard.REQUEST_PATH, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["action"], "apply")
        self.assertGreater(staged["deadline"], 0)

    def test_apply_syntax_checks_before_calling_the_helper(self):
        self.guard.apply()
        self.assertEqual(self.runner.calls[0][:2], ["/sbin/pfctl", "-n"])
        self.assertEqual(self.runner.actions()[-1], "apply")

    def test_apply_aborts_and_never_loads_when_syntax_fails(self):
        runner = FakeRunner({("/sbin/pfctl", "-n"): (1, "", "syntax error")})
        guard = pf_guard.PfGuard(OPTIONS, NODE, runner=runner)
        with self.assertRaises(RuntimeError):
            guard.apply()
        self.assertNotIn("apply", runner.actions())
        self.assertFalse(os.path.exists(pf_guard.RULESET_PATH))

    def test_apply_aborts_when_helper_fails(self):
        runner = FakeRunner({(pf_guard.HELPER, "apply"): (1, "", "pfctl: permission denied")})
        guard = pf_guard.PfGuard(OPTIONS, NODE, runner=runner)
        with self.assertRaises(RuntimeError):
            guard.apply()
        self.assertFalse(os.path.exists(pf_guard.REQUEST_PATH))

    def test_confirm_clears_the_deadline(self):
        self.guard.stage()
        self.guard.confirm()
        self.assertTrue(os.path.exists(pf_guard.CONFIRM_PATH))
        self.assertFalse(os.path.exists(pf_guard.REQUEST_PATH))
        self.assertFalse(self.guard.needs_rollback())

    def test_expired_unconfirmed_ruleset_rolls_back(self):
        clock = [1000.0]
        guard = pf_guard.PfGuard(OPTIONS, NODE, runner=self.runner, now=lambda: clock[0])
        guard.stage()
        self.assertFalse(guard.needs_rollback())
        clock[0] += 21
        self.assertTrue(guard.needs_rollback())
        self.assertTrue(guard.enforce_deadline())
        self.assertEqual(self.runner.actions()[-1], "rollback")

    def test_confirmed_ruleset_never_rolls_back(self):
        clock = [1000.0]
        guard = pf_guard.PfGuard(OPTIONS, NODE, runner=self.runner, now=lambda: clock[0])
        guard.stage()
        guard.confirm()
        clock[0] += 600
        self.assertFalse(guard.enforce_deadline())

    def test_clear_asks_the_helper_and_drops_markers(self):
        self.guard.stage()
        self.guard.clear()
        self.assertEqual(self.runner.actions()[-1], "clear")
        for path in (pf_guard.REQUEST_PATH, pf_guard.RULESET_PATH, pf_guard.ANCHOR_PATH):
            self.assertFalse(os.path.exists(path))


class SelfCheckTests(unittest.TestCase):
    def setUp(self):
        self.guard = pf_guard.PfGuard(OPTIONS, NODE, runner=FakeRunner())

    def test_pass_when_gate_matches_and_rules_are_loaded(self):
        ok, _ = self.guard.self_check(lambda: "198.51.100.7", lambda: True, "198.51.100.7")
        self.assertTrue(ok)

    def test_fail_when_gate_exit_is_wrong(self):
        ok, reason = self.guard.self_check(lambda: "203.0.113.99", lambda: True, "198.51.100.7")
        self.assertFalse(ok)
        self.assertIn("203.0.113.99", reason)

    def test_fail_when_rules_did_not_load(self):
        ok, reason = self.guard.self_check(lambda: "198.51.100.7", lambda: False, "198.51.100.7")
        self.assertFalse(ok)
        self.assertIn("没有出现在 pf 里", reason)


class PfctlSyntaxTests(unittest.TestCase):
    """Runs the real parser. `pfctl -n` needs no root, so this catches syntax the
    unit tests cannot: the negated-list form was accepted by review and rejected
    by macOS pf."""

    @unittest.skipUnless(os.path.exists("/sbin/pfctl"), "pfctl not available")
    def test_generated_anchor_parses(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "anchor.pf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(pf_guard.render_anchor(OPTIONS, NODE))
            proc = subprocess.run(["/sbin/pfctl", "-n", "-f", path],
                                  capture_output=True, text=True)
        combined = (proc.stdout + proc.stderr).lower()
        if "permission denied" in combined or "operation not permitted" in combined:
            self.skipTest("pfctl needs root here")
        self.assertEqual(proc.returncode, 0, combined)


if __name__ == "__main__":
    unittest.main()
