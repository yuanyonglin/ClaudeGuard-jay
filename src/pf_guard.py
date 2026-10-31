"""pf layer for the pinned gate.

The gate's proxy port only protects programs that are told to use it. To make a
bypass structurally impossible on macOS the redirect has to happen in the kernel,
and pf is the only mechanism available without an Apple entitlement. pf cannot
match on a process path, so the redirect is machine-wide and the gate decides by
domain instead (see gate.CLAUDE_DOMAINS).

Two rules matter and both are easy to get wrong:

* The redirect must exclude the pinned node's own address and loopback, or the
  gate's own upstream connection is redirected into itself.
* UDP:443 has to be dropped. mihomo cannot redirect UDP on macOS
  ("Failed to start Redir UDP Listener: not supported on current platform"), so
  leaving QUIC alone would let every Chromium-family client bypass the gate.

Applying rules is staged, never direct: this process runs unprivileged, writes
the desired ruleset under ~/.config/claudeguard/pending, and a root helper
validates ownership and loads it. A deadline marker makes a bad ruleset
self-revert instead of leaving the machine offline.
"""
import ipaddress
import json
import os
import subprocess
import time

CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
PENDING_DIR = os.path.join(CONFIG_DIR, "pending")

ANCHOR_PATH = os.path.join(PENDING_DIR, "gate.anchor")
RULESET_PATH = os.path.join(PENDING_DIR, "gate.ruleset")
REQUEST_PATH = os.path.join(PENDING_DIR, "gate.request")
APPLIED_PATH = os.path.join(PENDING_DIR, "gate.applied")
CONFIRM_PATH = os.path.join(PENDING_DIR, "gate.confirm")

HELPER = "/Library/Application Support/ClaudeGuard/gate-helper"
PF_CONF = "/etc/pf.conf"
ANCHOR_NAME = "com.claudeguard.gate"
ANCHOR_SYSTEM_PATH = f"/etc/pf.anchors/{ANCHOR_NAME}"

DEFAULTS = {"rollback_after": 20}

SKIP_TABLE = "claudeguard_skip"

PFCTL_NOISE = ("could result in flushing", "present in the main ruleset",
               "See /etc/pf.conf")


def _clean(text):
    return "\n".join(line for line in (text or "").splitlines()
                     if line.strip() and not any(n in line for n in PFCTL_NOISE)).strip()

# Anything that would widen access instead of narrowing it. The ruleset we
# generate is only ever redirect + drop, so a match here means a bug or tampering.
FORBIDDEN = ("pass in", "pass all", "pass out all", "nat ", "binat ", "dummynet ")


def settings(data):
    """Keep the caller's gate options, validating only the pf-specific one."""
    result = dict(DEFAULTS)
    result.update(data or {})
    value = result["rollback_after"]
    if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 600:
        raise ValueError("rollback_after 必须是 5～600 之间的整数")
    return result


def _ipv4(value):
    try:
        ipaddress.IPv4Address(str(value))
        return True
    except ValueError:
        return False


def exclusions(options, node):
    """Addresses the redirect must never touch, or the gate loops into itself."""
    result = ["127.0.0.0/8"]
    server = (node or {}).get("server")
    if _ipv4(server):
        result.append(str(server))
    main = options.get("main_proxy") or ""
    host = main.rpartition(":")[0] if main else ""
    if _ipv4(host):
        result.append(host)
    return result


def render_anchor(options, node):
    """The anchor body: redirect 80/443 on lo0, drop QUIC.

    The exclusions go in a pf table: macOS pf rejects a negated list
    (``to ! { a, b }`` is a syntax error) but accepts ``to ! <table>``.
    """
    redir = options["redir_port"]
    exclude = ", ".join(exclusions(options, node))
    lines = [
        "# ClaudeGuard pinned gate — generated, do not edit",
        f"table <{SKIP_TABLE}> {{ {exclude} }}",
        f"rdr pass on lo0 inet proto tcp from any to ! <{SKIP_TABLE}> "
        f"port 443 -> 127.0.0.1 port {redir}",
        f"rdr pass on lo0 inet proto tcp from any to ! <{SKIP_TABLE}> "
        f"port 80 -> 127.0.0.1 port {redir}",
    ]
    return "\n".join(lines) + "\n"


# pf evaluates rules in stage order — options, normalization, queuing,
# translation, filtering — and refuses a file that interleaves them. `rdr` is a
# translation rule, so it must sit before the first filtering statement.
FILTERING_PREFIXES = ("anchor ", "pass ", "block ", "match ")


def render_ruleset(anchor_path=ANCHOR_SYSTEM_PATH, stock_path=PF_CONF):
    """Stock ruleset plus our anchor, so applying never wipes system rules.

    Our anchor is referenced with `rdr-anchor`, not `anchor`: the rules inside it
    are translation rules, and an anchor pulled in by the filter stage would not
    redirect anything.
    """
    with open(stock_path, encoding="utf-8") as handle:
        stock = handle.read().splitlines()

    lines = []
    inserted = False
    for line in stock:
        if not inserted and line.strip().startswith(FILTERING_PREFIXES):
            lines.append(f'rdr-anchor "{ANCHOR_NAME}"')
            inserted = True
        lines.append(line)
    if not inserted:
        lines.append(f'rdr-anchor "{ANCHOR_NAME}"')

    lines.append(f'load anchor "{ANCHOR_NAME}" from "{anchor_path}"')
    # QUIC cannot be redirected on macOS, so it must not escape.
    lines.append("block drop out quick proto udp to any port 443")

    header = "# ClaudeGuard pinned gate — generated from " + stock_path
    return header + "\n" + "\n".join(lines) + "\n"


ALLOWED_PREFIXES = ("rdr ", "block ", "table ", "scrub-anchor", "nat-anchor", "rdr-anchor",
                    "dummynet-anchor", "anchor ", "load anchor")


def _validate(text, require_redirect):
    lowered = text.lower()
    for needle in FORBIDDEN:
        if needle in lowered:
            raise ValueError(f"规则集包含禁止的语句：{needle.strip()}")
    if require_redirect and "rdr pass" not in lowered:
        raise ValueError("锚点里没有重定向规则")
    if not require_redirect and "com.claudeguard.gate" not in lowered:
        raise ValueError("规则集没有引用 ClaudeGuard 锚点")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(ALLOWED_PREFIXES):
            continue
        raise ValueError(f"规则集包含无法识别的语句：{stripped[:60]}")
    return text


def validate_anchor(text):
    """An anchor may only redirect and drop."""
    return _validate(text, require_redirect=True)


def validate_ruleset(text):
    """A ruleset may only re-declare the stock anchors and load ours."""
    return _validate(text, require_redirect=False)


def _write(path, text, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + ".tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _remove(path):
    try:
        os.unlink(path)
    except OSError:
        pass


class PfGuard:
    """Stage, apply and roll back the redirect ruleset.

    ``runner`` is injected so the state machine can be tested without root:
    it receives an argv list and returns (returncode, stdout, stderr).
    """

    def __init__(self, options=None, node=None, runner=None, now=time.time):
        self.options = settings(options or {})
        self.node = node or {}
        self.runner = runner or self._run
        self.now = now

    @staticmethod
    def _run(argv):
        proc = subprocess.run(argv, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    # -- staging --

    def stage(self):
        """Write the anchor and ruleset, then arm the deadline marker."""
        anchor = validate_anchor(render_anchor(self.options, self.node))
        ruleset = validate_ruleset(render_ruleset())
        _write(ANCHOR_PATH, anchor)
        _write(RULESET_PATH, ruleset)
        _remove(CONFIRM_PATH)
        _remove(APPLIED_PATH)
        deadline = self.now() + self.options["rollback_after"]
        _write(REQUEST_PATH, json.dumps({"deadline": deadline, "action": "apply"}) + "\n")
        return {"anchor": ANCHOR_PATH, "ruleset": RULESET_PATH, "deadline": deadline}

    def syntax_check(self, path=None):
        """Parse an anchor without loading it; returns (ok, output).

        The anchor is self-contained, so it can be checked before anything is
        installed. The ruleset references the anchor by its /etc/pf.anchors path,
        so it can only be parsed after the helper puts it there.
        """
        code, out, err = self.runner(["/sbin/pfctl", "-n", "-f", path or ANCHOR_PATH])
        return code == 0, _clean(out or err)

    def apply(self):
        """Stage, syntax-check, then ask the helper to load. Never loads directly."""
        staged = self.stage()
        ok, detail = self.syntax_check()
        if not ok:
            self.abort()
            raise RuntimeError(f"pf 规则语法检查失败：{detail}")
        code, out, err = self.runner([HELPER, "apply"])
        if code != 0:
            self.abort()
            raise RuntimeError(f"应用 pf 规则失败：{(err or out).strip()}")
        return staged

    def confirm(self):
        """Mark the applied ruleset as healthy; only then is the deadline cleared."""
        _write(CONFIRM_PATH, json.dumps({"at": self.now()}) + "\n")
        _remove(REQUEST_PATH)

    def abort(self):
        _remove(REQUEST_PATH)
        _remove(RULESET_PATH)
        _remove(ANCHOR_PATH)
        _remove(APPLIED_PATH)
        _remove(CONFIRM_PATH)

    def clear(self):
        """Ask the helper to restore the stock ruleset."""
        code, out, err = self.runner([HELPER, "clear"])
        self.abort()
        if code != 0:
            raise RuntimeError(f"撤销 pf 规则失败：{(err or out).strip()}")
        return True

    def rollback(self):
        code, out, err = self.runner([HELPER, "rollback"])
        self.abort()
        if code != 0:
            raise RuntimeError(f"回滚 pf 规则失败：{(err or out).strip()}")
        return True

    # -- observation --

    def state(self):
        deadline = None
        try:
            with open(REQUEST_PATH, encoding="utf-8") as handle:
                deadline = json.load(handle).get("deadline")
        except (OSError, ValueError):
            pass
        return {
            "requested": os.path.exists(REQUEST_PATH),
            "applied": os.path.exists(APPLIED_PATH),
            "confirmed": os.path.exists(CONFIRM_PATH),
            "deadline": deadline,
            "expired": bool(deadline and not os.path.exists(CONFIRM_PATH)
                            and self.now() > deadline),
        }

    def needs_rollback(self):
        """True when rules were armed but never confirmed within the deadline."""
        state = self.state()
        return state["requested"] and not state["confirmed"] and state["expired"]

    def enforce_deadline(self):
        """Called from the daemon's poll loop; rolls back an unconfirmed ruleset."""
        if self.needs_rollback():
            self.rollback()
            return True
        return False

    def self_check(self, probe, rules_loaded, expected_ip):
        """Verify the redirect is both loaded and carrying the right exit.

        Note what is *not* checked: with `rdr` a direct connection is redirected
        rather than dropped, so "the direct connection failed" would be the wrong
        assertion here. What matters is that our rules are in the kernel and that
        the gate still proves the pinned exit.

        ``probe`` returns the exit IP seen through the gate; ``rules_loaded``
        returns True when pf reports the anchor's rules.
        """
        gate_ip = probe()
        if gate_ip != expected_ip:
            return False, f"经门卫的出口是 {gate_ip or '未获取'}，不是 {expected_ip}"
        if not rules_loaded():
            return False, "重定向规则没有出现在 pf 里，规则可能未加载"
        return True, "重定向已加载，门卫出口与预期一致"
