"""Pinned-exit gate for ClaudeGuard.

A dedicated mihomo core that can only reach the internet through exactly one
pinned node. Claude's traffic is pointed at this core's proxy port; the core's
exit IP is verified through a second, probe-only port that always uses the
pinned node, so a verification run never opens the path Claude uses.

Two listeners, one process:

    proxy_port   Claude Code / Claude Desktop (the path we open or reject)
    probe_port   verification only, hard-wired to the pinned node

The gate is READY only after a probe through the pinned node returns the
expected exit IP. Anything else switches the ``GATE`` group to REJECT, so the
proxy port answers but carries no traffic. Fail closed.

No pf rules, no root, no third-party Python packages: this module only manages
the mihomo process and speaks to its external controller.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")

DEFAULTS = {
    "proxy_port": 17899,
    "probe_port": 17898,
    "redir_port": 17897,
    "controller_port": 19099,
    "interface_name": "",
    "expected_ip": "",
    "verify_interval": 30,
    "verify_timeout": 8,
    # Upstream for traffic that is not Claude's. Empty means DIRECT; a value like
    # http://127.0.0.1:7897 keeps the user's existing Clash in the path.
    "main_proxy": "",
}

# Domains that must always leave through the pinned node, even when they arrive
# on the transparent port rather than Claude's explicit proxy port.
CLAUDE_DOMAINS = (
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    "anthropic.com",
    "anthropic.ai",
)

PROBE_URLS = (
    ("http", "https://api.ipify.org/"),
    ("cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
)

PINNED = "PINNED"
GATE_GROUP = "GATE"
REJECT = "REJECT"
MAIN_GROUP = "MAIN"
MAIN_PROXY = "MAIN-PROXY"

# Where a mihomo binary may live, in preference order. The Clash Verge copy is a
# development convenience, never the production choice: an app upgrade replaces it.
MIHOMO_CANDIDATES = (
    "~/.local/share/ClaudeGuard/bin/mihomo",
    "/opt/homebrew/bin/mihomo",
    "/usr/local/bin/mihomo",
    "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
)


def settings(data):
    """Validate and normalise the gate settings carried in ClaudeGuard's config."""
    result = dict(DEFAULTS)
    for key in DEFAULTS:
        if key in data:
            result[key] = data[key]

    ports = {}
    for key in ("proxy_port", "probe_port", "redir_port", "controller_port"):
        value = result[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
            raise ValueError(f"{key} 必须是 1024～65535 之间的整数")
        if value in ports:
            raise ValueError(f"{key} 与 {ports[value]} 端口冲突：{value}")
        ports[value] = key

    interval = result["verify_interval"]
    if isinstance(interval, bool) or not isinstance(interval, int) or not 5 <= interval <= 3600:
        raise ValueError("verify_interval 必须是 5～3600 之间的整数")

    timeout = result["verify_timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ValueError("verify_timeout 必须是 1～60 之间的整数")

    name = result["interface_name"]
    if not isinstance(name, str):
        raise ValueError("interface_name 必须是字符串（留空表示不绑定网卡）")

    expected = result["expected_ip"]
    if not isinstance(expected, str):
        raise ValueError("expected_ip 必须是字符串")
    result["expected_ip"] = expected.strip()

    result["main_proxy"] = parse_main_proxy(result.get("main_proxy"))
    return result


def parse_main_proxy(value):
    """Normalise the non-Claude upstream to host:port, or '' for DIRECT."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("main_proxy 必须是字符串，例如 http://127.0.0.1:7897")
    text = value.strip()
    if not text or text.lower() in ("direct", "none", "off"):
        return ""
    for prefix in ("http://", "https://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            break
    if "/" in text or "@" in text:
        raise ValueError("main_proxy 只能是 host:port，例如 127.0.0.1:7897")
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("main_proxy 必须包含端口，例如 127.0.0.1:7897")
    return f"{host}:{int(port)}"


# --- pinned node -----------------------------------------------------------

def validate_node(node):
    """Validate a pinned-node description; the shape mirrors claude-gute's guard-node.json."""
    if not isinstance(node, dict):
        raise ValueError("节点配置必须是 JSON 对象")

    kind = node.get("type")
    if kind not in ("vless", "vmess", "trojan", "ss"):
        raise ValueError("节点 type 只能是 vless、vmess、trojan 或 ss")

    server = node.get("server")
    if not isinstance(server, str) or not server.strip():
        raise ValueError("节点缺少 server")
    port = node.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("节点 port 必须是 1～65535 的整数")

    name = node.get("name") or f"{kind}-{server}:{port}"
    result = {"name": str(name), "type": kind, "server": server.strip(), "port": port}

    if kind == "ss":
        for field in ("cipher", "password"):
            if not isinstance(node.get(field), str) or not node[field]:
                raise ValueError(f"ss 节点缺少 {field}")
        result["cipher"] = node["cipher"]
        result["password"] = node["password"]
        return result

    if kind == "trojan":
        if not isinstance(node.get("password"), str) or not node["password"]:
            raise ValueError("trojan 节点缺少 password")
        result["password"] = node["password"]
    else:
        if not isinstance(node.get("uuid"), str) or not node["uuid"]:
            raise ValueError(f"{kind} 节点缺少 uuid")
        result["uuid"] = node["uuid"]
        if kind == "vmess" and "alterId" in node:
            alter = node["alterId"]
            if isinstance(alter, bool) or not isinstance(alter, int) or not 0 <= alter <= 65535:
                raise ValueError("vmess 节点 alterId 必须是 0～65535 的整数")
            result["alterId"] = alter

    network = node.get("network") or "tcp"
    if network not in ("tcp", "ws", "grpc", "h2"):
        raise ValueError("节点 network 只能是 tcp、ws、grpc 或 h2")
    result["network"] = network

    tls = node.get("tls", True)
    if not isinstance(tls, bool):
        raise ValueError("节点 tls 必须是布尔值")
    result["tls"] = tls

    for field in ("servername", "flow", "client-fingerprint"):
        value = node.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"节点 {field} 必须是字符串")
            if value:
                result[field] = value

    reality = node.get("reality-opts")
    if reality is not None:
        if not isinstance(reality, dict):
            raise ValueError("reality-opts 必须是对象")
        for field in ("public-key", "short-id"):
            if not isinstance(reality.get(field), str) or not reality[field]:
                raise ValueError(f"reality-opts 缺少 {field}")
        result["reality-opts"] = {"public-key": reality["public-key"], "short-id": reality["short-id"]}

    ws = node.get("ws-opts")
    if ws is not None:
        if not isinstance(ws, dict):
            raise ValueError("ws-opts 必须是对象")
        result["ws-opts"] = {k: v for k, v in ws.items() if isinstance(k, str)}

    grpc = node.get("grpc-opts")
    if grpc is not None:
        if not isinstance(grpc, dict):
            raise ValueError("grpc-opts 必须是对象")
        service = grpc.get("grpc-service-name")
        if not isinstance(service, str) or not service:
            raise ValueError("grpc-opts 缺少 grpc-service-name")
        result["grpc-opts"] = {"grpc-service-name": service}

    return result


def load_node(path):
    """Read and validate the pinned node from disk."""
    with open(path, encoding="utf-8") as handle:
        return validate_node(json.load(handle))


# --- YAML ------------------------------------------------------------------

def _yaml_scalar(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    if text == "" or any(ch in text for ch in ':#{}[],&*?|-<>=!%@`"\'\\ \t\n'):
        return json.dumps(text, ensure_ascii=False)
    return text


def yaml_dump(value, indent=0):
    """Minimal YAML writer for the fixed shapes mihomo accepts.

    Kept local on purpose: ClaudeGuard runs on the system Python with no third
    party packages, so importing PyYAML is not an option.
    """
    pad = "  " * indent
    lines = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.append(yaml_dump(item, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item) if not isinstance(item, (dict, list)) else ('{}' if isinstance(item, dict) else '[]')}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item:
                first = True
                for key, sub in item.items():
                    if isinstance(sub, (dict, list)) and sub:
                        lines.append(f"{pad}{'- ' if first else '  '}{key}:" if first else f"{pad}  {key}:")
                        lines.append(yaml_dump(sub, indent + 2))
                    else:
                        prefix = f"{pad}- " if first else f"{pad}  "
                        lines.append(f"{prefix}{key}: {_yaml_scalar(sub) if not isinstance(sub, (dict, list)) else ('{}' if isinstance(sub, dict) else '[]')}")
                    first = False
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    else:
        lines.append(f"{pad}{_yaml_scalar(value)}")
    return "\n".join(lines)


# --- config rendering ------------------------------------------------------

def render_config(node, options, token):
    """Build the mihomo configuration for one pinned node.

    ``GATE`` is a select group so the switch between PINNED and REJECT is a
    controller call rather than a process restart.
    """
    proxy = {"name": PINNED, "type": node["type"], "server": node["server"], "port": node["port"]}

    if node["type"] == "ss":
        proxy["cipher"] = node["cipher"]
        proxy["password"] = node["password"]
    else:
        if node["type"] == "trojan":
            proxy["password"] = node["password"]
        else:
            proxy["uuid"] = node["uuid"]
            if node["type"] == "vmess":
                proxy["alterId"] = node.get("alterId", 0)
                proxy["cipher"] = "auto"
            else:
                proxy["udp"] = True
        proxy["network"] = node["network"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        if node.get("client-fingerprint"):
            proxy["client-fingerprint"] = node["client-fingerprint"]
        if node["tls"]:
            proxy["tls"] = True
            if node.get("servername"):
                proxy["servername"] = node["servername"]
        if node.get("reality-opts"):
            proxy["reality-opts"] = dict(node["reality-opts"])
        if node.get("ws-opts"):
            proxy["ws-opts"] = dict(node["ws-opts"])
        if node.get("grpc-opts"):
            proxy["grpc-opts"] = dict(node["grpc-opts"])

    proxies = [proxy]
    groups = [{
        "name": GATE_GROUP,
        "type": "select",
        "proxies": [PINNED, REJECT],
    }]

    main_proxy = options.get("main_proxy") or ""
    if main_proxy:
        host, _, port = main_proxy.rpartition(":")
        proxies.append({"name": MAIN_PROXY, "type": "http", "server": host, "port": int(port)})
        groups.append({"name": MAIN_GROUP, "type": "select", "proxies": [MAIN_PROXY, "DIRECT"]})
    else:
        groups.append({"name": MAIN_GROUP, "type": "select", "proxies": ["DIRECT"]})

    # Claude's explicit proxy port always goes through the gate, whatever the
    # destination. The transparent port routes only Anthropic domains through
    # the gate; everything else keeps the user's normal upstream.
    rules = [f"IN-PORT,{options['proxy_port']},{GATE_GROUP}"]
    rules += [f"DOMAIN-SUFFIX,{domain},{GATE_GROUP}" for domain in CLAUDE_DOMAINS]
    rules.append(f"MATCH,{MAIN_GROUP}")

    config = {
        "mixed-port": options["proxy_port"],
        "redir-port": options["redir_port"],
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{options['controller_port']}",
        "secret": token,
        "proxies": proxies,
        "proxy-groups": groups,
        # The probe listener is bound to the pinned node directly, so verifying
        # never depends on the state of the group Claude is using.
        "listeners": [{
            "name": "probe",
            "type": "mixed",
            "port": options["probe_port"],
            "listen": "127.0.0.1",
            "proxy": PINNED,
        }],
        "rules": rules,
    }
    if options.get("interface_name"):
        config["interface-name"] = options["interface_name"]
    return config


def find_mihomo(explicit=None):
    """Locate a mihomo binary; None when nothing usable is installed."""
    for candidate in ([explicit] if explicit else []) + list(MIHOMO_CANDIDATES):
        if not candidate:
            continue
        path = Path(os.path.expanduser(candidate))
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


# --- gate ------------------------------------------------------------------

class Gate:
    """Owns the mihomo process, its config and the READY/BLOCKED verdict."""

    def __init__(self, directory=None, node_path=None, options=None, mihomo=None):
        self.dir = Path(directory or os.path.join(CONFIG_DIR, "gate"))
        self.node_path = Path(node_path or self.dir / "node.json")
        self.options = settings(options or {})
        self.mihomo = mihomo if mihomo is not None else find_mihomo()
        self.config_path = self.dir / "config.yaml"
        self.token_path = self.dir / "controller-token"
        self.pid_path = self.dir / "gate.pid"
        self.log_path = self.dir / "gate.log"
        self.state = "STOPPED"
        self.reason = ""
        self.last_verified = 0.0
        self.observed_ip = ""

    # -- files --

    def ensure_dir(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def token(self, create=True):
        try:
            value = self.token_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            if not create:
                return None
        if not create:
            return None
        self.ensure_dir()
        value = os.urandom(32).hex()
        fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
        return value

    def write_config(self, node=None):
        """Render config.yaml for the pinned node; returns the path."""
        node = node or load_node(self.node_path)
        self.ensure_dir()
        text = yaml_dump(render_config(node, self.options, self.token())) + "\n"
        temp = self.config_path.with_suffix(".tmp")
        temp.write_text(text, encoding="utf-8")
        os.replace(temp, self.config_path)
        os.chmod(self.config_path, 0o600)
        return self.config_path

    # -- process --

    def pid(self):
        try:
            return int(self.pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def running(self):
        pid = self.pid()
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def start(self, wait=15):
        """Start mihomo and wait for its controller. Fail closed on any error."""
        if self.running():
            self.state = "STARTING"
            return self.status()
        if not self.mihomo:
            raise RuntimeError("未找到 mihomo 可执行文件，请设置 gate_mihomo_path")
        self.write_config()
        self.ensure_dir()
        log = open(self.log_path, "ab")
        try:
            proc = subprocess.Popen(
                [self.mihomo, "-d", str(self.dir), "-f", str(self.config_path)],
                stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                start_new_session=True, cwd=str(self.dir))
        finally:
            log.close()
        self.pid_path.write_text(str(proc.pid), encoding="utf-8")

        deadline = time.time() + wait
        while time.time() < deadline:
            if proc.poll() is not None:
                self.state = "STOPPED"
                self.reason = "mihomo 启动即退出，请查看 gate.log"
                raise RuntimeError(self.reason)
            try:
                self.controller("GET", "/version", timeout=2)
                self.state = "STARTING"
                self.reason = ""
                return self.status()
            except Exception:
                time.sleep(0.25)
        self.stop()
        self.state = "STOPPED"
        self.reason = "mihomo 控制器未在限定时间内就绪"
        raise RuntimeError(self.reason)

    def stop(self, timeout=10):
        pid = self.pid()
        if pid:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
                time.sleep(0.1)
            else:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        try:
            self.pid_path.unlink()
        except OSError:
            pass
        self.state = "STOPPED"
        self.reason = "gate stopped"
        return self.status()

    # -- controller --

    def controller(self, method, path, body=None, timeout=5):
        token = self.token(create=False)
        if not token:
            raise RuntimeError("门卫控制器令牌缺失")
        url = f"http://127.0.0.1:{self.options['controller_port']}{path}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {token}")
        if data:
            request.add_header("Content-Type", "application/json")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1 << 20)
        return json.loads(raw) if raw.strip() else {}

    def set_gate(self, target):
        """Point the GATE group at PINNED or REJECT."""
        if target not in (PINNED, REJECT):
            raise ValueError("target 只能是 PINNED 或 REJECT")
        return self.controller("PUT", f"/proxies/{GATE_GROUP}", {"name": target})

    def gate_target(self):
        data = self.controller("GET", f"/proxies/{GATE_GROUP}")
        return data.get("now")

    # -- verification --

    def _fetch(self, url, timeout):
        proxy = f"http://127.0.0.1:{self.options['probe_port']}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        request = urllib.request.Request(url, headers={"User-Agent": "ClaudeGuard/1.0"})
        with opener.open(request, timeout=timeout) as response:
            return response.read(8192).decode("utf-8", "replace").strip()

    def probe(self):
        """Exit IP seen through the pinned node, per provider."""
        timeout = self.options["verify_timeout"]
        observed = {}
        errors = {}
        for label, url in PROBE_URLS:
            try:
                body = self._fetch(url, timeout)
                if label == "cloudflare":
                    value = ""
                    for line in body.splitlines():
                        if line.startswith("ip="):
                            value = line[3:].strip()
                            break
                else:
                    value = body.splitlines()[0].strip() if body else ""
                observed[label] = value
            except Exception as exc:  # a failed provider never becomes a pass
                errors[label] = f"{type(exc).__name__}: {exc}"
        return observed, errors

    def verify(self):
        """Open the path only when every provider agrees on the expected exit IP.

        The probe runs on its own listener, so a failed verification leaves the
        GATE group on REJECT and Claude never sees the unverified exit.
        """
        expected = self.options["expected_ip"]
        if not expected:
            self.set_gate(REJECT)
            self.state = "BLOCKED"
            self.reason = "未配置 expected_ip，拒绝放行"
            return self.status()

        observed, errors = self.probe()
        self.observed_ip = "; ".join(f"{k}={v or '未获取'}" for k, v in observed.items())

        mismatch = [f"{k}={v}" for k, v in observed.items() if v and v != expected]
        missing = [k for k in (label for label, _ in PROBE_URLS) if not observed.get(k)]

        if mismatch:
            self.set_gate(REJECT)
            self.state = "BLOCKED"
            self.reason = f"出口与预期不符（期望 {expected}）：{', '.join(mismatch)}"
            return self.status()
        if missing:
            self.set_gate(REJECT)
            self.state = "BLOCKED"
            detail = "; ".join(f"{k}: {errors.get(k, '无结果')}" for k in missing)
            self.reason = f"无法确认出口 IP：{detail}"
            return self.status()

        self.set_gate(PINNED)
        self.state = "READY"
        self.reason = f"固定出口已验证：{expected}"
        self.last_verified = time.time()
        return self.status()

    def status(self):
        return {
            "state": self.state,
            "reason": self.reason,
            "expected_ip": self.options["expected_ip"],
            "observed_ip": self.observed_ip,
            "last_verified": self.last_verified,
            "proxy_port": self.options["proxy_port"],
            "running": self.running(),
            "mihomo": self.mihomo,
        }

    def fresh(self, interval=None):
        """True while the last successful verification is still within its window."""
        if self.state != "READY":
            return False
        interval = interval or self.options["verify_interval"]
        return time.time() - self.last_verified <= interval
