"""Import pinned-node candidates from a subscription or a local client.

ClaudeGuard must not depend on one client's on-disk schema: v2rayN stores a
``ConfigType`` integer whose meaning has shifted between releases, and Clash
keeps YAML profiles. The subscription itself is self-describing — every line
starts with ``vless://``, ``ss://``, ``vmess://`` or ``trojan://`` — so the share
link is the source of truth and the client is only asked for its URL.

Nothing here writes configuration; the caller decides which node to pin.
"""
import base64
import json
import os
import sqlite3
import urllib.parse
import urllib.request

from src import gate

V2RAYN_DB = "~/Library/Application Support/v2rayN/guiConfigs/guiNDB.db"

SUPPORTED = ("vless", "ss", "vmess", "trojan")


def v2rayn_db_path(path=None):
    """Resolve the v2rayN database lazily: HOME is not fixed for the process life."""
    return os.path.expanduser(path or V2RAYN_DB)


def _b64(text):
    """Decode base64 that may be URL-safe and unpadded; returns text unchanged on failure."""
    raw = text.strip().replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw).decode("utf-8", "replace")
    except Exception:
        return text


def decode_subscription(body):
    """Subscription bodies are either plain share links or one base64 blob."""
    text = (body or "").strip()
    if "://" in text:
        return text
    decoded = _b64(text)
    return decoded if "://" in decoded else text


def _first(query, key, default=""):
    values = query.get(key)
    return values[0] if values else default


def parse_vless(uri):
    parts = urllib.parse.urlsplit(uri)
    uuid = urllib.parse.unquote(parts.username or "")
    if not uuid:
        raise ValueError("vless 链接缺少 uuid")
    server, port = parts.hostname, parts.port
    if not server or not port:
        raise ValueError("vless 链接缺少服务器或端口")

    query = urllib.parse.parse_qs(parts.query)
    network = _first(query, "type", "tcp")
    security = _first(query, "security", "none")
    node = {
        "name": urllib.parse.unquote(parts.fragment or "").strip() or f"{server}:{port}",
        "type": "vless", "server": server, "port": port, "uuid": uuid,
        "network": "tcp" if network in ("tcp", "raw") else network,
        "tls": security in ("tls", "reality"),
    }
    if _first(query, "flow"):
        node["flow"] = _first(query, "flow")
    sni = _first(query, "sni") or _first(query, "host")
    if sni:
        node["servername"] = sni
    if _first(query, "fp"):
        node["client-fingerprint"] = _first(query, "fp")
    if security == "reality":
        public_key = _first(query, "pbk")
        if not public_key:
            raise ValueError("reality 链接缺少 pbk")
        node["reality-opts"] = {"public-key": public_key, "short-id": _first(query, "sid")}
    if network == "ws":
        options = {"path": _first(query, "path", "/")}
        host = _first(query, "host")
        if host:
            options["headers"] = {"Host": host}
        node["ws-opts"] = options
    if network == "grpc":
        node["grpc-opts"] = {"grpc-service-name": _first(query, "serviceName")}
    return node


def parse_ss(uri):
    body = uri[len("ss://"):]
    remark = ""
    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark).strip()
    body = body.split("?", 1)[0]  # plugin options are not modelled

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        plain = urllib.parse.unquote(userinfo)
        decoded = plain if ":" in plain else _b64(userinfo)
        cipher, _, password = decoded.partition(":")
    else:
        # Legacy form: base64(method:password@host:port)
        userinfo, _, hostport = _b64(body).rpartition("@")
        cipher, _, password = userinfo.partition(":")

    host, _, port = hostport.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("ss 链接格式无法解析")
    if not cipher or not password:
        raise ValueError("ss 链接缺少加密方式或密码")
    return {"name": remark or f"{host}:{port}", "type": "ss", "server": host,
            "port": int(port), "cipher": cipher, "password": password}


def parse_vmess(uri):
    body = uri[len("vmess://"):].split("#", 1)[0]
    try:
        data = json.loads(_b64(body))
    except Exception as exc:
        raise ValueError(f"vmess 链接不是有效的 JSON：{exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("vmess 链接不是 JSON 对象")

    server, port, uuid = data.get("add"), data.get("port"), data.get("id")
    if not server or not uuid:
        raise ValueError("vmess 链接缺少 add 或 id")
    node = {
        "name": str(data.get("ps") or f"{server}:{port}"),
        "type": "vmess", "server": server, "port": int(port), "uuid": uuid,
        "network": data.get("net") or "tcp",
        "tls": str(data.get("tls") or "").lower() in ("tls", "reality"),
    }
    if data.get("aid") not in (None, "", 0):
        node["alterId"] = int(data["aid"])
    if data.get("sni"):
        node["servername"] = data["sni"]
    elif data.get("host"):
        node["servername"] = data["host"]
    if data.get("net") == "ws":
        options = {"path": data.get("path") or "/"}
        if data.get("host"):
            options["headers"] = {"Host": data["host"]}
        node["ws-opts"] = options
    if data.get("net") == "grpc" and data.get("path"):
        node["grpc-opts"] = {"grpc-service-name": data["path"]}
    return node


def parse_trojan(uri):
    parts = urllib.parse.urlsplit(uri)
    password = urllib.parse.unquote(parts.username or "")
    if not password:
        raise ValueError("trojan 链接缺少密码")
    server, port = parts.hostname, parts.port
    if not server or not port:
        raise ValueError("trojan 链接缺少服务器或端口")

    query = urllib.parse.parse_qs(parts.query)
    node = {
        "name": urllib.parse.unquote(parts.fragment or "").strip() or f"{server}:{port}",
        "type": "trojan", "server": server, "port": port,
        "password": password, "tls": True, "network": _first(query, "type", "tcp"),
    }
    sni = _first(query, "sni") or _first(query, "peer")
    if sni:
        node["servername"] = sni
    if _first(query, "fp"):
        node["client-fingerprint"] = _first(query, "fp")
    if node["network"] == "ws":
        options = {"path": _first(query, "path", "/")}
        host = _first(query, "host")
        if host:
            options["headers"] = {"Host": host}
        node["ws-opts"] = options
    return node


PARSERS = {"vless": parse_vless, "ss": parse_ss, "vmess": parse_vmess, "trojan": parse_trojan}


def parse_share_links(text):
    """Parse a decoded subscription body into validated gate nodes.

    Returns ``(nodes, skipped)`` where skipped holds ``(excerpt, reason)`` so the
    caller can explain what was dropped instead of silently losing a node.
    """
    nodes, skipped = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            skipped.append((line[:60], "不是分享链接"))
            continue
        scheme = line.split("://", 1)[0].strip().lower()
        parser = PARSERS.get(scheme)
        if parser is None:
            skipped.append((line[:60], f"不支持的协议 {scheme}"))
            continue
        try:
            nodes.append(gate.validate_node(parser(line)))
        except Exception as exc:
            skipped.append((line[:60], str(exc)))
    return nodes, skipped


def nodes_from_text(text):
    return parse_share_links(decode_subscription(text))


def subscription_url_from_v2rayn(db_path=None):
    """The subscription URL v2rayN imported; nodes themselves are re-fetched."""
    path = v2rayn_db_path(db_path)
    if not os.path.isfile(path):
        raise ValueError(f"未找到 v2rayN 数据库：{path}")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT Url FROM SubItem WHERE Url IS NOT NULL AND Url <> '' "
            "ORDER BY UpdateTime DESC LIMIT 1").fetchone()
    finally:
        connection.close()
    if not row:
        raise ValueError("v2rayN 数据库里没有订阅地址")
    return row[0].strip()


def fetch(url, timeout=15, proxy=None):
    """Download a subscription body. ``proxy`` is host:port or a URL, or None for env."""
    handlers = []
    if proxy:
        text = proxy if "://" in proxy else f"http://{proxy}"
        handlers.append(urllib.request.ProxyHandler({"http": text, "https": text}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": "ClaudeGuard/1.0"})
    with opener.open(request, timeout=timeout) as response:
        return response.read(1 << 20).decode("utf-8", "replace")


def nodes_from_url(url, timeout=15, proxy=None):
    return nodes_from_text(fetch(url, timeout=timeout, proxy=proxy))


def nodes_from_v2rayn(db_path=None, timeout=15, proxy=None):
    return nodes_from_url(subscription_url_from_v2rayn(db_path), timeout=timeout, proxy=proxy)


def nodes_from_file(path):
    with open(os.path.expanduser(path), encoding="utf-8") as handle:
        return nodes_from_text(handle.read())
