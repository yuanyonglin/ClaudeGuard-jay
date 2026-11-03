#!/usr/bin/env python3
"""Bypass guard: catch a Claude process that talks to the network behind the gate.

The Windows build gets this from a per-program firewall rule: Claude.exe may
only reach loopback. macOS pf cannot match a program path, so the closest
equivalent without an Apple Network Extension entitlement is a socket watch:
any Claude TCP connection whose peer is not loopback is a bypass.

The reaction is freeze, not kill: SIGSTOP stops the process from talking while
keeping its memory and session, and the dashboard's "恢复" button can undo it.
A frozen process is only reported once; resuming it re-arms the check.

Performance: ~20 ms per lsof on a few PIDs, so a 2 s interval costs well under
one percent of a core. CLAUDEGUARD_BYPASS_INTERVAL=1 halves the window.
"""
import json
import os
import signal
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME, ".config", "claudeguard")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
STATUS_PATH = os.path.join(CONFIG_DIR, "bypass.json")
EVENTS_PATH = os.path.join(CONFIG_DIR, "events.jsonl")

INTERVAL = float(os.environ.get("CLAUDEGUARD_BYPASS_INTERVAL", 2))
PATTERN = (r"Claude\.app/Contents/|claude-code/bin/claude\.exe|/bin/claude( |$)")


def log(message):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), message, flush=True)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def write_json(path, value):
    try:
        temp = path + ".tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False)
        os.replace(temp, path)
    except OSError as exc:
        log(f"status write failed: {exc}")


def protection_enabled():
    config = read_json(CONFIG_PATH) or {}
    return bool(config.get("protection_enabled", True))


def pgrep(arguments):
    result = subprocess.run(["pgrep"] + arguments, capture_output=True, text=True)
    return [int(value) for value in result.stdout.split() if value.isdigit()]


def command_of(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                            capture_output=True, text=True)
    return result.stdout.strip()[:160]


def state_of(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                            capture_output=True, text=True)
    return result.stdout.strip()


def tree(root):
    """root and its descendants: Electron helpers own sockets too."""
    seen = [root]
    queue = [root]
    while queue:
        parent = queue.pop(0)
        for child in pgrep(["-P", str(parent)]):
            if child not in seen:
                seen.append(child)
                queue.append(child)
    return seen


def sockets(pid):
    """TCP peers this pid is connected to; lsof -F n gives machine-readable names."""
    result = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-F", "n"],
                            capture_output=True, text=True)
    peers = []
    for line in result.stdout.splitlines():
        if not line.startswith("n") or "->" not in line:
            continue
        name = line[1:].split(" (", 1)[0].strip()
        peer = name.split("->", 1)[1].strip()
        peers.append(peer)
    return peers


def is_loopback(peer):
    host = peer[1:peer.index("]")] if peer.startswith("[") else peer.rsplit(":", 1)[0]
    return host.startswith("127.") or host in ("::1", "localhost")


def notify(title, body):
    safe_body = str(body).replace('"', '\\"')
    safe_title = str(title).replace('"', '\\"')
    subprocess.run(["/usr/bin/osascript", "-e",
                    f'display notification "{safe_body}" with title "{safe_title}"'],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def append_event(record):
    record = dict(record)
    record["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record["event"] = "proxy_bypass"
    try:
        with open(EVENTS_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        log(f"event append failed: {exc}")


def inspect():
    """Return [(pid, peer, command)] for every non-loopback connection."""
    violations = []
    for root in pgrep(["-f", PATTERN]):
        for pid in tree(root):
            for peer in sockets(pid):
                if not is_loopback(peer):
                    violations.append((pid, peer, command_of(pid)))
    return violations


def main():
    if "--once" in sys.argv:
        violations = inspect()
        if not violations:
            print("OK: no non-loopback Claude connections")
            return 0
        for pid, peer, command in violations:
            print(f"BYPASS pid={pid} peer={peer} {command}")
        return 1

    frozen = {}
    while True:
        if protection_enabled():
            for pid, peer, command in inspect():
                state = state_of(pid)
                if state.startswith("T"):
                    frozen.setdefault(pid, {"pid": pid, "peer": peer})
                    continue
                try:
                    os.kill(pid, signal.SIGSTOP)
                except OSError as exc:
                    log(f"freeze {pid} failed: {exc}")
                    continue
                frozen[pid] = {"pid": pid, "peer": peer,
                               "command": command, "at": time.time()}
                log(f"bypass frozen pid={pid} peer={peer}")
                append_event({"pid": pid, "peer": peer, "command": command})
                notify("ClaudeGuard 拦截到代理绕过",
                       f"已冻结 PID {pid}（目标 {peer}）。确认后可在主界面点“恢复”。")

        alive = [pid for pid in frozen if _alive(pid)]
        frozen = {pid: value for pid, value in frozen.items() if pid in alive}
        write_json(STATUS_PATH, {"checked_at": time.time(), "frozen": list(frozen.values())})
        time.sleep(INTERVAL)


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


if __name__ == "__main__":
    sys.exit(main())
