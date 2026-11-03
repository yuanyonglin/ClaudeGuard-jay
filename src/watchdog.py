#!/usr/bin/env python3
"""Heartbeat watchdog for ClaudeGuard.

Runs as its own LaunchAgent, so it survives whatever happens to the menu bar
daemon. It only reports (and, after a long outage, re-blocks Anthropic domains);
it never restarts anything — two supervisors restarting each other is how you
get a loop.

A healthy pair publishes:

  ~/.config/claudeguard/state.json        every 3s   (menu bar daemon)
  ~/.config/claudeguard/gate/state.json   every 30s  (gate watch)

If either file stops moving, the protection is gone even though nothing on
screen says so. That is the case this process exists for.

Usage:
  watchdog.py          run the loop (what the LaunchAgent does)
  watchdog.py --once   print one evaluation and exit (no notifications)
"""
import json
import os
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME, ".config", "claudeguard")
STATE_PATH = os.path.join(CONFIG_DIR, "state.json")
GATE_PATH = os.path.join(CONFIG_DIR, "gate", "state.json")
MEMO_PATH = os.path.join(CONFIG_DIR, "watchdog.json")

INTERVAL = float(os.environ.get("CLAUDEGUARD_WATCHDOG_INTERVAL", 10))
DAEMON_MAX_AGE = float(os.environ.get("CLAUDEGUARD_WATCHDOG_DAEMON_MAX_AGE", 20))
GATE_MAX_AGE = float(os.environ.get("CLAUDEGUARD_WATCHDOG_GATE_MAX_AGE", 120))
BLOCK_AFTER = float(os.environ.get("CLAUDEGUARD_WATCHDOG_BLOCK_AFTER", 90))


def log(message):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), message, flush=True)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def age_of(obj):
    try:
        return time.time() - float(obj.get("updated_at", 0))
    except Exception:
        return None


def notify(title, body):
    safe_body = str(body).replace('"', '\\"')
    safe_title = str(title).replace('"', '\\"')
    subprocess.run(
        ["/usr/bin/osascript", "-e",
         f'display notification "{safe_body}" with title "{safe_title}"'],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def block_domains():
    """Fail closed: write the same block list the daemon would have written."""
    sys.path.insert(0, os.path.join(HOME, ".local", "share", "ClaudeGuard"))
    from src.config import ConfigManager
    from src import network_guard
    return network_guard.sync_hosts_file(True, True, ConfigManager())


def evaluate():
    daemon = read_json(STATE_PATH)
    gate = read_json(GATE_PATH)
    daemon_age = age_of(daemon)
    gate_age = age_of(gate)
    problems = []
    if daemon_age is None or daemon_age > DAEMON_MAX_AGE:
        detail = "从未发布" if daemon_age is None else f"{int(daemon_age)} 秒未更新"
        problems.append(f"守护进程失联（{detail}）")
    if gate_age is None or gate_age > GATE_MAX_AGE:
        detail = "从未发布" if gate_age is None else f"{int(gate_age)} 秒未更新"
        problems.append(f"门卫状态停止更新（{detail}）")
    return problems, daemon_age, gate_age, gate


def write_memo(status, down_since, blocked, now):
    try:
        temp = MEMO_PATH + ".tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump({"status": status, "down_since": down_since,
                       "blocked": blocked, "checked_at": now}, handle)
        os.replace(temp, MEMO_PATH)
    except OSError as exc:
        log(f"memo write failed: {exc}")


def main():
    if "--once" in sys.argv:
        problems, daemon_age, gate_age, gate = evaluate()
        state = (gate or {}).get("state", "-")
        daemon_text = "-" if daemon_age is None else f"{int(daemon_age)}s"
        gate_text = "-" if gate_age is None else f"{int(gate_age)}s"
        print(f"daemon={daemon_text} gate={gate_text} state={state}")
        print("OK" if not problems else "ALERT: " + "；".join(problems))
        return 0 if not problems else 1

    memo = read_json(MEMO_PATH) or {}
    status = memo.get("status", "ok")
    down_since = memo.get("down_since")
    blocked = bool(memo.get("blocked"))

    while True:
        problems, daemon_age, gate_age, gate = evaluate()
        now = time.time()

        if problems:
            if status != "alert":
                status, down_since, blocked = "alert", now, False
                log("alert: " + "；".join(problems))
                notify("ClaudeGuard 已失联", "；".join(problems))
            elif (not blocked and down_since is not None
                  and now - down_since >= BLOCK_AFTER
                  and (daemon_age is None or daemon_age > DAEMON_MAX_AGE)):
                ok, message = block_domains()
                blocked = True
                log(f"fail-closed: hosts block after outage ({ok}: {message})")
        else:
            if status == "alert":
                log("recovered")
                notify("ClaudeGuard 已恢复", "守护与门卫都在正常发布状态")
            status, down_since, blocked = "ok", None, False

        write_memo(status, down_since, blocked, now)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
