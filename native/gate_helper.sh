#!/bin/sh
# ClaudeGuard gate helper — loads and reverts the redirect ruleset.
#
# Run by launchd as root (LaunchDaemon com.claudeguard.gate-helper) or manually
# with sudo while testing. It is the only component that touches pf, and it only
# ever applies a ruleset that was staged by the user who owns the config dir.
#
#   gate-helper <config-dir> apply|clear|rollback
#
# Trust model, same as hosts-helper.c: the staged files live in a user-writable
# directory, so the config dir's owner is the only uid we accept, symlinks are
# refused, and the ruleset is parsed with `pfctl -n` before it is loaded. A
# ruleset that does not parse is never applied.
set -eu

CONFIG_DIR="${1:?usage: gate-helper <config-dir> <apply|clear|rollback>}"
ACTION="${2:?usage: gate-helper <config-dir> <apply|clear|rollback>}"

PENDING="$CONFIG_DIR/pending"
RULESET="$PENDING/gate.ruleset"
ANCHOR="$PENDING/gate.anchor"
APPLIED="$PENDING/gate.applied"
CONFIRM="$PENDING/gate.confirm"
REQUEST="$PENDING/gate.request"

ANCHOR_NAME="com.claudeguard.gate"
ANCHOR_DST="/etc/pf.anchors/$ANCHOR_NAME"
PFCTL="/sbin/pfctl"
STOCK="/etc/pf.conf"

die() { echo "gate-helper: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -d "$CONFIG_DIR" ] || die "config dir not found: $CONFIG_DIR"

OWNER=$(stat -f %Su "$CONFIG_DIR" 2>/dev/null) || die "cannot stat $CONFIG_DIR"

trusted() {
    [ -f "$1" ] || return 1
    [ -L "$1" ] && return 1
    [ "$(stat -f %Su "$1" 2>/dev/null)" = "$OWNER" ] || return 1
    return 0
}

restore_stock() {
    "$PFCTL" -f "$STOCK" || die "failed to restore $STOCK"
    "$PFCTL" -F states >/dev/null 2>&1 || true
    rm -f "$ANCHOR_DST" "$APPLIED" "$CONFIRM" "$REQUEST"
    echo "gate-helper: restored $STOCK"
}

case "$ACTION" in
    apply)
        trusted "$RULESET" || die "refusing untrusted ruleset: $RULESET"
        trusted "$ANCHOR" || die "refusing untrusted anchor: $ANCHOR"

        # The anchor must be in place before the ruleset can be parsed: the
        # ruleset loads it by path. Installing the file alone changes nothing.
        mkdir -p /etc/pf.anchors
        install -o root -g wheel -m 0644 "$ANCHOR" "$ANCHOR_DST" \
            || die "failed to install anchor"

        # Parse before loading: a malformed ruleset must never reach the kernel.
        if ! "$PFCTL" -n -f "$RULESET" >/dev/null 2>&1; then
            rm -f "$ANCHOR_DST"
            die "ruleset failed syntax check; anchor removed, nothing applied"
        fi

        "$PFCTL" -e >/dev/null 2>&1 || true
        if ! "$PFCTL" -f "$RULESET"; then
            rm -f "$ANCHOR_DST"
            "$PFCTL" -f "$STOCK" >/dev/null 2>&1 || true
            die "failed to load ruleset; restored $STOCK"
        fi
        "$PFCTL" -F states >/dev/null 2>&1 || true

        : > "$APPLIED"
        echo "gate-helper: applied $RULESET"
        ;;
    clear|rollback)
        restore_stock
        ;;
    *)
        die "unknown action: $ACTION"
        ;;
esac
