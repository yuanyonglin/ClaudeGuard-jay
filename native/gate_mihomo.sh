#!/bin/sh
# ClaudeGuard gate: run mihomo as root.
#
# TUN mode needs root (it creates a utun device and rewrites routes). This
# wrapper exists so the privileged part is exactly "run this config", and the
# unprivileged daemon keeps owning the config and the verdict.
#
#   gate-mihomo <gate-dir> [mihomo-path]
#
# The config is written by the user daemon, so as root we check that it is a
# regular file, not a symlink, and owned by the config dir's owner.
set -eu

DIR="${1:?usage: gate-mihomo <gate-dir> [mihomo-path]}"
MIHOMO="${2:-/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo}"
CONFIG="$DIR/config.yaml"

[ "$(id -u)" -eq 0 ] || { echo "gate-mihomo: must run as root" >&2; exit 1; }
[ -d "$DIR" ] || { echo "gate-mihomo: no such dir: $DIR" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "gate-mihomo: missing $CONFIG" >&2; exit 1; }
[ -L "$CONFIG" ] && { echo "gate-mihomo: refusing symlinked config" >&2; exit 1; }
[ -x "$MIHOMO" ] || { echo "gate-mihomo: not executable: $MIHOMO" >&2; exit 1; }

OWNER=$(stat -f %Su "$DIR")
[ "$(stat -f %Su "$CONFIG")" = "$OWNER" ] || {
    echo "gate-mihomo: config is not owned by $OWNER" >&2
    exit 1
}

exec "$MIHOMO" -d "$DIR" -f "$CONFIG"
