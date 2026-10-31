#!/bin/bash
# P0b：判断 macOS 上 pf 的本机出站重定向到底卡在哪一环。
#
# 上一版有三个缺陷，导致结论不可信：
#   1. 用 `pfctl -s rules` 数 rdr 规则——它只列 filter 规则，rdr 属于 translation，
#      要看 `pfctl -s nat`。所以"规则数 0"是假象。
#   2. 固定端口 19999，上一次 root 运行留下的 nc 占着它，前两个变体根本没监听上。
#   3. `pfctl -E` 的错误被 || true 吞掉，无法判断 pf 是否真的启用。
#
# 这一版：每个变体用独立随机端口、显式校验监听、用 -s nat 确认规则进内核、
# 并在结论里区分"规则没进去"和"规则进去了但不生效"。
#
# 用法：sudo bash p0b-pf-variants.sh [--dry-run]
# 退出码：0 = 至少一种写法生效；1 = 全部不生效

set -uo pipefail

TARGET=223.5.5.5
WORK=$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-p0b.XXXXXX")
RULESET="$WORK/ruleset.pf"
CURL_ERR="$WORK/curl.err"

say() { echo "▶ $*"; }
die() { echo "❌ $*" >&2; exit 1; }

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
[ "$(uname -s)" = "Darwin" ] || die "仅支持 macOS"
[ "$DRY_RUN" = "1" ] || [ "$(id -u)" -eq 0 ] || die "请用 sudo 运行"

CURRENT_PORT=""

restore() {
    if [ "$DRY_RUN" = "1" ]; then rm -rf "$WORK"; return; fi
    [ -n "$CURRENT_PORT" ] && pkill -f "nc -k -l 127.0.0.1 ${CURRENT_PORT}" 2>/dev/null
    /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    /sbin/pfctl -d >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap restore EXIT INT TERM

pick_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

ruleset_for() {
    cat > "$RULESET" <<EOF
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"

$1

anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
EOF
}

# 变体名|规则模板（__PORT__ 会被替换成该变体的端口）
VARIANTS=(
    "lo0 + 指定目标|rdr pass on lo0 inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port __PORT__"
    "无 on 子句|rdr pass inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port __PORT__"
    "en0|rdr pass on en0 inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port __PORT__"
    "lo0 + any（ClashX 写法）|rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port __PORT__"
)

if [ "$DRY_RUN" = "1" ]; then
    say "dry-run：只做语法检查"
    for item in "${VARIANTS[@]}"; do
        name="${item%%|*}"; rule="${item#*|}"
        ruleset_for "${rule/__PORT__/19999}"
        /sbin/pfctl -n -f "$RULESET" >/dev/null 2>&1 \
            && echo "  ✅ ${name}" || echo "  ❌ ${name}"
    done
    exit 0
fi

say "预检：${TARGET}:443 必须直连可达"
curl -m 4 -sS -k --noproxy '*' "https://${TARGET}/" -o /dev/null 2>"$CURL_ERR" \
    || die "无法直连 ${TARGET}:443：$(head -1 "$CURL_ERR")"

echo
echo "pf 初始状态：$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}')"
echo

loaded_any=0
working=""

for item in "${VARIANTS[@]}"; do
    name="${item%%|*}"; template="${item#*|}"
    echo "──────── ${name} ────────"

    CURRENT_PORT=$(pick_port)
    rule="${template/__PORT__/${CURRENT_PORT}}"
    ruleset_for "$rule"

    if ! /sbin/pfctl -n -f "$RULESET" >/dev/null 2>&1; then
        echo "  ✗ 语法检查失败，跳过"
        continue
    fi

    /sbin/pfctl -e >/dev/null 2>&1 || true
    if ! /sbin/pfctl -f "$RULESET" >/dev/null 2>&1; then
        echo "  ✗ 加载失败"
        /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        continue
    fi

    status=$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}')
    nat_count=$(/sbin/pfctl -s nat 2>/dev/null | grep -c "rdr")
    echo "  pf=${status:-未知}  内核 translation 规则数（-s nat）=${nat_count}"
    if [ "${nat_count}" -ge 1 ]; then
        loaded_any=1
        /sbin/pfctl -s nat 2>/dev/null | grep "rdr" | head -1 | sed 's/^/     /'
    fi

    (nc -k -l 127.0.0.1 "${CURRENT_PORT}" >/dev/null 2>&1 &)
    up=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.2
        if nc -z 127.0.0.1 "${CURRENT_PORT}" 2>/dev/null; then up=1; break; fi
    done
    if [ "$up" = "0" ]; then
        echo "  ⚠️  监听端口 ${CURRENT_PORT} 没起来，本变体不可判定"
        pkill -f "nc -k -l 127.0.0.1 ${CURRENT_PORT}" 2>/dev/null
        /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        CURRENT_PORT=""
        continue
    fi

    if curl -m 3 -sS -k --noproxy '*' "https://${TARGET}/" -o /dev/null 2>"$CURL_ERR"; then
        echo "  ❌ 未生效：curl 直连成功（规则在，但没匹配）"
    else
        echo "  ✅ 生效：连接被截获（$(head -1 "$CURL_ERR" | cut -c1-50)）"
        working="$name"
    fi

    pkill -f "nc -k -l 127.0.0.1 ${CURRENT_PORT}" 2>/dev/null
    CURRENT_PORT=""
    /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    /sbin/pfctl -d >/dev/null 2>&1 || true
    sleep 0.3
    echo
done

echo "════════ 结论 ════════"
if [ -n "$working" ]; then
    echo "✅ 可用写法：${working}"
    exit 0
fi
if [ "$loaded_any" = "1" ]; then
    echo "❌ 规则确实进了内核（-s nat 有 rdr），但本机出站流量不被匹配。"
    echo "   → macOS 本机 pf rdr 不可用，换 TUN 方案（门卫已支持 tun_enabled）。"
else
    echo "❌ 规则根本没进内核（-s nat 为空）。"
    echo "   → 是加载环节的问题，不是 rdr 能力问题，还能修。"
    echo "   请把上面每个变体的 pf= 和 规则数= 一起贴出来。"
fi
exit 1
