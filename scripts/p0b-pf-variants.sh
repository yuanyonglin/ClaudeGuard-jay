#!/bin/bash
# P0b：一次性试完 pf 本地重定向的几种写法，并报告内核真实状态。
#
# 为什么要多个变体：p0 只试了 `rdr pass on lo0 ... to <IP>` 一种，失败后无法判断是
#   (a) lo0 不匹配本机出站流量，还是 (b) pf 根本没启用，还是 (c) 规则没进内核。
# 每个变体都会打印 pf 状态和内核里的 rdr 规则数，把这三件事分开。
#
# 用法：sudo bash p0b-pf-variants.sh [--dry-run]
# 退出码：0 = 至少一种写法生效；1 = 全部不生效

set -uo pipefail

TARGET=223.5.5.5
PORT=19999

WORK=$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-p0b.XXXXXX")
RULESET="$WORK/ruleset.pf"
CURL_ERR="$WORK/curl.err"

say() { echo "▶ $*"; }
die() { echo "❌ $*" >&2; exit 1; }

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

[ "$(uname -s)" = "Darwin" ] || die "仅支持 macOS"
[ "$DRY_RUN" = "1" ] || [ "$(id -u)" -eq 0 ] || die "请用 sudo 运行"

restore() {
    if [ "$DRY_RUN" = "1" ]; then rm -rf "$WORK"; return; fi
    /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    /sbin/pfctl -d >/dev/null 2>&1 || true
    pkill -f "nc -k -l 127.0.0.1 ${PORT}" 2>/dev/null || true
    rm -rf "$WORK"
}
trap restore EXIT INT TERM

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

VARIANTS=(
    "lo0+指定目标|rdr pass on lo0 inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port ${PORT}"
    "无 on 子句|rdr pass inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port ${PORT}"
    "en0|rdr pass on en0 inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port ${PORT}"
    "lo0+any（ClashX 写法）|rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port ${PORT}"
)

if [ "$DRY_RUN" = "1" ]; then
    say "dry-run：只做语法检查"
    for item in "${VARIANTS[@]}"; do
        name="${item%%|*}"; rule="${item#*|}"
        ruleset_for "$rule"
        if /sbin/pfctl -n -f "$RULESET" >/dev/null 2>&1; then
            echo "  ✅ ${name}"
        else
            echo "  ❌ ${name}"
        fi
    done
    exit 0
fi

say "预检：目标 ${TARGET}:443 必须直连可达"
curl -m 4 -sS -k --noproxy '*' "https://${TARGET}/" -o /dev/null 2>"$CURL_ERR" \
    || die "无法直连 ${TARGET}:443：$(head -1 "$CURL_ERR")"

echo
echo "pf 初始状态：$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}')"
echo

winning=""
for item in "${VARIANTS[@]}"; do
    name="${item%%|*}"; rule="${item#*|}"
    echo "──────── ${name} ────────"
    ruleset_for "$rule"

    if ! /sbin/pfctl -n -f "$RULESET" >/dev/null 2>&1; then
        echo "  语法检查失败，跳过"
        continue
    fi

    # 用 -e 而不是 -E：-E 是引用计数式启用，失败会被静默吞掉
    /sbin/pfctl -e >/dev/null 2>&1 || true
    if ! /sbin/pfctl -f "$RULESET" >/dev/null 2>&1; then
        echo "  加载失败，跳过"
        /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        continue
    fi

    status=$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}')
    rdr_count=$(/sbin/pfctl -s rules 2>/dev/null | grep -c "rdr")
    echo "  pf 状态：${status:-未知}｜内核中 rdr 规则数：${rdr_count}"

    : > "$CURL_ERR"
    (nc -k -l 127.0.0.1 "${PORT}" >/dev/null 2>&1 &)
    sleep 0.4
    if ! nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
        echo "  ⚠️  监听没起来，本变体结果不可信"
        pkill -f "nc -k -l 127.0.0.1 ${PORT}" 2>/dev/null || true
        /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        continue
    fi

    if curl -m 3 -sS -k --noproxy '*' "https://${TARGET}/" -o /dev/null 2>"$CURL_ERR"; then
        echo "  ❌ 未生效：curl 直连成功"
    else
        echo "  ✅ 生效：连接被截获（$(head -1 "$CURL_ERR" | cut -c1-60)）"
        [ -n "$winning" ] || winning="$name"
    fi

    pkill -f "nc -k -l 127.0.0.1 ${PORT}" 2>/dev/null || true
    /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    /sbin/pfctl -d >/dev/null 2>&1 || true
    sleep 0.3
    echo
done

echo "════════ 结论 ════════"
if [ -n "$winning" ]; then
    echo "✅ 可用写法：${winning}"
    exit 0
fi
echo "❌ 四种写法全部不生效。"
echo "   如果每个变体都显示「内核中 rdr 规则数 ≥ 1」且 pf 状态 Enabled，"
echo "   说明规则确实进了内核但不匹配本机出站流量 → macOS 本机 rdr 不可用。"
echo "   如果 rdr 规则数为 0 或 pf 未启用，问题在加载环节，不是 rdr 本身。"
exit 1
