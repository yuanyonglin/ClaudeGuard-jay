#!/bin/bash
# P0 验证：macOS pf 能否把本机出站 TCP:443 透明重定向到本地端口
#
# 安全性说明：
#   - 不修改 /etc/pf.conf，不动 /etc/pf.anchors
#   - 用临时规则集 pfctl -f 加载，退出时（含 Ctrl-C / 报错）自动还原
#   - 只影响 223.5.5.5:443 这一个目的地，不影响其他任何流量
#
# 用法：sudo bash p0-pf-test.sh [--dry-run]
# 退出码：
#   0 = rdr 生效（架构可行）
#   1 = rdr 不生效（需换方案）
#   2 = 规则语法错误（内核未改动）
#   3 = 测试目标不可直连（无法判定，换目标重试）

set -uo pipefail

PORT=19999
TARGET=223.5.5.5

# 每次运行独立目录：上一次 root 运行留下的 /tmp 文件属主是 root，
# 普通用户（dry-run）既写不了也删不掉。
WORK=$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-p0.XXXXXX")
RULESET="$WORK/ruleset.pf"
NC_LOG="$WORK/nc.log"
CURL_ERR="$WORK/curl.err"
SYNTAX_ERR="$WORK/syntax.err"

say() { echo "▶ $*"; }
die() { echo "❌ $*" >&2; exit 1; }

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

[ "$(uname -s)" = "Darwin" ] || die "仅支持 macOS"
[ "$DRY_RUN" = "1" ] || [ "$(id -u)" -eq 0 ] || die "请用 sudo 运行：sudo bash $0（加 --dry-run 可只做语法检查）"

PF_WAS_ENABLED=0
[ "$DRY_RUN" = "1" ] || PF_WAS_ENABLED=$(pfctl -s info 2>/dev/null | awk '/^Status:/{print ($2=="Enabled")?"1":"0"}')
say "pf 当前状态：$([ "${PF_WAS_ENABLED:-0}" = "1" ] && echo Enabled || echo Disabled)"

restore() {
  if [ "$DRY_RUN" = "1" ]; then
    rm -rf "$WORK"
    echo "▶ dry-run：内核未改动。"
    return
  fi
  say "还原 pf 规则集"
  pfctl -f /etc/pf.conf 2>/dev/null || true
  [ "${PF_WAS_ENABLED:-0}" = "1" ] || pfctl -d 2>/dev/null || true
  rm -f "$RULESET"
  pkill -f "nc -k -l 127.0.0.1 ${PORT}" 2>/dev/null || true
  echo "▶ 已还原。/etc/pf.conf 从未被修改。"
}
trap restore EXIT INT TERM

cat > "$RULESET" <<EOF
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"

# rdr 属于 translation 阶段，必须排在 anchor（filtering 阶段）之前。
# 顺序错了 pf 会报：Rules must be in order: options, normalization, queuing, translation, filtering
rdr pass on lo0 inet proto tcp from any to ${TARGET} port 443 -> 127.0.0.1 port ${PORT}

anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
EOF

say "预检：确认测试目标直连可达（否则无法区分"被重定向"和"网络不通"）"
if ! curl -m 4 -sS -k --noproxy '*' "https://${TARGET}/" -o /dev/null 2>"${CURL_ERR}"; then
  echo "❌ 无法直连 ${TARGET}:443：$(head -1 "${CURL_ERR}")"
  echo "   测试无法进行。可改用其他直连可达的 IP（修改脚本里的 TARGET）。"
  exit 3
fi
say "预检通过：${TARGET}:443 直连可达"

say "先做语法检查（不改内核）"
if ! pfctl -n -f "$RULESET" 2>"$SYNTAX_ERR"; then
  echo "❌ 语法检查失败，未加载任何规则："
  grep -vE "flushing|See /etc|present in the main|No ALTQ|ALTQ related|^$" "$SYNTAX_ERR" | sed 's/^/   /'
  exit 2
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "▶ dry-run 结束：语法通过，规则未加载，内核未改动。"
  exit 0
fi

say "启动临时监听 127.0.0.1:${PORT}"
: > "$NC_LOG"
(nc -l 127.0.0.1 "${PORT}" >>"$NC_LOG" 2>&1 &) || die "nc 启动失败"
sleep 0.5

say "加载临时规则集"
pfctl -f "$RULESET" || die "pfctl 加载失败"
pfctl -E >/dev/null 2>&1 || true
sleep 1

say "测试：curl https://${TARGET}（3 秒超时）"
if curl -m 3 -sS "https://${TARGET}" -o /dev/null 2>"$CURL_ERR"; then
  echo
  echo "❌ 未被重定向：curl 成功连上了 ${TARGET}"
  echo "   → rdr pass on lo0 在本机不生效，架构需要换方案（改走独立用户 + pf filter，或 T2 检测式）"
  RC=1
else
  echo
  echo "✅ 连接被截获（curl 失败），rdr 生效"
  echo "   curl 报错：$(head -2 "$CURL_ERR" | tr '\n' ' ')"
  echo "   监听器输出：$(head -2 "$NC_LOG" | tr '\n' ' ' | cut -c1-120)"
  RC=0
fi

# 附带探测：IPv6 是否也需要单独规则
say "IPv6 探测"
if curl -m 2 -6 -sS "https://[2606:4700:4700::1111]" -o /dev/null 2>/dev/null; then
  echo "   本机 IPv6 可达 → 正式方案必须补 inet6 规则，否则 IPv6 会绕过重定向"
else
  echo "   本机 IPv6 不可达（或未配置）→ 风险较低，仍建议加 inet6 兜底规则"
fi

say "附加检查：当前是否有 TUN / 其他透明代理在跑（会与 pf rdr 冲突）"
if ifconfig 2>/dev/null | grep -qE "^utun[0-9]+:.*(flags|mtu)"; then
  echo "   检测到 utun 接口（可能是 Clash Verge 的 TUN 模式）："
  ifconfig 2>/dev/null | grep -E "^utun[0-9]+:" | head -3
  echo "   ⚠️  TUN 模式与 pf rdr 会互相冲突，正式部署时必须二选一"
else
  echo "   未发现 TUN 接口"
fi

echo
if [ "$RC" = "0" ]; then
  echo "===== 结论：pf rdr 方案可行，可以按 T3 架构开发 ====="
else
  echo "===== 结论：pf rdr 不可用，需要回退到 T2（检测式）或独立用户方案 ====="
fi
exit $RC
