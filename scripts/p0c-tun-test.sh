#!/bin/bash
# P0c：验证 mihomo TUN 能否接管本机流量。
#
# 不依赖任何可用节点或代理上游：TUN 里用 MATCH,DIRECT，流量照常直连。
# 判据是结构性的——启动后目标 IP 的路由是否从物理网卡切到 utun：
#
#   生效：route -n get <IP> 显示 interface utunX，且百度仍可访问
#   失效：路由仍在 en0，或 mihomo 起不来
#
# 这样即使机场没流量、Clash 关了代理，也能得到确定结论。
#
# 安全性：mihomo 退出会移除它加的路由；脚本有 60 秒兜底强杀 + trap 清理。
#
# 用法：sudo bash p0c-tun-test.sh [--dry-run]
# 退出码：0 = TUN 捕获生效；1 = 不生效

set -uo pipefail

PROBE_IP=223.5.5.5
MIXED_PORT=27899
CONTROLLER_PORT=29099
TOKEN=p0c-token

WORK=$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-p0c.XXXXXX")
CFG="$WORK/config.yaml"
LOG="$WORK/mihomo.log"
MIHOMO="/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"
MIHOMO_PID=""

say() { echo "▶ $*"; }
die() { echo "❌ $*" >&2; exit 1; }
iface_of() { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
[ "$(uname -s)" = "Darwin" ] || die "仅支持 macOS"
[ "$DRY_RUN" = "1" ] || [ "$(id -u)" -eq 0 ] || die "请用 sudo 运行"
[ -x "$MIHOMO" ] || die "找不到 mihomo：$MIHOMO"

cleanup() {
    if [ -n "$MIHOMO_PID" ]; then
        kill "$MIHOMO_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$MIHOMO_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$MIHOMO_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cat > "$CFG" <<EOF
mixed-port: ${MIXED_PORT}
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: info
external-controller: 127.0.0.1:${CONTROLLER_PORT}
secret: ${TOKEN}

rules:
  - MATCH,DIRECT

dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
EOF

if [ "$DRY_RUN" = "1" ]; then
    say "dry-run：只校验配置"
    "$MIHOMO" -t -d "$WORK" -f "$CFG" 2>&1 | tail -2
    exit $?
fi

before_iface=$(iface_of "$PROBE_IP")
[ -n "$before_iface" ] || die "无法确定 ${PROBE_IP} 的当前路由"
say "启动前：${PROBE_IP} 走 ${before_iface}"

say "启动 mihomo（TUN + auto-route + DIRECT）"
"$MIHOMO" -d "$WORK" -f "$CFG" >"$LOG" 2>&1 &
MIHOMO_PID=$!
( sleep 60; kill -9 "$MIHOMO_PID" 2>/dev/null ) &

ready=0
for _ in $(seq 1 40); do
    sleep 0.25
    if curl -m 1 -sS -o /dev/null -H "Authorization: Bearer ${TOKEN}" \
        "http://127.0.0.1:${CONTROLLER_PORT}/version" 2>/dev/null; then
        ready=1; break
    fi
    kill -0 "$MIHOMO_PID" 2>/dev/null || break
done
[ "$ready" = "1" ] || { echo "--- mihomo 日志 ---"; tail -15 "$LOG"; die "mihomo 未就绪"; }
say "mihomo 已就绪"

sleep 1
after_iface=$(iface_of "$PROBE_IP")
echo
say "启动后：${PROBE_IP} 走 ${after_iface:-未知}"

case "$after_iface" in
    utun*) route_ok=1; echo "   ✅ 路由已切到 TUN 设备" ;;
    *)     route_ok=0; echo "   ❌ 路由仍在 ${after_iface:-未知}，auto-route 没生效" ;;
esac

echo
say "连通性：直连百度（TUN 接管后仍应可用）"
if curl -m 8 -sS --noproxy '*' -o /dev/null https://www.baidu.com 2>"$WORK/curl.err"; then
    echo "   ✅ 正常"
    net_ok=1
else
    echo "   ❌ 失败：$(head -1 "$WORK/curl.err")"
    net_ok=0
fi

echo
say "mihomo 是否记录了这条连接"
conns=$(curl -m 3 -sS -H "Authorization: Bearer ${TOKEN}" \
    "http://127.0.0.1:${CONTROLLER_PORT}/connections" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('connections') or []))" 2>/dev/null || echo "?")
echo "   活跃/近期连接数：${conns}"

echo
say "停止 mihomo，确认路由恢复"
kill "$MIHOMO_PID" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "$MIHOMO_PID" 2>/dev/null || break; sleep 0.2; done
MIHOMO_PID=""
sleep 1.5
restored_iface=$(iface_of "$PROBE_IP")
echo "   ${PROBE_IP} 现在走 ${restored_iface:-未知}（启动前是 ${before_iface}）"
if curl -m 6 -sS --noproxy '*' -o /dev/null https://www.baidu.com 2>/dev/null; then
    echo "   ✅ 网络正常"
    restored=1
else
    echo "   ❌ 网络不通"
    restored=0
fi

echo
echo "════════ 结论 ════════"
if [ "$route_ok" = "1" ] && [ "$net_ok" = "1" ]; then
    echo "✅ TUN 捕获生效：默认路由被接管到 utun，流量正常。"
    echo "   → 捕获层改用 TUN，pf 方案搁置。"
    [ "$restored" = "1" ] || echo "   ⚠️  停止后网络未恢复，请检查默认路由！"
    exit 0
fi
echo "❌ TUN 未按预期工作。日志末尾："
tail -12 "$LOG" | sed 's/^/   /'
[ "$restored" = "1" ] || echo "   ⚠️  停止后网络未恢复，请检查默认路由！"
exit 1
