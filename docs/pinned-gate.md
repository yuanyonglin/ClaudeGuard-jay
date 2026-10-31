# 固定出口门卫

门卫把 Claude 的流量钉在一个节点上：只有该节点的出口 IP 与预期一致时才放行，其余情况一律拒绝。它不依赖 Clash 或 v2rayN 的配置，只要求你指定一个节点。

## 为什么不是"检测后阻断"

轮询式检测总有窗口：节点一跳，新出口已经暴露给服务端，之后才被拦下。门卫改成结构性约束——Claude 只能从这一个节点出去，错误出口在物理上不发生。

## 两个监听口

```
Claude Code / Claude 桌面端
   │  HTTPS_PROXY=http://127.0.0.1:17899
   ▼
proxy_port 17899  →  GATE 组（PINNED 或 REJECT）   ← Claude 走这条
probe_port 17898  →  硬绑定 PINNED                  ← 验证走这条
redir_port 17897  →  透明代理入口（TCP，待接 pf）
```

`probe_port` 用 mihomo 的 `listeners[].proxy` 直接绑定固定节点，不经过 `GATE` 组。因此验证永远走固定节点，且**不依赖 Claude 正在使用的那条路**：验证通过才把 `GATE` 切到 `PINNED`，失败就切到 `REJECT`。切换是控制器 API 调用，不重启进程。

## 端口约定

| 端口 | 用途 | 备注 |
|---|---|---|
| 17899 | Claude 的显式代理 | 避开 Clash Verge 的 7897 与 v2rayN 的 10808 |
| 17898 | 验证专用 | 只监听回环 |
| 17897 | 透明代理 | 避开 Clash Verge 的 redir 7895 |
| 19099 | mihomo 控制器 | Bearer token，令牌在 `gate/controller-token`（0600） |

## 快速开始

```bash
# 1. 列出订阅里的节点（默认读 v2rayN 的订阅地址）
claudeguard gate nodes

# 2. 固定其中一个
claudeguard gate import 2

# 3. 指定该节点的出口 IP（在节点可用时用 curl 确认）
claudeguard set-gate-expected-ip 203.0.113.10

# 4. 启动并验证
claudeguard gate start

# 5. 以门卫为判定依据
claudeguard enable-gate
```

`gate nodes` 支持三种来源，优先级从高到低：

```bash
claudeguard gate nodes --url https://example.com/sub?token=...   # 任意订阅地址
claudeguard gate nodes --file ./nodes.txt                        # 本地分享链接列表
claudeguard gate nodes --v2rayn [~/path/guiNDB.db]               # 指定 v2rayN 数据库
```

## 订阅兼容

订阅体既可以是机场原生的 base64 分享链接列表，也可以是明文链接。支持 `vless://`、`ss://`、`vmess://`、`trojan://`。

**不读客户端的节点表**。v2rayN 的 `ConfigType` 整数在不同版本含义不同，Clash 用 YAML profile，两者都不可靠；分享链接自带协议标识，才是权威来源。所以门卫只向客户端要**订阅地址**，节点由自己重新解析。

解析失败的行不会中断导入，`gate nodes` 会逐条列出被跳过的行和原因。

## 节点文件

`gate import` 写入 `~/.config/claudeguard/gate/node.json`（0600），结构如下：

```json
{
  "name": "Example-A",
  "type": "vless",
  "server": "203.0.113.10",
  "port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "tls": true,
  "network": "tcp",
  "flow": "xtls-rprx-vision",
  "servername": "example.com",
  "client-fingerprint": "chrome",
  "reality-opts": { "public-key": "...", "short-id": "..." }
}
```

字段与 claude-gute 的 `guard-node.json` 一致，可以直接沿用。

## 分流规则

```yaml
rules:
  - IN-PORT,17899,GATE                      # Claude 的代理口：全部走门卫
  - DOMAIN-SUFFIX,claude.ai,GATE
  - DOMAIN-SUFFIX,claude.com,GATE
  - DOMAIN-SUFFIX,claudeusercontent.com,GATE
  - DOMAIN-SUFFIX,anthropic.com,GATE
  - DOMAIN-SUFFIX,anthropic.ai,GATE
  - MATCH,MAIN                              # 其余流量保持原有路径
```

`MAIN` 默认 `DIRECT`；设置 `gate_main_proxy`（例如 `127.0.0.1:7897`）会把它接成 HTTP 上游，让你现有的 Clash 继续服务非 Claude 流量。

## 当前限制

- **还没有 pf 规则**：门卫只保护"主动把代理指向它"的流量。绕过代理端口直连的进程目前拦不住，这一层由 P2 的 pf 重定向负责。
- **macOS 上 redir 不支持 UDP**：mihomo 日志会报 `Failed to start Redir UDP Listener: not supported on current platform`。因此 QUIC/HTTP3 无法透明代理，只能由 pf 阻断 UDP:443 强制回落 TCP。
- **桌面端尚未覆盖**：`Claude.app` 不读 `HTTPS_PROXY`，需要 pf 层在内核截获，或启动时加 `--proxy-server`。
- **mihomo 二进制**：默认会找到 Clash Verge 自带的那份，仅适合开发。正式使用请把独立副本放到 `~/.local/share/ClaudeGuard/bin/mihomo`。

## 与其他客户端共存

- 不要同时启用 Clash Verge 的 TUN / 增强模式：两套重定向会冲突。
- 门卫不修改 Clash 或 v2rayN 的配置，也不读它们的节点表。
- 节点失效时门卫 fail closed，Claude 直接断网；用 `claudeguard gate verify` 复查，换节点用 `gate import`。
