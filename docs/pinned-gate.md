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

## pf 重定向

门卫的代理端口只能保护"被告知要用它"的程序。要在 macOS 上让绕过不可能，重定向必须发生在内核里，而 pf 是唯一不需要 Apple entitlement 的手段。

pf 无法按进程路径匹配，所以重定向是**整机级**的，由门卫按域名分流：Anthropic 域名走 `PINNED`，其余走 `MAIN`。

```pf
table <claudeguard_skip> { 127.0.0.0/8, <节点服务器 IP>, <上游代理 IP> }
rdr pass on lo0 inet proto tcp from any to ! <claudeguard_skip> port 443 -> 127.0.0.1 port 17897
rdr pass on lo0 inet proto tcp from any to ! <claudeguard_skip> port 80  -> 127.0.0.1 port 17897
block drop out quick proto udp to any port 443
```

两个容易写错的地方，都已经在真机 `pfctl -n` 上验证过：

1. **排除项必须用 table**。macOS pf 拒绝否定列表 `to ! { a, b }`（语法错误），只接受 `to ! <table>`。排除表里少了节点服务器 IP，门卫的上游连接会被重定向回自己，形成环路。
2. **UDP:443 必须丢弃**。mihomo 在 macOS 上无法重定向 UDP（日志：`Failed to start Redir UDP Listener: not supported on current platform`），不阻断 QUIC 的话，Chromium 系客户端全部绕过门卫。

### 安全模型

- **不整表替换 pf**：规则集由 `/etc/pf.conf` 原文 + 一个锚点引用组成，应用时不会冲掉系统规则。
- **先解析再加载**：`pfctl -n` 通过才会进入内核；解析失败只删除锚点文件，不改变任何行为。
- **超期自动回滚**：应用时写入回滚期限（默认 20 秒），自检通过并 `pf verify` 确认后才清除；未确认就恢复 `/etc/pf.conf`。
- **门卫不 READY 时拒绝应用**：否则全机 :443 会被导进一个关闭的门卫，等于断网。
- **root helper 只应用用户态暂存的文件**：校验属主、拒绝符号链接，和现有 `hosts_helper.c` 同一套信任模型。

### 命令

```bash
claudeguard pf check      # 生成并做语法检查，不加载（不需要 root）
claudeguard pf apply      # 应用重定向（门卫必须 READY）
claudeguard pf verify     # 自检并确认，不通过自动回滚
claudeguard pf status     # 是否已应用 / 已确认 / 内核里有没有规则
claudeguard pf clear      # 撤销，恢复 /etc/pf.conf
```

`pf apply` 需要 root helper（`native/gate_helper.sh` 安装为 LaunchDaemon）。在 helper 装好之前，`pf check` 仍然可用，用来验证规则语法。

## 当前限制

- **pf helper 还没装进 install.sh**：`native/gate_helper.sh` 已写好并通过 `sh -n`，但要等 `install.sh` 注册成 LaunchDaemon 才能被 `pf apply` 调用。
- **macOS 上 redir 不支持 UDP**：mihomo 日志会报 `Failed to start Redir UDP Listener: not supported on current platform`。因此 QUIC/HTTP3 无法透明代理，只能由 pf 阻断 UDP:443 强制回落 TCP。
- **桌面端尚未验证**：pf 在内核层截获，理论上 `Claude.app` 从 Dock 启动也会被覆盖，但还没有在真机上跑通。
- **mihomo 二进制**：默认会找到 Clash Verge 自带的那份，仅适合开发。正式使用请把独立副本放到 `~/.local/share/ClaudeGuard/bin/mihomo`。

## 与其他客户端共存

- 不要同时启用 Clash Verge 的 TUN / 增强模式：两套重定向会冲突。
- 门卫不修改 Clash 或 v2rayN 的配置，也不读它们的节点表。
- 节点失效时门卫 fail closed，Claude 直接断网；用 `claudeguard gate verify` 复查，换节点用 `gate import`。
