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

# 3. 测出该节点的真实出口 IP（订阅里的地址是入口，不一定是出口）
claudeguard gate probe

# 4. 把探测结果固定下来
claudeguard set-gate-expected-ip 203.0.113.10

# 5. 启动并验证
claudeguard gate start

# 6. 以门卫为判定依据
claudeguard enable-gate
```

`gate nodes` 支持三种来源，优先级从高到低：

```bash
claudeguard gate nodes --url https://example.com/sub?token=...   # 任意订阅地址
claudeguard gate nodes --file ./nodes.txt                        # 本地分享链接列表
claudeguard gate nodes --v2rayn [~/path/guiNDB.db]               # 指定 v2rayN 数据库
```

## 入口 IP 与出口 IP

客户端里显示的"地址"是**入口**（你连到哪台服务器），不是**出口**（网站看到你是谁）。两者可能不同：

- 直连 VPS 通常相同；
- 服务商做中转或 NAT 时不同，出口甚至可能在多个 IP 之间轮换。

`gate probe` 会经固定节点问两个独立来源（ipify 与 Cloudflare），只有两边一致才给出可用值。出口若在轮换，这一步就会显示不一致，此时不能固定单一 `expected_ip`。

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

## 捕获层：TUN

门卫的代理端口只能保护"被告知要用它"的程序。要让绕过不可能，捕获必须发生在内核层。

**采用 mihomo 的 TUN 模式**，`auto-route` 由 mihomo 自己接管路由：

```yaml
tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack: ["any:53"]
```

实测结论（macOS 26.5，arm64）：启动后目标 IP 的路由从 `en0` 切到 `utun4`，流量正常，mihomo 的 `/connections` 能看到被捕获的连接；退出后路由自动恢复。

TUN 需要 root（创建 utun、改路由）。特权部分被限制到最小：`native/gate_mihomo.sh` 只做"校验暂存配置后 exec mihomo"，配置仍由用户态门卫生成和持有，判定也仍在用户态。

### 为什么不用 pf

pf 的 `rdr` 无法按进程匹配，只能整机重定向，这本身可接受。问题在于**它在本机不生效**：四种写法实测全部失败，包括 ClashX 增强模式使用的 `rdr pass on lo0 ... to any`。规则经 `pfctl -n` 解析通过、`pfctl -s nat` 也能看到，但本机出站流量不被匹配。

因此 `src/pf_guard.py` 与 `native/gate_helper.sh` 保留但默认不启用（`gate_pf_enabled`），仅作为其他 macOS 版本上的备选。相比之下 TUN 还有两个额外好处：能承载 UDP（不必再阻断 QUIC），且桌面端从 Dock 启动也一并覆盖。

## 当前限制

- **TUN 需要 root**：`install.sh` 尚未把 `native/gate_mihomo.sh` 注册成 LaunchDaemon。在那之前，`gate start` 需要先 `sudo -v` 缓存凭据。
- **出口 IP 未知**：订阅里的地址是入口，不是出口。`gate probe` 会在有流量时测出真实出口；若机场轮换出口，单一 `expected_ip` 会误拦。
- **桌面端尚未验证**：TUN 在内核层截获，理论上 `Claude.app` 从 Dock 启动也会被覆盖，但还没有在真机上跑通。
- **mihomo 二进制**：默认会找到 Clash Verge 自带的那份，仅适合开发。正式使用请把独立副本放到 `~/.local/share/ClaudeGuard/bin/mihomo`。

## 与其他客户端共存

- 不要同时启用 Clash Verge 的 TUN / 增强模式：两套重定向会冲突。
- 门卫不修改 Clash 或 v2rayN 的配置，也不读它们的节点表。
- 节点失效时门卫 fail closed，Claude 直接断网；用 `claudeguard gate verify` 复查，换节点用 `gate import`。
