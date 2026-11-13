# svpn-cli

[![CI](https://github.com/howtomakeaname/svpn-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/howtomakeaname/svpn-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/howtomakeaname/svpn-cli?include_prereleases)](https://github.com/howtomakeaname/svpn-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Headless access for iOA / SVPN.** 独立 Go 客户端，将组织授权资源接入开发机、SSH 服务器和 Agent 工作流。通过浏览器完成 SSO/MFA，在 CLI 中提供代理、策略分流与双向 TCP 端口转发。

## 核心能力

| 能力 | 提供什么 |
| --- | --- |
| **Headless** | 单一可执行文件；浏览器可在另一台机器完成登录，适合 SSH 环境 |
| **Agent-ready** | 结构化命令发现、版本化 JSON、分类退出码、NDJSON 生命周期与动态端口 |
| **Policy routing** | 域名/IP、端口及协议匹配；`vpn-only` / `auto`，按需取票，授权失败不回退直连 |
| **TCP / UDP** | HTTP / HTTPS CONNECT、SOCKS5 TCP/UDP；Linux TUN 支持 IPv4/IPv6，限 `vpn-only` |
| **Port forwarding** | SSH `ProxyCommand`、本地 TCP 转发、基于 SSH 的反向转发 |
| **Trust & interop** | TLS 1.2+、CA/证书指纹验证、可选 TLCP 1.1 双证书验证、自定义 UA / Headers |

![svpn-cli 的认证授权与策略转发架构](docs/assets/architecture.png)

上：登录与授权的逻辑交互。下：请求经共享策略引擎选择 VPN、直连或拒绝，响应沿连接返回。UDP、TUN 与 TLCP 的具体范围见 [传输能力](docs/transports.md)。

## Quick start

### 1. 安装

从 [Releases](https://github.com/howtomakeaname/svpn-cli/releases) 下载 **Linux / macOS / Windows × amd64 / arm64** 对应包，按同页 `SHA256SUMS.txt` 核验后解压。Windows 使用 `svpn-cli.exe`；二进制尚未代码签名或公证。

### 2. 登录

准备所属部署方提供的组织 PIN、认证域及网关信任信息。按序运行；`auth sso` 输出登录 URL，在浏览器完成 SSO/MFA 后，由 `auth finish` 提示粘贴最终的 **HTTPS 回调**，输入会隐藏。

```bash
svpn-cli auth init --state private/auth.json --pin YOUR_ORGANIZATION_PIN --machine My-Device
svpn-cli auth sso --state private/auth.json --domain YOUR_AUTH_DOMAIN
svpn-cli auth finish --state private/auth.json
svpn-cli auth exchange --state private/auth.json
```

状态与回调属于私密凭据，请勿提交到 Git 或共享日志。私有 CA、回调文件导入等配置见 [使用指南](docs/usage.md)。

### 3. 启动代理

```bash
svpn-cli serve --state private/auth.json --mode auto
```

默认 HTTP 为 `127.0.0.1:17890`，SOCKS5 为 `127.0.0.1:17891`。保持 CLI 运行，在另一终端访问自己的授权目标：

```bash
curl --proxy http://127.0.0.1:17890 http://web.internal.example/
curl --proxy socks5h://127.0.0.1:17891 https://web.internal.example/
```

## 选择路由模式

| 场景 | 启动选项 | 未命中资源时 |
| --- | --- | --- |
| mihomo / Clash 等上游选择流量 | `--mode vpn-only` | 拒绝 |
| 应用直接使用代理，由 CLI 分流 | `--mode auto` | 直连 |

两种模式都通过 VPN 访问获准资源；**受保护资源的端口/协议被拒绝、策略不可用或 VPN 失败时，一律拒绝，不回退直连。** `auto` 只处理送入代理的请求，不接管整机流量。

[mihomo 配置片段](examples/mihomo.yaml) · [完整路由语义、SSH 与双向转发](docs/usage.md)

## Agent interface

```bash
svpn-cli --json help
svpn-cli --json capabilities
svpn-cli --json serve --state private/auth.json --mode auto --http 127.0.0.1:0 --socks ''
```

前两条是只读发现命令；第三条是前台常驻代理，从 NDJSON `ready` 事件读取实际端口。有限命令返回版本化 JSON，错误通过 stderr 与分类退出码报告；浏览器登录仍由用户完成。调用约定见 [Agent 接口](docs/automation.md)。

## 验证与边界

**Experimental。** Linux 已完成真实登录与授权资源联调；三个系统均执行原生 CI，提供六个平台包。macOS/Windows 的真实部署兼容性仍待验证。

- **重复实测**：五轮共 300 批 TCP/TUN 传输、450 次 UDP DNS 请求全部成功；公开均值、样本标准差、中位数及脱敏 CSV，见 [v0.3 实测记录](docs/performance-v0.3.md)。数据为该链路的观测结果。
- **传输范围**：UDP 封装于 TLS/TCP；Linux TUN 需外部配置路由与 DNS，尚无 TUN `auto`、fake-IP 映射或 ICMP。TLCP 1.1 已通过独立 GmSSL 互操作，真实国密网关待验证；SPA、RFC 8998 国密 TLS 1.3 和原生 UDP/QUIC 外层尚未实现。
- **运行边界**：连接受票据期限约束，尚无自动续期或重连。本地入口限回环地址、无代理用户认证；配置说明见 [使用指南](docs/usage.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [使用指南](docs/usage.md) | 登录、路由、SSH、双向 TCP 转发、证书与 Headers |
| [Agent 接口](docs/automation.md) | JSON schema、退出码、登录交接与进程生命周期 |
| [传输能力](docs/transports.md) | UDP / TUN / TLCP 实现范围、配置与互操作 |
| [实测记录](docs/performance-v0.3.md) | 方法、吞吐、延迟、资源占用与原始数据 |
| [Security](SECURITY.md) | 私密信息处理与问题反馈 |

## 开发与发布

源码需 Go 1.27.3+，CI/Release 使用 Go 1.27.4。

```bash
go test -race ./...
go vet ./...
go build -trimpath -o bin/svpn-cli ./cmd/svpn-cli
```

[GitHub Actions](.github/workflows/release.yml) 在 `v*` 标签上完成三系统测试、六平台打包与 SHA-256 校验后发布 prerelease。本地打包：`python3 scripts/build_release.py --version v0.3.0`。

## License

原创代码采用 [MIT](LICENSE)。依赖许可证及归属见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) 与 [NOTICE](NOTICE)。项目为第三方互操作工具，与相关厂商或组织无隶属关系。
