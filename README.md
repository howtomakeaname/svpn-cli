# svpn-cli

[![CI](https://github.com/howtomakeaname/svpn-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/howtomakeaname/svpn-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/howtomakeaname/svpn-cli?include_prereleases)](https://github.com/howtomakeaname/svpn-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

面向 iOA / SVPN 的命令行客户端，使用 Go 独立实现。适合在开发机和 SSH 服务器上运行，通过本地代理或端口转发访问组织授权的资源，也可供 Agent 调用，或与 mihomo / Clash 配合使用。

## 核心能力

| 特性 | 说明 |
| --- | --- |
| **浏览器辅助登录** | CLI 可在无桌面的服务器上运行，在另一台设备的浏览器中完成 SSO/MFA。 |
| **Agent-friendly** | 提供 JSON 格式的帮助、能力查询结果和错误信息；通过 NDJSON 报告代理就绪事件与实际监听端口，便于 Agent 和脚本调用。 |
| **按策略分流** | 按域名/IP、端口和协议匹配组织策略，自动获取资源票据。支持 `vpn-only` 和 `auto`，授权失败时不会改走直连。 |
| **多种代理入口** | 支持 HTTP、HTTPS CONNECT 和 SOCKS5 TCP/UDP；Linux 还提供 IPv4/IPv6 TUN 入口，目前限 `vpn-only`。 |
| **SSH 与端口转发** | 可作为 SSH `ProxyCommand`；支持将远程服务转发到本机，也可通过 SSH 将本机服务转发到远程端口。 |
| **连接与信任配置** | 支持 TLS 1.2+、CA 与证书指纹验证，可选 TLCP 1.1 双证书验证；可配置 User-Agent 和附加 Headers。 |

![svpn-cli 的认证授权与策略转发架构](docs/assets/architecture.png)

图中区分了用户与应用、CLI 内部组件和远端服务。控制面负责登录、策略及资源票据，数据面按策略转发请求；响应沿已建立的连接返回。UDP、TUN 与 TLCP 的具体范围见 [传输能力](docs/transports.md)。

## Quick start

### 1. 安装

从 [Releases](https://github.com/howtomakeaname/svpn-cli/releases) 下载适合自己系统和架构的压缩包，按同页的 `SHA256SUMS.txt` 核验后解压，将可执行文件放入 `PATH` 中的目录。

提供 Linux、macOS、Windows 的 amd64 / arm64 包；macOS 对应文件名中的 `darwin`，Windows 可执行文件为 `svpn-cli.exe`。发布包尚未进行平台代码签名或公证。

### 2. 登录

首次使用需要所属部署方提供的组织 PIN、认证域及网关信任信息。先初始化设备，再生成登录链接：

```bash
svpn-cli auth init --state private/auth.json --pin YOUR_ORGANIZATION_PIN --machine My-Device
svpn-cli auth sso --state private/auth.json --domain YOUR_AUTH_DOMAIN
```

在浏览器中打开输出的 URL，完成 SSO/MFA。浏览器可以运行在另一台设备上。随后回到终端，运行 `auth finish` 并按提示粘贴最终的 **HTTPS 回调**；输入不会回显。最后交换访问凭据：

```bash
svpn-cli auth finish --state private/auth.json
svpn-cli auth exchange --state private/auth.json
```

状态文件和回调包含登录凭据，请保存在自己的私密目录中，不要提交到 Git 或共享日志。私有 CA、回调文件导入等配置见 [使用指南](docs/usage.md)。

### 3. 启动代理

```bash
svpn-cli serve --state private/auth.json --mode auto
```

默认 HTTP 代理监听 `127.0.0.1:17890`，SOCKS5 代理监听 `127.0.0.1:17891`。保持 CLI 运行，在另一终端访问自己获准使用的目标：

```bash
curl --proxy http://127.0.0.1:17890 http://web.internal.example/
curl --proxy socks5h://127.0.0.1:17891 https://web.internal.example/
```

## 选择路由模式

| 场景 | 启动选项 | 未命中资源时 |
| --- | --- | --- |
| mihomo / Clash 等上游选择流量 | `--mode vpn-only` | 拒绝 |
| 应用直接使用代理，由 CLI 分流 | `--mode auto` | 直连 |

两种模式都只在策略允许时通过 VPN 访问资源。**受保护资源的端口或协议不获准时，请求会被拒绝；策略不可用或 VPN 连接失败时，也不会改走直连。** `auto` 只处理应用送入代理的请求，不接管整机流量。

接入 mihomo 可参考 [配置片段](examples/mihomo.yaml)；完整的路由规则、SSH 和双向转发示例见 [使用指南](docs/usage.md)。

## Agent 与脚本调用

CLI 提供适合 Agent 和脚本读取的结构化接口。可以先查询命令和本地能力，再以动态端口启动代理：

```bash
svpn-cli --json help
svpn-cli --json capabilities
svpn-cli --json serve --state private/auth.json --mode auto --http 127.0.0.1:0 --socks ''
```

前两条命令只查询本地信息。第三条会保持代理进程运行，调用方从 NDJSON `ready` 事件中读取实际端口。

一次性命令完成后返回带版本号的 JSON；失败时将 JSON 错误写入 stderr，并返回对应类别的退出码。登录和二次验证仍由用户在浏览器中完成。输出格式和进程管理方式见 [Agent 接口](docs/automation.md)。

## 验证情况与当前限制

项目目前处于实验阶段。Linux 已完成真实登录及授权资源访问；Linux、macOS、Windows 均执行原生 CI 测试。macOS/Windows 的真实部署兼容性仍需验证。

- **真实链路测试**：五轮共 300 批 TCP/TUN 传输、450 次 UDP DNS 请求全部成功。[v0.3 实测记录](docs/performance-v0.3.md) 提供测试方法、均值、样本标准差、中位数和脱敏 CSV；这些数据反映该测试链路的表现。
- **UDP 与 TUN**：UDP 数据报通过 TLS/TCP 封装。Linux TUN 的路由和 DNS 需要外部配置，暂不支持 TUN `auto`、fake-IP 映射或 ICMP。
- **协议兼容性**：TLCP 1.1 已通过独立 GmSSL 互操作测试，真实国密网关尚待验证。SPA、RFC 8998 国密 TLS 1.3 和原生 UDP/QUIC 传输尚未实现。
- **会话与本地访问**：资源票据过期时连接会终止，当前还不支持自动续期和重连。本地代理仅监听回环地址，尚未提供代理用户名/密码认证。配置说明见 [使用指南](docs/usage.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [使用指南](docs/usage.md) | 登录、路由、SSH、双向 TCP 转发、证书与 Headers |
| [Agent 接口](docs/automation.md) | JSON 输出格式、退出码、浏览器登录配合与进程管理 |
| [传输能力](docs/transports.md) | UDP / TUN / TLCP 实现范围、配置与互操作 |
| [实测记录](docs/performance-v0.3.md) | 方法、吞吐、延迟、资源占用与原始数据 |
| [Security](SECURITY.md) | 私密信息处理与问题反馈 |

## 开发与发布

从源码构建需要 Go 1.27.3+；CI 和 Release 工作流使用 Go 1.27.4。

```bash
go test -race ./...
go vet ./...
go build -trimpath -o bin/svpn-cli ./cmd/svpn-cli
```

推送 `v*` 标签后，[GitHub Actions](.github/workflows/release.yml) 会执行三系统测试、六平台打包和 SHA-256 校验，通过后发布 prerelease。也可在本地运行 `python3 scripts/build_release.py --version v0.3.0` 打包。

## License

原创代码采用 [MIT](LICENSE)。依赖许可证及归属见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) 与 [NOTICE](NOTICE)。项目为第三方互操作工具，与相关厂商或组织无隶属关系。
