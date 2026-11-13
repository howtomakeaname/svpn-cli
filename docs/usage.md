# 使用指南

本文覆盖登录、代理分流、SSH、双向 TCP 转发及信任配置。JSON/NDJSON、退出码与进程管理见 [Agent 接口](automation.md)；UDP、Linux TUN 和 TLCP 的实现及验证范围见 [传输能力](transports.md)。

## 登录与私密状态

向所属部署方获取组织 PIN、认证域及网关信任信息，仅访问自己获准使用的资源。

```bash
svpn-cli auth init --state private/auth.json --pin YOUR_ORGANIZATION_PIN --machine My-Device
svpn-cli auth sso --state private/auth.json --domain YOUR_AUTH_DOMAIN
```

`auth init` 查询组织并注册设备，复用状态文件中已有的 MID。`--machine` 是设备显示名。在自己的浏览器打开 `auth sso` 输出的 URL，完成 SSO/MFA；浏览器可位于另一台机器。随后运行：

```bash
svpn-cli auth finish --state private/auth.json
svpn-cli auth exchange --state private/auth.json
svpn-cli auth status --state private/auth.json
```

`auth finish` 提示粘贴最终的 **HTTPS SSO 回调**，输入会隐藏。也可用 `--callback-file FILE` 导入私密文件；自动化还支持显式 `--callback-stdin`，详见 [登录状态与用户参与](automation.md#登录状态与用户参与)。不要把回调 URL 放进 argv、Issue、聊天或共享日志。CLI 检查来源、租户、随机 state、十分钟有效期及重复参数；state 单次消费。

Linux/macOS 上的凭据文件使用私密权限；Windows 使用受保护的 NTFS DACL，仅授予当前用户及 LocalSystem 访问。读取时也会验证访问控制。不要将状态文件、票据或原始服务端响应放到共享目录或版本控制中。

## 代理与路由

```bash
# 上游 mihomo / Clash 选择要送入 VPN 的流量。
svpn-cli serve --state private/auth.json --mode vpn-only

# 应用直接使用代理，CLI 按组织策略选择 VPN 或直连。
svpn-cli serve --state private/auth.json --mode auto
```

默认 HTTP 入口为 `127.0.0.1:17890`，SOCKS5 TCP 入口为 `127.0.0.1:17891`。

| 请求 | `vpn-only` | `auto` |
| --- | --- | --- |
| 命中资源且端口、协议允许 | VPN 网关 | VPN 网关 |
| 地址受保护，但端口或协议不允许 | 拒绝 | 拒绝 |
| 未命中资源 | 拒绝 | 直连 |
| 策略不可用、授权失败或隧道被拒绝 | 拒绝 | 拒绝 |

**VPN 失败不会回退直连。** `auto` 只处理送入代理的请求，不接管整机流量。日常使用 `--state` 自动获取策略和资源票据；策略启动时获取，缓存满五分钟后在下一次新连接时刷新。ST 按资源及协议缓存，遵守服务端寿命和次数，合并同目标的并发申请。

```bash
curl --proxy http://127.0.0.1:17890 http://web.internal.example/
curl --proxy socks5h://127.0.0.1:17891 https://web.internal.example/
```

域名规则命中后由网关解析；未命中域名先经过系统 DNS，再检查解析出的 IP。当前没有完整 split-DNS 或多地址容灾。普通 HTTP 代理不复用上游连接；频繁小请求需要连接复用时，可使用 SOCKS5、HTTPS CONNECT 或固定端口转发。

mihomo 集成见 [examples/mihomo.yaml](../examples/mihomo.yaml)。将文档地址替换为自己的授权目标，再并入现有规则。示例只路由 TCP SSH，因此保留 `udp: false`；使用 UDP 时，上游配置及组织 UDP 授权须同时允许。fake-IP 必须由上游还原为原始域名，CLI 不共享其映射。

本地代理无用户认证，监听限制为回环 IP，同机其他用户仍可能访问；跨机器使用请配合 SSH 转发。控制面与网关不继承环境代理，避免路由环路和出口不一致。

## SSH 与端口转发

### SSH ProxyCommand

```bash
ssh -o 'ProxyCommand=svpn-cli connect --state /absolute/path/to/private/auth.json %h %p' user@ssh.internal.example
```

`connect` 的 stdout 始终是原始 TCP 数据；JSON 错误仅走 stderr。SSH 密码和目标主机密钥由 OpenSSH 处理。Windows 请使用可执行文件与状态文件的实际路径。所有 CLI 选项须放在 `HOST PORT` 等位置参数之前。

### 本地端口 → 远程服务

适合 Jupyter、数据库等 TCP 服务，应用无需支持代理：

```bash
# 本机 127.0.0.1:8888 → VPN → 远程服务 :8888
svpn-cli --json forward --state private/auth.json \
  --listen 127.0.0.1:8888 --target notebook.internal.example:8888
```

`forward` 默认 `vpn-only`，每条流按 VPN 策略获取票据；显式 `--mode auto` 可让未命中的目标直连。

### 远程端口 → 本机服务

```bash
# SSH 主机 127.0.0.1:9000 → VPN + SSH → 本机 127.0.0.1:3000
svpn-cli --json reverse --state private/auth.json \
  --ssh-host ssh.internal.example:22 --ssh-user USER \
  --known-hosts /path/to/verified_known_hosts --identity-file /path/to/id_ed25519 \
  --listen 127.0.0.1:9000 --target 127.0.0.1:3000
```

`reverse` 通过一条 VPN + SSH 连接复用流量，使用原生 Go SSH；目标机须已有 SSH 服务并允许远程 TCP 转发，无需额外 frp 服务。最终本机目标由 CLI 直接拨号，不再次进入 VPN。

SSH 认证独立于 VPN 登录。用 `--identity-file` 指定专用私钥，或用 `--password-file` 指定私密密码文件；加密私钥可加 `--key-passphrase-file`。凭据文件须满足私密权限要求。CLI 不隐式读取默认私钥或 SSH agent；可用中性备注创建独立密钥，再显式指定路径。主机密钥须匹配已核实的 `known_hosts`，不自动接受新密钥或跳过检查。

### 生命周期与限制

两个命令均为前台长期进程，支持并发限制和关闭清理，输出 NDJSON `ready` / `stopped`。`ready.data.listen` 给出实际端口，`--listen 127.0.0.1:0` 可动态分配。就绪事件不保证最终目标已连通，具体语义见 [管理固定端口转发](automation.md#管理固定端口转发)。

监听请求限制为回环 IP，反向转发的本机目标也须为回环 IP；远程开放范围仍受 SSH 服务端配置控制。单个流连接失败会关闭该流，进程继续监听；SSH 连接结束会终止反向转发。目前没有自动重连、SSH agent、键盘交互认证或公开中继服务。

## Gateway trust 与 Headers

### 普通 TLS

默认使用系统 CA，验证证书主机名及有效期，最低 TLS 1.2。私有部署可显式选择以下一种信任方式：

```bash
svpn-cli serve --state private/auth.json --gateway-ca /path/to/trusted-ca.pem
svpn-cli serve --state private/auth.json --certificate-sha256 YOUR_VERIFIED_LEAF_SHA256
```

CA/指纹须通过可信渠道获取。叶证书固定仍检查主机名及有效期，没有自动接受证书或跳过验证的选项。这些参数也适用于 `connect`、`forward`、`reverse` 和 `tun`。

### 可选 TLCP

```bash
svpn-cli serve --state private/auth.json --gateway-tls tlcp --gateway-ca /absolute/path/to/ca.pem
```

TLCP 1.1 要求 CA 同时验证签名及加密双证书，不接受单叶指纹，失败不降级普通 TLS。控制面 SSO/API 仍使用普通 HTTPS；尚无 TLCP 客户端证书认证，实际国密网关待验证。TLCP 与 RFC 8998 国密 TLS 1.3 是不同协议；后者尚未实现。套件及独立互操作记录见 [传输能力](transports.md#tlcp-的信任与互操作)。

### User-Agent 与附加头

默认使用兼容 UA 与网关产品头，不附加实现产品标记。可自定义 UA，或用 [Headers profile](../examples/headers.example.json) 补充控制面、网关头：

```bash
svpn-cli auth init --state private/auth.json --header-profile examples/headers.example.json
svpn-cli serve --state private/auth.json --header-profile my-headers.json
svpn-cli serve --state private/auth.json --user-agent 'YOUR_USER_AGENT'
```

`auth init` 将配置写入私密状态；`serve/connect/forward/reverse/tun` 的覆盖仅作用于本次运行。Profile 字段为 `user_agent`、`control_headers`、`gateway_headers`。Host、认证、签名、身份、协议及消息长度字段禁止覆盖；拒绝控制字符、重复名字和过大的头。进程审计字段报告实际进程。

## 会话与部署边界

- 活动连接受 ST 到期时间约束，长连接可能届时断开；TGT 自动续期、额外交互挑战及实时撤销尚未实现。
- SPA、RFC 8998 国密 TLS 1.3 及原生 UDP/QUIC/WireGuard 外层尚未实现，需要这些功能的部署仍不兼容。UDP 当前为 TLS/TCP 封装，TUN 只在 Linux 提供设备入口；详见 [传输能力](transports.md)。
- `policy`、`ticket`、`check`、`--session` 用于诊断；日常使用 `--state`，不要跨进程重用手工票据。
- 六个平台发布包均未代码签名或公证，下载后按 `SHA256SUMS.txt` 核验；平台 CI 与打包成功不等于特定部署兼容。

问题反馈请附脱敏版本、配置结构和错误码，勿附凭据；见 [Security](../SECURITY.md)。
