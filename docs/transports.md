# 传输能力与验证范围

这里区分客户端实现、平台入口和实际部署授权。`svpn-cli --json capabilities` 只报告本地能力，不探测网关，也不保证当前账号、设备或系统权限满足运行条件。

| 功能 | 实现范围 | 已完成验证 | 限制 |
| --- | --- | --- | --- |
| UDP | SOCKS5 `UDP ASSOCIATE`，每目标 UDP 票据，TLS/TCP 数据报封装 | 真实网关的授权 DNS 请求；报文边界、错误帧、关联关闭、源端点固定及票据到期回归 | 不是原生 UDP、QUIC 或 WireGuard 外层；不支持 SOCKS 分片 |
| TUN | Linux，IPv4/IPv6 TCP/UDP 用户态栈，`vpn-only` | 真实 Linux TUN 经 VPN 接收 SSH banner、完成 UDP DNS；TCP/UDP 策略拒绝及命名空间清理；IPv4/IPv6 双端栈回归 | 路由、地址及 DNS 外部配置；macOS/Windows 设备入口、DNS 映射、ICMP 和 TUN auto 尚未实现 |
| SPA | 未实现 | 可见配置中没有足以验证 SPA 的启用参数和设备授权材料；现有实测连接没有显式发送 SPA | 这不证明部署全局关闭 SPA；不能宣称兼容要求 SPA 的部署 |
| TLCP 1.1 | 显式网关模式，SM2 / SM3 / SM4 GCM 或 CBC，CA 校验双证书 | 独立 GmSSL 3.2.0 服务端，各套件五批、每方向 8 MiB CONNECT/回显校验；双证书负向测试 | 真实 VPN 网关的国密分支尚未联调；未提供 TLCP 客户端证书认证；控制面仍为普通 HTTPS |
| 国密 TLS 1.3 | 未实现 | 无 | RFC 8998 与 TLCP 1.1 不等同 |

## UDP 的行为

TCP 和 UDP 使用不同策略匹配、请求协议和票据缓存。地址匹配但协议或端口不允许时，`auto` 也拒绝，不会直连；已有 TCP 票据不能被用于 UDP。

SOCKS 关联绑定到控制 TCP 对端，固定客户端 UDP 源端点；控制连接关闭时清理所有数据流。UDP 流空闲约 60 秒后关闭，后续请求重新建立流。控制关联和数据流都计入 `--max-connections`，因此 UDP 至少需要两个名额。每条数据报最多 65,507 字节，空数据报有效。

网关传输是带长度的数据报帧，而非把报文直接拼成字节流。拆包、粘包和调用方缓冲区截断均不会合并下一条报文；非法状态、端口绑定或长度会关闭该数据流。调用方设置读写超时不能延长资源票据期限。

外层 TCP 的重传和有序交付仍可能延迟后续数据报。实际业务能否使用 UDP，取决于下发的 UDP 资源及端口；本次真实部署仅提供了可验证的 UDP DNS 资源，未使用未获准的端口运行 UDP 吞吐服务。

## Linux TUN 的配置边界

```bash
svpn-cli --json help tun
svpn-cli --json tun --state private/auth.json --device svpn0 --mode vpn-only
```

设备须预先配置访问权限、地址、MTU 和需要引流的 IP 路由。也可由管理员在应用的网络命名空间打开 TUN，将描述符传给宿主网络中的 CLI：`--fd NUMBER` 接收编号至少为 3、无 PI 头的 Linux TUN 描述符，并负责在退出时关闭它。

实际验证采用后一种方式：应用在隔离命名空间中运行，CLI 经宿主网络连接控制面和网关，因此测试不需要改变宿主默认路由。命名空间、临时网卡和描述符在测试结束后删除或关闭。

同一网络命名空间使用 `--device` 时，应确保网关、控制面和必要的解析出口不会被重新送进 TUN；CLI 当前不自动添加出口旁路或恢复外部创建的路由。设备名、IP 地址、DNS 和路由都由管理员或调用方管理。

TUN 输入只有 IP，当前没有 DNS 到原域名的映射。无法安全识别仅按域名授权的资源，因此此入口只接受 `vpn-only`，不开放 `auto`。`ready` 表示设备与本地数据处理已准备好，不表示某个目标已连通或外部路由配置正确。

## TLCP 的信任与互操作

```bash
svpn-cli --json serve --state private/auth.json \
  --gateway-tls tlcp --gateway-ca /absolute/path/to/ca.pem
```

TLCP 显式选择后不会因握手失败重试普通 TLS。签名证书和加密证书分别检查证书链、名称和有效期；单张叶证书的指纹不足以信任双证书，所以此模式要求 CA 文件，并拒绝 `--certificate-sha256`。手工会话使用 `gateway_tls: "tlcp"` 与 `ca_file`。

独立互操作发现，上游库默认声明 SM2/SM3 编码 `0x0704`，GmSSL 3.2.0 的检查要求 `0x0708`。客户端使用[小范围兼容补丁](https://github.com/howtomakeaname/gotlcp/commit/97f5c590be74)显式允许同时声明两种对应同一算法的编码；没有移除证书检查或加入其他密码算法。依赖固定到补丁提交，保留原 MIT 许可证。

互操作服务端来自 [GmSSL 3.2.0 固定源码](https://github.com/guanzhi/GmSSL/tree/7c9f02904ef33e59c87b4f16621cc8fd434e7579)。原生 Go 负向测试覆盖错误 CA、错误名称、签名证书过期、加密证书过期、加密证书名称错误、单叶指纹拒绝，以及握手失败没有降级重试。

CI 在 Linux 编译独立 GmSSL 测试服务端，通过实际 CLI `forward --session` 验证 GCM/CBC 的 CONNECT 和完整载荷。只使用临时自建 CA、双证书及合成票据，不需要组织登录凭据；测试密钥自动删除，GmSSL 不进入产品运行依赖。

从源码仓库重现：

```bash
cmake -G "Unix Makefiles" -S .cache/GmSSL -B .cache/GmSSL-build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_TESTS=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build .cache/GmSSL-build --parallel 4
go build -o bin/svpn-cli ./cmd/svpn-cli
python3 scripts/test_tlcp_interop.py --cli bin/svpn-cli --repetitions 5 --size-mib 8
```

先将上述固定 GmSSL 源码检出到 `.cache/GmSSL`。测试脚本按该库的 CMake 定义编译辅助程序，以匹配其公开结构体布局。这里验证的是本地独立实现的互操作，不能替代真实组织的国密端点、证书链和附加认证流程验证。[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998.html) 描述的国密 TLS 1.3 不在此实现范围内。
