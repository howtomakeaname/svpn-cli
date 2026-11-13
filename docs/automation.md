# Agent 与自动化接口

CLI 可直接作为进程工具调用。对有限命令使用 argv 数组、捕获 stdout/stderr，并设置调用方超时；长期代理进程应单独由调用方管理。无需安装官方客户端或额外的 MCP 服务。

## 发现命令

```bash
svpn-cli --json version
svpn-cli --json help
svpn-cli --json help auth finish
svpn-cli --json help serve
svpn-cli --json help forward
svpn-cli --json help reverse
```

根帮助列出命令、用途、使用方式、执行影响（例如设备注册、写私密文件、启动监听）和退出码。命令帮助包含从真实参数解析器生成的 flags、类型和默认值。`help auth` / `auth --help` 列出认证子命令。发现命令不进行网络请求或修改状态。

建议把 `--json` 放在命令之前，保证参数解析早期的失败也返回 JSON。它也可放在命令选项中。所有选项必须位于位置参数之前；不要把选项附在 `connect HOST PORT` 后面。

## 结果与错误

有限命令成功时，stdout 恰好包含一行 JSON，退出码为 0：

```json
{"schema_version":1,"command":"auth inspect","ok":true,"data":{"state_file":"private/auth.json","state_exists":false,"stage":"uninitialized","registered":false,"server_validated":false,"credential_validity":"unknown","next_action":{"kind":"run_command","argv":["svpn-cli","--json","auth","init","--state","private/auth.json"],"message":"Supply --pin YOUR_ORGANIZATION_PIN for organization discovery."}}}
```

失败时有限命令的 stdout 为空，stderr 包含一行 JSON，退出码非零：

```json
{"schema_version":1,"command":"auth finish","ok":false,"error":{"code":"INTERACTION_REQUIRED","message":"Supply the HTTPS SSO callback using --callback-file or --callback-stdin; interactive input is disabled.","retryable":false,"next_action":{"kind":"supply_callback"}}}
```

`schema_version: 1` 是输出封装版本。调用方应验证版本、`ok` 和进程退出码，按 `error.code` / `next_action.kind` 分支，忽略未知附加字段；不要匹配人类帮助或 `message` 文字。`data` 的字段按命令区分：

| 命令 | 主要结果字段 |
| --- | --- |
| `version` | `version`、`commit`、`build_date`、`os`、`arch` |
| `auth init` | `state_file`、`registered`、`next_action` |
| `auth sso` | `state_file`、`login_url`、`expires_at`、浏览器登录动作 |
| `auth finish` / `auth exchange` | `state_file`、`response_saved`、`next_action` |
| `auth inspect` | 本地阶段、`registered`、待处理 SSO 有效期、`next_action` |
| `auth status` | `state_file`、`response_saved`、`credential_validity: "not_interpreted"` |
| `policy` | `output_file`、`host_policy`、`response_saved` |
| `ticket` | `output_file`、`response_saved`、`grant_validated: false` |
| `check` | `resource_count`、`expires_at`、`connectivity_tested: false` |

保存了响应不等于凭据仍有效，也不等于目标可访问。`auth status` 保存服务端响应，当前不把响应解释为有效期保证。策略、设备身份、票据、Cookie 和原始服务端响应不随 JSON 结果导出；显式诊断导出的文件仍是私密文件。`auth sso` 的登录 URL 供用户使用，也应避免公开或写入共享日志。

| 退出码 | 常见 `error.code` | 调用方动作 |
| --- | --- | --- |
| 0 | 无错误 | 消费 `data` 或生命周期事件 |
| 1 | `OPERATION_FAILED` | 未分类错误；检查配置和连接，不要盲目重试 |
| 2 | `INVALID_ARGUMENT`、`INVALID_CALLBACK` | 修正参数或回调输入 |
| 3 | `AUTH_REQUIRED`、`INTERACTION_REQUIRED`、`DOMAIN_SELECTION_REQUIRED`、`UNSUPPORTED_AUTH` | 查看下一动作；必要时交给用户完成认证 |
| 4 | `FILE_NOT_FOUND`、`PERMISSION_DENIED`、`INVALID_AUTH_STATE`、`INVALID_SESSION`、`INVALID_CALLBACK_FILE`、`LISTENER_FAILED` | 修正本地文件、权限或监听配置 |
| 5 | `REMOTE_REQUEST_FAILED`、`GATEWAY_REJECTED` | 检查网络、认证、策略和网关；连接结果可能未知 |

`DOMAIN_SELECTION_REQUIRED` 的 `error.details.domains` 提供 `{id, name}` 数组，用选定的 ID 重跑 `auth sso --domain ID`。网关拒绝的 `error.details.http_status` 仅含 HTTP 状态，不输出响应头或正文。未知底层错误不会原样复制进 JSON，避免泄漏 URL 中的票据等信息。

SSH 转发额外使用以下错误码：`SSH_KEY_PASSPHRASE_REQUIRED`（退出码 3），`INVALID_SSH_INPUT` / `INVALID_KNOWN_HOSTS`（4），`SSH_CONNECTION_FAILED` / `SSH_HOST_KEY_REJECTED` / `REMOTE_LISTENER_FAILED`（5）。不会自动接受新的主机密钥或提示输入 SSH 密码；调用方应准备私密凭据文件和经过核实的主机密钥。

当前错误均使用 `retryable: false`，表示不承诺重放安全。注册设备、交换票据、消耗回调及申请资源票据都有服务端影响；连接中断时可能已经生效。不得根据 HTTP 状态或某条文字自动反复注册/登录。

## 登录状态与用户参与

```bash
svpn-cli --json auth inspect --state private/auth.json
svpn-cli --json auth init --state private/auth.json --pin YOUR_ORGANIZATION_PIN --machine My-Device
svpn-cli --json auth sso --state private/auth.json --domain YOUR_AUTH_DOMAIN
# 用户在自己的浏览器完成 SSO/MFA，将 HTTPS 回调存入私密文件。
svpn-cli --json auth finish --state private/auth.json --callback-file private/callback.txt
svpn-cli --json auth exchange --state private/auth.json
```

`auth inspect` 不访问网络、不创建缺失文件、不输出设备或账号标识。阶段包括 `uninitialized`、`initialized`、`registered`、`awaiting_browser`、`sso_expired`、`challenge_required`、`login_saved` 和 `exchanged`。`server_validated` 始终为 false，`credential_validity` 始终为 `unknown`。`exchanged` 表示本地存在绑定到当前设备的凭据字段，下一步仍须通过实际请求验证。

`next_action.kind` 可能为 `run_command`、`browser_login`、`human_authentication`、`supply_callback`、`choose_domain` 或错误中的 `inspect_auth`。`argv` 是参数数组，不是 shell 命令字符串；有些动作仍需用户补充组织 PIN、域或回调输入。不要将服务端返回的文字解释为可执行指令。

`--json` 隐含禁止交互，也可在文本模式单独指定 `--non-interactive`。`auth finish` 此时必须明确指定 `--callback-file` 或 `--callback-stdin`，否则立即以退出码 3 返回，不会等待终端或隐式读取管道。`--callback-stdin` 读取到 EOF，限制为 8 KiB；调用方必须关闭输入流。两种回调来源不能同时使用。

不要把回调 URL、密码或验证码放进 argv、聊天记录或共享日志。登录/MFA 由用户完成；agent 接收私密文件路径即可。回调经过来源、租户、随机 state、有效期和重复参数检查，提交前消费本地待处理 state，且清除旧登录凭据。提交结果未知时需重新执行 `auth sso`，不要重放一次性回调。额外认证挑战目前仍不支持。

## 管理代理进程

```bash
svpn-cli --json serve --state private/auth.json --mode auto --http 127.0.0.1:0 --socks ''
```

stdout 是 NDJSON 事件流，代理保持前台运行。端口 0 由系统分配：

```json
{"schema_version":1,"command":"serve","ok":true,"event":"ready","data":{"listeners":{"HTTP":"127.0.0.1:49152"},"mode":"auto","target_connectivity_tested":false}}
{"schema_version":1,"command":"serve","ok":true,"event":"stopped","data":{"reason":"shutdown"}}
```

只有所有请求的监听器均已绑定，且使用 `--state` 时初始策略已获取，才会发布 `ready`。从 `listeners.HTTP` / `listeners.SOCKS5` 读取实际地址，分别配置 `http://` / `socks5h://` 代理。它不证明某个目标已成功认证或连接。

调用方应持续读取 stdout、监控 stderr 和退出码，并在任务结束时停止进程。正常处理的关闭会发出 `stopped`；异常退出、强制终止或断电可能没有此事件。不要用等待进程退出的普通工具调用启动长期代理，也不要把读取第一行后的 EOF 当作就绪。`vpn-only` / `auto` 的选择与路由边界见 README。

`connect` 是唯一的数据流例外：stdout 始终是原始 TCP，包括指定 `--json` 时；失败信息仅在 stderr 输出 JSON。继续用于 SSH `ProxyCommand`，不要把它的 stdout 交给 JSON 解析器。

## 管理固定端口转发

```bash
# 本机监听 → VPN 策略选择的远程服务
svpn-cli --json forward --state private/auth.json --listen 127.0.0.1:0 --target notebook.internal.example:8888

# 远程 SSH 主机监听 → VPN + SSH → 本机服务
svpn-cli --json reverse --state private/auth.json \
  --ssh-host ssh.internal.example:22 --ssh-user USER \
  --known-hosts /path/to/verified_known_hosts --identity-file /path/to/id_ed25519 \
  --listen 127.0.0.1:0 --target 127.0.0.1:3000
```

两个命令均为长期进程。与 `serve` 一样监听 NDJSON `ready` / `stopped`，从 `ready.data.listen` 取实际监听地址；它们不输出 `serve` 的 `listeners` 映射。示例：

```json
{"schema_version":1,"command":"forward","ok":true,"event":"ready","data":{"direction":"local_to_remote","listen":"127.0.0.1:49152","target":"notebook.internal.example:8888","mode":"vpn-only","target_connectivity_tested":false}}
{"schema_version":1,"command":"reverse","ok":true,"event":"ready","data":{"direction":"remote_to_local","ssh_host":"ssh.internal.example:22","listen":"127.0.0.1:49153","target":"127.0.0.1:3000","mode":"vpn-only","target_connectivity_tested":false}}
```

`forward` 的 ready 只保证本机端口已绑定，以及使用 `--state` 时初始策略已获取；按需为每条流申请资源票据。`reverse` 的 ready 还保证 VPN/SSH 连接和服务端监听请求已成功，但不预先连接本机目标。两者都不在 stdout 中输出转发的应用数据。

默认 `vpn-only`；显式 `--mode auto` 会按组织策略允许未命中资源直连，适用于 `forward` 的远程目标或 `reverse` 的 SSH 连接。反向转发的最终目标由本机直接拨号，须为回环 IP，不再次进入 VPN 代理。两个命令监听地址均须为回环 IP，端口 0 可动态分配；远程 SSH 服务端配置仍决定实际绑定行为。

`reverse` 的 SSH 主机须允许远程 TCP 监听，使用 `--identity-file` 或 `--password-file` 二选一。加密私钥可附加 `--key-passphrase-file`。这些凭据文件使用与其他私密文件相同的权限检查；密码/口令文件包含单行内容（可有行尾换行），上限 4 KiB。VPN 与 SSH 认证互相独立，不会用 NetID 凭据自动尝试 SSH。

单个流连接被策略拒绝或目标不可用时，该流直接关闭，监听进程继续运行；没有自动回退、重试或逐流 JSON 错误事件。`--max-connections` 限制并发（默认 128）。停止进程会关闭活动流及监听；反向转发关闭专用 SSH 连接以释放远程端口。SSH 连接每 30 秒发送保活请求，等待响应最多 10 秒。VPN 票据到期仍会终止它，当前无自动重连；调用方应监控进程退出，处理用户认证或配置问题后重新启动。

实现使用 Go SSH 的 [已有连接握手](https://pkg.go.dev/golang.org/x/crypto/ssh#NewClientConn)、[远程监听](https://pkg.go.dev/golang.org/x/crypto/ssh#Client.Listen) 和 [OpenSSH known_hosts 校验](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts#New)。

## 有限命令调用示例（Python）

```python
import json
import subprocess

result = subprocess.run(
    ["svpn-cli", "--json", "auth", "inspect", "--state", "private/auth.json"],
    capture_output=True, text=True, timeout=10, check=False,
)
record = json.loads(result.stdout if result.returncode == 0 else result.stderr)
if record.get("schema_version") != 1:
    raise RuntimeError("Unsupported CLI response version")
if result.returncode != 0 or not record["ok"]:
    raise RuntimeError(record["error"]["code"])
stage = record["data"]["stage"]
next_action = record["data"]["next_action"]
```
