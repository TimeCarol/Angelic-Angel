# Angelic Angel

Angelic Angel 是一个 Python 命令行工具, 通过 Mozilla AutoPush 接收 Twitter/X Web Push 通知, 解密后以 HTTP POST 转发至 webhook。

支持 `init`, `register`, `listen`, `status`, `unregister` 五个命令。需要 Python 3.11 或更高版本。

## 安装和运行

```sh
uv sync
uv run angelic-angel init
uv run angelic-angel register
WEBHOOK_ENDPOINT=https://your-webhook.example.com/endpoint uv run angelic-angel listen
```

也可以使用 `python -m pip install .`, 然后运行 `angelic-angel` 或 `python -m angelic_angel`。

`init` 会交互读取登录 Cookie `auth_token` 和 CSRF Cookie `ct0`, 也支持 `init --auth-token YOUR_AUTH_TOKEN --ct0 YOUR_CT0`。在浏览器登录 x.com 后可以从开发者工具的 Cookie 页面取得这两个值。

```sh
uv run angelic-angel status
uv run angelic-angel unregister
uv run angelic-angel --config /path/to/angelic-angel.toml --verbose listen
```

默认配置路径为当前工作目录下的 `angelic-angel.toml`, `-c/--config` 和 `-v/--verbose` 可用于所有命令。

## 功能和模块

| 模块 | 功能 |
| --- | --- |
| `cli.py`, `__main__.py` | 命令行, 交互初始化和 Ctrl+C 退出 |
| `config.py` | TOML 配置, 凭据, 订阅和密钥 |
| `errors.py` | 可区分的应用异常 |
| `autopush.py` | hello/register/unregister/ack, 心跳和去重 |
| `push.py` | P-256 密钥生成和订阅 |
| `twitter.py` | Twitter/X 通知设置 API 注册 |
| `listener.py`, `crypto.py` | 解密, webhook 和自动重连 |

- TOML 配置保存凭据和完整订阅, 密钥使用整数数组。
- 支持 `aes128gcm` 和旧版 `aesgcm`, 缺省编码为 `aes128gcm`。非 JSON 的 UTF-8 消息转为 `{"raw": "..."}`。
- 保留 ACK 100 (已处理), 101 (解密失败), 102 (其他处理失败), 空通知直接 ACK 100。
- 维护当前连接最近 100 个通知版本, 重复通知仍回复 ACK 100。
- 连接建立前的失败以 5, 10, 20, 40 秒等间隔重试, 上限 300 秒, 次数无限。成功连接后的断开重置重试计数, 1 秒后重连。
- 关闭码 4774 触发 1800 秒退避。UAID 失效时生成新的密钥和订阅, 更新 Twitter/X 后保存配置并重连。
- 使用 TCP keepalive (60 秒), WebSocket Ping (150 秒) 和应用层 `{}` 心跳 (300 秒, 响应超时 10 秒)。WebSocket 控制帧由 `websockets` 库处理。
- webhook 返回非 2xx 时记录警告, 通知仍回复 ACK 100; 传输异常或缺少 webhook 配置回复 ACK 102。
- Twitter/X API 仅在注册和 UAID 失效恢复时调用, 监听消息来源为 Mozilla AutoPush。
- 注册时读取 X Web 客户端的当前签名材料, 为请求生成 `x-client-transaction-id`。

应用代码全部为 Python, 加密使用 `cryptography` 和 `http-ece`, 网络使用 `asyncio`, `websockets` 和 `httpx`, 请求签名使用 `xclienttransaction`。源码与测试都有类型注释, 中文 reST docstring 和文件头, 遵循指定的代码注释规范。

JSON 以 UTF-8 发送, 所有 `json.dumps` 显式设置 `ensure_ascii=False`, 中文及其他非 ASCII 字符不会转换为 Unicode 转义序列。

Webhook 的 HTTPS 请求关闭 SSL 证书校验 (`verify=False`), 可直接转发到使用自签名证书的地址。

## 开发验证

```sh
uv run pytest --cov=angelic_angel --cov-report=term-missing
uv run mypy
uv run ruff check .
```

测试使用本地 WebSocket/HTTP 服务和独立加密样例, 不需要 Twitter/X 账号, 不会注册真实订阅。实际账号通知接收仍需使用有效 Cookie 和可访问的 webhook 进行验证。

## 许可证

MIT。
