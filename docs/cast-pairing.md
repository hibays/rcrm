# 投屏配对协议（RCrm Cast）

手机扫码 → 配对 → 领取 → 遥控，全链路 TLS + 证书 pinning，零明文落盘。

## 总体结构

```
手机 HTTPS 云服务器 ◄──► CastRemote（手机端）
                            │  ① 扫码（rcrmcast://v1 QR）
                            ▼
                         CastReceiver（TV/PC，Dart TLS 控制服务）
                            │  ② /v1/pair 换会话 token（Bearer）
                            │  ③ /v1/claim 交接服务器凭据 + 证书指纹
                            ▼
                         媒体代理 127.0.0.1:代理端口（Range/206 透传）
                            │  ④ 上游 HTTPS + Authorization（pin 服务器 SHA-1）
                            ▼
                        libmpv / 播放器（只看到 localhost 代理）
```

- 控制通道：TLS + 证书 pin（sha256，来自扫码）+ 会话 token。
- 媒体链路：TV 代理用 pin 过的 HttpClient（sha1，来自手机转交）拉流。
- 凭据：服务器密码仅配对瞬间经 TLS 传输，只存 TV 内存，绝不落盘。
- 二维码 token：一次性 + 30s 过期，配对成功立即作废。
- 代理仅本机可达，局域网内无法绕过控制服务直接取流。
- 已知限制：TV 侧解码后为明文（投屏本质）；TV 控制端口 0.0.0.0 监听，但有 TLS + 会话认证兜底。

## 二维码格式

`rcrmcast://v1?h=<ip>&p=<port>&t=<token>&f=<sha256>&n=<name>`

| 参数 | 含义 |
| --- | --- |
| `h` | TV 局域网 IPv4 地址 |
| `p` | TLS 控制端口（默认 8901，占用时自动换口并写入 QR） |
| `t` | 配对 token：32 随机字节 hex，一次性，30s 过期 |
| `f` | TV 证书 SHA-256（64 hex，小写），手机 pin 的对象 |
| `n` | TV 显示名（可选） |

`tryDecode` 严格校验：scheme/host 必须精确匹配、token 与指纹必须 64 位 hex、端口必须 1-65535，任何不符返回 null（继续扫）。

## 配对流程

1. **扫码**：手机 pin TV 证书 —— `badCertificateCallback` 只接受 `sha256(cert.der) == f`，其他一律拒绝（同主机不同证书也拒绝）。
2. **`POST /v1/pair`**（免认证）：body `{"token": "<qr token>"}`。TV 校验 token 未过期且常量时间比较通过后立即作废 token，返回 `{"session": "<64 hex>"}`。
3. **`POST /v1/claim`**（Bearer）：body `{"server": {"url", "username", "password"}, "serverSha1"}`。`url` 支持 `https://`（云服务器）与 `http://`（局域网自建服务器）。`https` 要求 `serverSha1` 为 40 位 hex（手机用户已确认过的服务器证书 SHA-1）；`http` 无 TLS、不 pin，`serverSha1` 传空串。TV 收到后重建上游 HttpClient（https 时 pin 该 SHA-1），并立即探测一次可达性。**手机本机自建服务器（默认绑定 `127.0.0.1`）**：手机在配对时启动一个 TLS 转发（`CastHttpsRelay`，监听 `0.0.0.0:<随机端口>`，证书每次启动现生成、只存内存），把 `url` 改写为 `https://<手机局域网IP>:<转发端口>`、`serverSha1` 传转发证书的 SHA-1；TV 的代理请求打到转发，转发再带 Basic 凭据转发给本机服务器。因此无需重启服务器改绑 `0.0.0.0`。自建服务器若本身绑定 `0.0.0.0` 则直连（http，不转发）。
4. **遥控**：`/v1/status`、`/v1/play`、`/v1/pause`、`/v1/resume`、`/v1/seek`、`/v1/stop`、`/v1/volume`、`/v1/setrate`，全部要求 `Authorization: Bearer <session>`，常量时间比较。
5. **退出**：`/v1/unpair`（Bearer）——停止播放、作废会话、清除服务器凭据并生成新配对 token，接收端回到可扫码状态。手机"断开遥控"（关闭本地连接，电视继续播放，会话保留）不调用它；"退出投屏"才调用。遥控端退出界面/断连后，配对（TV 地址 + 证书指纹 + 会话 token）持久化在手机 SharedPreferences（`CastSessionStore`），首页投屏入口直接恢复遥控，无需重新扫码；TV 端会话仍是内存态，TV 重启后遥控端 status 报 401 → 重新扫码。

## 媒体代理

- `GET http://127.0.0.1:<proxyPort>/stream?path=<服务器相对路径>`，只监听 loopback。
- 透传上游状态码、`Content-Type`、`Content-Length`、`Accept-Ranges`、`Content-Range`，支持 Range/206 拖进度。
- 上游请求自动带 `Authorization: Basic …`，证书 pin 手机转交的服务器 SHA-1。
- 未 claim 时返回 409；`path` 不以 `/` 开头返回 400。

## 安全要点

- **绝不无差别信任**：手机只信扫到的那份证书；TV 只信手机转交指纹对应的那份服务器证书。
- 会话 token 在 TV 端仅存内存（重启 → 重新扫码）；手机端持久化于 SharedPreferences（`CastSessionStore`），仅存 TV 地址 + 证书指纹 + 会话 token，绝不存服务器密码。
- 配对 token 一次性 + 30s 短窗口，偷扫二维码只能拿到已作废/即将作废的 token。
- 服务器凭据经 pin 过的 TLS 通道传输，TV 内存持有，进程退出即失。

## 代码位置

- 协议层（纯 Dart，可单测）：`crates/rcrm-gui/lib/services/cast_protocol.dart`
- 接收端（TLS 控制服务 + 本地代理）：`crates/rcrm-gui/lib/services/cast_receiver.dart`
- 遥控端（pin TV 证书的客户端）：`crates/rcrm-gui/lib/services/cast_remote.dart`
- 配对持久化（SharedPreferences）：`crates/rcrm-gui/lib/services/cast_session_store.dart`
- 手机端 HTTPS 转发（loopback 服务器投屏）：`crates/rcrm-gui/lib/services/cast_https_relay.dart`（端到端测试 `test/cast_https_relay_test.dart`）
- TV 证书生成（Rust bridge，ECDSA P-256）：`rcrm_generate_tv_cert`（`tls_cert.rs`）
- 端到端测试：`crates/rcrm-gui/test/cast_receiver_test.dart`（复用 `test/cert_pinning` 证书；identity 目录文件须命名为 `cast_cert.pem` / `cast_key.pem`）
