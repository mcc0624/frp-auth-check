# frp Auth Check

批量检测 frp 服务端（frps）是否启用了 token 密码认证的工具。

当 frp 服务端未配置 `auth.token` 时，任意客户端均可通过 frpc 连接并注册代理隧道，
造成严重的安全风险。本工具用于快速发现此类配置缺陷。

---

## 原理

使用官方 frpc 二进制文件连接目标 frps，模拟客户端登录流程，
根据返回结果判断认证状态。

```
Python 脚本 (调度层)
    │
    ├── 自动下载 frpc 二进制 (Go 编译，无需 Go 环境)
    ├── 生成临时 TOML 配置文件
    ├── 调用 subprocess 执行 frpc
    └── 分析 frpc 输出 → 判定认证状态
```

## 安装

### 依赖

- Python 3.6+
- 无第三方 Python 库依赖

### 下载工具

```bash
# 自动下载 frpc v0.69.1 二进制
python3 frp_auth_check.py --download
```

下载后 frpc 会被保存在 `/tmp/frp_bin/frpc`，后续使用无需重复下载。

## 快速使用

```bash
# 检测单个目标
python3 frp_auth_check.py -t 192.168.1.100:7000

# 批量检测
python3 frp_auth_check.py -l targets.txt

# 只显示无需认证的目标（重点关注）
python3 frp_auth_check.py -l targets.txt --no-auth-only

# 输出 JSON 格式结果
python3 frp_auth_check.py -l targets.txt -o result.json
```

### 目标文件格式

每行一个目标，支持 `host:port` 或纯域名/IP（默认端口 7000）：

```
hk.ctfstu.com:7000
192.168.1.100:7000
10.0.0.50
example.com:7000
```

## 使用示例

```bash
# 1. 下载 frpc
$ python3 frp_auth_check.py --download
[*] 下载 https://github.com/fatedier/frp/releases/download/v0.69.1/frp_0.69.1_linux_amd64.tar.gz ...
[*] frpc 已下载到: /tmp/frp_bin/frpc

# 2. 检测
$ python3 frp_auth_check.py -t hk.ctfstu.com:7000
[*] 目标: 1，并发: 5

  🔓 [hk.ctfstu.com:7000] 无需认证 - 默认(TLS+Mux): 登录成功，无需认证

==================================================
  总计:      1
  🔓 无认证: 1
  🔒 有认证: 0
  ❓ 未知:    0
==================================================

# 3. 批量检测
$ python3 frp_auth_check.py -l targets.txt
[*] 目标: 50，并发: 5

  🔓 [server1.com:7000] 无需认证 - 默认(TLS+Mux): 登录成功，无需认证
  🔒 [server2.com:7000] 需认证 - token 认证失败
  🔓 [server3.com:7000] 无需认证 - 无TLS+Mux: 登录成功，无需认证
  🔒 [server4.com:7000] 需认证 - token 认证失败
  ...
```

## 检测逻辑

工具会按优先级顺序尝试 **4 种连接配置**，直到某一种成功为止：

| 顺序 | 标签 | TLS | TCPMux | 说明 |
|------|------|-----|--------|------|
| ① | 默认(TLS+Mux) | ✅ 开 | ✅ 开 | 新版 frp 默认配置，优先尝试 |
| ② | 无TLS+Mux | ❌ 关 | ✅ 开 | 旧版 frp 不支持 TLS 的场景 |
| ③ | TLS+无Mux | ✅ 开 | ❌ 关 | 特殊配置场景 |
| ④ | 纯TCP | ❌ 关 | ❌ 关 | 最旧兼容模式 |

判定规则：

| frpc 输出特征 | 判定结果 |
|---------------|---------|
| `login to server success` | **无需认证** 🔓 |
| `token doesn't match` | **需要认证** 🔒 |
| `login to the server failed` | 是 frp 但状态未知 |
| `EOF` / `timeout` | 配置不兼容，尝试下一个 |
| 端口不可达 | 未运行 frp |

## 版本兼容性

| 服务端版本 | 协议编码 | 默认 TLS | 默认 TCPMux | 本工具兼容性 |
|-----------|---------|----------|------------|------------|
| **v0.60 ~ 最新** | JSON | ✅ 是 | ✅ 是 | ✅ 全兼容 |
| **v0.50 ~ v0.59** | JSON | ❌ 否 | ✅ 是 | ✅ 自动降级 |
| **v0.48 及以下** | **msgpack** | ❌ 否 | ❌ 否 | ❌ 不兼容 |

frp 在 **v0.48 及以下** 使用 msgpack 编码，与 v0.69.1 的 frpc 使用的 JSON 协议不互通。
如果目标运行的是古董版本，建议使用对应版本的 frpc 手动测试。

## 安全提醒

- **仅测试你有权访问的服务器**
- 发现无需认证的 frp 服务器后，攻击者可任意注册代理隧道，穿透内网
- 建议配置 `auth.token`：

```toml
# frps.toml
bindPort = 7000
auth.token = "your-random-secret-here"
```

## 输出格式 (JSON)

```json
{
  "host": "192.168.1.100",
  "port": 7000,
  "is_frp": true,
  "has_auth": false,
  "status": "no_auth",
  "detail": "默认(TLS+Mux): 登录成功，无需认证"
}
```

字段说明：

| 字段 | 类型 | 说明 |
|------|------|------|
| `host` | string | 目标主机 |
| `port` | int | 目标端口 |
| `is_frp` | bool | 是否识别为 frp 服务 |
| `has_auth` | bool/null | `false`=无认证, `true`=有认证, `null`=未知 |
| `status` | string | 状态码: `no_auth`/`has_auth`/其他 |
| `detail` | string | 详细信息 |

## 项目结构

```
frp-auth-check/
├── frp_auth_check.py   # 主脚本
└── README.md           # 本文档
```

## License

MIT
