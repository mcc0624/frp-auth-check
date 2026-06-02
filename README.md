# frp Auth Check

批量检测 frp 服务器是否启用了 token 密码认证。

## 原理

使用官方 `frpc` 二进制文件尝试连接目标 frps，分析登录结果判断认证状态。
自动尝试多种配置组合以兼容不同版本。

## 使用

```bash
python3 frp_auth_check.py --download
python3 frp_auth_check.py -t target.com:7000
python3 frp_auth_check.py -l targets.txt
python3 frp_auth_check.py -l targets.txt --no-auth-only
python3 frp_auth_check.py -l targets.txt -o result.json
```
