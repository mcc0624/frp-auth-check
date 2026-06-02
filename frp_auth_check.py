#!/usr/bin/env python3
"""
frp 服务器密码验证检测工具 (v3)

原理: 使用实际 frpc 二进制，尝试多种配置组合连接目标 frps，
判断是否需要 token 认证。

兼容性:
  - 新版 frp (v0.60+):  ✅ 默认 TLS + TCPMux
  - 旧版 frp (v0.50+):   ⚠️ 自动关 TLS 降级
  - 古董版 (v0.48 以下):  ❌ msgpack 协议，不兼容

用法:
  python3 frp_auth_check.py --download          # 下载 frpc
  python3 frp_auth_check.py -t target.com:7000   # 检测单个
  python3 frp_auth_check.py -l /tmp/targets.txt  # 批量
  python3 frp_auth_check.py -l targets.txt --no-auth-only
  python3 frp_auth_check.py -l targets.txt -o result.json
"""

import subprocess
import json
import sys
import os
import argparse
import tempfile
import urllib.request
import tarfile
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 7000
FRPC_DIR = "/tmp/frp_bin"
FRPC_PATH = os.path.join(FRPC_DIR, "frpc")
FRP_VERSION = "0.69.1"
FRP_URL = f"https://github.com/fatedier/frp/releases/download/v{FRP_VERSION}/frp_{FRP_VERSION}_linux_amd64.tar.gz"

# 优先使用仓库自带的二进制
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLED_VERSIONS = [
    os.path.join(SCRIPT_DIR, "bin", f"frpc_v{FRP_VERSION}"),
    os.path.join(SCRIPT_DIR, "bin", "frpc_v0.60.0"),
    os.path.join(SCRIPT_DIR, "bin", "frpc_v0.53.0"),
]


def find_frpc():
    """查找可用的 frpc 二进制：先找本地捆版，再找已下载的"""
    for p in BUNDLED_VERSIONS + [FRPC_PATH]:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return None


def download_frpc():
    if os.path.exists(FRPC_PATH):
        print(f"[*] frpc 已存在: {FRPC_PATH}")
        return True
    os.makedirs(FRPC_DIR, exist_ok=True)
    tarball = os.path.join(FRPC_DIR, "frp.tar.gz")
    print(f"[*] 下载 {FRP_URL} ...")
    try:
        urllib.request.urlretrieve(FRP_URL, tarball)
    except Exception as e:
        print(f"[!] 下载失败: {e}")
        return False
    print("[*] 解压中...")
    with tarfile.open(tarball, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/frpc"):
                member.name = os.path.basename(member.name)
                tar.extract(member, FRPC_DIR, filter='data')
                break
    os.chmod(FRPC_PATH, 0o755)
    os.remove(tarball)
    if os.path.exists(FRPC_PATH):
        print(f"[*] frpc 已下载到: {FRPC_PATH}")
        return True
    return False


def try_frpc_login(host, port, frpc_path, enable_tls, enable_tcpmux, timeout=5):
    """用指定配置运行 frpc，返回输出"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        cfg_path = f.name
        f.write(f'serverAddr = "{host}"\n')
        f.write(f'serverPort = {port}\n')
        f.write(f'transport.tls.enable = {"true" if enable_tls else "false"}\n')
        f.write(f'transport.tcpMux = {"true" if enable_tcpmux else "false"}\n')
        f.write('\n[[proxies]]\n')
        f.write('name = "probe"\ntype = "tcp"\n')
        f.write('localIP = "127.0.0.1"\nlocalPort = 28080\nremotePort = 28080\n')

    try:
        proc = subprocess.run(
            [frpc_path, '-c', cfg_path],
            capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b'').decode() if isinstance(e.stdout, bytes) else (e.stdout or '')
        err = (e.stderr or b'').decode() if isinstance(e.stderr, bytes) else (e.stderr or '')
        output = (out + err) or 'timeout'
    except Exception as e:
        output = str(e)
    finally:
        if os.path.exists(cfg_path):
            os.unlink(cfg_path)

    return output


def check_server(host, port=DEFAULT_PORT, frpc_path=FRPC_PATH):
    result = {
        'host': host, 'port': port,
        'is_frp': False, 'has_auth': None,
        'detail': ''
    }

    # 先验证端口是否开放
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, port))
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {**result, 'detail': '端口未开放'}
    except Exception:
        pass

    # 按优先级尝试多种配置
    configs = [
        ('默认(TLS+Mux)', True,  True),
        ('无TLS+Mux',     False, True),
        ('TLS+无Mux',     True,  False),
        ('纯TCP',         False, False),
    ]

    auth_detected = False
    last_output = ''

    for label, tls, mux in configs:
        output = try_frpc_login(host, port, frpc_path, tls, mux)
        last_output = output

        if 'login to server success' in output:
            return {
                **result, 'is_frp': True, 'has_auth': False,
                'status': 'no_auth',
                'detail': f'{label}: 登录成功，无需认证'
            }

        if 'token' in output.lower() and 'doesn' in output.lower():
            auth_detected = True
            continue

        if 'timeout' in output or 'EOF' in output:
            continue

        if 'login to the server failed' in output:
            err_line = [l for l in output.split('\n') if 'failed' in l.lower()]
            err_msg = err_line[0].strip() if err_line else ''
            return {
                **result, 'is_frp': True, 'has_auth': None,
                'detail': f'{label}: {err_msg or output[:120]}'
            }

        if output.strip():
            continue

    if auth_detected:
        return {
            **result, 'is_frp': True, 'has_auth': True,
            'status': 'has_auth',
            'detail': 'token 认证失败'
        }

    return {**result, 'detail': f'无法连接: {last_output[:100]}'}


def main():
    parser = argparse.ArgumentParser(
        description='frp 服务器认证状态检测',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-t', '--target', help='单个目标 host:port')
    parser.add_argument('-l', '--list', help='目标列表文件')
    parser.add_argument('-o', '--output', help='输出 JSON 文件')
    parser.add_argument('--no-auth-only', action='store_true', help='只显示无需认证')
    parser.add_argument('--threads', type=int, default=5, help='并发数 (默认5)')
    parser.add_argument('--download', action='store_true', help='下载 frpc')
    args = parser.parse_args()

    if args.download:
        download_frpc()
        return

    if not args.target and not args.list:
        parser.print_help()
        return

    frpc_bin = find_frpc()
    if frpc_bin:
        FRPC_PATH = frpc_bin if frpc_bin.startswith(SCRIPT_DIR) else FRPC_PATH
        if frpc_bin.startswith(SCRIPT_DIR):
            frpc_path = frpc_bin
        version_tag = os.path.basename(frpc_bin).replace('frpc_v', 'v')
        print(f"[*] 使用本地 frpc: {os.path.basename(frpc_bin)} ({os.path.getsize(frpc_bin)//1024//1024}MB)")
    else:
        print("[*] 未找到本地 frpc，尝试自动下载 ...")
        if not download_frpc():
            print("[!] 下载失败，请运行 --download")
            return

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)

    parsed = []
    for t in targets:
        if ':' in t:
            h, ps = t.rsplit(':', 1)
            try:
                pn = int(ps)
            except ValueError:
                pn = DEFAULT_PORT
        else:
            h, pn = t, DEFAULT_PORT
        parsed.append((h, pn))

    print(f"[*] 目标: {len(parsed)}，并发: {args.threads}\n")

    results = []
    no_auth = 0
    has_auth = 0
    other = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        fut = {executor.submit(check_server, h, p): (h, p) for h, p in parsed}
        for f in as_completed(fut):
            r = f.result()
            results.append(r)
            tag = f"[{r['host']}:{r['port']}]"

            if r.get('has_auth') is False:
                no_auth += 1
                print(f'  🔓 {tag} 无需认证 - {r["detail"]}')
            elif r.get('has_auth') is True:
                has_auth += 1
                if not args.no_auth_only:
                    print(f'  🔒 {tag} 需认证 - {r["detail"]}')
            else:
                other += 1
                if not args.no_auth_only:
                    print(f'  ❓ {tag} {r["detail"]}')

    print()
    print('=' * 50)
    print(f'  总计:      {len(results)}')
    print(f'  🔓 无认证: {no_auth}')
    print(f'  🔒 有认证: {has_auth}')
    print(f'  ❓ 未知:     {other}')
    print('=' * 50)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f'\n已保存: {args.output}')


if __name__ == '__main__':
    main()
