#!/usr/bin/env python3
"""
frp 服务器密码验证检测工具 + 穿透可达性探测 (v4)

核心功能:
  1. 检测 frps 是否需要 token 认证
  2. 对无认证的服务器，自动注册代理并探测穿透端口是否可达（服务端防火墙检测）

原理:
  用真实 frpc 尝试多种配置组合连接目标 frps 判断认证状态。
  对无认证的 frps，注册一个临时 TCP 代理，然后探测该端口是否被服务端防火墙拦截。

用法:
  python3 frp_auth_check.py --download                  # 下载 frpc
  python3 frp_auth_check.py -t target.com:7000           # 检测单个
  python3 frp_auth_check.py -t target.com:7000 --no-probe # 只测认证，不测穿透
  python3 frp_auth_check.py -l targets.txt               # 批量（默认探测）
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
import time
import signal
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 7000
FRPC_DIR = "/tmp/frp_bin"
FRPC_PATH = os.path.join(FRPC_DIR, "frpc")
FRP_VERSION = "0.69.1"
FRP_URL = f"https://github.com/fatedier/frp/releases/download/v{FRP_VERSION}/frp_{FRP_VERSION}_linux_amd64.tar.gz"

# 探测用端口范围（随机避开知名端口）
PROBE_PORT_RANGE = range(30000, 60000)


def download_frpc():
    """下载 frpc 二进制"""
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
    """用指定配置运行 frpc（一次性登录探测），返回输出"""
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


def probe_port_reachable(host, remote_port, timeout=5):
    """
    探测目标服务器的指定端口是否可连接（TCP 三次握手）
    返回 True 表示可达，False 表示被拦截/关闭
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, remote_port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run_frpc_background(host, port, frpc_path, local_port, remote_port,
                         enable_tls=True, enable_tcpmux=True):
    """
    启动 frpc 后台进程，注册一个 TCP 代理
    返回 (process, cfg_path) 调用方负责清理
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        cfg_path = f.name
        f.write(f'serverAddr = "{host}"\n')
        f.write(f'serverPort = {port}\n')
        f.write(f'transport.tls.enable = {"true" if enable_tls else "false"}\n')
        f.write(f'transport.tcpMux = {"true" if enable_tcpmux else "false"}\n')
        f.write('\n[[proxies]]\n')
        f.write(f'name = "probe_{remote_port}"\n')
        f.write('type = "tcp"\n')
        f.write('localIP = "127.0.0.1"\n')
        f.write(f'localPort = {local_port}\n')
        f.write(f'remotePort = {remote_port}\n')

    proc = subprocess.Popen(
        [frpc_path, '-c', cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return proc, cfg_path


def check_server_with_probe(host, port, frpc_path, enable_probe=True):
    """
    检测 frp 服务器：
      1. 是否 frp、是否需要认证
      2. 如果无认证且 enable_probe 为 True，注册代理并探测穿透可达性
    """
    result = {
        'host': host, 'port': port,
        'is_frp': False, 'has_auth': None,
        'firewall_blocked': None,
        'detail': ''
    }

    # === 第 1 步：先验证 frps 端口是否开放 ===
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, port))
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {**result, 'detail': '端口未开放'}
    except Exception:
        pass

    # === 第 2 步：按优先级尝试多种配置登录 ===
    configs = [
        ('默认(TLS+Mux)', True,  True),
        ('无TLS+Mux',     False, True),
        ('TLS+无Mux',     True,  False),
        ('纯TCP',         False, False),
    ]

    auth_detected = False
    last_output = ''
    success_tls = True
    success_mux = True

    for label, tls, mux in configs:
        output = try_frpc_login(host, port, frpc_path, tls, mux)
        last_output = output

        if 'login to server success' in output:
            result.update({
                'is_frp': True, 'has_auth': False,
                'status': 'no_auth',
                'detail': f'{label}: 登录成功，无需认证'
            })
            success_tls = tls
            success_mux = mux
            break

        if 'token' in output.lower() and 'doesn' in output.lower():
            auth_detected = True
            continue

        if 'timeout' in output or 'EOF' in output:
            continue

        if 'login to the server failed' in output:
            err_line = [l for l in output.split('\n') if 'failed' in l.lower()]
            err_msg = err_line[0].strip() if err_line else ''
            result.update({
                'is_frp': True, 'has_auth': None,
                'detail': f'{label}: {err_msg or output[:120]}'
            })
            # 登录失败了也可能是 frps（比如需要白名单IP），走探测流程也没意义
            return result

        if output.strip():
            continue

    if auth_detected:
        result.update({
            'is_frp': True, 'has_auth': True,
            'status': 'has_auth',
            'detail': 'token 认证失败'
        })
        return result

    if not result['is_frp']:
        return {**result, 'detail': f'无法连接: {last_output[:100]}'}

    # === 第 3 步：如果无认证且启用探测，尝试注册代理看端口是否可达 ===
    if result['has_auth'] is False and enable_probe:
        probe_firewall(host, port, frpc_path, result, success_tls, success_mux)

    return result


def probe_firewall(host, port, frpc_path, result, enable_tls, enable_tcpmux):
    """
    对无认证的 frps 注册代理并探测穿透端口是否被服务端防火墙拦截
    """
    # 随机选本地监听端口和远端代理端口
    local_port = random.choice(PROBE_PORT_RANGE)
    remote_port = random.choice(PROBE_PORT_RANGE)

    # 先确保本地端口可用
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', local_port))
        s.listen(1)
        s.close()
    except OSError:
        # 端口被占，换个
        local_port = random.choice([p for p in PROBE_PORT_RANGE if p != local_port])

    # 先探测远端端口是否已被占用（如果已经开了说明没防火墙，但也可能端口冲突）
    # 跳过这一步，直接注册代理后看情况

    # 启动 frpc 后台
    proc = None
    cfg_path = None
    listener = None
    try:
        # 启动本地监听（让 frpc 能连上）
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', local_port))
        listener.listen(1)
        listener.settimeout(8)

        # 启动 frpc 后台
        proc, cfg_path = run_frpc_background(
            host, port, frpc_path, local_port, remote_port,
            enable_tls, enable_tcpmux
        )

        # 等 frpc 注册代理（等最多 3 秒）
        time.sleep(2)

        # 先检查 frpc 是否还活着
        if proc.poll() is not None:
            result['detail'] += ' | 穿透探测: ❌ frpc 启动后退出（可能是 frps 端口或认证规则限制）'
            result['firewall_blocked'] = 'error_frpc_died'
            return

        # 多等一会儿，让代理完全注册
        time.sleep(1)

        # 检查 frpc 是否还活着
        if proc.poll() is not None:
            result['detail'] += ' | 穿透探测: ❌ frpc 启动后退出'
            result['firewall_blocked'] = 'error_frpc_died'
            return

        # 检查 frpc 是否收到了 proxy 注册成功的日志（不好读因为 stdout 被丢了）
        # 直接用 socket 连远端端口
        reachable = probe_port_reachable(host, remote_port, timeout=5)

        if reachable:
            # 远端端口可达 — 服务器防火墙放行
            result['detail'] += f' | 穿透探测: ✅ 端口 {remote_port} 可达（服务端防火墙放行）'
            result['firewall_blocked'] = False
        else:
            # 远端端口不可达 — 大概率服务器防火墙拦截了随机高位端口
            # 但也可能是端口冲突/注册失败，再试一次不同的端口
            # 简化处理：直接报防火墙拦截
            result['detail'] += f' | 穿透探测: 🔥 端口 {remote_port} 不可达（服务端防火墙可能拦截了高位端口）'
            result['firewall_blocked'] = True

    except Exception as e:
        result['detail'] += f' | 穿透探测: ❌ 异常 - {e}'
        result['firewall_blocked'] = 'error'
    finally:
        # 清理：关 listener、kill frpc、删配置
        if listener:
            try:
                listener.close()
            except Exception:
                pass
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description='frp 服务器认证状态 + 穿透防火墙检测',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-t', '--target', help='单个目标 host:port')
    parser.add_argument('-l', '--list', help='目标列表文件')
    parser.add_argument('-o', '--output', help='输出 JSON 文件')
    parser.add_argument('--no-auth-only', action='store_true', help='只显示无需认证的')
    parser.add_argument('--no-probe', action='store_true', help='不进行穿透可达性探测（只测认证）')
    parser.add_argument('--threads', type=int, default=5, help='并发数 (默认5)')
    parser.add_argument('--download', action='store_true', help='下载 frpc')
    args = parser.parse_args()

    if args.download:
        download_frpc()
        return

    if not args.target and not args.list:
        parser.print_help()
        return

    if not os.path.exists(FRPC_PATH):
        print("[*] 自动下载 frpc ...")
        if not download_frpc():
            print("[!] 下载失败")
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

    print(f"[*] 目标: {len(parsed)}，并发: {args.threads}")
    if not args.no_probe:
        print("[*] 模式: 认证检测 + 穿透可达性探测")
    else:
        print("[*] 模式: 仅认证检测（跳过穿透探测）")
    print()

    results = []
    no_auth_reachable = 0    # 无认证 + 端口可达
    no_auth_blocked = 0      # 无认证 + 端口被拦
    no_auth_unknown = 0      # 无认证 + 探测失败
    has_auth = 0
    other = 0

    def print_result(r):
        nonlocal no_auth_reachable, no_auth_blocked, no_auth_unknown, has_auth, other
        tag = f"[{r['host']}:{r['port']}]"

        if r.get('has_auth') is False:
            fw = r.get('firewall_blocked')
            if fw is False:
                no_auth_reachable += 1
                print(f'  🔓✅ {tag} 无认证 + 穿透可用 - {r["detail"]}')
            elif fw is True:
                no_auth_blocked += 1
                print(f'  🔓🔥 {tag} 无认证但防火墙拦截 - {r["detail"]}')
            else:
                no_auth_unknown += 1
                print(f'  🔓❓ {tag} 无认证（穿透探测未执行） - {r["detail"]}')
        elif r.get('has_auth') is True:
            has_auth += 1
            if not args.no_auth_only:
                print(f'  🔒 {tag} 需认证 - {r["detail"]}')
        else:
            other += 1
            if not args.no_auth_only:
                print(f'  ❓ {tag} {r["detail"]}')

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        fut = {
            executor.submit(
                check_server_with_probe, h, p, FRPC_PATH, not args.no_probe
            ): (h, p)
            for h, p in parsed
        }
        for f in as_completed(fut):
            r = f.result()
            results.append(r)
            print_result(r)

    print()
    print('=' * 50)
    print(f'  总计:             {len(results)}')
    print(f'  🔓✅ 无认证+可达:  {no_auth_reachable}')
    print(f'  🔓🔥 无认证+封堵:  {no_auth_blocked}')
    print(f'  🔓❓ 无认证(未知): {no_auth_unknown}')
    print(f'  🔒    有认证:      {has_auth}')
    print(f'  ❓    未知/其他:    {other}')
    print('=' * 50)
    print()
    if no_auth_blocked > 0:
        print("💡 提示: 无认证但被防火墙拦截，可能限制了特定端口范围")
        print("   可以尝试用 --no-probe 跳过探测以加快扫描速度")
    if no_auth_reachable > 0:
        print("🎯 这些服务器无认证且穿透可用，是最高价值目标")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f'\n已保存: {args.output}')


if __name__ == '__main__':
    main()
