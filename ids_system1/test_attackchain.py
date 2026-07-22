#!/usr/bin/env python3
"""
test_attack_chain.py - 模拟完整攻击链的自动化测试脚本
阶段演进：端口扫描 -> 漏洞利用/Web攻击 -> TLS/C2通信 -> 内网横向扩散
"""
from scapy.all import IP, TCP, Raw, send
import time
import os
import sys
import subprocess


def simulate_full_chain():
    target = "127.0.0.1"

    print("\n" + "=" * 60)
    print("开始模拟完整攻击链流量...")
    print("演进路径: 扫描  -> 漏洞利用 -> C2通信 -> 横向扩散")
    print("=" * 60)

    # 阶段 1: 侦察与端口扫描
    print("\n[阶段 1/4] 端口扫描侦察...")
    ports = [21, 22, 80, 443, 3306, 3389, 8080, 22, 23, 25]
    for i, port in enumerate(ports):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
        print(f"  -> 扫描端口 {port} ({i+1}/{len(ports)})")
    print("  阶段 1 完成 (已触发端口扫描告警)")
    time.sleep(1)

    # 阶段 2: 漏洞利用
    print("\n[阶段 2/4] Web漏洞攻击尝试...")

    print("  -> 发送 SQL注入 载荷...")
    pkt_sql = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"' OR '1'='1")
    send(pkt_sql, verbose=False)
    time.sleep(0.3)

    print("  -> 发送 XSS 载荷...")
    pkt_xss = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"<script>alert(1)</script>")
    send(pkt_xss, verbose=False)
    time.sleep(0.3)

    print("  -> 发送 命令执行 载荷...")
    pkt_cmd = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"cmd.exe /c whoami")
    send(pkt_cmd, verbose=False)
    print("  阶段 2 完成 (已触发 SQL/XSS/命令执行告警)")
    time.sleep(1)

    # 阶段 3: C2 控制通信
    print("\n[阶段 3/4] 建立 C2 隐蔽隧道 / TLS 异常通信...")
    target_domain = "ngrok.io"

    fake_tls = (
        b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03"
        b"\x00\x00\x00\x00\x00\x00\x02\x00\x2f\x01\x00\x00\x8b"
        b"\x00\x00\x00\x0c\x00\x0a\x00\x00\x09" + target_domain.encode('utf-8')
    )
    pkt_tls = IP(dst=target) / TCP(dport=443, flags="PA") / Raw(load=fake_tls)
    send(pkt_tls, verbose=False)

    try:
        subprocess.run(["curl.exe", "-vk", f"https://{target_domain}"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
    except Exception:
        pass

    print(f"  阶段 3 完成 (已触发 TLS 异常/C2 通信告警: {target_domain})")
    time.sleep(1)

    # 阶段 4: 内网横向扩散
    print("\n[阶段 4/4] 内网横向扩散与渗透...")
    internal_ips = ['192.168.1.2', '192.168.1.3', '192.168.1.4',
                    '192.168.1.5', '192.168.1.6', '192.168.1.7']
    src_ip = '192.168.1.100'

    for i, dst in enumerate(internal_ips):
        pkt_lateral = IP(src=src_ip, dst=dst) / TCP(dport=445, flags="S")
        send(pkt_lateral, verbose=False)
        time.sleep(0.05)
        print(f"  -> 横向探测 {src_ip} -> {dst}:445 ({i+1}/{len(internal_ips)})")
    print("  阶段 4 完成 (已触发横向扩散告警)")

    print("\n" + "=" * 60)
    print("攻击链模拟流量全部发送完毕！")
    print("请在 IDS GUI 界面点击工具栏上的【攻击链】按钮查看结果。")
    print("=" * 60)


if __name__ == "__main__":
    if sys.platform != 'win32' and os.geteuid() != 0:
        print("[!] 提示: 发包工具需要 root/管理员 权限！")
        print("[!] 请使用: sudo python3 test_attack_chain.py")
        sys.exit(1)

    simulate_full_chain()
