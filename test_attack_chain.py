#!/usr/bin/env python3
"""
攻击链测试 - 模拟完整攻击链：扫描 → 漏洞利用 → C2 → 横向扩散
"""
from scapy.all import IP, TCP, Raw, send
import time
import os
import sys


def simulate_full_chain():
    """模拟完整攻击链"""
    target = "127.0.0.1"

    print("\n" + "=" * 60)
    print("🔗 模拟完整攻击链")
    print("🔍 扫描 → 💥 漏洞利用 → 📡 C2 → 🔄 横向扩散")
    print("=" * 60)

    # ===== 阶段1: 扫描 =====
    print("\n🔍 阶段1: 端口扫描")
    ports = [21, 22, 80, 443, 3306, 3389, 8080, 22, 23, 25]
    for i, port in enumerate(ports):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
        print(f"  扫描端口 {port} ({i+1}/{len(ports)})")
    print("  ✅ 扫描完成")
    time.sleep(0.5)

    # ===== 阶段2: 漏洞利用 =====
    print("\n💥 阶段2: 漏洞利用")
    print("  - SQL注入")
    pkt = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"' OR '1'='1")
    send(pkt, verbose=False)
    time.sleep(0.3)

    print("  - XSS攻击")
    pkt = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"<script>alert(1)</script>")
    send(pkt, verbose=False)
    time.sleep(0.3)

    print("  - 命令执行")
    pkt = IP(dst=target) / TCP(dport=80, flags="PA") / Raw(load=b"cmd.exe /c whoami")
    send(pkt, verbose=False)
    print("  ✅ 漏洞利用完成")
    time.sleep(0.5)

    # ===== 阶段3: C2通信 =====
    print("\n📡 阶段3: C2通信")
    target_domain = "ngrok.io"
    fake_tls = (
        b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03"
        b"\x00\x00\x00\x00"
        b"\x00"
        b"\x00\x02\x00\x2f"
        b"\x01\x00"
        b"\x00\x8b"
        b"\x00\x00\x00\x0c\x00\x0a\x00\x00\x09" + target_domain.encode('utf-8')
    )
    pkt = IP(dst=target) / TCP(dport=443, flags="PA") / Raw(load=fake_tls)
    send(pkt, verbose=False)
    print(f"  ✅ C2建立 (SNI: {target_domain})")
    time.sleep(0.5)

    # ===== 阶段4: 横向扩散 =====
    print("\n🔄 阶段4: 横向扩散")
    internal_ips = ['192.168.1.2', '192.168.1.3', '192.168.1.4',
                    '192.168.1.5', '192.168.1.6', '192.168.1.7']
    src_ip = '192.168.1.100'
    for i, dst in enumerate(internal_ips):
        pkt = IP(src=src_ip, dst=dst) / TCP(dport=445, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
        print(f"  {src_ip} -> {dst} ({i+1}/{len(internal_ips)})")
    print("  ✅ 横向扩散完成")

    print("\n" + "=" * 60)
    print("✅ 完整攻击链模拟完成！")
    print("📊 请点击 IDS 界面的「攻击链分析」按钮查看")
    print("=" * 60)


if __name__ == "__main__":
    if sys.platform != 'win32' and os.geteuid() != 0:
        print("[!] 需要 root 权限运行!")
        print("[!] 请使用: sudo python3 test_attack_chain.py")
        sys.exit(1)
    simulate_full_chain()
