#!/usr/bin/env python3
import os
import sys
from scapy.all import IP, TCP, Raw, send

def send_tls_test():
    print("[*] 发送 TLS ClientHello 到本地 127.0.0.1:443...")
    
    target_domain = "ngrok.io"
    
    # 构造完整的 TLS ClientHello
    # TLS 记录头: 类型(0x16) | 版本(0x0303) | 长度
    # 握手: 类型(0x01) | 长度 | 版本 | 随机数 | session_id | 密码套件 | 压缩 | 扩展
    
    # 计算各部分的长度
    domain_bytes = target_domain.encode('utf-8')
    domain_len = len(domain_bytes)
    
    # SNI 扩展: 类型(0x0000) | 长度 | ServerNameList(类型+长度+域名)
    sni_extension = b"\x00\x00"  # server_name 扩展类型
    sni_extension += (domain_len + 5).to_bytes(2, 'big')  # 扩展长度
    sni_extension += (domain_len + 3).to_bytes(2, 'big')  # ServerNameList 长度
    sni_extension += b"\x00"  # name_type = host_name
    sni_extension += domain_len.to_bytes(2, 'big')  # name_len
    sni_extension += domain_bytes  # 域名
    
    # 构建 ClientHello
    client_hello = b"\x01\x00\x00\xb6\x03\x03"  # 握手类型 + 长度 + TLS 版本
    client_hello += b"\x00" * 32  # 随机数 (32字节)
    client_hello += b"\x00"  # Session ID 长度
    client_hello += b"\x00\x02\x00\x2f"  # 密码套件 (只包含一个)
    client_hello += b"\x01\x00"  # 压缩方法
    client_hello += (len(sni_extension)).to_bytes(2, 'big')  # 扩展总长度
    client_hello += sni_extension  # SNI 扩展
    
    # TLS 记录头
    tls_record = b"\x16\x03\x03"  # 类型 + 版本
    tls_record += len(client_hello).to_bytes(2, 'big')  # 记录长度
    tls_record += client_hello
    
    print(f"[*] 包长度: {len(tls_record)} 字节")
    print(f"[*] SNI: {target_domain}")
    print(f"[*] 前20字节: {tls_record[:20].hex()}")
    
    # 发送数据包
    pkt = IP(dst="127.0.0.1") / TCP(dport=443, flags="PA") / Raw(load=tls_record)
    print("[*] 发送数据包...")
    send(pkt, verbose=True)
    print("[✓] TLS 测试包发送完成！")
    print("[*] 请检查 IDS 界面是否有 TLS 告警")

if __name__ == "__main__":
    if sys.platform != 'win32':
        try:
            if os.geteuid() != 0:
                print("[!] 需要 root 权限运行!")
                print("[!] 请使用: sudo python3 tls_test.py")
                sys.exit(1)
        except:
            pass
    
    send_tls_test()
