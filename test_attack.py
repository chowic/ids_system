# test_attack.py
from scapy.all import IP, TCP, send, Raw
import time

def test_sql_injection():
    print("[*] 测试 SQL注入...")
    payload = b"' OR '1'='1"
    pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=payload)
    send(pkt, verbose=False)
    print("[✓] SQL注入测试完成")

def test_xss():
    print("[*] 测试 XSS...")
    payload = b"<script>alert(1)</script>"
    pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=payload)
    send(pkt, verbose=False)
    print("[✓] XSS测试完成")

def test_cmd_exec():
    print("[*] 测试 命令执行...")
    payload = b"cmd.exe /c dir"
    pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=payload)
    send(pkt, verbose=False)
    print("[✓] 命令执行测试完成")

def test_bruteforce():
    print("[*] 测试 暴力破解（需要发送10次失败登录）...")
    for i in range(10):
        payload = b"Login failed for user admin"
        pkt = IP(dst="8.8.8.8") / TCP(dport=22, flags="PA") / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.05)
        print(f"  发送暴力破解包 {i+1}/10")
    print("[✓] 暴力破解测试完成（等待5秒后查看告警）")

def test_scan():
    print("[*] 测试 端口扫描（扫描30个端口）...")
    ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080, 
             1433, 1521, 5432, 6379, 27017, 9200, 11211, 25, 110, 143,
             53, 69, 123, 161, 179, 389, 514, 636, 993, 995]
    for i, port in enumerate(ports):
        pkt = IP(dst="127.0.0.1") / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
        print(f"  扫描端口 {port} ({i+1}/{len(ports)})")
    print("[✓] 端口扫描测试完成（等待5秒后查看告警）")

def test_lateral_movement():
    """测试内网横向扩散检测"""
    print("[*] 测试 内网横向扩散（访问6个不同内网IP）...")
    internal_ips = ['192.168.1.2', '192.168.1.3', '192.168.1.4', 
                    '192.168.1.5', '192.168.1.6', '192.168.1.7']
    src_ip = '192.168.1.100'
    
    for i, dst_ip in enumerate(internal_ips):
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=445, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
        print(f"  {src_ip} -> {dst_ip} ({i+1}/{len(internal_ips)})")
    print("[✓] 横向扩散测试完成（等待5秒后查看告警）")

def test_bandwidth():
    """测试带宽异常检测"""
    print("[*] 测试 带宽异常（发送大量数据）...")
    # 发送大包
    large_payload = b"A" * 1500  # 1500字节
    for i in range(100):  # 发送100个包，约150KB
        pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=large_payload)
        send(pkt, verbose=False)
        time.sleep(0.01)
        if i % 10 == 0:
            print(f"  发送大包 {i+1}/100")
    print("[✓] 带宽测试完成（等待5秒后查看告警）")

def test_external():
    """测试异常外联"""
    print("[*] 测试 异常外联...")
    pkt = IP(dst="1.2.3.4") / TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print("[✓] 异常外联测试完成")

def test_session_duration():
    """测试会话时长异常"""
    print("[*] 测试 会话时长异常（建立长会话）...")
    # 模拟一个长会话：发SYN，等待，发FIN
    src_ip = "127.0.0.1"
    dst_ip = "8.8.8.8"
    dst_port = 80
    
    # 发送SYN（会话开始）
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="S")
    send(pkt, verbose=False)
    print("  会话已建立 (SYN)")
    
    # 注意：实际检测需要等待超过阈值，这里只是演示
    # 真实场景中需要等待3600秒，演示时缩短阈值或手动模拟
    print("  注意：会话时长检测需要等待超过阈值（默认3600秒）")
    print("  演示时可临时修改 config.SESSION_DURATION_THRESHOLD = 10")
    print("[✓] 会话时长测试完成")

def test_all():
    print("\n" + "="*50)
    print("开始测试所有功能")
    print("="*50 + "\n")
    
    print("【1/7】特征匹配 - SQL注入")
    test_sql_injection()
    time.sleep(0.5)
    
    print("\n【2/7】特征匹配 - XSS")
    test_xss()
    time.sleep(0.5)
    
    print("\n【3/7】特征匹配 - 命令执行")
    test_cmd_exec()
    time.sleep(0.5)
    
    print("\n【4/7】异常行为 - 暴力破解")
    test_bruteforce()
    time.sleep(0.5)
    
    print("\n【5/7】异常行为 - 端口扫描")
    test_scan()
    time.sleep(0.5)
    
    print("\n【6/7】异常行为 - 横向扩散")
    test_lateral_movement()
    time.sleep(0.5)
    
    print("\n【7/7】异常行为 - 异常外联")
    test_external()
    time.sleep(0.5)
    
    print("\n" + "="*50)
    print("✅ 所有测试完成！")
    print("📊 请查看IDS界面的告警表格")
    print("="*50)

if __name__ == "__main__":
    print("=== 攻击检测测试工具 ===")
    print("1. 测试 SQL注入 (特征匹配)")
    print("2. 测试 端口扫描 (异常行为)")
    print("3. 测试 XSS攻击 (特征匹配)")
    print("4. 测试 暴力破解 (异常行为)")
    print("5. 测试 命令执行 (特征匹配)")
    print("6. 全部测试 (推荐)")
    print("7. 异常外联测试")
    print("8. 横向扩散测试")
    print("9. 带宽测试")
    
    choice = input("\n请选择 (1-9): ")
    
    if choice == "1":
        test_sql_injection()
    elif choice == "2":
        test_scan()
    elif choice == "3":
        test_xss()
    elif choice == "4":
        test_bruteforce()
    elif choice == "5":
        test_cmd_exec()
    elif choice == "6":
        test_all()
    elif choice == "7":
        test_external()
    elif choice == "8":
        test_lateral_movement()
    elif choice == "9":
        test_bandwidth()
    else:
        print("无效选择")
    
    print("\n请检查IDS界面是否有告警产生")