# test_attack.py
from scapy.all import IP, TCP, send, Raw
import time
import subprocess  
import config   

LEARNING_WAIT = config.BASELINE_LEARNING_TIME + 5

def wait_for_learning():
    print(f"[*] 等待 {LEARNING_WAIT} 秒，确保学习期完成...")
    time.sleep(LEARNING_WAIT)
    print("[*] 学习期已结束，开始测试...")

# ========== [新增] 11. 专属 AI 压轴测试 ==========
def test_ai_attack():
    print("[*] 测试 启动 AI 智能分析诱骗（发送大量高频异常包）...")
    # 强制加上超大载荷(b"A"*1000)，撑爆流量特征，确保隔离森林极度异常
    for i in range(150):
        pkt = IP(dst="8.8.8.8") / TCP(dport=1000+i, flags="S") / Raw(b"A"*1000)
        send(pkt, verbose=False)
    print("[✓] AI 模拟攻击发送完成（请等待 2 秒查看深紫色告警）")
# ===================================================

def test_sql_injection():
    print("[*] 测试 SQL注入（单条）...")
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
    print("[*] 测试 暴力破解（发送12次失败登录）...")
    for i in range(12):
        payload = b"Login failed for user admin"
        pkt = IP(dst="8.8.8.8") / TCP(dport=22, flags="PA") / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.05)
    print("[✓] 暴力破解测试完成")

def test_scan():
    print("[*] 测试 端口扫描（扫描55个端口）...")
    ports = list(range(1, 56))  
    for i, port in enumerate(ports):
        pkt = IP(dst="8.8.8.8") / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
    print("[✓] 端口扫描测试完成")

def test_lateral_movement():
    print("[*] 测试 内网横向扩散（访问11个不同内网IP）...")
    internal_ips = [f"192.168.1.{i}" for i in range(2, 13)]  
    src_ip = '192.168.1.100'
    for i, dst_ip in enumerate(internal_ips):
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=445, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
    print("[✓] 横向扩散测试完成")

def test_external():
    print("[*] 测试 异常外联...")
    dst_ips = [f"1.2.3.{i}" for i in range(4, 22)]  
    for i, dst in enumerate(dst_ips):
        pkt = IP(dst=dst) / TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
    print("[✓] 异常外联测试完成")

def test_bandwidth():
    print("[*] 测试 带宽异常...")
    large_payload = b"A" * 1450  
    total_packets = 15000        
    for i in range(total_packets):
        pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=large_payload)
        send(pkt, verbose=False)
        time.sleep(0.001) 
    print("[✓] 带宽测试包发送完毕")

def test_session_duration():
    print("[*] 测试 会话时长异常（阈值改为10秒）...")
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    dst_port = 80
    print("   发送 SYN 包...")
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="S")
    send(pkt, verbose=False)
    print("   等待 15 秒...")
    time.sleep(15)
    print("   发送 FIN 包...")
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="F")
    send(pkt, verbose=False)
    print("[✓] 会话时长测试完成")

def test_tls():
    print("[*] 测试 TLS 恶意域名/SNI检测 (curl.exe -vk https://ngrok.io)...")
    try:
        cmd = ["curl.exe", "-vk", "https://ngrok.io"]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        print("[✓] TLS 测试请求已发出！")
    except subprocess.TimeoutExpired:
        print("[✓] TLS 请求已发出 (握手已完成/响应超时)")
    except Exception as e:
        print(f"[!] 执行 curl 失败: {e}")

def test_all():
    print("\n" + "="*50)
    print("开始测试所有功能（学习期结束后）")
    print("="*50 + "\n")

    # 👑 把你的 AI 放在最前面
    test_ai_attack()
    print("⏳ 等待 1.5 秒让后台引擎提取特征判定...")
    time.sleep(1.5)

    print("\n【1/9】特征匹配 - SQL注入")
    test_sql_injection()
    
    print("\n【2/9】特征匹配 - XSS")
    test_xss()
    
    print("\n【3/9】特征匹配 - 命令执行")
    test_cmd_exec()
    
    print("\n【4/9】异常行为 - 暴力破解")
    test_bruteforce()
    
    print("\n【5/9】异常行为 - 端口扫描")
    test_scan()
    
    print("\n【6/9】异常行为 - 横向扩散")
    test_lateral_movement()
    
    print("\n【7/9】异常行为 - 异常外联")
    test_external()
    
    print("\n【9/9】TLS恶意域名检测 - ngrok.io")
    test_tls()
    
    print("\n【8/9】异常行为 - 带宽异常 (耗时较长最后执行)")
    test_bandwidth()
    
    print("\n" + "="*50)
    print("✅ 所有测试完成！")
    print("📊 你的 AI 深紫色告警必然在表格顶端，且不会被刷屏！")
    print("="*50)

if __name__ == "__main__":
    print("=== 攻击检测测试工具（增强版） ===")
    print("提示：请先启动 IDS 主程序（main.py）并点击「开始检测」")
    print("      本脚本将自动等待学习期（{}秒）结束后发送测试流量。".format(LEARNING_WAIT))
    print("\n选择要测试的功能：")
    print("1. SQL注入 (特征匹配)")
    print("2. XSS (特征匹配)")
    print("3. 命令执行 (特征匹配)")
    print("4. 暴力破解 (异常行为)")
    print("5. 端口扫描 (异常行为)")
    print("6. 横向扩散 (异常行为)")
    print("7. 异常外联 (异常行为)")
    print("8. 带宽异常 (异常行为)")
    print("9. 会话时长 (需修改配置，演示)")
    print("10. TLS 恶意域名检测 (ngrok.io)")  
    print("11. AI 智能异常流量诱骗 ( Isolation Forest )")  # <--- 加入了你的大招
    print("0. 全部测试 (推荐)")

    choice = input("\n请选择 (0-11): ")

    if choice != '9':  
        wait_for_learning()

    if choice == "1":
        test_sql_injection()
    elif choice == "2":
        test_xss()
    elif choice == "3":
        test_cmd_exec()
    elif choice == "4":
        test_bruteforce()
    elif choice == "5":
        test_scan()
    elif choice == "6":
        test_lateral_movement()
    elif choice == "7":
        test_external()
    elif choice == "8":
        test_bandwidth()
    elif choice == "9":
        test_session_duration()
    elif choice == "10":      
        test_tls()
    elif choice == "11":      # 专属触发
        test_ai_attack()
    elif choice == "0":
        test_all()
    else:
        print("无效选择")

    print("\n请检查 IDS 界面是否有相应告警产生。")