# test_attack.py
from scapy.all import IP, TCP, send, Raw
import time
import config   # 导入配置，便于在测试中临时调整参数（若需要）

# 学习期等待时间（比 config.BASELINE_LEARNING_TIME 多几秒）
LEARNING_WAIT = config.BASELINE_LEARNING_TIME + 5

def wait_for_learning():
    """等待学习期结束（确保异常检测开始工作）"""
    print(f"[*] 等待 {LEARNING_WAIT} 秒，确保学习期完成...")
    time.sleep(LEARNING_WAIT)
    print("[*] 学习期已结束，开始测试...")

# ==================== 特征匹配测试（直接触发，不受阈值影响） ====================
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

# ==================== 异常行为测试（需超过阈值） ====================

def test_bruteforce():
    """发送 12 次失败登录（超过 BRUTE_FORCE_THRESHOLD 默认 10）"""
    print("[*] 测试 暴力破解（发送12次失败登录）...")
    for i in range(12):
        payload = b"Login failed for user admin"
        pkt = IP(dst="8.8.8.8") / TCP(dport=22, flags="PA") / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.05)
        print(f"  发送暴力破解包 {i+1}/12")
    print("[✓] 暴力破解测试完成（请等待10秒查看告警）")

def test_scan():
    """扫描 55 个端口（超过 SCAN_THRESHOLD 默认 50）"""
    print("[*] 测试 端口扫描（扫描55个端口）...")
    ports = list(range(1, 56))  # 1~55，共55个
    for i, port in enumerate(ports):
        pkt = IP(dst="127.0.0.1") / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
        if (i+1) % 10 == 0:
            print(f"  已扫描 {i+1} 个端口")
    print("[✓] 端口扫描测试完成（请等待10秒查看告警）")

def test_lateral_movement():
    """访问 11 个不同内网 IP（超过 LATERAL_THRESHOLD 默认 10）"""
    print("[*] 测试 内网横向扩散（访问11个不同内网IP）...")
    internal_ips = [f"192.168.1.{i}" for i in range(2, 13)]  # 2~12，共11个
    src_ip = '192.168.1.100'
    
    for i, dst_ip in enumerate(internal_ips):
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=445, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
        if (i+1) % 5 == 0:
            print(f"  {src_ip} -> {dst_ip} ({i+1}/{len(internal_ips)})")
    print("[✓] 横向扩散测试完成（请等待10秒查看告警）")

def test_external():
    """访问 18 个不同外网 IP（确保超过新阈值）"""
    print("[*] 测试 异常外联...")
    # 将 range(4, 10) 改为 range(4, 22)，共 18 个
    dst_ips = [f"1.2.3.{i}" for i in range(4, 22)]  
    for i, dst in enumerate(dst_ips):
        pkt = IP(dst=dst) / TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
        print(f"  外联 {dst} ({i+1}/18)")
    print("[✓] 异常外联测试完成（请等待10秒查看告警）")

def test_bandwidth():
    """发送大包测试带宽异常（加入微小延时防止网卡丢包，并增加总量）"""
    print("[*] 测试 带宽异常...")
    large_payload = b"A" * 1450  # 约符合标准的 MTU 大小
    total_packets = 15000        # 增加发包总量，确保稳过阈值
    
    for i in range(total_packets):
        pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="PA") / Raw(load=large_payload)
        send(pkt, verbose=False)
        
        # 每发一个包，强制让 CPU 歇 1 毫秒。这能彻底解决操作系统和网卡的严重丢包现象！
        time.sleep(0.001) 
        
        if (i+1) % 2000 == 0:
            print(f"  已发送大包 {i+1}/{total_packets}")
            
    print("[✓] 带宽测试包发送完毕（请等待 5 秒查看系统告警）")

def test_session_duration():
    """
    会话时长异常测试（演示用）
    由于需要等待超过 SESSION_DURATION_THRESHOLD（默认3600秒），
    实际测试无法快速触发。可临时修改 config 中的阈值（如设为10秒）后运行。
    """
    print("[*] 测试 会话时长异常（需要修改阈值才能快速触发）...")
    print("   提示：请将 config.SESSION_DURATION_THRESHOLD 临时改为 10")
    print("   然后发送 SYN 包，等待10秒以上发送 FIN 包。")
    print("   当前阈值较大，本函数仅演示建立会话，不等待长时。")
    # 演示建立会话
    pkt = IP(src="127.0.0.1", dst="8.8.8.8") / TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print("   已发送 SYN，会话开始。如需测试，请按提示操作。")
    # 为了不阻塞，这里不等待，直接返回
    print("[✓] 会话时长测试演示完成（实际触发需降低阈值）")

# ==================== 整合测试 ====================

def test_all():
    print("\n" + "="*50)
    print("开始测试所有功能（学习期结束后）")
    print("="*50 + "\n")

    # 等待学习期结束
    wait_for_learning()

    print("【1/8】特征匹配 - SQL注入")
    test_sql_injection()
    time.sleep(0.5)
    
    print("\n【2/8】特征匹配 - XSS")
    test_xss()
    time.sleep(0.5)
    
    print("\n【3/8】特征匹配 - 命令执行")
    test_cmd_exec()
    time.sleep(0.5)
    
    print("\n【4/8】异常行为 - 暴力破解")
    test_bruteforce()
    time.sleep(2)  # 等待检查周期
    
    print("\n【5/8】异常行为 - 端口扫描")
    test_scan()
    time.sleep(2)
    
    print("\n【6/8】异常行为 - 横向扩散")
    test_lateral_movement()
    time.sleep(2)
    
    print("\n【7/8】异常行为 - 异常外联")
    test_external()
    time.sleep(2)
    
    print("\n【8/8】异常行为 - 带宽异常")
    test_bandwidth()
    time.sleep(5)
    
    print("\n" + "="*50)
    print("✅ 所有测试完成！")
    print("📊 请查看 IDS 界面的告警表格，应已产生相应告警。")
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
    print("0. 全部测试 (推荐)")

    choice = input("\n请选择 (0-9): ")

    # 如果选择单个测试，也需等待学习期结束（除特征匹配外，但统一处理）
    if choice != '9':  # 会话时长特殊处理
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
    elif choice == "0":
        test_all()
    else:
        print("无效选择")

    print("\n请检查 IDS 界面是否有相应告警产生。")