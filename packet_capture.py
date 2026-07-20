# packet_capture.py
import sys
import time
import config
from tls_detector import TLSDetector
# packet_capture.py 顶部
from scapy.all import sniff, IP, IPv6, TCP, UDP, conf
from scapy.packet import Raw

class PacketCapture:
    def __init__(self, sig_detector, anomaly_detector, alert_manager):
        self.sig_detector = sig_detector
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.running = False
        self.packet_count = 0

        self.tls_detector = TLSDetector(alert_manager)
        self.traffic_stats = {}
        self.last_check_time = time.time()
        self.bandwidth_alerted_ips = set()
        # 控制异常检查频率
        self.last_anomaly_check_time = time.time()

    def packet_callback(self, pkt):
        if not self.running:
            return

        self.packet_count += 1

        # 兼容 IPv4 和 IPv6 两种数据包
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

     # 提取源 IP 和目的 IP
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        else:
            ip_layer = pkt[IPv6]
            
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_size = len(pkt)

        self.traffic_stats[src_ip] = self.traffic_stats.get(src_ip, 0) + pkt_size
        self.traffic_stats[dst_ip] = self.traffic_stats.get(dst_ip, 0) + pkt_size

        now = time.time()
        # ==================== 【核心修改：学习期彻底闭嘴保护】 ====================
        # 如果检测引擎当前处于学习期，我们只更新异常指标的统计，然后直接拦截，不走任何告警逻辑！
        if hasattr(self.anomaly_detector, 'learning') and self.anomaly_detector.learning:
            # 依然需要记录 TCP/UDP 的状态用于计算基线
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
                flags = str(tcp_layer.flags)
                self.anomaly_detector.update_stats(src_ip, dst_ip, tcp_layer.dport, payload, pkt_size=pkt_size, flags=flags)
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                payload = bytes(udp_layer.payload) if udp_layer.payload else b''
                self.anomaly_detector.update_stats(src_ip, dst_ip, udp_layer.dport, payload, pkt_size=pkt_size, flags='')
            
            # 定时触发学习期的数据采样收集（原版 10 秒调用一次，配合前述可调整为 3 秒）
            if now - self.last_anomaly_check_time >= 3: 
                self.anomaly_detector.check_anomalies()
                self.last_anomaly_check_time = now
            return  # <--- 关键：学习期在此直接拦截返回，后续的特征匹配和带宽告警全部不会被执行！
        # =========================================================================

        # 每5秒检查带宽 (学习期结束后的正常检测模式)
        if now - self.last_check_time >= 5:
            self.check_bandwidth_anomaly()
            self.last_check_time = now
            self.traffic_stats = {}

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            dst_port = tcp_layer.dport
            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
            flags = str(tcp_layer.flags)

            # 1. TLS 恶意检测
            is_malicious, alert_info = self.tls_detector.detect(pkt, src_ip, dst_ip, dst_port)
            if is_malicious and alert_info:
                print(f"[🚨 TLS 告警触发] {alert_info['type']} -> {alert_info['detail']}")
                self.alert_manager.add_alert(
                    alert_info['src_ip'],
                    alert_info['dst_ip'],
                    alert_info['dst_port'],
                    alert_info['type'],
                    alert_info['detail']
                )

            # 2. 端口扫描与暴力破解检测
            anomalies = self.anomaly_detector.detect_scan_and_brute(src_ip, dst_ip, dst_port, flags)
            for anomaly_type, detail in anomalies:
                self.alert_manager.add_alert(src_ip, dst_ip, dst_port, anomaly_type, detail)

            # 3. 签名特征检测
            if payload and len(payload) > 0:
                matches = self.sig_detector.detect(payload)
                for name, pattern in matches:
                    self.alert_manager.add_alert(
                        src_ip, dst_ip, dst_port,
                        f"特征匹配: {name}",
                        f"匹配特征: {pattern[:50]}"
                    )

            # 4. 统计更新与其它异常检测
            self.anomaly_detector.update_stats(
                src_ip, dst_ip, dst_port, payload,
                pkt_size=pkt_size,
                flags=flags
            )
            anomalies = self.anomaly_detector.check_anomalies()
            for ano in anomalies:
                self.alert_manager.add_alert(
                    ano['src_ip'], ano['dst_ip'], 0,
                    f"异常行为: {ano['type']}",
                    ano['detail']
                )

        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            dst_port = udp_layer.dport
            payload = bytes(udp_layer.payload) if udp_layer.payload else b''

            self.anomaly_detector.update_stats(
                src_ip, dst_ip, dst_port, payload,
                pkt_size=pkt_size,
                flags=''
            )
        # 每3秒进行一次异常检查（无论TCP/UDP，配合采样频率优化）
        if now - self.last_anomaly_check_time >= 3:
            
            anomalies = self.anomaly_detector.check_anomalies()
            for ano in anomalies:
                self.alert_manager.add_alert(
                    ano['src_ip'], ano['dst_ip'], 0,
                    f"异常行为: {ano['type']}",
                    ano['detail']
                )
            self.last_anomaly_check_time = now
    def check_bandwidth_anomaly(self):
        """带宽异常检测"""
        for ip, bytes_count in self.traffic_stats.items():
            if bytes_count > config.BANDWIDTH_THRESHOLD:
                alert_key = f"{ip}_{int(time.time()/60)}"
                if alert_key in self.bandwidth_alerted_ips:
                    continue
                self.bandwidth_alerted_ips.add(alert_key)

                self.alert_manager.add_alert(
                    ip,
                    '网络',
                    0,
                    '异常行为: 带宽异常',
                    f'{ip} 在5秒内传输数据超过阈值'
                )

                if len(self.bandwidth_alerted_ips) > 1000:
                    self.bandwidth_alerted_ips = set()

    # packet_capture.py 中的 start 方法替换如下：

    def start(self, iface=None, filter_str=""):
        """全平台兼容且自动识别真实网卡的抓包逻辑"""
        self.running = True
        
        selected_iface = iface

        # 如果是 Windows，自动寻找有真实 IPv4 地址的活跃网卡（避开 VMware/Loopback）
        if sys.platform == "win32" and (selected_iface is None or selected_iface == "lo"):
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                
                # 优先挑选含有真实 IP 且不是 VMware/Loopback 的网卡
                for iface_info in interfaces:
                    name = iface_info.get('name', '')
                    description = iface_info.get('description', '')
                    ips = iface_info.get('ips', [])
                    
                    # 避开 VMware 和 127.0.0.1
                    if 'VMware' not in description and 'Loopback' not in description:
                        # 查找包含类似 10.x.x.x 或 192.168.x.x 的局域网 IP 网卡
                        for ip in ips:
                            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
                                selected_iface = iface_info.get('win_name')
                                print(f"[*] 自动锁定真实活动网卡: {description} (IP: {ip})")
                                break
                    if selected_iface and selected_iface != "lo":
                        break
            except Exception as e:
                print(f"[!] 网卡筛选警告: {e}")

        # 兜底处理
        if selected_iface is None or selected_iface == "lo":
            selected_iface = conf.iface

        print(f"[*] 开始抓包 (接口: {selected_iface}, 系统: {sys.platform})...")
        
        try:
            sniff(iface=selected_iface, filter=filter_str, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            print("[*] 用户中断抓包")
        except Exception as e:
            print(f"[!] 抓包错误: {e}")
            print("[!] 提示: 请确保以“管理员身份”运行 PowerShell/CMD！")
        finally:
            self.running = False
            print(f"[*] 抓包停止，共处理 {self.packet_count} 个数据包")

    def stop(self):
        self.running = False
        print("[*] 正在停止抓包...")