# packet_capture.py
from scapy.all import sniff, IP, TCP, UDP
from scapy.packet import Raw
import time
import config

class PacketCapture:
    def __init__(self, sig_detector, anomaly_detector, alert_manager):
        self.sig_detector = sig_detector
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.running = False
        self.packet_count = 0
        
        # ===== 带宽统计 =====
        self.traffic_stats = {}  # {ip: 累计字节数}
        self.last_check_time = time.time()
        self.bandwidth_alerted_ips = set()  # 避免重复告警

    def packet_callback(self, pkt):
        if not self.running:
            return
        
        self.packet_count += 1
        
        if not pkt.haslayer(IP):
            return
        
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        pkt_size = len(pkt)
        
        self.traffic_stats[src_ip] = self.traffic_stats.get(src_ip, 0) + pkt_size
        self.traffic_stats[dst_ip] = self.traffic_stats.get(dst_ip, 0) + pkt_size
        
        self.alert_manager.record_traffic(pkt_size, 1)
        
        # 每5秒检查一次带宽异常
        now = time.time()
        if now - self.last_check_time >= 5:
            self.check_bandwidth_anomaly()
            self.last_check_time = now
            # 重置统计，保持最近5秒的数据
            self.traffic_stats = {}
        
        # 处理TCP
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            dst_port = tcp_layer.dport
            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
            flags = str(tcp_layer.flags)
            
            # ===== 特征匹配检测 =====
            if payload and len(payload) > 0:
                matches = self.sig_detector.detect(payload)
                for name, pattern in matches:
                    self.alert_manager.add_alert(
                        src_ip, dst_ip, dst_port,
                        f"特征匹配: {name}",
                        f"匹配特征: {pattern[:50]}"
                    )
            
            # ===== 异常行为检测（传入包大小和flags） =====
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
        
        # 处理UDP
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            dst_port = udp_layer.dport
            payload = bytes(udp_layer.payload) if udp_layer.payload else b''
            
            # UDP也做异常检测（不传flags）
            self.anomaly_detector.update_stats(
                src_ip, dst_ip, dst_port, payload,
                pkt_size=pkt_size,
                flags=''
            )
            anomalies = self.anomaly_detector.check_anomalies()
            for ano in anomalies:
                self.alert_manager.add_alert(
                    ano['src_ip'], ano['dst_ip'], 0,
                    f"异常行为: {ano['type']}",
                    ano['detail']
                )

    def check_bandwidth_anomaly(self):
        """检查带宽异常"""
        for ip, bytes_count in self.traffic_stats.items():
            if bytes_count > config.BANDWIDTH_THRESHOLD:
                # 避免对同一个IP重复告警
                alert_key = f"{ip}_{int(time.time()/60)}"  # 每分钟最多告警一次
                if alert_key in self.bandwidth_alerted_ips:
                    continue
                self.bandwidth_alerted_ips.add(alert_key)
                
                self.alert_manager.add_alert(
                    ip,
                    '网络',
                    0,
                    '异常行为: 带宽异常',
                    f'{ip} 在5秒内传输 {bytes_count/1024/1024:.2f} MB 数据（超过阈值 {config.BANDWIDTH_THRESHOLD/1024/1024:.0f}MB）'
                )
                print(f"[带宽告警] {ip} 在5秒内传输 {bytes_count/1024/1024:.2f} MB")
                
                # 限制集合大小，防止无限增长
                if len(self.bandwidth_alerted_ips) > 1000:
                    self.bandwidth_alerted_ips = set()

    def start(self, iface=None, filter_str="tcp"):
        self.running = True
        print(f"[*] 开始抓包 (过滤: {filter_str})...")
        print(f"[*] 带宽阈值: {config.BANDWIDTH_THRESHOLD/1024/1024:.0f} MB/5秒")
        print(f"[*] 扫描阈值: {config.SCAN_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        print(f"[*] 暴力破解阈值: {config.BRUTE_FORCE_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        try:
            sniff(iface=iface, filter=filter_str, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            print("[*] 用户中断抓包")
        except Exception as e:
            print(f"[!] 抓包错误: {e}")
        finally:
            self.running = False
            print(f"[*] 抓包停止，共处理 {self.packet_count} 个数据包")

    def stop(self):
        self.running = False
        print("[*] 正在停止抓包...")