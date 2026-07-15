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

        # 带宽统计
        self.traffic_stats = {}
        self.last_check_time = time.time()
        self.bandwidth_alerted_ips = set()

        # 控制异常检查频率
        self.last_anomaly_check_time = time.time()

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

        # 带宽统计
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

        # 处理TCP
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            dst_port = tcp_layer.dport
            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
            flags = str(tcp_layer.flags)

            # 特征匹配
            if payload:
                matches = self.sig_detector.detect(payload)
                for name, pattern in matches:
                    self.alert_manager.add_alert(
                        src_ip, dst_ip, dst_port,
                        f"特征匹配: {name}",
                        f"匹配特征: {pattern[:50]}"
                    )

            # 更新异常统计
            self.anomaly_detector.update_stats(
                src_ip, dst_ip, dst_port, payload,
                pkt_size=pkt_size,
                flags=flags
            )

        # UDP处理
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

    def start(self, iface=None, filter_str="ip"): # <--- 默认过滤从 tcp 宽放到了 ip，提升异常检测覆盖率
        self.running = True
        print(f"[*] 开始抓包 (过滤: {filter_str})...")
        print(f"[*] 带宽阈值: {config.BANDWIDTH_THRESHOLD/1024/1024:.0f} MB/5秒")
        print(f"[*] 扫描阈值: {config.SCAN_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        print(f"[*] 暴力破解阈值: {config.BRUTE_FORCE_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        try:
            while self.running:
                sniff(iface=iface, filter=filter_str, prn=self.packet_callback,
                      store=0, timeout=1)
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