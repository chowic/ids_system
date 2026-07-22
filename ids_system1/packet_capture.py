# packet_capture.py
from scapy.all import sniff, IP, TCP, UDP, get_if_list
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

        self.traffic_stats = {}
        self.last_check_time = time.time()
        self.bandwidth_alerted_ips = set()

        # ===== 学习期保护 =====
        self.is_learning_mode = False
        self.learning_start_time = None
        self.learning_duration = getattr(config, "BASELINE_LEARNING_TIME", 30)

        # ===== TLS 检测器 =====
        try:
            from tls_detector import TLSDetector
            self.tls_detector = TLSDetector(alert_manager)
            self.tls_enabled = True
        except Exception as e:
            print(f"[!] TLS检测器加载失败: {e}")
            self.tls_detector = None
            self.tls_enabled = False

        # ===== AI 检测器 =====
        try:
            from ai_detector import AIDetector
            self.ai_detector = AIDetector()
            self.ai_enabled = True
        except Exception as e:
            print(f"[!] AI检测器加载失败: {e}")
            self.ai_detector = None
            self.ai_enabled = False

        # AI 统计缓冲
        self.ai_stats_buffer = {}

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

        # 学习期保护：只统计，不告警
        if self.is_learning_mode:
            elapsed = time.time() - self.learning_start_time
            if elapsed < self.learning_duration:
                return
            else:
                self.is_learning_mode = False
                print(f"[*] 学习期结束，开始正式检测")

        # 每5秒检查一次带宽异常
        now = time.time()
        if now - self.last_check_time >= 5:
            self.check_bandwidth_anomaly()
            self.last_check_time = now
            self.traffic_stats = {}

        dst_port = 0
        payload = b''
        flags = ''

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

            # ===== TLS 恶意检测 (端口 443 或 TLS payload) =====
            if self.tls_enabled and self.tls_detector:
                is_tls, alert_info = self.tls_detector.detect(pkt, src_ip, dst_ip, dst_port)
                if is_tls and alert_info:
                    self.alert_manager.add_alert(
                        alert_info['src_ip'],
                        alert_info['dst_ip'],
                        dst_port,
                        alert_info['type'],
                        alert_info['detail']
                    )

            # ===== 异常行为检测 =====
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

            # ===== AI 智能检测 =====
            if self.ai_enabled and self.ai_detector:
                self._update_ai_stats(src_ip, dst_port, pkt_size)

        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            dst_port = udp_layer.dport
            payload = bytes(udp_layer.payload) if udp_layer.payload else b''

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

            if self.ai_enabled and self.ai_detector:
                self._update_ai_stats(src_ip, dst_port, pkt_size)

    def _update_ai_stats(self, src_ip, dst_port, pkt_size):
        if src_ip not in self.ai_stats_buffer:
            self.ai_stats_buffer[src_ip] = {
                'ports': set(),
                'sizes': [],
                'sessions': 0,
                'count': 0
            }
        buf = self.ai_stats_buffer[src_ip]
        buf['ports'].add(dst_port)
        buf['sizes'].append(pkt_size)
        buf['count'] += 1

        if buf['count'] >= 50:
            avg_size = sum(buf['sizes']) / len(buf['sizes'])
            result = self.ai_detector.detect_anomaly(
                connections=buf['count'],
                ports=len(buf['ports']),
                pkt_size=int(avg_size),
                avg_traffic=avg_size,
                sessions=buf['sessions']
            )
            if result == "Anomaly":
                self.alert_manager.add_alert(
                    src_ip, '多个目标', 0,
                    'AI智能分析异常',
                    f'AI引擎检测到 {src_ip} 的流量特征异常 (端口数:{len(buf["ports"])}, 连接数:{buf["count"]})'
                )
            self.ai_stats_buffer[src_ip] = {
                'ports': set(),
                'sizes': [],
                'sessions': 0,
                'count': 0
            }

    def check_bandwidth_anomaly(self):
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
                    f'{ip} 在5秒内传输 {bytes_count/1024/1024:.2f} MB 数据（超过阈值 {config.BANDWIDTH_THRESHOLD/1024/1024:.0f}MB）'
                )
                print(f"[带宽告警] {ip} 在5秒内传输 {bytes_count/1024/1024:.2f} MB")

                if len(self.bandwidth_alerted_ips) > 1000:
                    self.bandwidth_alerted_ips = set()

    @staticmethod
    def _auto_select_interface():
        try:
            interfaces = get_if_list()
            for iface in interfaces:
                if iface.lower().startswith('wi-fi') or iface.lower().startswith('wlan'):
                    print(f"[*] 自动选择无线网卡: {iface}")
                    return iface
                if iface.lower().startswith('以太网') or iface.lower().startswith('ethernet'):
                    print(f"[*] 自动选择以太网卡: {iface}")
                    return iface
                if 'eth' in iface.lower() and 'lo' not in iface.lower():
                    print(f"[*] 自动选择网卡: {iface}")
                    return iface
            if interfaces:
                default = interfaces[0]
                print(f"[*] 自动选择默认网卡: {default}")
                return default
        except Exception:
            pass
        return None

    def start(self, iface=None, filter_str="tcp or udp"):
        self.running = True
        selected_iface = iface if iface else self._auto_select_interface()

        print(f"[*] 开始抓包 (网卡: {selected_iface or '默认'}, 过滤: {filter_str})...")
        print(f"[*] 带宽阈值: {config.BANDWIDTH_THRESHOLD/1024/1024:.0f} MB/5秒")
        print(f"[*] 扫描阈值: {config.SCAN_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        print(f"[*] 暴力破解阈值: {config.BRUTE_FORCE_THRESHOLD} 次/{config.STATS_WINDOW}秒")
        print(f"[*] TLS检测: {'已启用' if self.tls_enabled else '未启用'}")
        print(f"[*] AI检测: {'已启用' if self.ai_enabled else '未启用'}")

        try:
            sniff(iface=selected_iface, filter=filter_str, prn=self.packet_callback, store=0)
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

    def start_learning(self):
        self.is_learning_mode = True
        self.learning_start_time = time.time()
        print(f"[*] 进入学习期，持续 {self.learning_duration} 秒（不告警）...")
