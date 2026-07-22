# anomaly_detection.py
import time
import json
import os
from collections import defaultdict
import config

class AnomalyDetector:
    def __init__(self):
        self.conn_count = defaultdict(list)
        self.fail_login_count = defaultdict(list)
        self.external_connections = defaultdict(list)
        self.lateral_movement = defaultdict(list)
        self.session_start = {}
        self.session_duration = defaultdict(list)
        self.last_clean_time = time.time()

        # ===== 基线学习 =====
        self.use_baseline = getattr(config, "USE_BASELINE", False)
        self.baseline_file = getattr(config, "BASELINE_FILE", "data/baseline.json")
        self.baseline = {
            "conn_rate": {},
            "bandwidth": {},
            "port_count": {},
            "learned": False
        }
        self.learning_mode = False
        self.learning_start_time = None
        self._load_baseline()

    def _load_baseline(self):
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    self.baseline.update(saved)
                    print(f"[AnomalyDetector] 已加载基线数据: {self.baseline_file}")
            except Exception as e:
                print(f"[!] 加载基线失败: {e}")

    def save_baseline(self):
        try:
            os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(self.baseline, f, indent=2, ensure_ascii=False)
            print(f"[AnomalyDetector] 基线已保存到 {self.baseline_file}")
        except Exception as e:
            print(f"[!] 保存基线失败: {e}")

    def start_learning(self, duration_sec=30):
        self.learning_mode = True
        self.learning_start_time = time.time()
        print(f"[AnomalyDetector] 开始基线学习模式，持续 {duration_sec} 秒...")

        self.baseline = {
            "conn_rate": {},
            "bandwidth": {},
            "port_count": {},
            "learned": False
        }

    def is_learning(self):
        if not self.learning_mode:
            return False
        elapsed = time.time() - self.learning_start_time
        duration = getattr(config, "BASELINE_LEARNING_TIME", 30)
        if elapsed >= duration:
            self.learning_mode = False
            self.baseline["learned"] = True
            self.save_baseline()
            print(f"[AnomalyDetector] 基线学习完成，已自动保存。")
            return False
        return True

    def _is_internal(self, ip):
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return True
        if ip.startswith('172.16.') or ip.startswith('172.17.'):
            return True
        if ip.startswith('172.18.') or ip.startswith('172.19.'):
            return True
        if ip.startswith('172.2') or ip.startswith('172.3'):
            return True
        if ip.startswith('127.'):
            return True
        return False

    def update_stats(self, src_ip, dst_ip, dst_port, payload, pkt_size=0, flags=''):
        now = time.time()

        # 基线学习模式：只记录，不告警
        if self.is_learning():
            if src_ip not in self.baseline["conn_rate"]:
                self.baseline["conn_rate"][src_ip] = []
            self.baseline["conn_rate"][src_ip].append(now)
            if src_ip not in self.baseline["port_count"]:
                self.baseline["port_count"][src_ip] = set()
            self.baseline["port_count"][src_ip].add(dst_port)
            return

        self.conn_count[src_ip].append(now)

        if payload:
            payload_lower = payload.lower()
            if b'login failed' in payload_lower or b'failed password' in payload_lower or b'authentication failure' in payload_lower:
                self.fail_login_count[src_ip].append(now)

        if not self._is_internal(dst_ip) and dst_ip not in config.WHITELIST_IPS:
            self.external_connections[src_ip].append((dst_ip, now))

        if self._is_internal(src_ip) and self._is_internal(dst_ip) and src_ip != dst_ip:
            self.lateral_movement[src_ip].append(dst_ip)

        if flags:
            session_key = (src_ip, dst_ip, dst_port)
            if 'S' in flags and 'A' not in flags:
                self.session_start[session_key] = now
            elif 'F' in flags or 'R' in flags:
                if session_key in self.session_start:
                    duration = now - self.session_start[session_key]
                    if duration > config.SESSION_DURATION_THRESHOLD:
                        self.session_duration[src_ip].append(duration)
                    del self.session_start[session_key]

        if now - self.last_clean_time > 10:
            self._clean_old_records()
            self.last_clean_time = now

    def check_anomalies(self):
        anomalies = []
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        # 端口扫描检测
        for ip, timestamps in self.conn_count.items():
            count = len([t for t in timestamps if t > cutoff])
            threshold = config.SCAN_THRESHOLD
            if self.use_baseline and self.baseline.get("learned") and ip in self.baseline.get("port_count", {}):
                baseline_ports = len(self.baseline["port_count"].get(ip, set()))
                threshold = max(threshold, baseline_ports * 2)
            if count > threshold:
                anomalies.append({
                    'src_ip': ip,
                    'dst_ip': '多个目标',
                    'type': '端口扫描',
                    'detail': f'{ip} 在 {config.STATS_WINDOW}s 内发起 {count} 次连接 (基线阈值: {threshold})'
                })

        # 暴力破解检测
        for ip, timestamps in self.fail_login_count.items():
            count = len([t for t in timestamps if t > cutoff])
            if count > config.BRUTE_FORCE_THRESHOLD:
                anomalies.append({
                    'src_ip': ip,
                    'dst_ip': '目标系统',
                    'type': '暴力破解',
                    'detail': f'{ip} 在 {config.STATS_WINDOW}s 内失败登录 {count} 次'
                })

        # 异常外联检测
        for src_ip, dst_list in self.external_connections.items():
            if dst_list:
                recent_dsts = [d for d, t in dst_list if t > cutoff]
                if recent_dsts:
                    unique_dsts = set(recent_dsts)
                    anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': list(unique_dsts)[0],
                        'type': '异常外联',
                        'detail': f'{src_ip} 外联陌生IP: {", ".join(list(unique_dsts)[:5])}'
                    })
                self.external_connections[src_ip] = []

        # 横向扩散检测
        for src_ip, dst_list in self.lateral_movement.items():
            unique_targets = set(dst_list)
            if len(unique_targets) > config.LATERAL_THRESHOLD:
                anomalies.append({
                    'src_ip': src_ip,
                    'dst_ip': '内网多个目标',
                    'type': '内网横向扩散',
                    'detail': f'{src_ip} 在内网中访问了 {len(unique_targets)} 个不同的目标IP: {", ".join(list(unique_targets)[:5])}'
                })
                self.lateral_movement[src_ip] = []

        # 会话时长异常检测
        for ip, durations in self.session_duration.items():
            for duration in durations:
                if duration > config.SESSION_DURATION_THRESHOLD:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '目标',
                        'type': '会话时长异常',
                        'detail': f'{ip} 存在会话时长 {duration/60:.1f} 分钟（超过阈值）'
                    })
            self.session_duration[ip] = []

        return anomalies

    def _clean_old_records(self):
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        for ip in list(self.conn_count.keys()):
            self.conn_count[ip] = [t for t in self.conn_count[ip] if t > cutoff]
            if not self.conn_count[ip]:
                del self.conn_count[ip]

        for ip in list(self.fail_login_count.keys()):
            self.fail_login_count[ip] = [t for t in self.fail_login_count[ip] if t > cutoff]
            if not self.fail_login_count[ip]:
                del self.fail_login_count[ip]

        for ip in list(self.external_connections.keys()):
            self.external_connections[ip] = [(d, t) for d, t in self.external_connections[ip] if t > cutoff]
            if not self.external_connections[ip]:
                del self.external_connections[ip]

        for ip in list(self.lateral_movement.keys()):
            if len(self.lateral_movement[ip]) > 100:
                self.lateral_movement[ip] = self.lateral_movement[ip][-100:]

        for key, start_time in list(self.session_start.items()):
            if now - start_time > config.SESSION_DURATION_THRESHOLD:
                del self.session_start[key]
