# anomaly_detection.py
import time
from collections import defaultdict
import config
import json
import os

class AnomalyDetector:
    def __init__(self):
        # 原始统计（用于实时计数）
        self.conn_count = defaultdict(list)           # {src_ip: [(dst_port, timestamp), ...]}
        self.fail_login_count = defaultdict(list)     # {src_ip: [timestamp, ...]}
        self.external_connections = defaultdict(list) # {src_ip: [(dst_ip, timestamp), ...]}
        self.lateral_movement = defaultdict(list)     # {src_ip: [dst_ip, ...]}
        self.session_start = {}                       # {(src_ip, dst_ip, dst_port): start_time}
        self.session_duration = defaultdict(list)     # {src_ip: [duration, ...]}

        self.last_clean_time = time.time()
        self.last_check_time = time.time()            # 控制检查频率

        # ===== 基线相关 =====
        self.baseline = {}            # 格式: {'conn': {ip: {'mean':, 'std':}}, 'fail': {}, 'lateral': {}, 'external': {}}
        self.learning = False
        self.learning_start = 0
        self.learning_data = None     # 学习期间收集的数据
        self.baseline_loaded = False

        # 尝试加载基线文件
        if config.USE_BASELINE and os.path.exists(config.BASELINE_FILE):
            self.load_baseline()
            if self.baseline:
                self.baseline_loaded = True
                print("[*] 基线已加载，使用基线检测模式")
            else:
                self.start_learning()
        else:
            if config.USE_BASELINE:
                print("[*] 未找到基线文件，进入学习模式（60秒）")
                self.start_learning()
            else:
                print("[*] 使用固定阈值检测模式")

    def start_learning(self):
        """进入学习模式"""
        self.learning = True
        self.learning_start = time.time()
        # 学习数据结构：每个IP记录各个指标在每次采样时的值列表
        self.learning_data = {
            'conn': defaultdict(list),
            'fail': defaultdict(list),
            'lateral': defaultdict(list),
            'external': defaultdict(list)  # 新增：收集异常外联基线
        }
        print("[*] 开始学习网络正常行为，将持续 {} 秒".format(config.BASELINE_LEARNING_TIME))

    def load_baseline(self):
        """从文件加载基线"""
        try:
            with open(config.BASELINE_FILE, 'r') as f:
                self.baseline = json.load(f)
        except Exception as e:
            print(f"[!] 加载基线失败: {e}")
            self.baseline = {}

    def save_baseline(self):
        """保存基线到文件"""
        try:
            os.makedirs(os.path.dirname(config.BASELINE_FILE), exist_ok=True)
            with open(config.BASELINE_FILE, 'w') as f:
                json.dump(self.baseline, f, indent=2)
            print(f"[*] 基线已保存至 {config.BASELINE_FILE}")
        except Exception as e:
            print(f"[!] 保存基线失败: {e}")

    def _is_internal(self, ip):
        """判断是否为内网IP"""
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
        """更新统计信息（增加对端口去重的支持）"""
        now = time.time()

        # 1. 连接与端口统计：保存 (端口, 时间) 元组
        self.conn_count[src_ip].append((dst_port, now))

        # 2. 失败登录
        if payload:
            payload_lower = payload.lower()
            if b'login failed' in payload_lower or b'failed password' in payload_lower or b'authentication failure' in payload_lower:
                self.fail_login_count[src_ip].append(now)

        # 3. 异常外联
        if not self._is_internal(dst_ip) and dst_ip not in config.WHITELIST_IPS:
            self.external_connections[src_ip].append((dst_ip, now))

        # 4. 横向扩散
        if self._is_internal(src_ip) and self._is_internal(dst_ip) and src_ip != dst_ip:
            self.lateral_movement[src_ip].append(dst_ip)

        # 5. 会话时长
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

        # 清理旧数据（每10秒）
        if now - self.last_clean_time > 10:
            self._clean_old_records()
            self.last_clean_time = now

    def check_anomalies(self):
        """
        检查异常（学习模式或检测模式）
        返回告警列表
        """
        now = time.time()
        # 控制检查频率（每3秒一次）
        if now - self.last_check_time < 3:
            return []
        self.last_check_time = now

        # 如果处于学习模式，收集数据并判断是否结束学习
        if self.learning:
            if now - self.learning_start >= config.BASELINE_LEARNING_TIME:
                self._finish_learning()
                # 结束学习时重置时间差，不给历史残留检测留出任何空隙
                self.last_check_time = now
                return []
            return self._handle_learning(now)
        # 否则使用基线或固定阈值检测
        else:
            return self._detect_anomalies(now)

    def _handle_learning(self, now):
        """学习模式：收集当前60秒窗口内的统计数据供后续计算基线"""
        cutoff = now - config.STATS_WINDOW

        # 收集不同端口数（60秒窗口内）
        for ip, port_records in list(self.conn_count.items()):
            recent_records = [item for item in port_records if item[1] > cutoff]
            unique_ports = set(port for port, t in recent_records)
            count = len(unique_ports)
            if count > 0:
                self.learning_data['conn'][ip].append(count)

        # 收集失败登录数（60秒窗口内）
        for ip, timestamps in list(self.fail_login_count.items()):
            count = len([t for t in timestamps if t > cutoff])
            if count > 0:
                self.learning_data['fail'][ip].append(count)

        # 收集内网横向扩散数（60秒窗口内访问过的不同内网目标数）
        for ip, dst_list in list(self.lateral_movement.items()):
            count = len(set(dst_list))
            if count > 0:
                self.learning_data['lateral'][ip].append(count)

        # 新增：收集外联 IP 数量（60秒窗口内访问过的不同外网目标数）
        for ip, dst_list in list(self.external_connections.items()):
            recent_dsts = [d for d, t in dst_list if t > cutoff]
            count = len(set(recent_dsts))
            if count > 0:
                self.learning_data['external'][ip].append(count)

        return []  # 学习期间不产生告警

    def _finish_learning(self):
        """完成学习，计算基线并保存"""
        print("[*] 学习结束，计算基线...")
        baseline = {'conn': {}, 'fail': {}, 'lateral': {}, 'external': {}}

        # 计算每个IP每个指标的均值和标准差
        for metric in ['conn', 'fail', 'lateral', 'external']:
            data_dict = self.learning_data.get(metric, {})
            for ip, values in data_dict.items():
                if len(values) < 3:  # 样本太少，忽略
                    continue
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std = variance ** 0.5 if variance > 0 else 0.1
                baseline[metric][ip] = {'mean': mean, 'std': std}

        self.baseline = baseline
        self.save_baseline()
        self.learning = False
        self.learning_data = None
        self.baseline_loaded = True
        
        # 彻底将学习期间累积在内存中的各类旧背景流量清零
        self.conn_count.clear()
        self.fail_login_count.clear()
        self.external_connections.clear()
        self.lateral_movement.clear()
        self.session_duration.clear()
        print("[*] 基线建立完成，切换到检测模式")

    def _detect_anomalies(self, now):
        """检测模式：使用基线或固定阈值"""
        anomalies = []
        cutoff = now - config.STATS_WINDOW

        # ===== 1. 端口扫描检测 (已修改为：检测不同端口数) =====
        for ip, port_records in list(self.conn_count.items()):
            recent_records = [item for item in port_records if item[1] > cutoff]
            if not recent_records:
                continue
            
            # 统计当前时间窗内探测到的不同端口数
            unique_ports = set(port for port, t in recent_records)
            ports_count = len(unique_ports)

            # 检查基线是否存在
            if self.baseline_loaded and ip in self.baseline.get('conn', {}):
                mean = self.baseline['conn'][ip]['mean']
                std = self.baseline['conn'][ip]['std']
                threshold = mean + 3 * std
                if ports_count > threshold and ports_count > 5:  # 至少扫描5个不同端口才告警
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '多个目标',
                        'type': '端口扫描',
                        'detail': f'{ip} 在 {config.STATS_WINDOW}s 内探测了 {ports_count} 个不同端口 (基线均值{mean:.1f}, 阈值{threshold:.1f})'
                    })
                    self.conn_count[ip] = []  # 清空避免重复告警
            else:
                # 使用固定阈值（此时SCAN_THRESHOLD代表探测的不同端口数限制）
                if ports_count > config.SCAN_THRESHOLD:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '多个目标',
                        'type': '端口扫描',
                        'detail': f'{ip} 在 {config.STATS_WINDOW}s 内探测了 {ports_count} 个不同端口'
                    })
                    self.conn_count[ip] = []

        # ===== 2. 暴力破解检测 =====
        for ip, timestamps in list(self.fail_login_count.items()):
            count = len([t for t in timestamps if t > cutoff])
            if count == 0:
                continue
            if self.baseline_loaded and ip in self.baseline.get('fail', {}):
                mean = self.baseline['fail'][ip]['mean']
                std = self.baseline['fail'][ip]['std']
                threshold = mean + 3 * std
                if count > threshold and count > 3:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '目标系统',
                        'type': '暴力破解',
                        'detail': f'{ip} 在 {config.STATS_WINDOW}s 内失败登录 {count} 次 (基线均值{mean:.1f}, 阈值{threshold:.1f})'
                    })
                    self.fail_login_count[ip] = []
            else:
                if count > config.BRUTE_FORCE_THRESHOLD:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '目标系统',
                        'type': '暴力破解',
                        'detail': f'{ip} 在 {config.STATS_WINDOW}s 内失败登录 {count} 次'
                    })
                    self.fail_login_count[ip] = []

        # ===== 3. 异常外联检测（完美支持新增的外联基线） =====
        for src_ip, dst_list in list(self.external_connections.items()):
            recent_dsts = [d for d, t in dst_list if t > cutoff]
            if not recent_dsts:
                continue
            unique_dsts = set(recent_dsts)
            outbound_count = len(unique_dsts)

            # 检查基线中是否有该 IP 的外联记录
            if self.baseline_loaded and src_ip in self.baseline.get('external', {}):
                mean = self.baseline['external'][src_ip]['mean']
                std = self.baseline['external'][src_ip]['std']
                threshold = mean + 3 * std
                # 如果超过了你平时上网的基线水平（且至少大于5），才判定为异常
                if outbound_count > threshold and outbound_count > 5:
                    anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': '外网多个IP',
                        'type': '异常外联',
                        'detail': f'{src_ip} 在 {config.STATS_WINDOW}s 内外联 {outbound_count} 个IP (基线均值{mean:.1f}, 阈值{threshold:.1f})'
                    })
                    self.external_connections[src_ip] = []
            else:
                # 如果没有基线数据，才使用硬编码的固定阈值
                if outbound_count > 15: # 适当提高非基线阶段的容忍度
                    anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': '外网多个IP',
                        'type': '异常外联',
                        'detail': f'{src_ip} 在 {config.STATS_WINDOW}s 内访问了 {outbound_count} 个不同外网IP'
                    })
                    self.external_connections[src_ip] = []

        # ===== 4. 横向扩散检测 =====
        for ip, dst_list in list(self.lateral_movement.items()):
            unique_targets = set(dst_list)
            if self.baseline_loaded and ip in self.baseline.get('lateral', {}):
                mean = self.baseline['lateral'][ip]['mean']
                std = self.baseline['lateral'][ip]['std']
                threshold = mean + 3 * std
                if len(unique_targets) > threshold and len(unique_targets) > 3:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '内网多个目标',
                        'type': '内网横向扩散',
                        'detail': f'{ip} 在内网中访问了 {len(unique_targets)} 个不同的目标IP (基线均值{mean:.1f}, 阈值{threshold:.1f})'
                    })
                    self.lateral_movement[ip] = []
            else:
                if len(unique_targets) > config.LATERAL_THRESHOLD:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '内网多个目标',
                        'type': '内网横向扩散',
                        'detail': f'{ip} 在内网中访问了 {len(unique_targets)} 个不同的目标IP'
                    })
                    self.lateral_movement[ip] = []

        # ===== 5. 会话时长异常 =====
        for ip, durations in list(self.session_duration.items()):
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
        """清理过期统计（保留最近窗口的数据）"""
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        for ip in list(self.conn_count.keys()):
            self.conn_count[ip] = [item for item in self.conn_count[ip] if item[1] > cutoff]
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

        # 横向扩散保留最近100条
        for ip in list(self.lateral_movement.keys()):
            if len(self.lateral_movement[ip]) > 100:
                self.lateral_movement[ip] = self.lateral_movement[ip][-100:]

        # 修复 del self.session_start[key][source] 语法错误
        for key, start_time in list(self.session_start.items()):
            if now - start_time > config.SESSION_DURATION_THRESHOLD:
                del self.session_start[key]