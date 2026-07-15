# anomaly_detection.py
import time
from collections import defaultdict
import config


class AnomalyDetector:
    def __init__(self):
        # 原有统计
        # {src_ip: [timestamp, ...]}
        self.conn_count = defaultdict(list)
        self.fail_login_count = defaultdict(
            list)     # {src_ip: [timestamp, ...]}
        # {src_ip: [(dst_ip, timestamp), ...]}
        self.external_connections = defaultdict(list)

        # 新增：横向扩散检测
        self.lateral_movement = defaultdict(list)     # {src_ip: [dst_ip, ...]}

        # 新增：会话时长检测
        # {(src_ip, dst_ip, dst_port): start_time}
        self.session_start = {}
        self.session_duration = defaultdict(
            list)     # {src_ip: [duration, ...]}

        # 新增：扫描检测统计（用于 detect_scan_and_brute）
        # {(src_ip, dst_ip): set(ports)}
        self.scan_stats = defaultdict(set)

        self.last_clean_time = time.time()

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
        if ip.startswith('127.'):  # localhost
            return True
        return False

    # ========== 新增方法 ==========
    def detect_scan_and_brute(self, src_ip, dst_ip, dst_port, flags):
        """
        实时检测端口扫描和暴力破解
        返回: [(anomaly_type, detail), ...]
        """
        anomalies = []
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        # 1. 检测端口扫描：统计源IP访问的不同端口数
        scan_key = (src_ip, dst_ip)
        self.scan_stats[scan_key].add(dst_port)

        # 如果短时间内访问了超过阈值的不同端口，视为扫描
        if len(self.scan_stats[scan_key]) > config.SCAN_THRESHOLD:
            anomalies.append((
                "端口扫描",
                f"{src_ip} 扫描了 {dst_ip} 的 {len(self.scan_stats[scan_key])} 个端口"
            ))
            # 清空避免重复告警
            self.scan_stats[scan_key] = set()

        # 2. 检测暴力破解：统计失败登录次数
        login_key = (src_ip, dst_ip)
        # 注意：这里需要从 update_stats 中获取失败登录计数
        # 我们使用 fail_login_count 中的数据
        fail_count = len(
            [t for t in self.fail_login_count[src_ip] if t > cutoff])
        if fail_count > config.BRUTE_FORCE_THRESHOLD:
            anomalies.append((
                "暴力破解",
                f"{src_ip} 对 {dst_ip} 进行了 {fail_count} 次失败登录"
            ))
            # 清空避免重复告警
            self.fail_login_count[src_ip] = []

        return anomalies

    def update_stats(self, src_ip, dst_ip, dst_port,
                     payload, pkt_size=0, flags=''):
        """
        更新统计信息
        params:
            src_ip: 源IP
            dst_ip: 目的IP
            dst_port: 目的端口
            payload: TCP/UDP载荷
            pkt_size: 数据包大小（字节）
            flags: TCP标志位
        """
        now = time.time()

        # ========== 1. 连接统计（用于端口扫描检测） ==========
        self.conn_count[src_ip].append(now)

        # ========== 2. 失败登录检测（用于暴力破解检测） ==========
        if payload:
            payload_lower = payload.lower()
            if b'login failed' in payload_lower or b'failed password' in payload_lower or b'authentication failure' in payload_lower:
                self.fail_login_count[src_ip].append(now)

        # ========== 3. 异常外联检测 ==========
        if not self._is_internal(
                dst_ip) and dst_ip not in config.WHITELIST_IPS:
            self.external_connections[src_ip].append((dst_ip, now))

        # ========== 4. 横向扩散检测（内网IP之间通信） ==========
        if self._is_internal(src_ip) and self._is_internal(
                dst_ip) and src_ip != dst_ip:
            self.lateral_movement[src_ip].append(dst_ip)

        # ========== 5. 会话时长检测（仅TCP有flags） ==========
        if flags:
            session_key = (src_ip, dst_ip, dst_port)
            # SYN包（不含ACK）→ 会话开始
            if 'S' in flags and 'A' not in flags:
                self.session_start[session_key] = now
            # FIN或RST包 → 会话结束
            elif 'F' in flags or 'R' in flags:
                if session_key in self.session_start:
                    duration = now - self.session_start[session_key]
                    if duration > config.SESSION_DURATION_THRESHOLD:
                        self.session_duration[src_ip].append(duration)
                    del self.session_start[session_key]

        # 清理过期数据（每10秒执行一次）
        if now - self.last_clean_time > 10:
            self._clean_old_records()
            self.last_clean_time = now

    def check_anomalies(self):
        """检查所有异常行为，返回告警列表"""
        anomalies = []
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        # ========== 1. 端口扫描检测 ==========
        for ip, timestamps in self.conn_count.items():
            count = len([t for t in timestamps if t > cutoff])
            if count > config.SCAN_THRESHOLD:
                anomalies.append({
                    'src_ip': ip,
                    'dst_ip': '多个目标',
                    'type': '端口扫描',
                    'detail': f'{ip} 在 {config.STATS_WINDOW}s 内发起 {count} 次连接'
                })

        # ========== 2. 暴力破解检测 ==========
        for ip, timestamps in self.fail_login_count.items():
            count = len([t for t in timestamps if t > cutoff])
            if count > config.BRUTE_FORCE_THRESHOLD:
                anomalies.append({
                    'src_ip': ip,
                    'dst_ip': '目标系统',
                    'type': '暴力破解',
                    'detail': f'{ip} 在 {config.STATS_WINDOW}s 内失败登录 {count} 次'
                })

        # ========== 3. 异常外联检测 ==========
        for src_ip, dst_list in self.external_connections.items():
            if dst_list:
                # 获取最近窗口内的外联目标
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

        # ========== 4. 横向扩散检测 ==========
        for src_ip, dst_list in self.lateral_movement.items():
            # 获取最近窗口内的目标
            unique_targets = set(dst_list)
            if len(unique_targets) > config.LATERAL_THRESHOLD:
                anomalies.append({
                    'src_ip': src_ip,
                    'dst_ip': '内网多个目标',
                    'type': '内网横向扩散',
                    'detail': f'{src_ip} 在内网中访问了 {len(unique_targets)} 个不同的目标IP: {", ".join(list(unique_targets)[:5])}'
                })
                # 清空避免重复告警
                self.lateral_movement[src_ip] = []

        # ========== 5. 会话时长异常检测 ==========
        for ip, durations in self.session_duration.items():
            for duration in durations:
                if duration > config.SESSION_DURATION_THRESHOLD:
                    anomalies.append({
                        'src_ip': ip,
                        'dst_ip': '目标',
                        'type': '会话时长异常',
                        'detail': f'{ip} 存在会话时长 {duration/60:.1f} 分钟（超过阈值）'
                    })
            # 清空已处理的记录
            self.session_duration[ip] = []

        return anomalies

    def _clean_old_records(self):
        """清理过期的统计记录"""
        now = time.time()
        cutoff = now - config.STATS_WINDOW

        # 清理连接统计
        for ip in list(self.conn_count.keys()):
            self.conn_count[ip] = [
                t for t in self.conn_count[ip] if t > cutoff]
            if not self.conn_count[ip]:
                del self.conn_count[ip]

        # 清理失败登录统计
        for ip in list(self.fail_login_count.keys()):
            self.fail_login_count[ip] = [
                t for t in self.fail_login_count[ip] if t > cutoff]
            if not self.fail_login_count[ip]:
                del self.fail_login_count[ip]

        # 清理异常外联统计（保留最近的数据）
        for ip in list(self.external_connections.keys()):
            self.external_connections[ip] = [
                (d, t) for d, t in self.external_connections[ip] if t > cutoff]
            if not self.external_connections[ip]:
                del self.external_connections[ip]

        # 清理横向扩散统计（只保留最新的）
        for ip in list(self.lateral_movement.keys()):
            # 保留最近100条记录
            if len(self.lateral_movement[ip]) > 100:
                self.lateral_movement[ip] = self.lateral_movement[ip][-100:]

        # 清理会话开始记录（超过1小时的会话强制清除）
        for key, start_time in list(self.session_start.items()):
            if now - start_time > config.SESSION_DURATION_THRESHOLD:
                del self.session_start[key]

        # 清理扫描统计
        for key in list(self.scan_stats.keys()):
            # 扫描统计在 detect_scan_and_brute 中会自行清理
            pass
