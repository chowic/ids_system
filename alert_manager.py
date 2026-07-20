# alert_manager.py
import time
from collections import defaultdict
import config
from ai_detector import AIDetector  # [新增] 导入你的 AI 检测模块

class AnomalyDetector:
    def __init__(self):
        # 使用 set 来存储目标，避免大流量导致的列表无限膨胀
        # 端口扫描：统计 src_ip 访问了多少个不同的 (dst_ip, dst_port)
        self.scan_targets = defaultdict(set)
        
        # 失败登录：记录次数而不是时间戳列表
        self.fail_login_count = defaultdict(int)
        
        # 异常外联：{src_ip: set(dst_ip, ...)}
        self.external_connections = defaultdict(set)
        
        # 横向扩散：{src_ip: set(dst_ip, ...)}
        self.lateral_movement = defaultdict(set)
        
        # 会话时长：{(src_ip, dst_ip, dst_port): start_time}
        self.session_start = {}
        
        # ========== [新增] 为 AI 智能检测准备的基础变量 ==========
        self.ai_detector = AIDetector()          # 初始化 AI 模型
        self.ip_packet_count = defaultdict(int)  # 统计单 IP 发包数 (近似为连接数)
        self.ip_bytes_count = defaultdict(int)   # 统计单 IP 总流量大小
        self.ip_sessions = defaultdict(int)      # 统计单 IP 会话数
        # ==========================================================

        self.last_clean_time = time.time()
        self.last_check_time = time.time()

    def _is_internal(self, ip):
        """判断是否为内网IP"""
        if ip.startswith(('192.168.', '10.', '127.')):
            return True
        parts = ip.split('.')
        if len(parts) == 4 and parts[0] == '172':
            if 16 <= int(parts[1]) <= 31:
                return True
        return False

    def update_stats(self, src_ip, dst_ip, dst_port, payload, pkt_size=0, flags=''):
        now = time.time()
        
        # ========== 1. 端口扫描检测 (统计不同的目标IP和端口) ==========
        self.scan_targets[src_ip].add((dst_ip, dst_port))
        
        # ========== 2. 失败登录检测 ==========
        if payload:
            payload_lower = payload.lower()
            if b'login failed' in payload_lower or b'failed password' in payload_lower or b'authentication failure' in payload_lower:
                self.fail_login_count[src_ip] += 1
        
        # ========== 3. 异常外联检测 ==========
        if not self._is_internal(dst_ip) and dst_ip not in config.WHITELIST_IPS:
            self.external_connections[src_ip].add(dst_ip)
        
        # ========== 4. 横向扩散检测 (内网多目标访问) ==========
        if self._is_internal(src_ip) and self._is_internal(dst_ip) and src_ip != dst_ip:
            self.lateral_movement[src_ip].add(dst_ip)
        
        # ========== 5. 会话记录 ==========
        if flags:
            session_key = (src_ip, dst_ip, dst_port)
            # SYN包（建立连接）
            if 'S' in flags and 'A' not in flags:
                self.session_start[session_key] = now
                # [新增] 记录 AI 模块需要的会话数特征
                self.ip_sessions[src_ip] += 1  
            # FIN/RST包（连接断开）
            elif 'F' in flags or 'R' in flags:
                if session_key in self.session_start:
                    del self.session_start[session_key]

        # ========== [新增] 6. 累加 AI 模块需要的基础特征 ==========
        self.ip_packet_count[src_ip] += 1
        self.ip_bytes_count[src_ip] += pkt_size
        # ==========================================================

        # 降频：清理与检测逻辑剥离，每 config.STATS_WINDOW 秒执行一次数据重置
        if now - self.last_clean_time > config.STATS_WINDOW:
            self._reset_windows()
            self.last_clean_time = now

    def check_anomalies(self):
        """检查所有异常行为，返回告警列表"""
        anomalies = []
        now = time.time()
        
        # 降频检查：没必要每收到一个包就查一次，每 2 秒查一次足够了
        if now - self.last_check_time < 2:
            return anomalies
            
        self.last_check_time = now

        # 1. 端口扫描检测
        for ip, targets in self.scan_targets.items():
            if len(targets) > config.SCAN_THRESHOLD:
                anomalies.append({
                    'src_ip': ip, 'dst_ip': '多目标/端口', 'type': '端口扫描',
                    'detail': f'{ip} 在近期扫描了 {len(targets)} 个不同的目标/端口'
                })

        # 2. 暴力破解检测
        for ip, count in self.fail_login_count.items():
            if count > config.BRUTE_FORCE_THRESHOLD:
                anomalies.append({
                    'src_ip': ip, 'dst_ip': '目标系统', 'type': '暴力破解',
                    'detail': f'{ip} 近期失败登录 {count} 次'
                })

        # 3. 异常外联检测
        for ip, dsts in self.external_connections.items():
            if len(dsts) > 0:
                anomalies.append({
                    'src_ip': ip, 'dst_ip': list(dsts)[0], 'type': '异常外联',
                    'detail': f'{ip} 外联陌生IP数: {len(dsts)}，如 {list(dsts)[:3]}'
                })

        # 4. 横向扩散检测
        for ip, targets in self.lateral_movement.items():
            if len(targets) > config.LATERAL_THRESHOLD:
                anomalies.append({
                    'src_ip': ip, 'dst_ip': '内网多目标', 'type': '内网横向扩散',
                    'detail': f'{ip} 试图连接 {len(targets)} 个不同内网主机'
                })

        # 5. 会话时长异常检测 (直接检查当前还活着的 session)
        expired_sessions = []
        for session_key, start_time in self.session_start.items():
            duration = now - start_time
            if duration > config.SESSION_DURATION_THRESHOLD:
                src_ip, dst_ip, _ = session_key
                anomalies.append({
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'type': '会话时长异常',
                    'detail': f'存在超过 {duration/60:.1f} 分钟的长连接会话'
                })
                # 记录下来准备删除，防止重复一直告警
                expired_sessions.append(session_key)
                
        for key in expired_sessions:
            del self.session_start[key]

        # ========== [新增] 6. 调用 AI 孤立森林模型进行异常检测 ==========
        for ip, pkt_count in self.ip_packet_count.items():
            # 为避免全是零散的单包正常流量导致频繁调用，我们只让发包数大于 5 的 IP 走 AI 判定
            if pkt_count > 5:
                # 提取 AI 需要的 5 个特征
                connections = pkt_count                             # 1. 连接数 (近似用包数替代)
                ports = len(self.scan_targets.get(ip, set()))       # 2. 端口数
                avg_traffic = self.ip_bytes_count[ip] / pkt_count   # 3. 平均流量
                pkt_size = avg_traffic                              # 4. 包大小 (复用平均值，答辩展示足够)
                sessions = self.ip_sessions.get(ip, 1)              # 5. 会话数
                
                # 调用你的 ai_detector.py 接口
                result = self.ai_detector.detect_anomaly(connections, ports, pkt_size, avg_traffic, sessions)
                
                if result == "Anomaly":
                    anomalies.append({
                        'src_ip': ip, 
                        'dst_ip': 'Multiple', 
                        'type': 'AI智能分析异常',  # 这个名字对应 gui.py 里的高亮渲染
                        'detail': f'[模型告警] 识别到异常流量模式 (连接数:{connections}, 端口:{ports})'
                    })
        # ====================================================================

        return anomalies

    def _reset_windows(self):
        """滑动窗口重置：定时清空计数器"""
        self.scan_targets.clear()
        self.fail_login_count.clear()
        self.external_connections.clear()
        self.lateral_movement.clear()
        
        # ========== [新增] 定时清空 AI 的统计特征窗口 ==========
        self.ip_packet_count.clear()
        self.ip_bytes_count.clear()
        self.ip_sessions.clear()
        # =======================================================
        # 注意：session_start 不能清空，因为长连接可能跨越多个统计窗口