# alert_manager.py
import time
from datetime import datetime
import config
import os


class AlertDeduplicator:
    """告警去重器：在时间窗口内对同一告警进行合并更新，避免产生重复ID。"""

    def __init__(self, time_window=60):
        self.time_window = time_window
        # key -> {'count': n, 'timestamp': float}
        self.alert_history = {}

    def _make_key(self, alert):
        return (alert.get('src_ip'), alert.get('dst_ip'),
                alert.get('dst_port'), alert.get('type'))

    def process_alert(self, alert):
        """
        处理一条告警，返回 (是否更新已有告警, 累计次数)。
        count == 1 视为新告警；count >= 2 统一走更新逻辑（_update = True），
        不再单独处理 count == 2 的情况，避免重复ID。
        """
        now = time.time()
        key = self._make_key(alert)
        _update = False

        if key in self.alert_history:
            entry = self.alert_history[key]
            if now - entry['timestamp'] <= self.time_window:
                entry['count'] += 1
                count = entry['count']
            else:
                # 超出时间窗口，重新计数
                entry['count'] = 1
                entry['timestamp'] = now
                count = 1
        else:
            self.alert_history[key] = {'count': 1, 'timestamp': now}
            count = 1

        if count >= 2:
            _update = True

        return _update, count


class AlertManager:
    def __init__(self):
        self.alerts = []
        self.callbacks = []
        self.alert_count = 0
        self.deduplicator = AlertDeduplicator()
        # key -> 已存在告警对象（用于更新而非新建ID）
        self.alert_keys = {}
        # 确保日志目录存在
        os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)

    def add_alert(self, src_ip, dst_ip, dst_port, alert_type, detail):
        alert = {
            'id': self.alert_count + 1,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'type': alert_type,
            'detail': detail,
            '_update': False
        }

        _update, count = self.deduplicator.process_alert(alert)

        # 重复告警：更新已有记录，不新增ID
        if _update:
            key = self.deduplicator._make_key(alert)
            existing = self.alert_keys.get(key)
            if existing is not None:
                existing['time'] = alert['time']
                existing['detail'] = f"{detail} (累计 {count} 次)"
                existing['_update'] = True

                log_msg = (f"[{existing['time']}] (更新) {existing['src_ip']} -> "
                           f"{existing['dst_ip']}:{existing['dst_port']} "
                           f"[{existing['type']}] {existing['detail']}\n")
                with open(config.LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(log_msg)
                print(f"[ALERT] {log_msg.strip()}")

                for cb in self.callbacks:
                    try:
                        cb(existing)
                    except Exception as e:
                        print(f"[!] 回调执行错误: {e}")
                return

        # 新告警：分配新ID并记录
        self.alerts.append(alert)
        self.alert_count += 1
        key = self.deduplicator._make_key(alert)
        self.alert_keys[key] = alert

        log_msg = (f"[{alert['time']}] {alert['src_ip']} -> "
                   f"{alert['dst_ip']}:{alert['dst_port']} "
                   f"[{alert['type']}] {alert['detail']}\n")
        with open(config.LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_msg)

        print(f"[ALERT] {log_msg.strip()}")

        # 触发界面回调
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception as e:
                print(f"[!] 回调执行错误: {e}")

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def get_alerts(self):
        return self.alerts

    def get_recent_alerts(self, count=100):
        return self.alerts[-count:]

    def clear_alerts(self):
        self.alerts = []
        self.alert_count = 0
        self.deduplicator.alert_history.clear()
        self.alert_keys.clear()
        # 清空日志文件
        open(config.LOG_FILE, 'w', encoding='utf-8').close()

    def get_stats(self):
        total = len(self.alerts)
        scan = sum(1 for a in self.alerts if '扫描' in a['type'])
        brute = sum(1 for a in self.alerts if '暴力' in a['type'])
        web = sum(1 for a in self.alerts if 'SQL' in a['type'] or 'XSS' in a['type'] or '命令' in a['type'])
        trojan = sum(1 for a in self.alerts if '木马' in a['type'] or '后门' in a['type'])
        lateral = sum(1 for a in self.alerts if '横向扩散' in a['type'])
        bandwidth = sum(1 for a in self.alerts if '带宽异常' in a['type'])
        tls = sum(1 for a in self.alerts if 'TLS' in a['type'])
        ai = sum(1 for a in self.alerts if 'AI' in a['type'])
        return {'total': total, 'scan': scan, 'brute': brute, 'web': web,
                'trojan': trojan, 'lateral': lateral, 'bandwidth': bandwidth,
                'tls': tls, 'other': ai}
