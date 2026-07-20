# alert_manager.py
import time

class AlertManager:
    def __init__(self):
        self.alerts = []
        self.callbacks = []
        self.alert_id = 1

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def add_alert(self, src_ip, dst_ip, dst_port, alert_type, detail):
        alert = {
            'id': self.alert_id,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'type': alert_type,
            'detail': detail
        }
        self.alerts.append(alert)
        self.alert_id += 1
        print(f"[ALERT] [{alert['time']}] {src_ip} -> {dst_ip}:{dst_port} [{alert_type}] {detail}")
        
        # 触发回调
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception as e:
                print(f"[!] 告警回调异常: {e}")

    def clear_alerts(self):
        self.alerts = []
        self.alert_id = 1

    def get_stats(self):
        stats = {
            'total': len(self.alerts),
            'scan': 0,
            'brute': 0,
            'web': 0,
            'trojan': 0,
            'tls': 0  # <--- 确保包含 tls 字段
        }
        for alert in self.alerts:
            t = alert['type']
            if 'TLS' in t:
                stats['tls'] += 1
            elif '扫描' in t:
                stats['scan'] += 1
            elif '暴力' in t:
                stats['brute'] += 1
            elif any(k in t for k in ['SQL', 'XSS', '命令']):
                stats['web'] += 1
            elif '木马' in t or '后门' in t:
                stats['trojan'] += 1
        return stats