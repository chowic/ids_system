# alert_manager.py
import time
from datetime import datetime
import config
import os


class AlertManager:
    def __init__(self):
        self.alerts = []
        self.callbacks = []
        self.alert_count = 0
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
            'detail': detail
        }
        self.alerts.append(alert)
        self.alert_count += 1

        # 写入日志
        log_msg = f"[{alert['time']}] {alert['src_ip']} -> {alert['dst_ip']}:{alert['dst_port']} [{alert['type']}] {alert['detail']}\n"
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
        # 清空日志文件
        open(config.LOG_FILE, 'w', encoding='utf-8').close()

    def get_stats(self):
        total = len(self.alerts)
        scan = sum(1 for a in self.alerts if '扫描' in a['type'])
        brute = sum(1 for a in self.alerts if '暴力' in a['type'])
        web = sum(
            1 for a in self.alerts if 'SQL' in a['type'] or 'XSS' in a['type'] or '命令' in a['type'])
        trojan = sum(
            1 for a in self.alerts if '木马' in a['type'] or '后门' in a['type'])
        lateral = sum(1 for a in self.alerts if '横向扩散' in a['type'])
        bandwidth = sum(1 for a in self.alerts if '带宽异常' in a['type'])
        return {'total': total, 'scan': scan, 'brute': brute, 'web': web,
                'trojan': trojan, 'lateral': lateral, 'bandwidth': bandwidth}
