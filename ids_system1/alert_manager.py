import time
from datetime import datetime
from collections import defaultdict
import config
import os


class AssetManager:
    def __init__(self):
        self.assets = {}
        self._load_defaults()

    def _load_defaults(self):
        default_assets = [
            ("192.168.1.1", "核心路由器", "critical"),
            ("192.168.1.10", "Web服务器", "high"),
            ("192.168.1.20", "数据库服务器", "critical"),
            ("192.168.1.30", "邮件服务器", "medium"),
            ("192.168.1.100", "员工工作站", "low"),
        ]
        for ip, name, importance in default_assets:
            self.assets[ip] = {"name": name, "importance": importance}

    def get_importance(self, ip):
        if ip in self.assets:
            return self.assets[ip]["importance"]
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            return "medium"
        return "low"

    def get_importance_score(self, ip):
        imp = self.get_importance(ip)
        return {"critical": 100, "high": 70, "medium": 40, "low": 10}.get(imp, 20)

    def get_name(self, ip):
        return self.assets.get(ip, {}).get("name", ip)

    def add_asset(self, ip, name, importance):
        self.assets[ip] = {"name": name, "importance": importance}

    def remove_asset(self, ip):
        if ip in self.assets:
            del self.assets[ip]

    def get_all_assets(self):
        return self.assets


class BaselineManager:
    def __init__(self):
        self.baseline = defaultdict(lambda: {"count": 0, "first_seen": time.time(), "last_seen": time.time()})
        self.traffic_baseline = defaultdict(lambda: {"total_bytes": 0, "samples": 0})

    def record_alert(self, src_ip, alert_type):
        key = f"{src_ip}_{alert_type}"
        self.baseline[key]["count"] += 1
        self.baseline[key]["last_seen"] = time.time()
        if self.baseline[key]["first_seen"] == 0:
            self.baseline[key]["first_seen"] = time.time()

    def is_baseline_alert(self, src_ip, alert_type):
        key = f"{src_ip}_{alert_type}"
        if key not in self.baseline:
            return False
        record = self.baseline[key]
        if record["count"] >= 10 and (time.time() - record["first_seen"]) > 3600:
            return True
        return False

    def record_traffic(self, ip, bytes_count):
        self.traffic_baseline[ip]["total_bytes"] += bytes_count
        self.traffic_baseline[ip]["samples"] += 1

    def get_avg_traffic(self, ip):
        if ip in self.traffic_baseline and self.traffic_baseline[ip]["samples"] > 0:
            return self.traffic_baseline[ip]["total_bytes"] / self.traffic_baseline[ip]["samples"]
        return 0


class AlertDeduplicator:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.alert_buffer = defaultdict(list)

    def _make_key(self, src_ip, alert_type, dst_ip=""):
        base_type = alert_type
        if "SQL" in alert_type:
            base_type = "SQL注入"
        elif "XSS" in alert_type:
            base_type = "XSS攻击"
        elif "命令" in alert_type:
            base_type = "命令执行"
        elif "扫描" in alert_type:
            base_type = "端口扫描"
        elif "暴力" in alert_type:
            base_type = "暴力破解"
        elif "木马" in alert_type or "WebShell" in alert_type or "后门" in alert_type:
            base_type = "木马/后门"
        elif "外联" in alert_type:
            base_type = "异常外联"
        elif "横向" in alert_type:
            base_type = "横向扩散"
        elif "带宽" in alert_type:
            base_type = "带宽异常"
        elif "会话" in alert_type:
            base_type = "会话时长异常"
        elif "TLS" in alert_type:
            base_type = "TLS恶意通信"
        elif "AI" in alert_type:
            base_type = "AI智能分析异常"
        return f"{src_ip}|{dst_ip}|{base_type}"

    def process_alert(self, alert):
        now = time.time()
        key = self._make_key(alert["src_ip"], alert["type"], alert.get("dst_ip", ""))

        self.alert_buffer[key] = [a for a in self.alert_buffer[key] if now - a["_timestamp"] < self.window]
        self.alert_buffer[key].append({**alert, "_timestamp": now})

        count = len(self.alert_buffer[key])

        if count == 1:
            alert["occurrence_count"] = 1
            alert["is_aggregated"] = False
            return alert

        first_alert = self.alert_buffer[key][0]
        if count == 2:
            aggregated = dict(first_alert)
            aggregated["id"] = first_alert["id"]
            aggregated["occurrence_count"] = count
            aggregated["is_aggregated"] = True
            aggregated["detail"] = f"{alert.get('detail', '')} (时间窗口内共发现 {count} 次)"
            aggregated["_agg_key"] = key
            return aggregated
        else:
            first_alert["occurrence_count"] = count
            first_alert["detail"] = f"{first_alert.get('original_detail', first_alert['detail'])} (时间窗口内共发现 {count} 次)"
            if "original_detail" not in first_alert:
                first_alert["original_detail"] = first_alert["detail"]
            first_alert["is_aggregated"] = True
            first_alert["_update"] = True
            first_alert["_agg_key"] = key
            return first_alert

    def get_buffer(self):
        return self.alert_buffer


class AlertManager:
    def __init__(self):
        self.alerts = []
        self.callbacks = []
        self.update_callbacks = []
        self.alert_count = 0
        self.deduplicator = AlertDeduplicator(window_seconds=60)
        self.asset_manager = AssetManager()
        self.baseline_manager = BaselineManager()
        self.aggregated_alerts = {}

        self.noise_reduction_enabled = True
        self.asset_importance_enabled = True
        self.baseline_enabled = True

        self.traffic_stats = {"total_packets": 0, "total_bytes": 0, "start_time": time.time()}
        self.realtime_stats = []

        os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)

    def add_alert(self, src_ip, dst_ip, dst_port, alert_type, detail):
        alert = {
            "id": self.alert_count + 1,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "type": alert_type,
            "detail": detail,
            "severity": self._calculate_severity(src_ip, dst_ip, alert_type),
            "occurrence_count": 1,
            "is_aggregated": False,
        }

        if self.noise_reduction_enabled:
            processed = self.deduplicator.process_alert(alert)
            if processed is None:
                return

            if processed.get("_update"):
                agg_key = processed.get("_agg_key")
                if agg_key and agg_key in self.aggregated_alerts:
                    idx = self.aggregated_alerts[agg_key]
                    if idx < len(self.alerts):
                        self.alerts[idx]["occurrence_count"] = processed["occurrence_count"]
                        self.alerts[idx]["detail"] = processed["detail"]
                        self.alerts[idx]["time"] = alert["time"]
                        self._notify_update(idx)
                return

            if processed.get("is_aggregated"):
                agg_key = processed.get("_agg_key")
                if agg_key:
                    self.aggregated_alerts[agg_key] = len(self.alerts)
                alert = processed
                alert["original_detail"] = detail

        self.alerts.append(alert)
        self.alert_count += 1

        if self.baseline_enabled:
            self.baseline_manager.record_alert(src_ip, alert_type)

        log_msg = f"[{alert['time']}] {alert['src_ip']} -> {alert['dst_ip']}:{alert['dst_port']} [{alert['type']}] {alert['detail']} [严重度:{alert['severity']}]\n"
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_msg)

        print(f"[ALERT] {log_msg.strip()}")

        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception as e:
                print(f"[!] 回调执行错误: {e}")

    def _calculate_severity(self, src_ip, dst_ip, alert_type):
        score = 50

        if "SQL" in alert_type or "命令" in alert_type:
            score += 30
        elif "XSS" in alert_type:
            score += 20
        elif "木马" in alert_type or "WebShell" in alert_type or "后门" in alert_type:
            score += 40
        elif "扫描" in alert_type:
            score += 10
        elif "暴力" in alert_type:
            score += 25
        elif "横向" in alert_type:
            score += 35
        elif "带宽" in alert_type:
            score += 15
        elif "外联" in alert_type:
            score += 10
        elif "会话" in alert_type:
            score += 5
        elif "TLS" in alert_type:
            score += 30
        elif "AI" in alert_type:
            score += 25

        if self.asset_importance_enabled:
            dst_score = self.asset_manager.get_importance_score(dst_ip)
            src_score = self.asset_manager.get_importance_score(src_ip)
            score += int(dst_score * 0.3)
            if self._is_internal(src_ip):
                score += int(src_score * 0.2)

        if self.baseline_enabled and self.baseline_manager.is_baseline_alert(src_ip, alert_type):
            score = int(score * 0.6)

        return min(max(score, 1), 100)

    def _is_internal(self, ip):
        return (
            ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("172.3")
            or ip.startswith("127.")
        )

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def register_update_callback(self, callback):
        self.update_callbacks.append(callback)

    def _notify_update(self, index):
        for cb in self.update_callbacks:
            try:
                cb(index)
            except Exception as e:
                print(f"[!] 更新回调错误: {e}")

    def get_alerts(self):
        return self.alerts

    def get_recent_alerts(self, count=100):
        return self.alerts[-count:]

    def clear_alerts(self):
        self.alerts = []
        self.alert_count = 0
        self.aggregated_alerts = {}
        self.deduplicator = AlertDeduplicator(window_seconds=60)
        open(config.LOG_FILE, "w", encoding="utf-8").close()

    def get_stats(self):
        total = len(self.alerts)
        scan = sum(1 for a in self.alerts if "扫描" in a["type"])
        brute = sum(1 for a in self.alerts if "暴力" in a["type"])
        web = sum(1 for a in self.alerts if "SQL" in a["type"] or "XSS" in a["type"] or "命令" in a["type"])
        trojan = sum(1 for a in self.alerts if "木马" in a["type"] or "后门" in a["type"])
        lateral = sum(1 for a in self.alerts if "横向扩散" in a["type"])
        bandwidth = sum(1 for a in self.alerts if "带宽异常" in a["type"])
        tls = sum(1 for a in self.alerts if "TLS" in a["type"])
        ai = sum(1 for a in self.alerts if "AI" in a["type"])

        today = datetime.now().strftime("%Y-%m-%d")
        today_risk = sum(
            a.get("severity", 50) for a in self.alerts if a.get("time", "").startswith(today)
        )

        sql_count = sum(1 for a in self.alerts if "SQL" in a["type"])
        xss_count = sum(1 for a in self.alerts if "XSS" in a["type"])

        total_occurrences = sum(a.get("occurrence_count", 1) for a in self.alerts)

        return {
            "total": total,
            "total_occurrences": total_occurrences,
            "scan": scan,
            "brute": brute,
            "web": web,
            "trojan": trojan,
            "lateral": lateral,
            "bandwidth": bandwidth,
            "sql": sql_count,
            "xss": xss_count,
            "tls": tls,
            "ai": ai,
            "today_risk": today_risk,
        }

    def record_traffic(self, bytes_count, packet_count=1):
        self.traffic_stats["total_bytes"] += bytes_count
        self.traffic_stats["total_packets"] += packet_count
        self.baseline_manager.record_traffic("global", bytes_count)

    def get_traffic_stats(self):
        elapsed = max(time.time() - self.traffic_stats["start_time"], 1)
        return {
            "total_bytes": self.traffic_stats["total_bytes"],
            "total_packets": self.traffic_stats["total_packets"],
            "bps": self.traffic_stats["total_bytes"] / elapsed,
            "pps": self.traffic_stats["total_packets"] / elapsed,
            "elapsed": elapsed,
        }

    def add_realtime_sample(self, sample):
        self.realtime_stats.append(sample)
        if len(self.realtime_stats) > 300:
            self.realtime_stats = self.realtime_stats[-300:]

    def get_realtime_stats(self):
        return self.realtime_stats
