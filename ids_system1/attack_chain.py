# attack_chain.py
from datetime import datetime

class AttackChainAnalyzer:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager

    def _classify_stage(self, alert_type):
        t = str(alert_type)
        if '扫描' in t:
            return 'Reconnaissance (信息收集/扫描)'
        elif 'SQL' in t or 'XSS' in t or '命令' in t or 'Web' in t or '漏洞' in t:
            return 'Exploitation (漏洞利用/入侵)'
        elif '暴力' in t:
            return 'Credential Access (凭据破解)'
        elif 'TLS' in t or '外联' in t or 'C2' in t or '木马' in t:
            return 'Command & Control (C2通信/异常外联)'
        elif '横向' in t:
            return 'Lateral Movement (内网横向扩散)'
        elif '带宽' in t:
            return 'Exfiltration / Impact (数据渗漏/服务干扰)'
        elif 'AI' in t:
            return 'AI Detected Anomaly (AI检测异常)'
        return 'Unknown Stage (其他异常行为)'

    def analyze(self):
        alerts = self.alert_manager.alerts
        if not alerts:
            return []

        grouped = {}
        for alert in alerts:
            src = alert.get('src_ip', '0.0.0.0')
            if src not in grouped:
                grouped[src] = []
            grouped[src].append(alert)

        chains = []
        for src_ip, alert_list in grouped.items():
            sorted_alerts = sorted(alert_list, key=lambda x: str(x.get('time', '')))
            stages = []
            target_ips = set()

            for a in sorted_alerts:
                dst = a.get('dst_ip', 'N/A')
                target_ips.add(dst)
                stage_name = self._classify_stage(a.get('type', ''))
                stages.append({
                    'time': a.get('time', ''),
                    'stage': stage_name,
                    'type': a.get('type', ''),
                    'dst_ip': dst,
                    'dst_port': a.get('dst_port', ''),
                    'detail': a.get('detail', '')
                })

            stage_types = set(s['stage'] for s in stages)
            if len(stage_types) >= 3:
                risk_level = 'HIGH'
            elif len(stage_types) == 2:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'

            chains.append({
                'attacker_ip': src_ip,
                'target_ips': list(target_ips),
                'risk_level': risk_level,
                'total_alerts': len(sorted_alerts),
                'stages': stages
            })

        return chains

    def get_summary(self):
        chains = self.analyze()
        high_count = sum(1 for c in chains if c['risk_level'] == 'HIGH')
        med_count = sum(1 for c in chains if c['risk_level'] == 'MEDIUM')
        low_count = sum(1 for c in chains if c['risk_level'] == 'LOW')

        return {
            'total': len(chains),
            'high': high_count,
            'medium': med_count,
            'low': low_count,
            'chains': chains
        }


def format_chain(chain):
    lines = []
    risk_symbol = "[高危]" if chain['risk_level'] == 'HIGH' else (
        "[中危]" if chain['risk_level'] == 'MEDIUM' else "[低危]"
    )

    lines.append(f"\n{risk_symbol} 攻击源 IP: {chain['attacker_ip']}")
    lines.append(f"涉及目标: {', '.join(chain['target_ips'])}")
    lines.append(f"告警总数: {chain['total_alerts']} 条")
    lines.append("-" * 55)
    lines.append("时间线与攻击演进步骤:")

    for idx, step in enumerate(chain['stages'], 1):
        lines.append(f"  [{idx}] {step['time']} | {step['stage']}")
        lines.append(f"      -> 目标: {step['dst_ip']}:{step['dst_port']}")
        lines.append(f"      -> 类型: {step['type']}")
        lines.append(f"      -> 详情: {step['detail']}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)
