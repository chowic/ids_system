# tls_detector.py
import hashlib
import config
from scapy.all import TCP, Raw

class TLSDetector:
    """TLS 恶意流量检测器"""

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        # 获取恶意 SNI 列表
        self.malicious_snis = getattr(config, "MALICIOUS_SNIS", ["malicious-c2.com", "ngrok.io", "evil-domain.com"])
        self.malicious_ja3s = getattr(config, "MALICIOUS_JA3S", [])
        print(f"[TLSDetector] 初始化完成，恶意SNI列表: {self.malicious_snis}")

    def detect(self, pkt, src_ip, dst_ip, dst_port):
        """
        检测 TLS 恶意流量
        返回: (bool, alert_info)
        """
        payload = self._extract_payload(pkt)
        if not payload or len(payload) < 5:
            return False, None

        # 1. 检查 TLS Handshake Record (0x16)
        if payload[0] != 0x16:
            return False, None

        # 2. 检查 Handshake Type 是否为 Client Hello (0x01)
        # record_header(5字节) + handshake_type(1字节)
        if len(payload) > 5 and payload[5] != 0x01:
            return False, None

        print(f"[TLSDetector] 🎯 捕获到 TLS ClientHello: {src_ip} -> {dst_ip}:{dst_port}")

        # 3. 解析 SNI 域名
        sni = self._extract_sni(payload)
        ja3 = self._calculate_simple_ja3(payload)
        
        print(f"[TLSDetector] 解析结果: SNI={sni}, JA3={ja3[:8]}...")

        # 4. 检查是否在恶意 SNI 黑名单中
        is_sni_malicious = False
        if sni != "Unknown":
            for m_sni in self.malicious_snis:
                if m_sni.lower() in sni.lower():
                    is_sni_malicious = True
                    break

        if is_sni_malicious:
            print(f"[TLSDetector] ⚠️ 匹配恶意SNI: {sni}")
            alert_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'type': 'TLS恶意通信: 恶意C2域名',
                'detail': f'检测到恶意 TLS 请求指向可疑域名 SNI: {sni} (JA3: {ja3[:8]}...)'
            }
            return True, alert_info

        # 5. 检查恶意 JA3 指纹
        if ja3 in self.malicious_ja3s:
            print(f"[TLSDetector] ⚠️ 匹配恶意JA3: {ja3}")
            alert_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'type': 'TLS恶意通信: 恶意JA3指纹',
                'detail': f'检测到恶意 TLS 客户端指纹 JA3: {ja3} (SNI: {sni})'
            }
            return True, alert_info

        return False, None

    def _extract_payload(self, pkt):
        """准确提取 TCP Payload"""
        try:
            if pkt.haslayer(Raw):
                return bytes(pkt[Raw].load)
            elif pkt.haslayer(TCP):
                return bytes(pkt[TCP].payload)
        except Exception:
            pass
        return b''

    def _extract_sni(self, payload):
        """提取 TLS SNI"""
        try:
            # 1. 优先搜索字符串（最稳妥兜底）
            for m_sni in self.malicious_snis:
                if m_sni.encode('utf-8') in payload:
                    return m_sni

            # 2. 结构化解析
            pos = 43 # Record(5) + Handshake(4) + Version(2) + Random(32)
            if pos >= len(payload): return "Unknown"
            
            session_id_len = payload[pos]
            pos += 1 + session_id_len + 2
            
            if pos >= len(payload): return "Unknown"
            cipher_len = (payload[pos - 2] << 8) | payload[pos - 1]
            pos += cipher_len
            
            if pos >= len(payload): return "Unknown"
            compress_len = payload[pos]
            pos += 1 + compress_len + 2
            
            end_pos = len(payload)
            while pos + 4 <= end_pos:
                ext_type = (payload[pos] << 8) | payload[pos + 1]
                ext_len = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4

                if ext_type == 0 and pos + 5 <= end_pos: # extension: server_name
                    name_len = (payload[pos + 3] << 8) | payload[pos + 4]
                    if pos + 5 + name_len <= end_pos:
                        return payload[pos + 5: pos + 5 + name_len].decode('utf-8', errors='ignore')
                pos += ext_len
        except Exception:
            pass
        return "Unknown"

    def _calculate_simple_ja3(self, payload):
        try:
            version = (payload[9] << 8) | payload[10] if len(payload) > 10 else 0
            ja3_str = f"{version},{len(payload)}"
            return hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
        except Exception:
            return "00000000000000000000000000000000"