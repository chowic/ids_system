# tls_detector.py
"""
TLS/SSL 恶意流量检测模块
独立于主检测逻辑，专门用于 TLS 协议分析
"""
import hashlib
import config


class TLSDetector:
    """TLS 恶意流量检测器"""

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.malicious_snis = getattr(
            config, "MALICIOUS_SNIS", [
                "malicious-c2.com", "ngrok.io"])
        self.malicious_ja3s = getattr(config, "MALICIOUS_JA3S", [])
        print(f"[TLSDetector] 初始化完成，恶意SNI列表: {self.malicious_snis}")

    def detect(self, pkt, src_ip, dst_ip, dst_port):
        """
        检测 TLS 恶意流量
        返回: (bool, alert_info)  (是否检测到恶意, 告警信息)
        """
        # 1. 检查是否为 TLS 包
        payload = self._extract_payload(pkt)
        if not payload or len(payload) < 5:
            return False, None

        # 2. 检查是否为 TLS ClientHello (0x16 0x03)
        if not (payload[0] == 0x16 and payload[1] == 0x03):
            return False, None

        print(
            f"[TLSDetector] 检测到TLS ClientHello: {src_ip} -> {dst_ip}:{dst_port}")
        print(f"[TLSDetector] payload前20字节: {payload[:20].hex()}")

        # 3. 解析 TLS ClientHello
        tls_info = self._parse_client_hello(payload)
        if not tls_info:
            print(f"[TLSDetector] 解析TLS ClientHello失败")
            return False, None

        sni = tls_info.get('sni', 'Unknown')
        ja3 = tls_info.get('ja3', '')
        print(f"[TLSDetector] 解析结果: SNI={sni}, JA3={ja3}")

        # 4. 检查恶意域名
        if sni in self.malicious_snis:
            print(f"[TLSDetector] ⚠️ 匹配恶意SNI: {sni}")
            alert_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'type': 'TLS恶意通信: 恶意C2域名',
                'detail': f'检测到恶意 TLS 请求指向可疑域名 SNI: {sni} (JA3: {ja3[:8]}...)'
            }
            return True, alert_info

        # 5. 检查恶意 JA3 指纹（可选）
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

        print(f"[TLSDetector] SNI '{sni}' 不在黑名单中，放行")
        return False, None

    def _extract_payload(self, pkt):
        """从数据包中提取 TCP payload"""
        try:
            if pkt.haslayer('TCP'):
                tcp_layer = pkt['TCP']
                return bytes(tcp_layer.payload) if tcp_layer.payload else b''
        except BaseException:
            pass
        return b''

    def _parse_client_hello(self, payload):
        """
        手动解析 TLS ClientHello
        返回: {'sni': 'domain.com', 'ja3': 'md5hash', 'version': 0x0303}
        """
        try:
            if len(payload) < 43:
                return None

            # 跳过记录头 (5) + 握手头 (4) + 版本 (2) + 随机数 (32) = 43
            pos = 43

            # Session ID 长度
            if pos >= len(payload):
                return None
            session_id_len = payload[pos]
            pos += 1 + session_id_len

            # 密码套件长度
            if pos + 1 >= len(payload):
                return None
            cipher_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2 + cipher_len

            # 压缩方法长度
            if pos >= len(payload):
                return None
            compress_len = payload[pos]
            pos += 1 + compress_len

            # 扩展长度
            if pos + 1 >= len(payload):
                return None
            extensions_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2

            # 解析扩展，查找 SNI
            sni = "Unknown"
            end_pos = min(pos + extensions_len, len(payload))

            while pos + 4 <= end_pos:
                ext_type = (payload[pos] << 8) | payload[pos + 1]
                ext_len = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4

                if ext_type == 0:  # server_name 扩展
                    # ServerNameList 长度
                    if pos + 2 > end_pos:
                        break
                    pos += 2  # 跳过 name_list_len

                    # 解析 ServerName
                    if pos + 3 > end_pos:
                        break
                    name_type = payload[pos]
                    name_len = (payload[pos + 1] << 8) | payload[pos + 2]
                    pos += 3

                    if name_type == 0 and pos + name_len <= end_pos:
                        sni = payload[pos:pos +
                                      name_len].decode('utf-8', errors='ignore')
                        break

                pos += ext_len

            # 生成 JA3 指纹（简化版）
            # 实际 JA3 需要更多字段，这里简化为 TLS版本+密码套件
            version = (payload[9] << 8) | payload[10] if len(
                payload) > 10 else 0
            ja3_string = f"{version},{cipher_len}"
            ja3 = hashlib.md5(ja3_string.encode('utf-8')).hexdigest()

            return {
                'sni': sni,
                'ja3': ja3,
                'version': version
            }

        except Exception as e:
            print(f"[TLSDetector] 解析错误: {e}")
            return None
