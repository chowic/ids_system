# signature_detection.py
import os

class SignatureDetector:
    def __init__(self, sig_file):
        self.signatures = []
        self.sig_file = sig_file
        self.load_signatures()

    def load_signatures(self):
        if not os.path.exists(self.sig_file):
            print(f"[!] 特征库文件不存在: {self.sig_file}")
            return
        with open(self.sig_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('|')
                    if len(parts) == 2:
                        self.signatures.append({
                            'name': parts[0].strip(),
                            'pattern': parts[1].strip().encode('utf-8')
                        })
        print(f"[*] 加载了 {len(self.signatures)} 条攻击特征")

    def reload(self):
        """热更新特征库"""
        self.signatures = []
        self.load_signatures()

    def detect(self, payload_bytes):
        """
        检测payload中是否包含已知攻击特征
        返回: [(攻击名, 特征串), ...]
        """
        results = []
        if not payload_bytes:
            return results
        for sig in self.signatures:
            if sig['pattern'] in payload_bytes:
                results.append((sig['name'], sig['pattern'].decode('utf-8', errors='ignore')))
        return results