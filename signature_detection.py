# signature_detection.py
import os
import re

class SignatureDetector:
    def __init__(self, sig_file):
        self.signatures = []          # 列表元素: (name, compiled_regex)
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
                        name = parts[0].strip()
                        pattern = parts[1].strip()
                        # 尝试编译为正则，若失败则自动转义为普通字符串
                        try:
                            regex = re.compile(pattern, re.IGNORECASE)
                        except re.error:
                            # 若不是合法正则，则当作字面字符串，转义后编译
                            escaped = re.escape(pattern)
                            regex = re.compile(escaped, re.IGNORECASE)
                        self.signatures.append((name, regex))
        print(f"[*] 加载了 {len(self.signatures)} 条攻击特征 (支持正则)")

    def reload(self):
        """热更新特征库"""
        self.signatures = []
        self.load_signatures()

    def detect(self, payload_bytes):
        """
        检测payload中是否包含已知攻击特征（支持正则）
        返回: [(攻击名, 特征串), ...]
        """
        results = []
        if not payload_bytes:
            return results
        # 将payload转为字符串（支持UTF-8和Latin-1）
        try:
            payload_str = payload_bytes.decode('utf-8', errors='ignore')
        except:
            payload_str = payload_bytes.decode('latin-1', errors='ignore')
        for name, regex in self.signatures:
            if regex.search(payload_str):
                # 返回原始特征模式（便于查看）
                results.append((name, regex.pattern))
        return results