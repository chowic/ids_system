# config.py
# 配置文件

SIGNATURE_FILE = "data/signatures.txt"

# 异常检测阈值
SCAN_THRESHOLD = 30          # 单IP每分钟连接数超过此值视为扫描
BRUTE_FORCE_THRESHOLD = 5    # 单IP每分钟失败登录次数
WHITELIST_IPS = ["8.8.8.8", "114.114.114.114", "223.5.5.5"]

# 统计窗口时间（秒）
STATS_WINDOW = 60

# 带宽阈值（字节），5秒内超过10MB视为异常
BANDWIDTH_THRESHOLD = 10 * 1024 * 1024

# 横向扩散阈值：访问不同内网IP数量超过此值视为横向扩散
LATERAL_THRESHOLD = 5

# 会话时长异常阈值（秒），默认1小时
SESSION_DURATION_THRESHOLD = 3600

# 日志文件
LOG_FILE = "logs/alerts.log"

# ========== 新增：TLS/SSL 恶意检测配置 ==========
# 恶意 SNI 域名黑名单（检测 TLS ClientHello 中的 SNI 字段）
MALICIOUS_SNIS = [
    "malicious-c2.com",
    "ngrok.io",           # 内网穿透工具，常被用于C2通信
    "evil-domain.com",
    "test.com",
    "c2-server.com",
    "malware.xyz",
    "bad-domain.net"
]

# 恶意 JA3 指纹黑名单（用于识别恶意 TLS 客户端）
# JA3 是 TLS 客户端的指纹，用于识别恶意软件
MALICIOUS_JA3S = [
    "e3b0c44298fc1c149afbf4c8996fb924",  # 示例：Cobalt Strike 默认 JA3
    "a0e9f5d64349fb13191bc781f81f42e1",  # 示例：Meterpreter
    "6734f37431670b3ab4292b8f60f29984",  # 示例：某些僵尸网络
]
