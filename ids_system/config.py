# config.py
# 配置文件

SIGNATURE_FILE = "data/signatures.txt"

# 异常检测阈值（作为后备，当基线未建立时使用）
SCAN_THRESHOLD = 15          # 单IP每分钟探测的不同端口数 (已优化为按不同端口统计)
BRUTE_FORCE_THRESHOLD = 10   # 单IP每分钟失败登录次数
WHITELIST_IPS = ["8.8.8.8", "114.114.114.114", "223.5.5.5"]

# 统计窗口时间（秒）
STATS_WINDOW = 60

# 带宽阈值（字节），5秒内超过500kB视为异常
BANDWIDTH_THRESHOLD = 500 * 1024

# 横向扩散阈值（后备）
LATERAL_THRESHOLD = 10

# 会话时长异常阈值（秒），默认1小时，若测试改为10秒
SESSION_DURATION_THRESHOLD = 3600

# 日志文件
LOG_FILE = "logs/alerts.log"

# ===== 新增基线学习配置 =====
BASELINE_LEARNING_TIME = 30   # 学习时长（秒）
BASELINE_FILE = "data/baseline.json"
USE_BASELINE = True           # 是否启用基线检测（若文件存在自动加载）

# ===== TLS 恶意流量检测配置 =====
MALICIOUS_SNIS = ["malicious-c2.com", "ngrok.io", "evil-domain.com"]
MALICIOUS_JA3S = []