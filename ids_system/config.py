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