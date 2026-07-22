# 网络入侵检测系统 (IDS) v3.0

基于 Python + PyQt5 + Scapy 的实时网络入侵检测系统，融合特征匹配、AI智能分析、TLS恶意检测、攻击链分析、基线学习等多种检测手段。

## 功能特性

### 1. 多引擎检测体系

| 检测引擎 | 说明 |
|---------|------|
| **特征匹配** | 基于自定义特征库（签名）检测SQL注入、XSS、命令执行、木马等攻击 |
| **AI智能分析** | 使用IsolationForest算法，实时分析流量特征异常 |
| **TLS恶意检测** | 检测TLS握手包中的恶意SNI域名和JA3指纹 |
| **异常行为检测** | 端口扫描、暴力破解、异常外联、横向扩散、带宽异常、会话时长异常 |
| **攻击链分析** | 将告警按攻击源IP关联，识别完整攻击演进路径 |
| **基线学习** | 自动学习正常流量基线，降低误报率 |

### 2. 误报降噪

- **告警聚合**：同一IP同类型告警在60秒内合并为一条，显示"共发现N次"
- **资产重要性权重**：核心路由器、数据库等关键资产告警严重度自动提升
- **基线自适应**：学习正常流量后，按基线动态调整检测阈值
- **严重度分级**：1-100分自动计算，分为严重/高危/中危/低危四档

### 3. GUI界面

- **实时统计面板**：总流量、攻击数、扫描数、SQL注入、XSS攻击、TLS恶意、AI检测、今日风险
- **实时曲线图**：流量(bps)、包速率(pps)、告警数三条曲线
- **告警列表**：支持过滤（SQL/XSS/扫描/暴力破解/TLS/AI等）、搜索（IP/时间/详情）、排序
- **特征库管理**：图形化增删改查攻击特征，支持保存/重新加载
- **资产管理**：管理受保护资产及其重要性等级
- **攻击链分析**：一键分析攻击演进路径，支持导出报告
- **基线学习**：一键启动30秒学习期，自动建立流量基线
- **CSV导出**：导出所有告警记录

## 项目结构

```
ids_system/
├── main.py                 # 程序入口
├── gui.py                  # PyQt5 GUI界面
├── alert_manager.py        # 告警管理（降噪、严重度、资产、基线）
├── packet_capture.py       # 抓包引擎（TLS/AI/基线学习/自动网卡）
├── signature_detection.py  # 特征匹配检测
├── anomaly_detection.py    # 异常行为检测（含基线学习）
├── ai_detector.py          # AI智能检测（IsolationForest）
├── tls_detector.py         # TLS恶意流量检测
├── attack_chain.py         # 攻击链分析引擎
├── config.py               # 配置文件
├── test_attack.py          # 单功能测试脚本
├── test_attackchain.py     # 完整攻击链测试脚本
└── data/
    ├── signatures.txt      # 攻击特征库
    └── baseline.json       # 基线数据（自动保存）
```

## 安装依赖

```bash
pip install scapy PyQt5 scikit-learn numpy
```

Windows 用户可能还需要安装 Npcap/WinPcap。

## 使用方法

### 1. 启动GUI

```bash
cd ids_system
python main.py
```

### 2. 开始检测

点击 **"开始检测"** 按钮，系统自动选择网卡并开始抓包分析。

### 3. 基线学习（推荐首次使用）

点击 **"基线学习"** 按钮，系统进入30秒学习期，只记录正常流量不告警。学习完成后自动保存基线数据。

### 4. 攻击链分析

产生一定数量的告警后，点击 **"攻击链分析"** 按钮，系统按攻击源IP关联告警，展示完整攻击演进路径。

### 5. 测试攻击流量

```bash
# 单功能测试
python test_attack.py

# 完整攻击链测试（扫描->漏洞利用->C2通信->横向扩散）
python test_attackchain.py
```

## 配置说明

编辑 `config.py`：

```python
# 扫描阈值（每分钟探测端口数）
SCAN_THRESHOLD = 15

# 暴力破解阈值（每分钟失败登录次数）
BRUTE_FORCE_THRESHOLD = 10

# 带宽阈值（5秒内字节数）
BANDWIDTH_THRESHOLD = 500 * 1024

# 白名单IP
WHITELIST_IPS = ["8.8.8.8", "114.114.114.114"]

# 基线学习时长（秒）
BASELINE_LEARNING_TIME = 30

# 恶意TLS域名
MALICIOUS_SNIS = ["malicious-c2.com", "ngrok.io"]
```

## 攻击特征库格式

编辑 `data/signatures.txt`：

```
# 攻击描述|特征串
SQL注入|SELECT * FROM
SQL注入|' OR '1'='1
XSS攻击|<script>
命令执行|cmd.exe
WebShell|eval(
```

## 系统要求

- Python 3.7+
- Windows / Linux / macOS
- 管理员/root权限（用于抓包）

## 技术架构

```
流量数据
   |
抓包引擎 (PacketCapture)
   |
   |---> 特征匹配 (SignatureDetector)
   |---> TLS检测 (TLSDetector)
   |---> AI分析 (AIDetector)
   |---> 异常检测 (AnomalyDetector)
   |---> 基线学习 (Baseline)
   |
告警管理 (AlertManager)
   |---> 降噪聚合
   |---> 严重度评分
   |---> 资产权重
   |
GUI展示 (PyQt5)
   |---> 实时统计/曲线
   |---> 告警列表/过滤/搜索
   |---> 攻击链分析
   |---> 特征库/资产管理
```

## 更新日志

### v3.0 (合并版)
- 融合ids_system1和ids_system2全部功能
- 新增AI智能检测引擎
- 新增TLS恶意流量检测
- 新增攻击链分析功能
- 新增基线学习功能
- 新增自动网卡选择
- 优化GUI界面，增加TLS/AI统计面板
- 优化告警聚合和降噪算法

### v2.0
- 新增误报降噪（告警聚合、资产权重、基线学习）
- 新增统计面板和实时曲线
- 新增过滤、搜索、CSV导出
- 新增特征库管理和资产管理界面

### v1.0
- 基础特征匹配检测
- 端口扫描、暴力破解、异常外联检测
- 基础GUI界面
