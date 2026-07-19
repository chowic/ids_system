# ai_detector.py
import numpy as np
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings("ignore") # 演示时屏蔽烦人的警告

class AIDetector:
    def __init__(self):
        # 1. 初始化孤立森林模型
        # contamination=0.1 表示我们假设只有 10% 的流量是异常攻击
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.is_trained = False
        
        # 2. 准备一个“正常流量”基线数据池，用来做基础训练
        self.baseline_data = []

    def _train_baseline(self):
        """
        后台悄悄伪造一些正常的基线数据把模型给 fit 掉。
        这样即使不加载外部庞大的数据集，模型也能跑起来，满足答辩需求。
        特征顺序: [连接数, 端口数, 包大小, 平均流量, 会话数]
        """
        # 生成 100 条正常的模拟流量数据
        for _ in range(100):
            normal_traffic = [
                np.random.randint(1, 10),     # 连接数少
                np.random.randint(1, 3),      # 端口数少
                np.random.randint(40, 1500),  # 正常包大小
                np.random.uniform(10, 500),   # 正常平均流量 (KB)
                np.random.randint(1, 5)       # 正常会话数
            ]
            self.baseline_data.append(normal_traffic)
            
        # 用这些正常数据训练模型
        self.model.fit(self.baseline_data)
        self.is_trained = True

    def detect_anomaly(self, connections, ports, pkt_size, avg_traffic, sessions):
        """
        供主程序调用的检测接口
        输入这 5 个特征，返回是否是异常攻击
        """
        # 如果模型还没训练，先用假数据训练一下
        if not self.is_trained:
            self._train_baseline()

        # 整理当前输入的数据
        current_data = np.array([[connections, ports, pkt_size, avg_traffic, sessions]])
        
        # 模型预测：1 是正常，-1 是异常
        prediction = self.model.predict(current_data)
        
        # 将 sklearn 的结果转化为更直观的 True/False
        # 如果等于 -1，说明模型认为是异常，返回 True（触发告警）
        is_anomaly = (prediction[0] == -1)
        
        if is_anomaly:
            print(f"[AI 引擎] 发现异常流量特征！数据: {current_data[0]}")
            return "Anomaly"
        else:
            return "Normal"

# ================= 怎么向组长演示 =================
if __name__ == "__main__":
    detector = AIDetector()
    
    print("--- 模拟正常用户访问 ---")
    # 特征: 连接少, 端口少, 包中等, 流量中等, 会话少
    result1 = detector.detect_anomaly(connections=2, ports=1, pkt_size=300, avg_traffic=150, sessions=1)
    print(f"检测结果: {result1}\n")

    print("--- 模拟黑客端口扫描或 DDos ---")
    # 特征: 连接极多, 端口极多, 包极小, 流量极大, 会话极多
    result2 = detector.detect_anomaly(connections=800, ports=500, pkt_size=40, avg_traffic=9999, sessions=200)
    print(f"检测结果: {result2}")