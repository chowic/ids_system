# ai_detector.py
import numpy as np
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings("ignore")

class AIDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.is_trained = False
        self.baseline_data = []

    def _train_baseline(self):
        for _ in range(100):
            normal_traffic = [
                np.random.randint(1, 10),
                np.random.randint(1, 3),
                np.random.randint(40, 1500),
                np.random.uniform(10, 500),
                np.random.randint(1, 5)
            ]
            self.baseline_data.append(normal_traffic)
        self.model.fit(self.baseline_data)
        self.is_trained = True

    def detect_anomaly(self, connections, ports, pkt_size, avg_traffic, sessions):
        if not self.is_trained:
            self._train_baseline()
        current_data = np.array([[connections, ports, pkt_size, avg_traffic, sessions]])
        prediction = self.model.predict(current_data)
        is_anomaly = (prediction[0] == -1)
        if is_anomaly:
            print(f"[AI 引擎] 发现异常流量特征！数据: {current_data[0]}")
            return "Anomaly"
        else:
            return "Normal"
