# gui.py
import sys
import os
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableView, QHeaderView,
    QStatusBar, QMessageBox, QFileDialog, QAbstractItemView
)
from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QTimer, QThread, pyqtSignal
)
from PyQt5.QtGui import QColor

from alert_manager import AlertManager


class AlertTableModel(QAbstractTableModel):
    def __init__(self, alert_manager):
        super().__init__()
        self.alert_manager = alert_manager
        self.headers = ['ID', '时间', '源IP', '目的IP', '端口', '告警类型', '详情']

    def rowCount(self, parent=QModelIndex()):
        return len(self.alert_manager.alerts)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
            
        alert = self.alert_manager.alerts[index.row()]
        if role == Qt.DisplayRole:
            fields = ['id', 'time', 'src_ip', 'dst_ip', 'dst_port', 'type', 'detail']
            return str(alert[fields[index.column()]])
        elif role == Qt.TextColorRole:
            if 'TLS' in alert['type']:
                return QColor(220, 20, 60)    # 深红色 - TLS 恶意域名/指纹
            elif any(k in alert['type'] for k in ['SQL', '命令', 'XSS']):
                return QColor(255, 0, 0)      # 红色 - Web 攻击
            elif '扫描' in alert['type']:
                return QColor(255, 165, 0)    # 橙色 - 扫描
            elif '暴力' in alert['type']:
                return QColor(255, 0, 255)    # 紫色 - 暴力破解
            elif '外联' in alert['type']:
                return QColor(0, 102, 204)    # 蓝色 - 异常外联
            return None
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def refresh(self):
        self.beginResetModel()
        self.endResetModel()


class CaptureThread(QThread):
    def __init__(self, sig_detector, anomaly_detector, alert_manager):
        super().__init__()
        self.sig_detector = sig_detector
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.capture = None

    def run(self):
        from packet_capture import PacketCapture
        self.capture = PacketCapture(
            self.sig_detector,
            self.anomaly_detector,
            self.alert_manager
        )
        self.capture.start(iface=None)

    def stop(self):
        if self.capture:
            self.capture.stop()
        self.quit()
        self.wait()


class IDSGui(QMainWindow):
    # 定义 Qt 信号，解决跨线程安全调用问题
    new_alert_signal = pyqtSignal(dict)

    def __init__(self, alert_manager):
        super().__init__()
        self.alert_manager = alert_manager
        
        # 绑定 Qt 信号到主线程槽函数
        self.new_alert_signal.connect(self.handle_new_alert)
        self.alert_manager.register_callback(lambda alert: self.new_alert_signal.emit(alert))
        
        self.capture_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('网络入侵检测系统 v1.0')
        self.setGeometry(100, 100, 1300, 700)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # ===== 工具栏 =====
        toolbar = QHBoxLayout()

        self.start_btn = QPushButton('▶ 开始检测')
        self.start_btn.setStyleSheet(
            'QPushButton { background-color: #4CAF50; color: white; '
            'font-weight: bold; padding: 8px; border-radius: 4px; }'
            'QPushButton:hover { background-color: #45a049; }'
        )
        self.start_btn.clicked.connect(self.start_capture)

        self.stop_btn = QPushButton('■ 停止检测')
        self.stop_btn.setStyleSheet(
            'QPushButton { background-color: #f44336; color: white; '
            'font-weight: bold; padding: 8px; border-radius: 4px; }'
            'QPushButton:hover { background-color: #d32f2f; }'
        )
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)

        self.clear_btn = QPushButton('🗑 清空告警')
        self.clear_btn.clicked.connect(self.clear_alerts)

        self.export_btn = QPushButton('📤 导出日志')
        self.export_btn.clicked.connect(self.export_logs)

        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        toolbar.addStretch()

        self.status_label = QLabel('⏸ 状态: 未启动')
        self.status_label.setStyleSheet('font-weight: bold; padding: 5px;')
        toolbar.addWidget(self.status_label)
        layout.addLayout(toolbar)

        # ===== 统计面板 =====
        stats_layout = QHBoxLayout()

        self.total_label = QLabel('📊 总告警: 0')
        self.total_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        self.tls_label = QLabel('🔒 TLS异常: 0')
        self.tls_label.setStyleSheet('font-weight: bold; font-size: 12px; color: #DC143C;')

        self.scan_label = QLabel('🔍 端口扫描: 0')
        self.scan_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        self.brute_label = QLabel('🔑 暴力破解: 0')
        self.brute_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        self.web_label = QLabel('🌐 Web攻击: 0')
        self.web_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        self.trojan_label = QLabel('🐴 木马/后门: 0')
        self.trojan_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(self.tls_label)
        stats_layout.addWidget(self.scan_label)
        stats_layout.addWidget(self.brute_label)
        stats_layout.addWidget(self.web_label)
        stats_layout.addWidget(self.trojan_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # ===== 告警表格 =====
        self.table_model = AlertTableModel(self.alert_manager)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.horizontalHeader().setStretchLastSection(True)

        self.table_view.setColumnWidth(0, 50)    # ID
        self.table_view.setColumnWidth(1, 150)   # 时间
        self.table_view.setColumnWidth(2, 130)   # 源IP
        self.table_view.setColumnWidth(3, 130)   # 目的IP
        self.table_view.setColumnWidth(4, 60)    # 端口
        self.table_view.setColumnWidth(5, 180)   # 告警类型

        layout.addWidget(self.table_view)

        # ===== 状态栏 =====
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage('就绪 | 请点击"开始检测"')

        # 启动定时刷新统计面板（每秒 1 次）
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)

    def handle_new_alert(self, alert):
        """安全地在主线程中更新 UI"""
        self.table_model.refresh()
        self.table_view.scrollToBottom()
        self.update_stats()
        self.statusBar.showMessage(
            f'[新告警] {alert["time"]} {alert["src_ip"]} -> {alert["dst_ip"]}: {alert["type"]}',
            3000
        )

    def update_stats(self):
        stats = self.alert_manager.get_stats()
        self.total_label.setText(f'📊 总告警: {stats["total"]}')
        self.tls_label.setText(f'🔒 TLS异常: {stats.get("tls", 0)}')
        self.scan_label.setText(f'🔍 端口扫描: {stats["scan"]}')
        self.brute_label.setText(f'🔑 暴力破解: {stats["brute"]}')
        self.web_label.setText(f'🌐 Web攻击: {stats["web"]}')
        self.trojan_label.setText(f'🐴 木马/后门: {stats.get("trojan", 0)}')

    def start_capture(self):
        from signature_detection import SignatureDetector
        from anomaly_detection import AnomalyDetector
        import config

        if not os.path.exists(config.SIGNATURE_FILE):
            QMessageBox.warning(self, '警告', f'特征库文件不存在:\n{config.SIGNATURE_FILE}')
            return

        try:
            sig_detector = SignatureDetector(config.SIGNATURE_FILE)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'加载特征库失败: {e}')
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText('▶ 状态: 检测中...')
        self.status_label.setStyleSheet('font-weight: bold; color: #4CAF50; padding: 5px;')
        self.statusBar.showMessage('正在抓包检测...')

        anomaly_detector = AnomalyDetector()

        self.capture_thread = CaptureThread(
            sig_detector,
            anomaly_detector,
            self.alert_manager
        )
        self.capture_thread.finished.connect(self.on_capture_stopped)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
        self.status_label.setText('⏹ 状态: 正在停止...')
        self.status_label.setStyleSheet('font-weight: bold; color: #f44336; padding: 5px;')

    def on_capture_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('⏸ 状态: 已停止')
        self.status_label.setStyleSheet('font-weight: bold; color: #666; padding: 5px;')
        self.statusBar.showMessage('检测已停止', 2000)

    def clear_alerts(self):
        if len(self.alert_manager.alerts) == 0:
            return
        reply = QMessageBox.question(
            self, '确认清空', f'确定清空所有 {len(self.alert_manager.alerts)} 条告警？',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.alert_manager.clear_alerts()
            self.table_model.refresh()
            self.update_stats()

    def export_logs(self):
        import config
        import shutil

        if not os.path.exists(config.LOG_FILE) or os.path.getsize(config.LOG_FILE) == 0:
            QMessageBox.information(self, '提示', '没有可导出的日志')
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, '导出日志', f"ids_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", '日志文件 (*.log)'
        )
        if file_path:
            try:
                shutil.copy(config.LOG_FILE, file_path)
                QMessageBox.information(self, '成功', f'日志已导出到:\n{file_path}')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'导出失败: {e}')