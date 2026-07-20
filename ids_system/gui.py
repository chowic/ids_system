# gui.py
import sys
import os
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableView, QHeaderView,
    QStatusBar, QMessageBox, QFileDialog, QAbstractItemView,
    QTextEdit, QDialog, QDialogButtonBox)
# 新增 pyqtSignal，解决抓包子线程直接更新 GUI 导致的崩溃问题
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
        if role == Qt.DisplayRole:
            alert = self.alert_manager.alerts[index.row()]
            fields = ['id', 'time', 'src_ip', 'dst_ip', 'dst_port', 'type', 'detail']
            value = alert[fields[index.column()]]
            return str(value)
        elif role == Qt.TextColorRole:
            alert = self.alert_manager.alerts[index.row()]
            if 'TLS' in alert['type']:                        # <--- 新增 TLS 高亮显示 (深红色)
                return QColor(220, 20, 60)
            elif 'SQL' in alert['type'] or '命令' in alert['type'] or 'XSS' in alert['type']:
                return QColor(255, 0, 0)      # 红色 - 严重
            elif '扫描' in alert['type']:
                return QColor(255, 165, 0)    # 橙色 - 中等
            elif '暴力' in alert['type']:
                return QColor(255, 0, 255)    # 紫色 - 高危
            elif '外联' in alert['type']:
                return QColor(0, 0, 255)      # 蓝色 - 可疑
            return None
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def add_alert(self, alert):
        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self.endInsertRows()

    def refresh(self):
        self.layoutChanged.emit()


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
        self.capture.start()

    def stop(self):
        if self.capture:
            self.capture.stop()
        self.quit()
        self.wait()


class IDSGui(QMainWindow):
    # 定义 Qt 信号，解决跨线程安全调用问题 (整合自前面的版本)
    new_alert_signal = pyqtSignal(dict)

    def __init__(self, alert_manager):
        super().__init__()
        self.alert_manager = alert_manager
        
        # 绑定 Qt 信号到主线程槽函数
        self.new_alert_signal.connect(self.on_new_alert)
        self.alert_manager.register_callback(lambda alert: self.new_alert_signal.emit(alert))
        
        self.capture_thread = None
        self.sig_detector = None   
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

        self.reload_btn = QPushButton('🔄 重载特征')
        self.reload_btn.setStyleSheet(
            'QPushButton { background-color: #FFA500; color: white; '
            'font-weight: bold; padding: 8px; border-radius: 4px; }'
            'QPushButton:hover { background-color: #FF8C00; }'
        )
        self.reload_btn.clicked.connect(self.reload_signatures)
        
        self.clear_btn = QPushButton('🗑 清空告警')
        self.clear_btn.clicked.connect(self.clear_alerts)
        
        self.export_btn = QPushButton('📤 导出日志')
        self.export_btn.clicked.connect(self.export_logs)
         # ===== 攻击链按钮（新增） =====
        self.chain_btn = QPushButton('🔗 攻击链')
        self.chain_btn.clicked.connect(self.show_attack_chain)
        
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.reload_btn)   
        toolbar.addWidget(self.export_btn)
        toolbar.addWidget(self.chain_btn)  # ← 添加这行
        toolbar.addStretch()
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        toolbar.addStretch()
        
        self.status_label = QLabel('⏸ 状态: 未启动')
        self.status_label.setStyleSheet('font-weight: bold; padding: 5px;')
        toolbar.addWidget(self.status_label)
        layout.addLayout(toolbar)

        # ===== 统计信息 =====
        stats_layout = QHBoxLayout()
        
        self.total_label = QLabel('📊 总告警: 0')
        self.total_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        # <--- 新增 TLS 统计标签 --->
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

        self.lateral_label = QLabel('🔄 横向扩散: 0')
        self.lateral_label.setStyleSheet('font-weight: bold; font-size: 12px;')

        self.bandwidth_label = QLabel('📶 带宽异常: 0')
        self.bandwidth_label.setStyleSheet('font-weight: bold; font-size: 12px;')
        
        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(self.tls_label)      # 加入布局
        stats_layout.addWidget(self.scan_label)
        stats_layout.addWidget(self.brute_label)
        stats_layout.addWidget(self.web_label)
        stats_layout.addWidget(self.trojan_label)
        stats_layout.addWidget(self.lateral_label)
        stats_layout.addWidget(self.bandwidth_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # ===== 告警表格 =====
        self.table_model = AlertTableModel(self.alert_manager)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSortingEnabled(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # 设置列宽
        self.table_view.setColumnWidth(0, 50)    
        self.table_view.setColumnWidth(1, 160)   
        self.table_view.setColumnWidth(2, 130)   
        self.table_view.setColumnWidth(3, 130)   
        self.table_view.setColumnWidth(4, 60)    
        self.table_view.setColumnWidth(5, 200)   
        
        layout.addWidget(self.table_view)

        # ===== 底部状态栏 =====
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage('就绪 | 请点击"开始检测"启动入侵检测系统')

        # ===== 定时刷新统计 =====
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)

    def on_new_alert(self, alert):
        self.table_model.add_alert(alert)
        self.table_view.scrollToBottom()
        self.statusBar.showMessage(
            f'[新告警] {alert["time"]} {alert["src_ip"]} -> {alert["dst_ip"]}: {alert["type"]}',
            3000
        )

    def update_stats(self):
        stats = self.alert_manager.get_stats()
        self.total_label.setText(f'📊 总告警: {stats["total"]}')
        self.tls_label.setText(f'🔒 TLS异常: {stats.get("tls", 0)}') # <--- 更新 TLS 数量
        self.scan_label.setText(f'🔍 端口扫描: {stats["scan"]}')
        self.brute_label.setText(f'🔑 暴力破解: {stats["brute"]}')
        self.web_label.setText(f'🌐 Web攻击: {stats["web"]}')
        self.trojan_label.setText(f'🐴 木马/后门: {stats.get("trojan", 0)}')
        self.lateral_label.setText(f'🔄 横向扩散: {stats.get("lateral", 0)}')
        self.bandwidth_label.setText(f'📶 带宽异常: {stats.get("bandwidth", 0)}')

    def start_capture(self):
        from packet_capture import PacketCapture
        from signature_detection import SignatureDetector
        from anomaly_detection import AnomalyDetector
        import config

        if not os.path.exists(config.SIGNATURE_FILE):
            QMessageBox.warning(
                self, 
                '警告', 
                f'特征库文件不存在:\n{config.SIGNATURE_FILE}\n\n请创建 data/signatures.txt 文件'
            )
            return

        try:
            sig_detector = SignatureDetector(config.SIGNATURE_FILE)
            if len(sig_detector.signatures) == 0:
                QMessageBox.warning(self, '警告', '特征库为空，请添加攻击特征')
                return
        except Exception as e:
            QMessageBox.critical(self, '错误', f'加载特征库失败: {e}')
            return

        self.sig_detector = sig_detector

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
        self.statusBar.showMessage('正在停止抓包...')

    def on_capture_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('⏸ 状态: 已停止')
        self.status_label.setStyleSheet('font-weight: bold; color: #666; padding: 5px;')
        self.statusBar.showMessage('检测已停止', 2000)

    def reload_signatures(self):
        if self.sig_detector is None:
            QMessageBox.information(self, '提示', '请先启动检测（加载特征库）再重载，或直接点击开始检测。')
            return
        try:
            self.sig_detector.reload()
            count = len(self.sig_detector.signatures)
            self.statusBar.showMessage(f'✅ 特征库重载成功，当前共 {count} 条特征', 3000)
            QMessageBox.information(self, '成功', f'特征库重载完成！\n当前共加载 {count} 条攻击特征。')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'重载特征库失败：{e}')

    def clear_alerts(self):
        if len(self.alert_manager.alerts) == 0:
            QMessageBox.information(self, '提示', '当前没有告警记录')
            return
            
        reply = QMessageBox.question(
            self, 
            '确认清空', 
            f'确定要清空所有告警记录吗？\n(共 {len(self.alert_manager.alerts)} 条记录)',
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.alert_manager.clear_alerts()
            self.table_model.refresh()
            self.statusBar.showMessage('已清空所有告警', 2000)

    def export_logs(self):
        import config
        import shutil
        
        if not os.path.exists(config.LOG_FILE):
            QMessageBox.information(self, '提示', '没有日志文件可导出')
            return

        if os.path.getsize(config.LOG_FILE) == 0:
            QMessageBox.information(self, '提示', '日志文件为空，没有内容可导出')
            return

        default_name = f"ids_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            '导出日志', 
            default_name, 
            '日志文件 (*.log);;文本文件 (*.txt);;所有文件 (*)'
        )

        if file_path:
            try:
                shutil.copy(config.LOG_FILE, file_path)
                QMessageBox.information(self, '成功', f'日志已导出到:\n{file_path}')
                self.statusBar.showMessage(f'日志已导出: {file_path}', 3000)
            except Exception as e:
                QMessageBox.critical(self, '错误', f'导出失败: {e}')
        # ===== 攻击链分析 =====
    def show_attack_chain(self):
        from attack_chain import AttackChainAnalyzer, format_chain
        analyzer = AttackChainAnalyzer(self.alert_manager)
        summary = analyzer.get_summary()

        if summary['total'] == 0:
            QMessageBox.information(self, '提示', '暂无攻击链数据')
            return

        lines = []
        lines.append("=" * 60)
        lines.append(f"共 {summary['total']} 条攻击链")
        lines.append(f"高危: {summary['high']}  中危: {summary['medium']}  低危: {summary['low']}")
        lines.append("=" * 60)

        for chain in summary['chains']:
            lines.append(format_chain(chain))

        dialog = QDialog(self)
        dialog.setWindowTitle("攻击链分析")
        dialog.resize(800, 500)
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setFontFamily("monospace")
        text.setPlainText("\n".join(lines))
        layout.addWidget(text)
        btn = QDialogButtonBox(QDialogButtonBox.Ok)
        btn.accepted.connect(dialog.accept)
        layout.addWidget(btn)
        dialog.exec_()