import sys
import os
import csv
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableView, QHeaderView,
    QStatusBar, QMessageBox, QFileDialog, QAbstractItemView,
    QLineEdit, QComboBox, QTabWidget, QListWidget, QListWidgetItem,
    QDialog, QFormLayout, QDialogButtonBox, QSpinBox,
    QGroupBox, QCheckBox, QFrame
)
from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QTimer, QThread, pyqtSignal
)
from PyQt5.QtGui import QColor, QPainter, QPen, QFont

from alert_manager import AlertManager
from attack_chain import AttackChainAnalyzer, format_chain


class AlertTableModel(QAbstractTableModel):
    def __init__(self, alert_manager):
        super().__init__()
        self.alert_manager = alert_manager
        self.headers = ['ID', '时间', '源IP', '目的IP', '端口', '告警类型', '严重度', '次数', '详情']
        self.filter_type = '全部'
        self.search_text = ''
        self.filtered_alerts = []
        self._apply_filter()

    def rowCount(self, parent=QModelIndex()):
        return len(self.filtered_alerts)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            alert = self.filtered_alerts[index.row()]
            fields = ['id', 'time', 'src_ip', 'dst_ip', 'dst_port', 'type', 'severity_display', 'occurrence_count', 'detail']
            field = fields[index.column()]
            if field == 'severity_display':
                sev = alert.get('severity', 50)
                if sev >= 80:
                    return '严重'
                elif sev >= 60:
                    return '高危'
                elif sev >= 40:
                    return '中危'
                else:
                    return '低危'
            value = alert.get(field, '')
            return str(value)
        elif role == Qt.TextColorRole:
            alert = self.filtered_alerts[index.row()]
            sev = alert.get('severity', 50)
            if sev >= 80:
                return QColor(220, 20, 60)
            elif sev >= 60:
                return QColor(255, 69, 0)
            elif sev >= 40:
                return QColor(255, 165, 0)
            else:
                return QColor(100, 149, 237)
        elif role == Qt.BackgroundRole:
            alert = self.filtered_alerts[index.row()]
            if alert.get('is_aggregated', False):
                return QColor(255, 250, 205)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def _apply_filter(self):
        all_alerts = self.alert_manager.alerts
        filtered = []
        for a in all_alerts:
            if self.filter_type != '全部':
                if self.filter_type == 'SQL注入' and 'SQL' not in a['type']:
                    continue
                if self.filter_type == 'XSS攻击' and 'XSS' not in a['type']:
                    continue
                if self.filter_type == '端口扫描' and '扫描' not in a['type']:
                    continue
                if self.filter_type == '暴力破解' and '暴力' not in a['type']:
                    continue
                if self.filter_type == '命令执行' and '命令' not in a['type']:
                    continue
                if self.filter_type == '木马后门' and not ('木马' in a['type'] or '后门' in a['type'] or 'WebShell' in a['type']):
                    continue
                if self.filter_type == '横向扩散' and '横向' not in a['type']:
                    continue
                if self.filter_type == '带宽异常' and '带宽' not in a['type']:
                    continue
                if self.filter_type == 'TLS恶意通信' and 'TLS' not in a['type']:
                    continue
                if self.filter_type == 'AI智能分析异常' and 'AI' not in a['type']:
                    continue
            if self.search_text:
                search_lower = self.search_text.lower()
                if (search_lower not in a['src_ip'].lower() and
                    search_lower not in a['dst_ip'].lower() and
                    search_lower not in a['detail'].lower() and
                    search_lower not in a['time']):
                    continue
            filtered.append(a)
        self.filtered_alerts = filtered

    def set_filter_type(self, filter_type):
        self.filter_type = filter_type
        self._apply_filter()
        self.layoutChanged.emit()

    def set_search_text(self, text):
        self.search_text = text
        self._apply_filter()
        self.layoutChanged.emit()

    def add_alert(self, alert):
        self._apply_filter()
        self.layoutChanged.emit()

    def refresh(self):
        self._apply_filter()
        self.layoutChanged.emit()


class RealtimeChart(QWidget):
    def __init__(self, alert_manager, parent=None):
        super().__init__(parent)
        self.alert_manager = alert_manager
        self.setMinimumHeight(180)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()

        bg_color = QColor(245, 245, 250)
        painter.fillRect(0, 0, w, h, bg_color)

        painter.setPen(QPen(QColor(220, 220, 230), 1))
        for i in range(5):
            y = int(h * (i + 1) / 5)
            painter.drawLine(0, y, w, y)

        stats = self.alert_manager.get_realtime_stats()
        if not stats:
            painter.setPen(QColor(150, 150, 150))
            painter.setFont(QFont('Arial', 10))
            painter.drawText(10, 20, '等待数据...')
            return

        recent = stats[-60:]
        if len(recent) < 2:
            return

        max_val = 1
        for s in recent:
            max_val = max(max_val, s.get('bps', 0), s.get('pps', 0), s.get('alerts', 0) * 1000)

        painter.setPen(QPen(QColor(52, 152, 219), 2))
        points_bps = []
        for i, s in enumerate(recent):
            x = int(w * i / (len(recent) - 1))
            y = int(h - (s.get('bps', 0) / max_val) * (h - 30) - 10)
            points_bps.append((x, y))
        for i in range(len(points_bps) - 1):
            painter.drawLine(points_bps[i][0], points_bps[i][1],
                           points_bps[i + 1][0], points_bps[i + 1][1])

        painter.setPen(QPen(QColor(46, 204, 113), 2))
        points_pps = []
        for i, s in enumerate(recent):
            x = int(w * i / (len(recent) - 1))
            y = int(h - (s.get('pps', 0) / max_val) * (h - 30) - 10)
            points_pps.append((x, y))
        for i in range(len(points_pps) - 1):
            painter.drawLine(points_pps[i][0], points_pps[i][1],
                           points_pps[i + 1][0], points_pps[i + 1][1])

        painter.setPen(QPen(QColor(231, 76, 60), 2))
        points_alerts = []
        for i, s in enumerate(recent):
            x = int(w * i / (len(recent) - 1))
            y = int(h - (s.get('alerts', 0) * 1000 / max_val) * (h - 30) - 10)
            points_alerts.append((x, y))
        for i in range(len(points_alerts) - 1):
            painter.drawLine(points_alerts[i][0], points_alerts[i][1],
                           points_alerts[i + 1][0], points_alerts[i + 1][1])

        painter.setPen(QColor(50, 50, 50))
        painter.setFont(QFont('Arial', 9))
        legend_y = 15
        painter.setPen(QColor(52, 152, 219))
        painter.drawText(10, legend_y, '— 流量(bps)')
        painter.setPen(QColor(46, 204, 113))
        painter.drawText(110, legend_y, '— 包速率(pps)')
        painter.setPen(QColor(231, 76, 60))
        painter.drawText(220, legend_y, '— 告警数')


class SignatureDialog(QDialog):
    def __init__(self, parent=None, name='', pattern=''):
        super().__init__(parent)
        self.setWindowTitle('编辑特征')
        self.setMinimumWidth(400)
        layout = QFormLayout(self)

        self.name_edit = QLineEdit(name)
        self.pattern_edit = QLineEdit(pattern)
        self.pattern_edit.setMinimumWidth(300)

        layout.addRow('攻击名称:', self.name_edit)
        layout.addRow('特征串:', self.pattern_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_data(self):
        return self.name_edit.text().strip(), self.pattern_edit.text().strip()


class CaptureThread(QThread):
    def __init__(self, sig_detector, anomaly_detector, alert_manager, iface=None):
        super().__init__()
        self.sig_detector = sig_detector
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.iface = iface
        self.capture = None

    def run(self):
        from packet_capture import PacketCapture
        self.capture = PacketCapture(
            self.sig_detector,
            self.anomaly_detector,
            self.alert_manager
        )
        self.capture.start(iface=self.iface)

    def stop(self):
        if self.capture:
            self.capture.stop()
        self.quit()
        self.wait()


class IDSGui(QMainWindow):
    new_alert_signal = pyqtSignal(dict)
    alert_updated_signal = pyqtSignal(int)

    def __init__(self, alert_manager):
        super().__init__()
        self.alert_manager = alert_manager
        self.alert_manager.register_callback(self._on_new_alert_from_thread)
        self.alert_manager.register_update_callback(self._on_alert_updated_from_thread)
        self.capture_thread = None
        self.sig_detector = None

        self.new_alert_signal.connect(self.on_new_alert)
        self.alert_updated_signal.connect(self.on_alert_updated)

        self.init_ui()

    def _on_new_alert_from_thread(self, alert):
        self.new_alert_signal.emit(alert)

    def _on_alert_updated_from_thread(self, index):
        self.alert_updated_signal.emit(index)

    def init_ui(self):
        self.setWindowTitle('网络入侵检测系统 v3.0 (合并版)')
        self.setGeometry(100, 100, 1300, 800)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        self._init_toolbar(main_layout)
        self._init_stats_panel(main_layout)
        self._init_chart_panel(main_layout)
        self._init_filter_bar(main_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)

        self._init_alerts_tab()
        self._init_signature_tab()
        self._init_assets_tab()
        self._init_attackchain_tab()
        self._init_settings_tab()

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage('就绪 | 请点击"开始检测"启动入侵检测系统')

        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)

        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_chart)
        self.chart_timer.start(2000)

        self.table_refresh_timer = QTimer()
        self.table_refresh_timer.timeout.connect(self._refresh_table)
        self.table_refresh_timer.start(500)

    def _init_toolbar(self, layout):
        toolbar = QHBoxLayout()

        self.start_btn = QPushButton('▶ 开始检测')
        self.start_btn.setStyleSheet(
            'QPushButton { background-color: #4CAF50; color: white; '
            'font-weight: bold; padding: 8px 16px; border-radius: 4px; }'
            'QPushButton:hover { background-color: #45a049; }'
        )
        self.start_btn.clicked.connect(self.start_capture)

        self.stop_btn = QPushButton('■ 停止检测')
        self.stop_btn.setStyleSheet(
            'QPushButton { background-color: #f44336; color: white; '
            'font-weight: bold; padding: 8px 16px; border-radius: 4px; }'
            'QPushButton:hover { background-color: #d32f2f; }'
        )
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)

        self.clear_btn = QPushButton('🗑 清空告警')
        self.clear_btn.clicked.connect(self.clear_alerts)

        self.export_btn = QPushButton('📤 导出CSV')
        self.export_btn.clicked.connect(self.export_csv)

        self.chain_btn = QPushButton('🔗 攻击链分析')
        self.chain_btn.clicked.connect(self.show_attack_chain)
        self.chain_btn.setEnabled(False)

        self.learn_btn = QPushButton('🎓 基线学习')
        self.learn_btn.clicked.connect(self.start_baseline_learning)

        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        toolbar.addWidget(self.chain_btn)
        toolbar.addWidget(self.learn_btn)
        toolbar.addStretch()

        self.status_label = QLabel('⏸ 状态: 未启动')
        self.status_label.setStyleSheet('font-weight: bold; padding: 5px 10px;')
        toolbar.addWidget(self.status_label)
        layout.addLayout(toolbar)

    def _init_stats_panel(self, layout):
        stats_group = QGroupBox('📊 实时统计')
        stats_group.setStyleSheet(
            'QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 6px; padding-top: 8px; }'
            'QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }'
        )
        stats_layout = QHBoxLayout(stats_group)

        stat_items = [
            ('total', '总流量', '📶', '#3498db', '0'),
            ('attacks', '攻击数', '⚠️', '#e74c3c', '0'),
            ('scan', '扫描数', '🔍', '#e67e22', '0'),
            ('sql', 'SQL注入', '💉', '#c0392b', '0'),
            ('xss', 'XSS攻击', '📝', '#8e44ad', '0'),
            ('tls', 'TLS恶意', '🔐', '#1abc9c', '0'),
            ('ai', 'AI检测', '🤖', '#9b59b6', '0'),
            ('today_risk', '今日风险', '🔥', '#d35400', '0'),
        ]

        self.stat_labels = {}
        for key, name, icon, color, init_val in stat_items:
            frame = QFrame()
            frame.setStyleSheet(
                f'QFrame {{ background-color: white; border: 1px solid {color}33; '
                f'border-radius: 6px; padding: 4px; }}'
            )
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(8, 4, 8, 4)

            title = QLabel(f'{icon} {name}')
            title.setStyleSheet('font-size: 11px; color: #666;')

            val = QLabel(init_val)
            val.setStyleSheet(f'font-size: 20px; font-weight: bold; color: {color};')
            val.setAlignment(Qt.AlignCenter)

            fl.addWidget(title)
            fl.addWidget(val)
            self.stat_labels[key] = val
            stats_layout.addWidget(frame)

        layout.addWidget(stats_group)

    def _init_chart_panel(self, layout):
        chart_group = QGroupBox('📈 实时曲线')
        chart_group.setStyleSheet(
            'QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 6px; padding-top: 8px; }'
            'QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }'
        )
        chart_layout = QVBoxLayout(chart_group)

        self.chart = RealtimeChart(self.alert_manager)
        chart_layout.addWidget(self.chart)

        layout.addWidget(chart_group)

    def _init_filter_bar(self, layout):
        filter_bar = QHBoxLayout()

        filter_label = QLabel('🔍 过滤:')
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            '全部', 'SQL注入', 'XSS攻击', '端口扫描', '暴力破解',
            '命令执行', '木马后门', '横向扩散', '带宽异常',
            'TLS恶意通信', 'AI智能分析异常'
        ])
        self.filter_combo.currentTextChanged.connect(self.on_filter_changed)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText('搜索 IP / 时间 / 详情...')
        self.search_edit.textChanged.connect(self.on_search_changed)
        self.search_edit.setMaximumWidth(300)

        filter_bar.addWidget(filter_label)
        filter_bar.addWidget(self.filter_combo)
        filter_bar.addSpacing(10)
        filter_bar.addWidget(self.search_edit)
        filter_bar.addStretch()

        layout.addLayout(filter_bar)

    def _init_alerts_tab(self):
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)

        self.table_model = AlertTableModel(self.alert_manager)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSortingEnabled(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.table_view.setColumnWidth(0, 50)
        self.table_view.setColumnWidth(1, 160)
        self.table_view.setColumnWidth(2, 130)
        self.table_view.setColumnWidth(3, 130)
        self.table_view.setColumnWidth(4, 60)
        self.table_view.setColumnWidth(5, 180)
        self.table_view.setColumnWidth(6, 70)
        self.table_view.setColumnWidth(7, 60)

        alerts_layout.addWidget(self.table_view)
        self.tabs.addTab(alerts_widget, '🚨 告警列表')

    def _init_signature_tab(self):
        sig_widget = QWidget()
        sig_layout = QVBoxLayout(sig_widget)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton('➕ 添加特征')
        add_btn.clicked.connect(self.add_signature)
        edit_btn = QPushButton('✏️ 编辑特征')
        edit_btn.clicked.connect(self.edit_signature)
        del_btn = QPushButton('🗑 删除特征')
        del_btn.clicked.connect(self.delete_signature)
        reload_btn = QPushButton('🔄 重新加载')
        reload_btn.clicked.connect(self.reload_signatures)
        save_btn = QPushButton('💾 保存到文件')
        save_btn.clicked.connect(self.save_signatures)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(edit_btn)
        btn_layout.addWidget(del_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(reload_btn)
        btn_layout.addWidget(save_btn)

        sig_layout.addLayout(btn_layout)

        self.sig_list = QListWidget()
        sig_layout.addWidget(self.sig_list, 1)

        self.tabs.addTab(sig_widget, '📋 特征库管理')
        self._load_signatures_to_list()

    def _init_assets_tab(self):
        assets_widget = QWidget()
        assets_layout = QVBoxLayout(assets_widget)

        btn_layout = QHBoxLayout()
        add_asset_btn = QPushButton('➕ 添加资产')
        add_asset_btn.clicked.connect(self.add_asset)
        del_asset_btn = QPushButton('🗑 删除资产')
        del_asset_btn.clicked.connect(self.delete_asset)
        btn_layout.addWidget(add_asset_btn)
        btn_layout.addWidget(del_asset_btn)
        btn_layout.addStretch()
        assets_layout.addLayout(btn_layout)

        self.asset_list = QListWidget()
        assets_layout.addWidget(self.asset_list, 1)
        self._load_assets_to_list()

        self.tabs.addTab(assets_widget, '🏢 资产管理')

    def _init_settings_tab(self):
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)

        noise_group = QGroupBox('🔇 误报降噪设置')
        noise_layout = QVBoxLayout(noise_group)

        self.noise_check = QCheckBox('启用告警聚合（同IP同类型60秒内合并为一条）')
        self.noise_check.setChecked(self.alert_manager.noise_reduction_enabled)
        self.noise_check.stateChanged.connect(self.on_noise_changed)

        self.asset_check = QCheckBox('启用资产重要性权重（提高重要资产告警等级）')
        self.asset_check.setChecked(self.alert_manager.asset_importance_enabled)
        self.asset_check.stateChanged.connect(self.on_asset_importance_changed)

        self.baseline_check = QCheckBox('启用基线学习（频繁告警降低严重度）')
        self.baseline_check.setChecked(self.alert_manager.baseline_enabled)
        self.baseline_check.stateChanged.connect(self.on_baseline_changed)

        window_layout = QHBoxLayout()
        window_layout.addWidget(QLabel('聚合时间窗口(秒):'))
        self.window_spin = QSpinBox()
        self.window_spin.setRange(10, 3600)
        self.window_spin.setValue(60)
        self.window_spin.valueChanged.connect(self.on_window_changed)
        window_layout.addWidget(self.window_spin)
        window_layout.addStretch()

        noise_layout.addWidget(self.noise_check)
        noise_layout.addWidget(self.asset_check)
        noise_layout.addWidget(self.baseline_check)
        noise_layout.addLayout(window_layout)

        settings_layout.addWidget(noise_group)
        settings_layout.addStretch()

        self.tabs.addTab(settings_widget, '⚙️ 设置')

    def _init_attackchain_tab(self):
        chain_widget = QWidget()
        chain_layout = QVBoxLayout(chain_widget)

        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton('🔍 分析攻击链')
        analyze_btn.clicked.connect(self.show_attack_chain)
        export_chain_btn = QPushButton('📤 导出攻击链报告')
        export_chain_btn.clicked.connect(self.export_attack_chain)
        btn_layout.addWidget(analyze_btn)
        btn_layout.addWidget(export_chain_btn)
        btn_layout.addStretch()
        chain_layout.addLayout(btn_layout)

        self.chain_text = QLabel('暂无攻击链数据，请先开始检测并产生告警。')
        self.chain_text.setWordWrap(True)
        self.chain_text.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.chain_text.setStyleSheet('font-family: Consolas, monospace; font-size: 12px; padding: 10px;')
        chain_layout.addWidget(self.chain_text, 1)

        self.tabs.addTab(chain_widget, '🔗 攻击链分析')

    def on_new_alert(self, alert):
        self.table_model.add_alert(alert)
        self.table_view.scrollToBottom()
        self.statusBar.showMessage(
            f'[新告警] {alert["time"]} {alert["src_ip"]} -> {alert["dst_ip"]}: {alert["type"]}',
            3000
        )

    def on_alert_updated(self, index):
        self.table_model.refresh()

    def _refresh_table(self):
        if hasattr(self, 'table_model') and hasattr(self, 'table_view'):
            self.table_model.refresh()

    def update_stats(self):
        stats = self.alert_manager.get_stats()
        traffic = self.alert_manager.get_traffic_stats()

        total_mb = traffic['total_bytes'] / (1024 * 1024)
        if total_mb >= 1024:
            self.stat_labels['total'].setText(f'{total_mb/1024:.2f} GB')
        else:
            self.stat_labels['total'].setText(f'{total_mb:.2f} MB')

        self.stat_labels['attacks'].setText(str(stats['total']))
        self.stat_labels['scan'].setText(str(stats['scan']))
        self.stat_labels['sql'].setText(str(stats['sql']))
        self.stat_labels['xss'].setText(str(stats['xss']))
        self.stat_labels['tls'].setText(str(stats['tls']))
        self.stat_labels['ai'].setText(str(stats['ai']))

        risk = stats['today_risk']
        if risk >= 1000:
            self.stat_labels['today_risk'].setText(f'{risk/1000:.1f}K')
        else:
            self.stat_labels['today_risk'].setText(str(risk))

    def update_chart(self):
        traffic = self.alert_manager.get_traffic_stats()
        stats = self.alert_manager.get_stats()

        sample = {
            'time': datetime.now(),
            'bps': traffic['bps'],
            'pps': traffic['pps'],
            'alerts': stats['total_occurrences'],
        }
        self.alert_manager.add_realtime_sample(sample)
        self.chart.update()

    def on_filter_changed(self, text):
        self.table_model.set_filter_type(text)

    def on_search_changed(self, text):
        self.table_model.set_search_text(text)

    def on_noise_changed(self, state):
        self.alert_manager.noise_reduction_enabled = (state == Qt.Checked)

    def on_asset_importance_changed(self, state):
        self.alert_manager.asset_importance_enabled = (state == Qt.Checked)

    def on_baseline_changed(self, state):
        self.alert_manager.baseline_enabled = (state == Qt.Checked)

    def on_window_changed(self, value):
        self.alert_manager.deduplicator.window = value

    def start_capture(self):
        from packet_capture import PacketCapture
        from signature_detection import SignatureDetector
        from anomaly_detection import AnomalyDetector
        from scapy.all import get_if_list
        import config

        if not os.path.exists(config.SIGNATURE_FILE):
            QMessageBox.warning(
                self,
                '警告',
                f'特征库文件不存在:\n{config.SIGNATURE_FILE}\n\n请创建 data/signatures.txt 文件'
            )
            return

        try:
            self.sig_detector = SignatureDetector(config.SIGNATURE_FILE)
            if len(self.sig_detector.signatures) == 0:
                QMessageBox.warning(self, '警告', '特征库为空，请添加攻击特征')
                return
        except Exception as e:
            QMessageBox.critical(self, '错误', f'加载特征库失败: {e}')
            return

        # 网卡选择
        try:
            interfaces = get_if_list()
            if not interfaces:
                QMessageBox.critical(self, '错误', '未找到可用网卡，请检查网络适配器')
                return
        except Exception as e:
            QMessageBox.critical(self, '错误', f'获取网卡列表失败: {e}')
            return

        from PyQt5.QtWidgets import QInputDialog
        iface, ok = QInputDialog.getItem(
            self, '选择网卡', '请选择要监听的网卡（建议选择当前正在使用的网络适配器）:',
            interfaces, 0, False
        )
        if not ok:
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText('▶ 状态: 检测中...')
        self.status_label.setStyleSheet('font-weight: bold; color: #4CAF50; padding: 5px 10px;')
        self.statusBar.showMessage(f'正在抓包检测... (网卡: {iface})')

        self.alert_manager.traffic_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': datetime.now().timestamp()
        }
        self.alert_manager.realtime_stats = []

        self.anomaly_detector = AnomalyDetector()

        self.capture_thread = CaptureThread(
            self.sig_detector,
            self.anomaly_detector,
            self.alert_manager,
            iface=iface
        )
        self.capture_thread.finished.connect(self.on_capture_stopped)
        self.capture_thread.start()
        self.chain_btn.setEnabled(True)

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
        self.status_label.setText('⏹ 状态: 正在停止...')
        self.status_label.setStyleSheet('font-weight: bold; color: #f44336; padding: 5px 10px;')
        self.statusBar.showMessage('正在停止抓包...')

    def on_capture_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.chain_btn.setEnabled(False)
        self.status_label.setText('⏸ 状态: 已停止')
        self.status_label.setStyleSheet('font-weight: bold; color: #666; padding: 5px 10px;')
        self.statusBar.showMessage('检测已停止', 2000)

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

    def export_csv(self):
        if len(self.alert_manager.alerts) == 0:
            QMessageBox.information(self, '提示', '当前没有告警记录可导出')
            return

        default_name = f"ids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            '导出告警CSV',
            default_name,
            'CSV文件 (*.csv);;所有文件 (*)'
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', '时间', '源IP', '目的IP', '端口', '告警类型', '严重度', '发生次数', '详情'])
                for a in self.alert_manager.alerts:
                    sev = a.get('severity', 50)
                    sev_text = '严重' if sev >= 80 else '高危' if sev >= 60 else '中危' if sev >= 40 else '低危'
                    writer.writerow([
                        a['id'], a['time'], a['src_ip'], a['dst_ip'],
                        a['dst_port'], a['type'], sev_text,
                        a.get('occurrence_count', 1), a['detail']
                    ])
            QMessageBox.information(self, '成功', f'告警已导出到:\n{file_path}\n共 {len(self.alert_manager.alerts)} 条记录')
            self.statusBar.showMessage(f'CSV已导出: {file_path}', 3000)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'导出失败: {e}')

    def _load_signatures_to_list(self):
        import config
        self.sig_list.clear()
        sig_file = config.SIGNATURE_FILE
        if not os.path.exists(sig_file):
            return
        try:
            with open(sig_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        item = QListWidgetItem(line)
                        self.sig_list.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'读取特征库失败: {e}')

    def add_signature(self):
        dlg = SignatureDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            name, pattern = dlg.get_data()
            if name and pattern:
                item = QListWidgetItem(f'{name}|{pattern}')
                self.sig_list.addItem(item)
                self.statusBar.showMessage('已添加特征，请点击"保存到文件"持久化', 3000)

    def edit_signature(self):
        current = self.sig_list.currentItem()
        if not current:
            QMessageBox.information(self, '提示', '请先选择要编辑的特征')
            return
        text = current.text()
        parts = text.split('|', 1)
        name = parts[0] if len(parts) > 0 else ''
        pattern = parts[1] if len(parts) > 1 else ''
        dlg = SignatureDialog(self, name, pattern)
        if dlg.exec_() == QDialog.Accepted:
            new_name, new_pattern = dlg.get_data()
            if new_name and new_pattern:
                current.setText(f'{new_name}|{new_pattern}')
                self.statusBar.showMessage('已修改特征，请点击"保存到文件"持久化', 3000)

    def delete_signature(self):
        current = self.sig_list.currentRow()
        if current < 0:
            QMessageBox.information(self, '提示', '请先选择要删除的特征')
            return
        reply = QMessageBox.question(
            self, '确认删除',
            '确定要删除选中的特征吗？',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.sig_list.takeItem(current)
            self.statusBar.showMessage('已删除特征，请点击"保存到文件"持久化', 3000)

    def reload_signatures(self):
        self._load_signatures_to_list()
        if self.sig_detector:
            self.sig_detector.reload()
        self.statusBar.showMessage('特征库已重新加载', 2000)

    def save_signatures(self):
        import config
        sig_file = config.SIGNATURE_FILE
        try:
            os.makedirs(os.path.dirname(sig_file), exist_ok=True)
            with open(sig_file, 'w', encoding='utf-8') as f:
                f.write('# 攻击特征库\n')
                f.write('# 格式：攻击描述|特征串\n')
                for i in range(self.sig_list.count()):
                    f.write(self.sig_list.item(i).text() + '\n')
            if self.sig_detector:
                self.sig_detector.reload()
            QMessageBox.information(self, '成功', f'特征库已保存到:\n{sig_file}')
            self.statusBar.showMessage('特征库已保存', 2000)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败: {e}')

    def _load_assets_to_list(self):
        self.asset_list.clear()
        assets = self.alert_manager.asset_manager.get_all_assets()
        imp_map = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}
        for ip, info in sorted(assets.items()):
            imp = imp_map.get(info['importance'], info['importance'])
            item = QListWidgetItem(f'{ip}  |  {info["name"]}  |  重要性: {imp}')
            self.asset_list.addItem(item)

    def add_asset(self):
        dlg = QDialog(self)
        dlg.setWindowTitle('添加资产')
        dlg.setMinimumWidth(350)
        layout = QFormLayout(dlg)

        ip_edit = QLineEdit()
        name_edit = QLineEdit()
        imp_combo = QComboBox()
        imp_combo.addItems(['critical (严重)', 'high (高危)', 'medium (中危)', 'low (低危)'])

        layout.addRow('IP地址:', ip_edit)
        layout.addRow('资产名称:', name_edit)
        layout.addRow('重要性:', imp_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addRow(buttons)

        if dlg.exec_() == QDialog.Accepted:
            ip = ip_edit.text().strip()
            name = name_edit.text().strip()
            imp = imp_combo.currentText().split(' ')[0]
            if ip and name:
                self.alert_manager.asset_manager.add_asset(ip, name, imp)
                self._load_assets_to_list()
                self.statusBar.showMessage(f'已添加资产: {ip}', 2000)

    def delete_asset(self):
        current = self.asset_list.currentRow()
        if current < 0:
            QMessageBox.information(self, '提示', '请先选择要删除的资产')
            return
        item = self.asset_list.currentItem()
        ip = item.text().split(' ')[0]
        reply = QMessageBox.question(
            self, '确认删除',
            f'确定要删除资产 {ip} 吗？',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.alert_manager.asset_manager.remove_asset(ip)
            self._load_assets_to_list()
            self.statusBar.showMessage(f'已删除资产: {ip}', 2000)

    def show_attack_chain(self):
        if len(self.alert_manager.alerts) == 0:
            QMessageBox.information(self, '提示', '当前没有告警记录，无法分析攻击链')
            return

        analyzer = AttackChainAnalyzer(self.alert_manager)
        summary = analyzer.get_summary()
        chains = summary['chains']

        if not chains:
            self.chain_text.setText('暂无攻击链数据，请等待更多告警产生。')
            return

        lines = []
        lines.append(f"攻击链分析结果 - 共发现 {summary['total']} 条攻击链")
        lines.append(f"高危: {summary['high']} | 中危: {summary['medium']} | 低危: {summary['low']}")
        lines.append("=" * 60)

        for chain in chains:
            lines.append(format_chain(chain))

        self.chain_text.setText("\n".join(lines))
        self.tabs.setCurrentIndex(4)
        self.statusBar.showMessage(f'攻击链分析完成: {summary["total"]} 条链', 3000)

    def export_attack_chain(self):
        if len(self.alert_manager.alerts) == 0:
            QMessageBox.information(self, '提示', '当前没有告警记录可导出')
            return

        default_name = f"attack_chain_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        file_path, _ = QFileDialog.getSaveFileName(
            self, '导出攻击链报告', default_name, '文本文件 (*.txt);;所有文件 (*)'
        )
        if not file_path:
            return

        try:
            analyzer = AttackChainAnalyzer(self.alert_manager)
            summary = analyzer.get_summary()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"攻击链分析报告\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"共发现 {summary['total']} 条攻击链\n")
                f.write(f"高危: {summary['high']} | 中危: {summary['medium']} | 低危: {summary['low']}\n")
                f.write("=" * 60 + "\n")
                for chain in summary['chains']:
                    f.write(format_chain(chain) + "\n")
            QMessageBox.information(self, '成功', f'攻击链报告已导出到:\n{file_path}')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'导出失败: {e}')

    def start_baseline_learning(self):
        if not self.capture_thread or not self.capture_thread.capture:
            QMessageBox.information(self, '提示', '请先开始检测，再进行基线学习')
            return

        reply = QMessageBox.question(
            self, '确认基线学习',
            '基线学习将持续30秒，期间不会产生告警。\n确定开始基线学习吗？',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.capture_thread.capture.start_learning()
            self.anomaly_detector.start_learning(30)
            self.statusBar.showMessage('基线学习已启动，30秒内不告警...', 5000)
