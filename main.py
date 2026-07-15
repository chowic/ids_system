# main.py
from alert_manager import AlertManager
from gui import IDSGui
from PyQt5.QtWidgets import QApplication
import sys
import os

# 确保在项目根目录运行
os.chdir(os.path.dirname(os.path.abspath(__file__)))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('网络入侵检测系统')

    # 创建告警管理器
    alert_manager = AlertManager()

    # 创建主窗口
    gui = IDSGui(alert_manager)
    gui.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
