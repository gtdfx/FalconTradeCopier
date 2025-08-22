import sys
from PySide6.QtWidgets import QApplication
from theme import qss
from ui.main_window import MainWindowUI
from ui.dashboard_page import DashboardPage
from ui.activation_page import ActivationPage
from ui.mt5_page import MT5Page
from ui.telegram_page import TelegramPage
from managers_bridge import build_managers

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(qss())  # apply theme
    managers = build_managers()
    pages = {
        "dashboard": DashboardPage(managers),
        "telegram": TelegramPage(managers),
        "mt5": MT5Page(managers),
        "activation": ActivationPage(managers),
    }
    win = MainWindowUI(pages)
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
