from PySide6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QListWidget, QListWidgetItem, QStackedWidget
from PySide6.QtCore import Qt
from config import APP_NAME, VERSION
from ui.components import PrimaryButton, SecondaryButton, StatusDot

class MainWindowUI(QWidget):
    def __init__(self, pages: dict[str, QWidget]):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — {VERSION}")
        self.resize(1200, 800)
        root = QHBoxLayout(self); root.setContentsMargins(12,12,12,12); root.setSpacing(12)

        # Sidebar
        sidebar = QVBoxLayout()
        title = QLabel(f"<b>{APP_NAME}</b><br><span style='color:#94a3b8'>{VERSION}</span>")
        sidebar.addWidget(title)
        self.nav = QListWidget()
        self.nav.addItem("Dashboard")
        self.nav.addItem("Telegram")
        self.nav.addItem("MT5")
        self.nav.addItem("Activation")
        sidebar.addWidget(self.nav, 1)

        # Status and theme controls placeholder
        sidebar.addWidget(QLabel("<small style='color:#94a3b8'>Status</small>"))
        status = QHBoxLayout()
        status.addWidget(StatusDot(False)); status.addWidget(QLabel("Idle"))
        sbw = QWidget(); sbw.setLayout(status)
        sidebar.addWidget(sbw)
        root.addLayout(sidebar, 0)

        # Pages
        self.stack = QStackedWidget()
        self.page_keys = ["dashboard", "telegram", "mt5", "activation"]
        for k in self.page_keys:
            self.stack.addWidget(pages[k])
        root.addWidget(self.stack, 1)

        # connect nav
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
