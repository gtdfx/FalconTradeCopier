from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFormLayout, QLineEdit, QHBoxLayout, QGroupBox
from ui.components import PrimaryButton, SecondaryButton

class MT5Page(QWidget):
    def __init__(self, managers=None):
        super().__init__()
        self.mt5 = managers[2] if managers else None
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h2>MT5</h2>"))
        gb = QGroupBox("Connection"); form = QFormLayout()
        self.server = QLineEdit(); self.login = QLineEdit(); self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Server:", self.server); form.addRow("Login:", self.login); form.addRow("Password:", self.password)
        gb.setLayout(form); lay.addWidget(gb)
        row = QHBoxLayout()
        row.addWidget(PrimaryButton("Connect"))
        row.addWidget(SecondaryButton("Disconnect"))
        lay.addLayout(row)
