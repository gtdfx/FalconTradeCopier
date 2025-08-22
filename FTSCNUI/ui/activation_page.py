from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QHBoxLayout
from ui.components import PrimaryButton, SecondaryButton

class ActivationPage(QWidget):
    def __init__(self, managers=None):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(10)
        lay.addWidget(QLabel("<h2>Activation</h2>"))
        self.key = QLineEdit(); self.key.setPlaceholderText("Enter license key")
        lay.addWidget(self.key)
        row = QHBoxLayout()
        row.addWidget(PrimaryButton("Activate"))
        row.addWidget(SecondaryButton("Check Status"))
        lay.addLayout(row)
