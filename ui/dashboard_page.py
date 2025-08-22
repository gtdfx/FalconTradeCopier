from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QGridLayout, QPushButton
from ui.components import PrimaryButton, SecondaryButton

class DashboardPage(QWidget):
    def __init__(self, managers=None):
        super().__init__()
        layout = QVBoxLayout(self); layout.setSpacing(10)
        layout.addWidget(QLabel("<h2>Dashboard</h2>"))
        cards = QGridLayout(); cards.setHorizontalSpacing(10); cards.setVerticalSpacing(10)
        # KPI cards
        for title in ["Open Trades", "P/L Today", "Signals Parsed", "Auto-Exec"]:
            box = QGroupBox(title); box_lay = QVBoxLayout(); box_lay.addWidget(QLabel("<h3>--</h3>")); box.setLayout(box_lay)
            cards.addWidget(box)
        layout.addLayout(cards)
        layout.addWidget(QLabel("<b>Quick Actions</b>"))
        row = QGridLayout()
        row.addWidget(PrimaryButton("Start Copier"))
        row.addWidget(SecondaryButton("Stop Copier"))
        row.addWidget(SecondaryButton("Settings"))
        layout.addLayout(row)
