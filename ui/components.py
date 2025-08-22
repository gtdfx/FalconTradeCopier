from PySide6.QtWidgets import QPushButton, QWidget
from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor

class PrimaryButton(QPushButton):
    def __init__(self, text, *args, **kwargs):
        super().__init__(text, *args, **kwargs)
        self.setFixedHeight(40)

class SecondaryButton(QPushButton):
    def __init__(self, text, *args, **kwargs):
        super().__init__(text, *args, **kwargs)
        self.setObjectName("secondary")
        self.setFixedHeight(36)

class StatusDot(QWidget):
    def __init__(self, on=False, color_on="#22c55e", color_off="#9ca3af", size=12):
        super().__init__()
        self._on = on
        self._color_on = color_on
        self._color_off = color_off
        self._size = size
        self.setFixedSize(size, size)
    def set_on(self, val: bool):
        self._on = bool(val); self.update()
    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(self._color_on if self._on else self._color_off))
        p.drawEllipse(0,0,self._size,self._size)
