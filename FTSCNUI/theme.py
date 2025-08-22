from config import PALETTES, DEFAULT_THEME

def qss(theme_name: str | None = None) -> str:
    name = theme_name or DEFAULT_THEME
    p = PALETTES.get(name, PALETTES[DEFAULT_THEME])
    return f'''
    QWidget {{ background-color: {p["bg"]}; color: {p["text"]}; }}
    QGroupBox {{ background-color: {p["card"]}; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; margin-top: 12px; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; color: {p["muted"]}; }}
    QPushButton {{ background-color: {p["primary"]}; color: #000; border: none; border-radius: 10px; padding: 10px 14px; }}
    QPushButton:hover {{ filter: brightness(1.1); }}
    QPushButton#secondary {{ background-color: {p["card"]}; color: {p["text"]}; border: 1px solid rgba(255,255,255,0.10); }}
    QLineEdit, QTextEdit, QSpinBox, QComboBox, QListWidget, QTableWidget {{ background-color: {p["card"]}; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 6px; }}
    QHeaderView::section {{ background-color: {p["card"]}; border: none; padding: 8px; }}
    '''
