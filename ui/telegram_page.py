from PySide6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QListWidget, QListWidgetItem, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog, QMessageBox, QCheckBox, QGroupBox, QFormLayout, QSpinBox
from PySide6.QtCore import Qt, Signal
from ui.components import PrimaryButton, SecondaryButton, StatusDot
from helpers import parse_signal

class TelegramPage(QWidget):
    execute_signal_requested = Signal(dict)
    def __init__(self, managers=None):
        super().__init__()
        self.telegram = managers[0] if managers else None
        self.settings = managers[1] if managers else None
        self.mt5 = managers[2] if managers else None
        self._build_ui(); self._connect()
        try:
            chans = self.settings.get_telegram_channels() if self.settings else []
            for c in chans: self._add_ch_item(c)
        except Exception: pass

    def _build_ui(self):
        root = QHBoxLayout(self); root.setContentsMargins(8,8,8,8); root.setSpacing(10)
        # left
        left = QVBoxLayout()
        left.addWidget(QLabel("<b>Channels</b>"))
        self.list = QListWidget(); self.list.setFixedWidth(260); left.addWidget(self.list)
        r = QHBoxLayout(); self.btn_add = SecondaryButton("Add"); self.btn_rem = SecondaryButton("Remove"); self.btn_ref = SecondaryButton("Refresh")
        r.addWidget(self.btn_add); r.addWidget(self.btn_rem); r.addWidget(self.btn_ref); left.addLayout(r)
        root.addLayout(left,0)
        # right
        right = QVBoxLayout()
        hdr = QHBoxLayout(); t = QLabel("Telegram"); t.setStyleSheet("font-size:18px;font-weight:700;"); hdr.addWidget(t); hdr.addStretch()
        self.dot = StatusDot(False); self.btn_conn = PrimaryButton("Connect"); self.btn_dis = SecondaryButton("Disconnect"); self.btn_dis.setEnabled(False)
        hdr.addWidget(self.dot); hdr.addWidget(self.btn_conn); hdr.addWidget(self.btn_dis)
        right.addLayout(hdr)
        # detail + table
        row = QHBoxLayout()
        card = QGroupBox("Channel Details"); form = QFormLayout()
        self.d_name = QLabel("-"); self.d_id = QLabel("-"); self.d_user = QLabel("-")
        self.d_listen = QCheckBox("Listen"); self.d_auto = QCheckBox("Auto-execute"); self.d_tol = QSpinBox(); self.d_tol.setRange(0,100); self.d_tol.setValue(2)
        form.addRow("Name:", self.d_name); form.addRow("ID:", self.d_id); form.addRow("Username:", self.d_user); form.addRow("", self.d_listen); form.addRow("", self.d_auto); form.addRow("Pip tolerance:", self.d_tol)
        card.setLayout(form); row.addWidget(card,0)
        self.table = QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Time","Sender","Preview","Parsed","Actions"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        row.addWidget(self.table,1); right.addLayout(row,1)
        # manual
        box = QGroupBox("Manual Parse / Test"); v = QVBoxLayout(); self.txt = QTextEdit(); self.txt.setPlaceholderText("Paste a message..."); btns = QHBoxLayout(); self.btn_parse = PrimaryButton("Parse"); self.btn_exec = PrimaryButton("Execute (simulate)"); btns.addWidget(self.btn_parse); btns.addWidget(self.btn_exec); v.addWidget(self.txt); v.addLayout(btns); box.setLayout(v); right.addWidget(box)
        # bottom
        bottom = QHBoxLayout(); self.btn_listen = SecondaryButton("Start Listening"); bottom.addWidget(self.btn_listen); bottom.addStretch(); self.lbl = QLabel("Idle"); bottom.addWidget(self.lbl); right.addLayout(bottom)
        root.addLayout(right,1)

    def _connect(self):
        self.btn_add.clicked.connect(self.on_add); self.btn_rem.clicked.connect(self.on_remove); self.btn_ref.clicked.connect(self.on_refresh)
        self.list.itemSelectionChanged.connect(self.on_sel)
        self.btn_conn.clicked.connect(self.on_connect); self.btn_dis.clicked.connect(self.on_disconnect); self.btn_listen.clicked.connect(self.on_listen)
        self.btn_parse.clicked.connect(self.on_parse); self.btn_exec.clicked.connect(self.on_exec)
        if self.telegram:
            for name in ["channels_loaded","trade_signal","new_signal_parsed","connection_status_changed","management_command"]:
                if hasattr(self.telegram, name): getattr(self.telegram, name).connect(getattr(self, f"_on_{name}", lambda *a,**k: None))

    # actions
    def on_add(self):
        text, ok = QInputDialog.getText(self,"Add Channel","Channel id or username:")
        if ok and text:
            self._add_ch_item(text)
            if self.settings:
                xs = self.settings.get_telegram_channels() or []
                if text not in xs: xs.append(text); self.settings.set_telegram_channels(xs)
            self.lbl.setText("Added channel")
    def on_remove(self):
        it = self.list.currentItem()
        if not it: return
        ch = it.data(Qt.UserRole); self.list.takeItem(self.list.row(it))
        if self.settings:
            xs = [c for c in (self.settings.get_telegram_channels() or []) if c != ch]; self.settings.set_telegram_channels(xs)
        self.lbl.setText("Removed channel")
    def on_refresh(self):
        if self.telegram and hasattr(self.telegram,"load_channels"): self.telegram.load_channels(); self.lbl.setText("Refreshing...")
    def on_sel(self):
        it = self.list.currentItem(); 
        if not it: return
        ch = it.data(Qt.UserRole)
        if isinstance(ch, dict):
            self.d_name.setText(ch.get("name","-")); self.d_id.setText(str(ch.get("id","-"))); self.d_user.setText(ch.get("username","-"))
        else:
            self.d_name.setText(str(ch)); self.d_id.setText(str(ch)); self.d_user.setText("-")
    def on_connect(self):
        if not self.telegram: return
        self.btn_conn.setEnabled(False)
        try:
            self.telegram.connect_telegram(getattr(self.telegram,"api_id",None), getattr(self.telegram,"api_hash",None), None)
        except Exception: self.btn_conn.setEnabled(True)
    def on_disconnect(self):
        if not self.telegram: return
        try: self.telegram.stop_listening(); self.btn_dis.setEnabled(False); self.btn_conn.setEnabled(True)
        except Exception: pass
    def on_listen(self):
        if not self.telegram: return
        if getattr(self.telegram,"running",False):
            try: self.telegram.stop_listening(); self.btn_listen.setText("Start Listening"); self.lbl.setText("Stopped")
            except Exception: pass
        else:
            try: self.telegram.start_listening(); self.btn_listen.setText("Stop Listening"); self.lbl.setText("Listening")
            except Exception: pass
    def on_parse(self):
        msg = self.txt.toPlainText().strip()
        if not msg: return
        parsed = parse_signal(msg)
        self._append_row({"time":"", "sender":"Manual", "preview":msg, "parsed":parsed})
    def on_exec(self):
        msg = self.txt.toPlainText().strip()
        parsed = parse_signal(msg)
        if parsed and self.mt5:
            # hook for real execution
            pass

    # callbacks
    def _on_channels_loaded(self, xs):
        self.list.clear()
        for ch in xs: self._add_ch_item(ch)
    def _on_trade_signal(self, title, message):
        self._append_row({"time":"", "sender":title, "preview":message, "parsed":"raw"})
    def _on_new_signal_parsed(self, obj):
        preview = f"{obj.get('symbol')} {obj.get('order_type')} {obj.get('entry_price') or ''}"
        self._append_row({"time":obj.get('timestamp'), "sender":obj.get('channel'), "preview":preview, "parsed":obj})
    def _on_connection_status_changed(self, st):
        self.dot.set_on(st)
        self.btn_conn.setEnabled(not st); self.btn_dis.setEnabled(st)

    # utils
    def _add_ch_item(self, ch):
        import typing as _t
        from PySide6.QtWidgets import QListWidgetItem
        if isinstance(ch, dict):
            display = ch.get("name") or str(ch.get("id"))
        else: display = str(ch)
        it = QListWidgetItem(display); it.setData(Qt.UserRole, ch); self.list.addItem(it)
    def _append_row(self, obj):
        r = self.table.rowCount(); self.table.insertRow(r)
        for i, key in enumerate(["time","sender","preview","parsed"]):
            from PySide6.QtWidgets import QTableWidgetItem
            self.table.setItem(r,i,QTableWidgetItem(str(obj.get(key,""))))
        self.table.setItem(r,4,QTableWidgetItem("..."))
        self.table.scrollToBottom()
