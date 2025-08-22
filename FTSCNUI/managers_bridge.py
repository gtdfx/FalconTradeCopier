# This file centralizes access to your existing managers in falcon_trade_copier.py
# If not found, lightweight dummies are provided so the UI runs.
from PySide6.QtCore import QObject, Signal, QTimer

try:
    import falcon_trade_copier as orig
    TelegramManager = getattr(orig, "TelegramManager", None)
    SettingsManager = getattr(orig, "SettingsManager", None)
    MT5Manager = getattr(orig, "MT5Manager", None)
except Exception:
    TelegramManager = SettingsManager = MT5Manager = None

class DummyTelegramManager(QObject):
    channels_loaded = Signal(list)
    trade_signal = Signal(str, str)
    new_signal_parsed = Signal(dict)
    connection_status_changed = Signal(bool)
    management_command = Signal(dict)
    def __init__(self):
        super().__init__(); self.running = False; self.api_id=None; self.api_hash=None
    def connect_telegram(self, api_id, api_hash, phone=None):
        self.api_id, self.api_hash = api_id, api_hash
        QTimer.singleShot(500, lambda: self.connection_status_changed.emit(True))
        QTimer.singleShot(700, lambda: self.channels_loaded.emit([{"id":"12345","name":"VIP Signals","username":"vip"}]))
    def load_channels(self): self.channels_loaded.emit([{"id":"12345","name":"VIP Signals","username":"vip"}])
    def start_listening(self):
        self.running=True
    def stop_listening(self):
        self.running=False

class DummySettingsManager:
    def __init__(self): self._d = {"telegram":{"channels":["VIP Signals"]}, "risk":{"auto_execute":False,"fixed_lot":0.1}}
    def get_telegram_channels(self): return self._d["telegram"]["channels"]
    def set_telegram_channels(self, xs): self._d["telegram"]["channels"]=xs
    def get_telegram_session(self): return ""
    def get_risk_settings(self): return self._d["risk"]

class DummyMT5Manager:
    def execute_trade(self, symbol, order_type, entry, volume, sl=None, tp=None, tps=None):
        return {"ok": True, "symbol": symbol, "type": order_type, "entry": entry, "vol": volume, "tp": tp, "sl": sl}

def build_managers():
    tg = TelegramManager() if TelegramManager else DummyTelegramManager()
    st = SettingsManager() if SettingsManager else DummySettingsManager()
    mt = MT5Manager() if MT5Manager else DummyMT5Manager()
    return tg, st, mt
