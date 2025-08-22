from cx_Freeze import setup, Executable
import sys

base = None
if sys.platform == "win32":
    base = "Win32GUI"  # Use this for GUI applications

build_options = {
    "packages": ["os", "sys", "json", "re", "logging", "threading", "asyncio", "datetime", "time", "hashlib", "uuid", "socket", "requests", "platform", "psutil", "numpy", "spacy", "telethon", "MetaTrader5", "PySide6"],
    "excludes": ["tkinter"],
    "include_files": ["resources/"],
}

executables = [Executable("falcon_trade_copier_clean.py", base=base)]

setup(
    name="Falcon Trade Copier",
    version="1.2",
    description="Automated Telegram Signal Copier for MT5",
    options={"build_exe": build_options},
    executables=executables
)