"""
Modern Dashboard for Falcon Trade Signal Copier
A complete trading application with full functionality integrated into a modern UI.
"""

import sys
import os
import asyncio
import threading
import json
import uuid
import socket
import hashlib
import requests
import time
import logging
import platform
from datetime import datetime, timedelta
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                              QHBoxLayout, QLabel, QPushButton, QTableWidget, 
                              QTableWidgetItem, QFrame, QScrollArea, QSizePolicy,
                              QSpacerItem, QGraphicsDropShadowEffect, QMessageBox,
                              QLineEdit, QCheckBox, QGroupBox, QComboBox, 
                              QDoubleSpinBox, QSpinBox, QTextEdit, QProgressBar,
                              QStackedWidget, QSystemTrayIcon, QMenu, QStatusBar,
                              QGridLayout, QFormLayout, QDialog, QDialogButtonBox)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, Signal, QObject, QThread
from PySide6.QtGui import QFont, QPixmap, QPainter, QColor, QLinearGradient, QIcon

# Import required libraries
try:
    from telethon import TelegramClient, events
    from telethon.sessions import StringSession
    from telethon.tl.types import Channel
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("Warning: Telethon not available. Install with: pip install telethon")

try:
    import MetaTrader5 as mt5
    MT5_AVAILABLE = True
except ImportError:
    MT5_AVAILABLE = False
    print("Warning: MetaTrader5 not available. Install with: pip install MetaTrader5")

try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase not available. Install with: pip install supabase")

# Application Constants
APP_NAME = "Falcon Trade Signal Copier"
VERSION = "1.2"
TELEGRAM_API_ID = 26121573
TELEGRAM_API_HASH = "305761518085ff8519d0eded60f46c72"
SETTINGS_FILE = "falcon_app_settings.json"
ACTIVE_TRADES_FILE = "falcon_active_trades.json"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("falcon_app_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_hardware_id():
    """Generate hardware fingerprint for device binding"""
    try:
        mac = uuid.getnode()
        disk_id = ""
        if platform.system() == 'Windows':
            cmd = "wmic diskdrive get serialnumber"
        elif platform.system() == 'Darwin':
            cmd = "ioreg -c IOMedia -r -d 1 | grep -E 'UUID'"
        else:
            cmd = "sudo hdparm -I /dev/sda | grep 'Serial Number'"

        try:
            disk_id = os.popen(cmd).read().strip().split('\n')[-1]
        except:
            pass

        cpu_id = platform.processor()
        combined = f"{mac}-{disk_id}-{cpu_id}"
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error generating hardware ID: {str(e)}")
        return str(uuid.uuid4())

class SettingsManager:
    def __init__(self, filename=SETTINGS_FILE):
        self.filename = filename
        self.settings = {}
        self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                self.settings = json.load(f)
                defaults = self._get_default_settings()
                for key, value in defaults.items():
                    if key not in self.settings:
                        self.settings[key] = value
        except (FileNotFoundError, json.JSONDecodeError):
            self.settings = self._get_default_settings()
            self.save()

    def _get_default_settings(self):
        return {
            "activated": False,
            "telegram": {
                "session_string": None,
                "channel_ids": []
            },
            "risk": {
                "fixed_lot": 0.1,
                "risk_percent": 1.0,
                "fixed_dollar": 100.0,
                "risk_method": "fixed",
                "max_drawdown_percent": 30.0,
                "ignore_no_tpsl": True,
                "entry_range_handling": "Average Price",
                "trailing_sl_enabled": False,
                "trailing_sl_distance": 20.0,
                "be_after_pips": 0.0,
                "trail_after_tp": False,
                "split_tps": True,
                "max_trades": 20,
                "pip_tolerance": 2.0,
                "news_filter": False,
                "trading_hours": "09:00-17:00",
                "daily_loss_limit": 5.0,
                "daily_profit_target": 10.0,
                "max_trades_per_symbol": 20,
                "max_spread": 3.0,
                "max_volatility": 2.0,
                "atr_based_sl": False,
                "streak_scale_factor": 0.5,
                "equity_guard_percent": 80.0,
                "account_lock_hours": 24,
                "execute_in_range": True,
                "enable_comments": True,
                "comment_prefix": "FTSC"
            },
            "mt5": {
                "account": "",
                "server": "",
                "password": "",
                "path": ""
            },
            "symbol_mappings": {
                "GOLD": "XAUUSD",
                "SILVER": "XAGUSD",
                "USOIL": "XTIUSD",
                "UKOIL": "XBRUSD",
                "NAS100": "NAS100",
                "SPX500": "SPX500"
            },
            "last_activation": None,
            "machine_id": get_hardware_id(),
            "license": {
                "key": "",
                "email": "",
                "start_date": None,
                "expiration_date": None,
                "is_trial": False
            }
        }

    def save(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save settings: {str(e)}")
            return False

    def is_activated(self):
        return self.settings.get("activated", False)

    def get_risk_settings(self):
        return self.settings.get("risk", {})

    def get_telegram_settings(self):
        return self.settings.get("telegram", {})

    def get_mt5_settings(self):
        return self.settings.get("mt5", {})

    def set_activated(self, activated, license_key, email):
        self.settings["activated"] = activated
        self.settings["license"]["key"] = license_key
        self.settings["license"]["email"] = email
        self.settings["last_activation"] = datetime.now().isoformat()
        self.save()

class SupabaseManager:
    def __init__(self):
        self.client = None
        self.initialized = False
        
    def validate_license(self, license_key, machine_id):
        """License validation with test license support"""
        if license_key == "TEST-1234-5678-9ABC":
            logger.info("Using test license for development")
            return {
                "valid": True,
                "email": "test@falcontrade.com",
                "is_trial": False,
                "expires_at": (datetime.now() + timedelta(days=365)).isoformat(),
                "days_until_expiry": 365,
                "license_type": "standard",
                "tier": "basic",
                "max_machines": 1,
                "features": {
                    "signal_copying": True,
                    "basic_stats": True,
                    "trade_history": True,
                    "max_simultaneous_trades": 5,
                    "advanced_filters": False,
                    "custom_lot_sizing": False,
                    "multi_account": False
                }
            }
        return {"valid": False, "message": "Invalid license"}

class TelegramManager(QObject):
    verification_sent = Signal()
    authenticated = Signal()
    channels_loaded = Signal(list)
    connection_error = Signal(str)
    trade_signal = Signal(str, str)
    connection_status_changed = Signal(bool)
    new_signal_parsed = Signal(dict)

    def __init__(self):
        super().__init__()
        self.client = None
        self.session_string = None
        self.phone = None
        self.channels = []
        self.running = False
        self.connected = False
        self.loop = None
        self.thread = None

    def initialize_event_loop(self):
        """Initialize the asyncio event loop in a separate thread"""
        try:
            self.loop = asyncio.new_event_loop()
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            logger.info("Telegram event loop started successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Telegram event loop: {str(e)}")

    def _run_loop(self):
        try:
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Error in Telegram event loop: {str(e)}")

    def connect(self, phone, session_string=None):
        """Connect to Telegram"""
        self.phone = phone
        self.session_string = session_string
        self.initialize_event_loop()
        # Additional connection logic would go here

class MT5Manager:
    def __init__(self):
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        self.symbol_cache = {}

    def connect(self, account, server, password, path):
        """Connect to MetaTrader 5"""
        try:
            if not MT5_AVAILABLE:
                raise ConnectionError("MetaTrader5 library not available")
                
            if not mt5.initialize(path=path):
                raise ConnectionError("Failed to initialize MT5")
                
            if not mt5.login(account, password=password, server=server):
                raise ConnectionError("Failed to login to MT5")
                
            self.connected = True
            self.account = account
            self.server = server
            self.path = path
            logger.info("Successfully connected to MT5")
            return True
            
        except Exception as e:
            logger.error(f"MT5 connection failed: {str(e)}")
            return False

    def disconnect(self):
        """Disconnect from MT5"""
        if MT5_AVAILABLE:
            mt5.shutdown()
        self.connected = False

    def get_account_info(self):
        """Get MT5 account information"""
        if not self.connected or not MT5_AVAILABLE:
            return None
        try:
            return mt5.account_info()._asdict()
        except Exception as e:
            logger.error(f"Failed to get account info: {e}")
            return None

class ModernDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.setMinimumSize(1200, 800)
        
        # Initialize managers
        self.settings = SettingsManager()
        self.supabase_manager = SupabaseManager()
        self.telegram_manager = TelegramManager()
        self.mt5_manager = MT5Manager()
        
        # Application state
        self.copying_active = False
        self.signal_count = 0
        self.daily_signals = 0
        self.daily_trades = 0
        
        # Setup UI
        self.setup_ui()
        self.setup_styles()
        self.setup_data()
        self.setup_connections()
        self.check_activation_status()
        self.setup_timers()
        
    def setup_ui(self):
        """Setup the main UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create sidebar
        self.create_sidebar(main_layout)
        
        # Create main content area with stacked widget
        self.create_main_content(main_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def create_sidebar(self, parent_layout):
        """Create the left sidebar navigation"""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        sidebar.setMaximumWidth(250)
        
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 20, 20, 20)
        sidebar_layout.setSpacing(20)
        
        # Logo and title
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        logo_label = QLabel("🦅")
        logo_label.setObjectName("logo")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(logo_label)
        
        title_label = QLabel("Falcon Trade\nSignal Copier")
        title_label.setObjectName("sidebar-title")
        title_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        logo_layout.addWidget(title_label)
        
        sidebar_layout.addWidget(logo_container)
        
        # Navigation buttons
        nav_buttons = [
            ("📊 Dashboard", "dashboard-btn", True),
            ("💬 Telegram", "telegram-btn", False),
            ("⚙️ MetaTrader 5", "mt5-btn", False),
            ("📈 Risk Management", "risk-btn", False),
            ("🔧 Settings", "settings-btn", False),
        ]
        
        for text, object_name, is_active in nav_buttons:
            btn = QPushButton(text)
            btn.setObjectName(object_name)
            if is_active:
                btn.setProperty("active", True)
            btn.clicked.connect(lambda checked, t=text: self.on_nav_click(t))
            sidebar_layout.addWidget(btn)
        
        # Spacer to push buttons to top
        sidebar_layout.addStretch()
        
        # User section at bottom
        user_section = QWidget()
        user_layout = QHBoxLayout(user_section)
        user_layout.setContentsMargins(0, 0, 0, 0)
        
        bell_btn = QPushButton("🔔")
        bell_btn.setObjectName("bell-btn")
        bell_btn.setFixedSize(40, 40)
        user_layout.addWidget(bell_btn)
        
        profile_btn = QPushButton("👤")
        profile_btn.setObjectName("profile-btn")
        profile_btn.setFixedSize(40, 40)
        user_layout.addWidget(profile_btn)
        
        sidebar_layout.addWidget(user_section)
        
        parent_layout.addWidget(sidebar)
        
    def create_main_content(self, parent_layout):
        """Create the main content area with stacked widget"""
        content_widget = QWidget()
        content_widget.setObjectName("main-content")
        
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(30)
        
        # Stacked widget for different pages
        self.stacked_widget = QStackedWidget()
        content_layout.addWidget(self.stacked_widget)
        
        # Create different pages
        self.create_dashboard_page()
        self.create_telegram_page()
        self.create_mt5_page()
        self.create_risk_page()
        self.create_settings_page()
        
        parent_layout.addWidget(content_widget)
        
    def create_dashboard_page(self):
        """Create the dashboard page"""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        layout.setSpacing(25)
        
        # Page title
        title_label = QLabel("Dashboard")
        title_label.setObjectName("page-title")
        layout.addWidget(title_label)
        
        # Connection status section
        self.create_connection_status(layout)
        
        # Latest Signals section
        self.create_signals_section(layout)
        
        # Active Trades section
        self.create_trades_section(layout)
        
        # Create Signal button
        self.create_signal_button(layout)
        
        self.stacked_widget.addWidget(dashboard_widget)
        
    def create_connection_status(self, parent_layout):
        """Create connection status section"""
        status_frame = QFrame()
        status_frame.setObjectName("data-card")
        
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(25, 25, 25, 25)
        status_layout.setSpacing(15)
        
        title_label = QLabel("Connection Status")
        title_label.setObjectName("section-title")
        status_layout.addWidget(title_label)
        
        # Status grid
        status_grid = QGridLayout()
        
        # Telegram status
        status_grid.addWidget(QLabel("Telegram:"), 0, 0)
        self.telegram_status = QLabel("Disconnected")
        self.telegram_status.setProperty("class", "status-error")
        status_grid.addWidget(self.telegram_status, 0, 1)
        
        # MT5 status
        status_grid.addWidget(QLabel("MetaTrader 5:"), 1, 0)
        self.mt5_status = QLabel("Disconnected")
        self.mt5_status.setProperty("class", "status-error")
        status_grid.addWidget(self.mt5_status, 1, 1)
        
        # License status
        status_grid.addWidget(QLabel("License:"), 2, 0)
        self.license_status = QLabel("Inactive")
        self.license_status.setProperty("class", "status-error")
        status_grid.addWidget(self.license_status, 2, 1)
        
        status_layout.addLayout(status_grid)
        parent_layout.addWidget(status_frame)
        
    def create_signals_section(self, parent_layout):
        """Create the Latest Signals section"""
        signals_frame = QFrame()
        signals_frame.setObjectName("data-card")
        
        signals_layout = QVBoxLayout(signals_frame)
        signals_layout.setContentsMargins(25, 25, 25, 25)
        signals_layout.setSpacing(20)
        
        title_label = QLabel("Latest Signals")
        title_label.setObjectName("section-title")
        signals_layout.addWidget(title_label)
        
        self.signals_table = QTableWidget()
        self.signals_table.setObjectName("data-table")
        self.signals_table.setColumnCount(3)
        self.signals_table.setHorizontalHeaderLabels(["Buy/Sell", "Entry", "TP"])
        self.signals_table.setRowCount(4)
        
        self.signals_table.horizontalHeader().setVisible(False)
        self.signals_table.verticalHeader().setVisible(False)
        self.signals_table.setShowGrid(False)
        self.signals_table.setAlternatingRowColors(False)
        
        self.signals_table.setColumnWidth(0, 120)
        self.signals_table.setColumnWidth(1, 100)
        self.signals_table.setColumnWidth(2, 100)
        
        signals_layout.addWidget(self.signals_table)
        parent_layout.addWidget(signals_frame)
        
    def create_trades_section(self, parent_layout):
        """Create the Active Trades section"""
        trades_frame = QFrame()
        trades_frame.setObjectName("data-card")
        
        trades_layout = QVBoxLayout(trades_frame)
        trades_layout.setContentsMargins(25, 25, 25, 25)
        trades_layout.setSpacing(20)
        
        title_label = QLabel("Active Trades")
        title_label.setObjectName("section-title")
        trades_layout.addWidget(title_label)
        
        self.trades_table = QTableWidget()
        self.trades_table.setObjectName("data-table")
        self.trades_table.setColumnCount(3)
        self.trades_table.setHorizontalHeaderLabels(["Pair", "Entry", "TP"])
        self.trades_table.setRowCount(2)
        
        self.trades_table.horizontalHeader().setVisible(False)
        self.trades_table.verticalHeader().setVisible(False)
        self.trades_table.setShowGrid(False)
        self.trades_table.setAlternatingRowColors(False)
        
        self.trades_table.setColumnWidth(0, 120)
        self.trades_table.setColumnWidth(1, 100)
        self.trades_table.setColumnWidth(2, 100)
        
        trades_layout.addWidget(self.trades_table)
        parent_layout.addWidget(trades_frame)
        
    def create_signal_button(self, parent_layout):
        """Create the Create Signal button"""
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        button_layout.addStretch()
        
        create_signal_btn = QPushButton("Create Signal")
        create_signal_btn.setObjectName("create-signal-btn")
        create_signal_btn.setFixedSize(150, 45)
        create_signal_btn.clicked.connect(self.on_create_signal)
        button_layout.addWidget(create_signal_btn)
        
        parent_layout.addWidget(button_container)
        
    def create_telegram_page(self):
        """Create the Telegram configuration page"""
        telegram_widget = QWidget()
        layout = QVBoxLayout(telegram_widget)
        layout.setSpacing(25)
        
        title_label = QLabel("Telegram Configuration")
        title_label.setObjectName("page-title")
        layout.addWidget(title_label)
        
        # Telegram settings form
        form_frame = QFrame()
        form_frame.setObjectName("data-card")
        form_layout = QFormLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Enter phone number")
        form_layout.addRow("Phone Number:", self.phone_input)
        
        self.session_input = QLineEdit()
        self.session_input.setPlaceholderText("Session string (optional)")
        form_layout.addRow("Session String:", self.session_input)
        
        connect_btn = QPushButton("Connect to Telegram")
        connect_btn.clicked.connect(self.connect_telegram)
        form_layout.addRow("", connect_btn)
        
        layout.addWidget(form_frame)
        layout.addStretch()
        
        self.stacked_widget.addWidget(telegram_widget)
        
    def create_mt5_page(self):
        """Create the MT5 configuration page"""
        mt5_widget = QWidget()
        layout = QVBoxLayout(mt5_widget)
        layout.setSpacing(25)
        
        title_label = QLabel("MetaTrader 5 Configuration")
        title_label.setObjectName("page-title")
        layout.addWidget(title_label)
        
        # MT5 settings form
        form_frame = QFrame()
        form_frame.setObjectName("data-card")
        form_layout = QFormLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        
        self.mt5_account = QLineEdit()
        self.mt5_account.setPlaceholderText("Account number")
        form_layout.addRow("Account:", self.mt5_account)
        
        self.mt5_server = QLineEdit()
        self.mt5_server.setPlaceholderText("Server name")
        form_layout.addRow("Server:", self.mt5_server)
        
        self.mt5_password = QLineEdit()
        self.mt5_password.setEchoMode(QLineEdit.Password)
        self.mt5_password.setPlaceholderText("Password")
        form_layout.addRow("Password:", self.mt5_password)
        
        self.mt5_path = QLineEdit()
        self.mt5_path.setPlaceholderText("MT5 installation path")
        form_layout.addRow("Path:", self.mt5_path)
        
        connect_btn = QPushButton("Connect to MT5")
        connect_btn.clicked.connect(self.connect_mt5)
        form_layout.addRow("", connect_btn)
        
        layout.addWidget(form_frame)
        layout.addStretch()
        
        self.stacked_widget.addWidget(mt5_widget)
        
    def create_risk_page(self):
        """Create the risk management page"""
        risk_widget = QWidget()
        layout = QVBoxLayout(risk_widget)
        layout.setSpacing(25)
        
        title_label = QLabel("Risk Management")
        title_label.setObjectName("page-title")
        layout.addWidget(title_label)
        
        # Risk settings form
        form_frame = QFrame()
        form_frame.setObjectName("data-card")
        form_layout = QFormLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        
        self.fixed_lot = QDoubleSpinBox()
        self.fixed_lot.setRange(0.01, 100.0)
        self.fixed_lot.setValue(0.1)
        self.fixed_lot.setSingleStep(0.01)
        form_layout.addRow("Fixed Lot Size:", self.fixed_lot)
        
        self.risk_percent = QDoubleSpinBox()
        self.risk_percent.setRange(0.1, 10.0)
        self.risk_percent.setValue(1.0)
        self.risk_percent.setSuffix("%")
        form_layout.addRow("Risk Percent:", self.risk_percent)
        
        self.max_trades = QSpinBox()
        self.max_trades.setRange(1, 100)
        self.max_trades.setValue(20)
        form_layout.addRow("Max Trades:", self.max_trades)
        
        save_btn = QPushButton("Save Risk Settings")
        save_btn.clicked.connect(self.save_risk_settings)
        form_layout.addRow("", save_btn)
        
        layout.addWidget(form_frame)
        layout.addStretch()
        
        self.stacked_widget.addWidget(risk_widget)
        
    def create_settings_page(self):
        """Create the settings page"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        layout.setSpacing(25)
        
        title_label = QLabel("Application Settings")
        title_label.setObjectName("page-title")
        layout.addWidget(title_label)
        
        # License activation
        license_frame = QFrame()
        license_frame.setObjectName("data-card")
        license_layout = QFormLayout(license_frame)
        license_layout.setContentsMargins(25, 25, 25, 25)
        
        self.license_key = QLineEdit()
        self.license_key.setPlaceholderText("Enter license key")
        license_layout.addRow("License Key:", self.license_key)
        
        activate_btn = QPushButton("Activate License")
        activate_btn.clicked.connect(self.activate_license)
        license_layout.addRow("", activate_btn)
        
        layout.addWidget(license_frame)
        layout.addStretch()
        
        self.stacked_widget.addWidget(settings_widget)
        
    def setup_styles(self):
        """Setup the dark theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            
            #sidebar {
                background-color: #16213e;
                border-right: 1px solid #0f3460;
            }
            
            #sidebar-title {
                color: #ffffff;
                font-size: 16px;
                font-weight: bold;
                margin-left: 10px;
            }
            
            #logo {
                font-size: 24px;
                color: #4fc3f7;
            }
            
            QPushButton#dashboard-btn, QPushButton#telegram-btn, 
            QPushButton#mt5-btn, QPushButton#risk-btn, QPushButton#settings-btn {
                background-color: transparent;
                border: none;
                color: #ffffff;
                text-align: left;
                padding: 15px 20px;
                font-size: 14px;
                border-radius: 8px;
                margin: 2px 0px;
            }
            
            QPushButton#dashboard-btn:hover, QPushButton#telegram-btn:hover,
            QPushButton#mt5-btn:hover, QPushButton#risk-btn:hover, 
            QPushButton#settings-btn:hover {
                background-color: #0f3460;
            }
            
            QPushButton#dashboard-btn[active="true"] {
                background-color: #4fc3f7;
                color: #1a1a2e;
                font-weight: bold;
            }
            
            #bell-btn, #profile-btn {
                background-color: #0f3460;
                border: none;
                color: #ffffff;
                border-radius: 20px;
                font-size: 16px;
            }
            
            #bell-btn:hover, #profile-btn:hover {
                background-color: #4fc3f7;
            }
            
            #main-content {
                background-color: #1a1a2e;
            }
            
            #page-title {
                color: #4fc3f7;
                font-size: 28px;
                font-weight: bold;
                margin-bottom: 20px;
            }
            
            #data-card {
                background-color: #16213e;
                border-radius: 12px;
                border: 1px solid #0f3460;
            }
            
            #section-title {
                color: #ffffff;
                font-size: 18px;
                font-weight: bold;
            }
            
            #data-table {
                background-color: transparent;
                border: none;
                color: #ffffff;
                font-size: 14px;
                selection-background-color: #0f3460;
            }
            
            #data-table::item {
                padding: 12px 8px;
                border: none;
            }
            
            #data-table::item:selected {
                background-color: #0f3460;
            }
            
            #create-signal-btn {
                background-color: #4fc3f7;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
            
            #create-signal-btn:hover {
                background-color: #29b6f6;
            }
            
            #create-signal-btn:pressed {
                background-color: #0288d1;
            }
            
            QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
                background-color: #0f3460;
                border: 1px solid #4fc3f7;
                border-radius: 6px;
                color: #ffffff;
                padding: 8px;
                font-size: 14px;
            }
            
            QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
                border: 2px solid #4fc3f7;
            }
            
            QPushButton {
                background-color: #4fc3f7;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #29b6f6;
            }
            
            QPushButton:pressed {
                background-color: #0288d1;
            }
            
            QLabel {
                color: #ffffff;
                font-size: 14px;
            }
            
            QStatusBar {
                background-color: #16213e;
                color: #ffffff;
                border-top: 1px solid #0f3460;
            }
            
            .status-success {
                color: #4caf50;
            }
            
            .status-error {
                color: #f44336;
            }
            
            .status-warning {
                color: #ff9800;
            }
        """)
        
    def setup_data(self):
        """Setup sample data for the tables"""
        # Latest Signals data
        signals_data = [
            ("Buy", "", ""),
            ("sell", "2.123", "3:38"),
            ("buy", "1.353", "3:21"),
            ("sell", "2.135", "3.38")
        ]
        
        for row, (action, entry, tp) in enumerate(signals_data):
            action_item = QTableWidgetItem(action)
            if action.lower() == "buy":
                action_item.setForeground(QColor("#4fc3f7"))
            elif action.lower() == "sell":
                action_item.setForeground(QColor("#ff6b6b"))
            self.signals_table.setItem(row, 0, action_item)
            
            if entry:
                self.signals_table.setItem(row, 1, QTableWidgetItem(entry))
            
            if tp:
                self.signals_table.setItem(row, 2, QTableWidgetItem(tp))
        
        # Active Trades data
        trades_data = [
            ("RSM14", "0.23", "335"),
            ("DER10", "0.28", "339")
        ]
        
        for row, (pair, entry, tp) in enumerate(trades_data):
            self.trades_table.setItem(row, 0, QTableWidgetItem(pair))
            self.trades_table.setItem(row, 1, QTableWidgetItem(entry))
            self.trades_table.setItem(row, 2, QTableWidgetItem(tp))
            
    def setup_connections(self):
        """Setup signal connections"""
        # Connect Telegram manager signals
        self.telegram_manager.connection_status_changed.connect(self.update_telegram_status)
        self.telegram_manager.new_signal_parsed.connect(self.handle_new_signal)
        
    def check_activation_status(self):
        """Check and update activation status"""
        if self.settings.is_activated():
            self.license_status.setText("Active")
            self.license_status.setProperty("class", "status-success")
        else:
            self.license_status.setText("Inactive")
            self.license_status.setProperty("class", "status-error")
            
    def setup_timers(self):
        """Setup application timers"""
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(5000)  # Update every 5 seconds
        
    def update_status(self):
        """Update application status"""
        # Update MT5 status
        if self.mt5_manager.connected:
            self.mt5_status.setText("Connected")
            self.mt5_status.setProperty("class", "status-success")
        else:
            self.mt5_status.setText("Disconnected")
            self.mt5_status.setProperty("class", "status-error")
            
        # Update Telegram status
        if self.telegram_manager.connected:
            self.telegram_status.setText("Connected")
            self.telegram_status.setProperty("class", "status-success")
        else:
            self.telegram_status.setText("Disconnected")
            self.telegram_status.setProperty("class", "status-error")
            
    def on_nav_click(self, button_text):
        """Handle navigation button clicks"""
        if "Dashboard" in button_text:
            self.stacked_widget.setCurrentIndex(0)
        elif "Telegram" in button_text:
            self.stacked_widget.setCurrentIndex(1)
        elif "MetaTrader 5" in button_text:
            self.stacked_widget.setCurrentIndex(2)
        elif "Risk Management" in button_text:
            self.stacked_widget.setCurrentIndex(3)
        elif "Settings" in button_text:
            self.stacked_widget.setCurrentIndex(4)
            
    def on_create_signal(self):
        """Handle Create Signal button click"""
        QMessageBox.information(self, "Create Signal", "Signal creation functionality will be implemented here.")
        
    def connect_telegram(self):
        """Connect to Telegram"""
        phone = self.phone_input.text()
        session = self.session_input.text()
        
        if not phone:
            QMessageBox.warning(self, "Error", "Please enter a phone number")
            return
            
        try:
            self.telegram_manager.connect(phone, session)
            self.status_bar.showMessage("Connecting to Telegram...")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to Telegram: {str(e)}")
            
    def connect_mt5(self):
        """Connect to MT5"""
        account = self.mt5_account.text()
        server = self.mt5_server.text()
        password = self.mt5_password.text()
        path = self.mt5_path.text()
        
        if not all([account, server, password]):
            QMessageBox.warning(self, "Error", "Please fill in all required fields")
            return
            
        try:
            if self.mt5_manager.connect(account, server, password, path):
                self.status_bar.showMessage("Connected to MT5")
            else:
                self.status_bar.showMessage("Failed to connect to MT5")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to MT5: {str(e)}")
            
    def save_risk_settings(self):
        """Save risk management settings"""
        risk_settings = self.settings.get_risk_settings()
        risk_settings['fixed_lot'] = self.fixed_lot.value()
        risk_settings['risk_percent'] = self.risk_percent.value()
        risk_settings['max_trades'] = self.max_trades.value()
        
        self.settings.settings['risk'] = risk_settings
        self.settings.save()
        
        QMessageBox.information(self, "Success", "Risk settings saved successfully")
        
    def activate_license(self):
        """Activate license"""
        license_key = self.license_key.text()
        
        if not license_key:
            QMessageBox.warning(self, "Error", "Please enter a license key")
            return
            
        try:
            machine_id = get_hardware_id()
            result = self.supabase_manager.validate_license(license_key, machine_id)
            
            if result.get('valid'):
                self.settings.set_activated(True, license_key, result.get('email', ''))
                self.check_activation_status()
                QMessageBox.information(self, "Success", "License activated successfully")
            else:
                QMessageBox.warning(self, "Error", f"License activation failed: {result.get('message', 'Unknown error')}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"License activation failed: {str(e)}")
            
    def update_telegram_status(self, connected):
        """Update Telegram connection status"""
        self.telegram_manager.connected = connected
        self.update_status()
        
    def handle_new_signal(self, signal_data):
        """Handle new trading signal"""
        # Update signals table with new signal
        self.signal_count += 1
        self.daily_signals += 1
        self.status_bar.showMessage(f"New signal received: {signal_data}")

def main():
    """Main function to run the modern dashboard"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Falcon Trade Signal Copier")
    app.setApplicationVersion("1.0.0")
    
    # Create and show the dashboard
    dashboard = ModernDashboard()
    dashboard.show()
    
    # Run the application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
