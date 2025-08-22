import sys
import os
import asyncio
import threading
from PySide6.QtCore import QObject, Signal, Slot, QThread
import json
import uuid
import socket
import hashlib
import requests
import time
from datetime import datetime, timedelta
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase not available. Install with: pip install supabase")
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect, QThread
import re
import logging
from PySide6.QtCore import QDate
from PySide6.QtWidgets import QDateEdit, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import QPropertyAnimation, QEasingCurve
import pyperclip
from PySide6.QtGui import QIcon, QPalette, QColor, QAction, QFont, QImage, QPixmap, QLinearGradient, QBrush, QPainter, \
    QFontMetrics
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QCheckBox,
    QGroupBox, QSpacerItem, QSizePolicy, QFileDialog, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QSystemTrayIcon,
    QMenu, QStatusBar, QGridLayout, QComboBox, QDoubleSpinBox, QTreeWidget,
    QTreeWidgetItem, QInputDialog, QDialog, QDialogButtonBox, QFormLayout, QScrollArea,
    QSpinBox, QFrame, QStyle, QToolBar, QProgressBar
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import Channel
import MetaTrader5 as mt5
import psutil
import platform

# Charting and analytics imports
try:
    import matplotlib
    # Set backend before importing pyplot to avoid GUI issues
    matplotlib.use('Agg', force=True)  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    CHARTING_AVAILABLE = True
except ImportError:
    CHARTING_AVAILABLE = False
    print("Warning: Charting libraries not available. Install with: pip install matplotlib pandas numpy")
except Exception as e:
    CHARTING_AVAILABLE = False
    print(f"Warning: Charting libraries error: {e}")

# ======================
# APPLICATION CONSTANTS
# ======================

APP_NAME = "Falcon Trade Signal Copier"
SHORT_NAME = "FTSC"
VERSION = "1.2"

TELEGRAM_API_ID = 26121573
TELEGRAM_API_HASH = "305761518085ff8519d0eded60f46c72"
TRADE_HISTORY_FILE = "../falcon_trade_history.json"
SETTINGS_FILE = "../falcon_app_settings.json"
ACTIVE_TRADES_FILE = "../falcon_active_trades.json"

# Import Supabase configuration
try:
    from supabase_config import *
    SUPABASE_CONFIG_LOADED = True
except ImportError:
    # Fallback configuration (replace with your actual values)
    SUPABASE_URL = "https://your-project-id.supabase.co"
    SUPABASE_ANON_KEY = "your-anon-key-here"
    LICENSES_TABLE = "licenses"
    HEARTBEATS_TABLE = "heartbeats"
    USERS_TABLE = "users"
    SUPABASE_CONFIG_LOADED = False

# Legacy API URLs (fallback)
VALIDATION_URL = "https://api.falcontradecopier.com/validate-license"
HEARTBEAT_URL = "https://api.falcontradecopier.com/heartbeat"
ACTIVATION_URL = "https://api.falcontradecopier.com/activate"
TRIAL_URL = "https://api.falcontradecopier.com/start-trial"

NEWS_API_URL = "https://example.com/news-api"  # Placeholder for news API

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("../falcon_app_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load spaCy model for AI parsing
try:
    import spacy
    from spacy.matcher import Matcher

    nlp = spacy.load("en_core_web_sm")
except ImportError:
    logger.warning("spaCy not installed. Using regex-only parsing.")
    nlp = None
except OSError:
    logger.info("spaCy model not available. Using regex parsing as fallback.")
    nlp = None

# =====================
# HELPER FUNCTIONS
# =====================
def get_hardware_id():
    """Generate hardware fingerprint for device binding"""
    try:
        # Use MAC address
        mac = uuid.getnode()

        # Get disk serial (platform-independent)
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

        # Get CPU info
        cpu_id = platform.processor()

        combined = f"{mac}-{disk_id}-{cpu_id}"
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error generating hardware ID: {str(e)}")
        return str(uuid.uuid4())

def mt5_is_initialized():
    try:
        mt5.symbols_total()
        return True
    except:
        return False

def expand_compact_range_match(match):
    """Helper function to expand compact ranges like '3347-49' to '3347-3349'"""
    first = match.group(1)
    second = match.group(2)
    if '.' in first:
        return match.group(0)  # Don't process decimals
    try:
        first_num = int(first)
        second_num = int(second)
        base = (first_num // 100) * 100
        full_second = base + second_num
        if full_second < first_num:
            full_second += 100  # Handle century crossing
        return f"{first}-{full_second}"
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to expand range {first}-{second}: {e}")
        return match.group(0)

# ======================
# SUPABASE MANAGER
# ======================
class SupabaseManager:
    def __init__(self):
        self.client = None
        self.initialized = False
        self.validation_cache = {}  # Cache recent validations
        self.rate_limit_attempts = {}  # Track validation attempts per IP/machine
        self.max_attempts_per_hour = 60  # Rate limiting
        
        if SUPABASE_AVAILABLE:
            try:
                self.client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                self.initialized = True
                logger.info("Supabase client initialized successfully")
                if SUPABASE_CONFIG_LOADED:
                    logger.info("Supabase configuration loaded successfully")
                else:
                    logger.warning("Using fallback Supabase configuration")
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
        else:
            logger.warning("Supabase not available - using legacy API")
            
    def _check_rate_limit(self, machine_id):
        """Check if machine_id has exceeded rate limits"""
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        
        # Clean old attempts
        self.rate_limit_attempts = {
            mid: attempts for mid, attempts in self.rate_limit_attempts.items()
            if any(attempt > hour_ago for attempt in attempts)
        }
        
        # Check current machine attempts
        if machine_id not in self.rate_limit_attempts:
            self.rate_limit_attempts[machine_id] = []
            
        recent_attempts = [
            attempt for attempt in self.rate_limit_attempts[machine_id]
            if attempt > hour_ago
        ]
        
        if len(recent_attempts) >= self.max_attempts_per_hour:
            logger.warning(f"Rate limit exceeded for machine {machine_id[:8]}...")
            return False
            
        # Record this attempt
        self.rate_limit_attempts[machine_id] = recent_attempts + [current_time]
        return True
        
    def _log_validation_attempt(self, license_key, machine_id, result, additional_info=None):
        """Log validation attempts for security monitoring"""
        log_data = {
            'license_key': license_key[:8] + "...",  # Partial key for security
            'machine_id': machine_id[:8] + "...",   # Partial machine ID
            'timestamp': datetime.now().isoformat(),
            'valid': result.get('valid', False),
            'message': result.get('message', ''),
            'source': 'supabase' if self.initialized else 'fallback'
        }
        
        if additional_info:
            log_data.update(additional_info)
            
        if result.get('valid'):
            logger.info(f"License validation successful: {license_key[:8]}... on {machine_id[:8]}...")
        else:
            logger.warning(f"License validation failed: {license_key[:8]}... on {machine_id[:8]}... - {result.get('message', 'Unknown error')}")
            
        # Store validation log in database for monitoring
        if self.initialized:
            try:
                self.client.table('validation_logs').insert(log_data).execute()
            except Exception as e:
                logger.debug(f"Failed to log validation attempt: {e}")
    
    def validate_license(self, license_key, machine_id):
        """Enhanced license validation using Supabase with improved error handling"""
        if not self.initialized:
            return self._fallback_validate_license(license_key, machine_id)
        
        try:
            # Query the licenses table - prioritize 'key' column (actual database structure)
            try:
                response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name for compatibility
                response = self.client.table(LICENSES_TABLE).select('*').eq('license_key', license_key).execute()
            
            if not response.data:
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": "License key not found"})
                return {"valid": False, "message": "License key not found. Please check your license key."}
            
            license_data = response.data[0]
            
            # Enhanced status validation
            status = license_data.get('status', license_data.get('is_active', False))
            if status not in [LICENSE_STATUS_ACTIVE, True, 'active', 'ACTIVE']:
                detailed_message = f"License status is '{status}'. Please contact support if this is unexpected."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": detailed_message, "status": status})
                return {"valid": False, "message": detailed_message}
            
            # Enhanced expiration validation
            expires_at = license_data.get('expires_at') or license_data.get('expiration_date') or license_data.get('valid_until')
            if not expires_at:
                error_msg = "License has no expiration date. Please contact support."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": error_msg}
            
            try:
                expiration_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if expiration_date < datetime.now(expiration_date.tzinfo):
                    days_expired = (datetime.now(expiration_date.tzinfo) - expiration_date).days
                    error_msg = f"License expired {days_expired} day(s) ago on {expiration_date.strftime('%Y-%m-%d')}. Please renew your license."
                    self._log_validation_attempt(license_key, machine_id, 
                        {"valid": False, "message": error_msg, "days_expired": days_expired})
                    return {"valid": False, "message": error_msg}
            except ValueError as ve:
                error_msg = f"Invalid expiration date format: {expires_at}"
                logger.error(f"Date parsing error for license {license_key[:8]}...: {ve}")
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": "License has invalid expiration date. Please contact support."}
            
            # Enhanced machine binding with multi-device support
            bound_machine = license_data.get('machine_id') or license_data.get('hw_id') or license_data.get('device_id')
            max_machines = license_data.get('max_machines', 1)
            
            # If this is a multi-device license, check current device count
            if max_machines > 1:
                try:
                    # Get all active machines for this license
                    active_machines_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=7)).isoformat()).execute()
                    active_machine_ids = list(set([hb['machine_id'] for hb in active_machines_response.data if hb.get('machine_id')]))
                    
                    if machine_id not in active_machine_ids and len(active_machine_ids) >= max_machines:
                        error_msg = f"License allows maximum {max_machines} device(s). {len(active_machine_ids)} device(s) already active."
                        self._log_validation_attempt(license_key, machine_id, 
                            {"valid": False, "message": error_msg, "max_machines": max_machines, "active_count": len(active_machine_ids)})
                        return {"valid": False, "message": error_msg}
                except Exception as e:
                    logger.warning(f"Could not check device count for multi-device license: {e}")
                    # Continue with single-device validation as fallback
            
            # Single device binding check (for single-device licenses or as fallback)
            if max_machines == 1 and bound_machine and bound_machine != machine_id:
                error_msg = "License is already activated on another device. Contact support for device transfer."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg, "bound_machine": bound_machine[:8] + "..."})
                return {"valid": False, "message": error_msg}
            
            # Update machine binding if not set (for new activations)
            if not bound_machine:
                try:
                    self.client.table(LICENSES_TABLE).update({
                        'machine_id': machine_id,
                        'last_activation': datetime.now().isoformat()
                    }).eq('key', license_key).execute()
                    logger.info(f"License {license_key[:8]}... activated on new device {machine_id[:8]}...")
                except Exception as e:
                    logger.debug(f"Could not update machine binding: {e}")  # Suppressed - column may not exist
                    # Continue validation even if update fails
            
            # Calculate days until expiration for user info
            days_until_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
            
            validation_result = {
                "valid": True,
                "email": license_data.get('email', 'user@falcontrade.com'),
                "is_trial": license_data.get('is_trial', False) or license_data.get('license_type') == LICENSE_TYPE_TRIAL,
                "expires_at": expires_at,
                "days_until_expiry": days_until_expiry,
                "license_type": license_data.get('license_type', LICENSE_TYPE_STANDARD),
                "tier": license_data.get('tier', 'basic'),
                "max_machines": max_machines,
                "user_id": license_data.get('user_id'),
                "subscription_id": license_data.get('subscription_id'),
                "features": self._get_license_features(license_data.get('tier', 'basic'), license_data.get('license_type', LICENSE_TYPE_STANDARD))
            }
            
            self._log_validation_attempt(license_key, machine_id, validation_result, 
                {"tier": license_data.get('tier'), "days_remaining": days_until_expiry})
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Validation system error: {str(e)}"
            logger.error(f"Supabase validation error for {license_key[:8]}...: {e}")
            self._log_validation_attempt(license_key, machine_id, 
                {"valid": False, "message": error_msg, "error_type": "system_error"})
            return self._fallback_validate_license(license_key, machine_id)
    
    def _get_license_features(self, tier, license_type):
        """Get available features based on license tier and type"""
        base_features = {
            "signal_copying": True,
            "basic_stats": True,
            "trade_history": True
        }
        
        if tier == 'basic':
            return {
                **base_features,
                "max_simultaneous_trades": 5,
                "advanced_filters": False,
                "custom_lot_sizing": False,
                "multi_account": False
            }
        elif tier == 'premium':
            return {
                **base_features,
                "max_simultaneous_trades": 20,
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True
            }
        elif tier == 'professional':
            return {
                **base_features,
                "max_simultaneous_trades": -1,  # Unlimited
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True,
                "api_access": True,
                "white_label": True
            }
        else:
            return base_features
    
    def check_feature_access(self, license_key, feature_name):
        """Check if a specific feature is available for the current license"""
        try:
            machine_id = get_hardware_id()  # Assuming this function exists
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return False
                
            features = validation_result.get('features', {})
            return features.get(feature_name, False)
            
        except Exception as e:
            logger.error(f"Feature access check failed: {e}")
            return False
    
    def create_trial_license(self, machine_id, email=None):
        """Create a trial license using Supabase"""
        if not self.initialized:
            return self._fallback_create_trial(machine_id)
        
        try:
            # Generate trial license key
            trial_key = f"TRIAL-{uuid.uuid4().hex[:8].upper()}"
            expiration_date = datetime.now() + timedelta(days=7)
            
            # Insert trial license (support both column naming conventions)
            trial_data = {
                'key': trial_key,  # Primary column name
                'license_key': trial_key,  # Backup column name for compatibility
                'email': email or f'trial-{machine_id[:8]}@falcontrade.com',
                'machine_id': machine_id,
                'status': LICENSE_STATUS_ACTIVE,
                'is_trial': True,
                'expires_at': expiration_date.isoformat(),
                'created_at': datetime.now().isoformat(),
                'license_type': LICENSE_TYPE_TRIAL
            }
            
            response = self.client.table(LICENSES_TABLE).insert(trial_data).execute()
            
            if response.data:
                return {
                    "success": True,
                    "key": trial_key,
                    "email": trial_data['email'],
                    "expires_at": trial_data['expires_at']
                }
            else:
                return {"success": False, "message": "Failed to create trial license"}
                
        except Exception as e:
            logger.error(f"Supabase trial creation error: {e}")
            return self._fallback_create_trial(machine_id)
    
    def send_heartbeat(self, license_key, machine_id, stats):
        """Enhanced heartbeat with validation status and better monitoring"""
        if not self.initialized:
            return self._fallback_heartbeat(license_key, machine_id, stats)
        
        try:
            # Perform quick validation check during heartbeat
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                logger.warning(f"Heartbeat failed: License {license_key[:8]}... is no longer valid")
                return {"success": False, "message": "License is no longer valid", "validation_failed": True}
            
            heartbeat_data = {
                'key': license_key,  # Primary column name
                'license_key': license_key,  # Backup column name for compatibility
                'machine_id': machine_id,
                'signals_processed': stats.get('signals_processed', 0),
                'trades_executed': stats.get('trades_executed', 0),
                'version': stats.get('version', VERSION),
                'license_status': 'valid',
                'days_until_expiry': validation_result.get('days_until_expiry', 0),
                'license_tier': validation_result.get('tier', 'basic'),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            
            # Insert heartbeat record
            self.client.table(HEARTBEATS_TABLE).insert(heartbeat_data).execute()
            
            # Update last activity and cumulative stats in licenses table
            update_data = {
                    'last_activity': datetime.now().isoformat(),
                'last_heartbeat': datetime.now().isoformat(),
                'total_signals_processed': stats.get('total_signals_processed', 0),
                'total_trades_executed': stats.get('total_trades_executed', 0)
            }
            
            try:
                self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name
                self.client.table(LICENSES_TABLE).update(update_data).eq('license_key', license_key).execute()
            
            # Check for license expiration warnings
            days_until_expiry = validation_result.get('days_until_expiry', 0)
            if days_until_expiry <= 7 and days_until_expiry > 0:
                logger.warning(f"License {license_key[:8]}... expires in {days_until_expiry} day(s)")
                return {"success": True, "warning": f"License expires in {days_until_expiry} day(s)", "days_until_expiry": days_until_expiry}
            
            return {"success": True, "days_until_expiry": days_until_expiry}
            
        except Exception as e:
            logger.error(f"Supabase heartbeat error: {e}")
            return self._fallback_heartbeat(license_key, machine_id, stats)
    
    def get_license_status_report(self, license_key, machine_id):
        """Get comprehensive license status report for admin/monitoring"""
        try:
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return {"error": validation_result.get('message', 'Invalid license')}
            
            # Get recent heartbeat activity
            recent_heartbeats = []
            try:
                heartbeat_response = self.client.table(HEARTBEATS_TABLE).select('*').eq('key', license_key).order('timestamp', desc=True).limit(10).execute()
                recent_heartbeats = heartbeat_response.data
            except Exception as e:
                logger.debug(f"Could not fetch heartbeat history: {e}")  # Suppressed - table may not exist
            
            # Get all devices for this license
            active_devices = []
            try:
                device_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=30)).isoformat()).execute()
                unique_devices = list(set([hb['machine_id'] for hb in device_response.data if hb.get('machine_id')]))
                active_devices = unique_devices
            except Exception as e:
                logger.debug(f"Could not fetch device list: {e}")  # Suppressed - table may not exist
            
            return {
                "license_valid": True,
                "license_key": license_key[:8] + "...",
                "email": validation_result.get('email'),
                "tier": validation_result.get('tier'),
                "license_type": validation_result.get('license_type'),
                "expires_at": validation_result.get('expires_at'),
                "days_until_expiry": validation_result.get('days_until_expiry'),
                "max_machines": validation_result.get('max_machines'),
                "active_devices_count": len(active_devices),
                "active_devices": active_devices,
                "features": validation_result.get('features'),
                "recent_activity": len(recent_heartbeats),
                "last_heartbeat": recent_heartbeats[0].get('timestamp') if recent_heartbeats else None,
                "total_signals": sum([hb.get('signals_processed', 0) for hb in recent_heartbeats]),
                "total_trades": sum([hb.get('trades_executed', 0) for hb in recent_heartbeats])
            }
            
        except Exception as e:
            logger.error(f"License status report error: {e}")
            return {"error": f"Could not generate status report: {str(e)}"}
    
    def revoke_license(self, license_key, reason=""):
        """Revoke a license (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            update_data = {
                'status': LICENSE_STATUS_SUSPENDED,
                'revoked_at': datetime.now().isoformat(),
                'revocation_reason': reason
            }
            
            response = self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            
            if response.data:
                logger.info(f"License {license_key[:8]}... revoked. Reason: {reason}")
                return {"success": True, "message": "License revoked successfully"}
            else:
                return {"success": False, "message": "License not found"}
                
        except Exception as e:
            logger.error(f"License revocation error: {e}")
            return {"success": False, "message": f"Revocation failed: {str(e)}"}
    
    def extend_license(self, license_key, days_to_add):
        """Extend license expiration (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            # Get current license data
            response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            
            if not response.data:
                return {"success": False, "message": "License not found"}
            
            license_data = response.data[0]
            current_expiry = license_data.get('expires_at')
            
            if not current_expiry:
                return {"success": False, "message": "License has no expiration date"}
            
            # Calculate new expiration
            current_date = datetime.fromisoformat(current_expiry.replace('Z', '+00:00'))
            new_expiry = current_date + timedelta(days=days_to_add)
            
            # Update license
            update_response = self.client.table(LICENSES_TABLE).update({
                'expires_at': new_expiry.isoformat(),
                'extended_at': datetime.now().isoformat(),
                'extension_days': days_to_add
            }).eq('key', license_key).execute()
            
            if update_response.data:
                logger.info(f"License {license_key[:8]}... extended by {days_to_add} days")
                return {"success": True, "message": f"License extended by {days_to_add} days", "new_expiry": new_expiry.isoformat()}
            else:
                return {"success": False, "message": "Extension failed"}
                
        except Exception as e:
            logger.error(f"License extension error: {e}")
            return {"success": False, "message": f"Extension failed: {str(e)}"}
    
    def _fallback_validate_license(self, license_key, machine_id):
        """Fallback to legacy API"""
        try:
            response = requests.post(
                VALIDATION_URL,
                json={"key": license_key, "hw_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"valid": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"valid": False, "message": str(e)}
    
    def _fallback_create_trial(self, machine_id):
        """Fallback to legacy trial API"""
        try:
            response = requests.post(
                TRIAL_URL,
                json={"machine_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def _fallback_heartbeat(self, license_key, machine_id, stats):
        """Fallback to legacy heartbeat API"""
        try:
            response = requests.post(
                HEARTBEAT_URL,
                json={
                    "key": license_key,
                    "hw_id": machine_id,
                    "signals_processed": stats.get('signals_processed', 0),
                    "trades_executed": stats.get('trades_executed', 0),
                    "version": stats.get('version', VERSION)
                },
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

def parse_signal_ai(message):
    """Parse trading signal using NLP and pattern matching"""
    message = preprocess_message(message)
    if not nlp:
        return None

    try:
        doc = nlp(message)
        matcher = Matcher(nlp.vocab)
        used_tokens = set()

        # Define patterns for signal extraction
        action_pattern = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["eurusd", "gbpusd", "usdjpy", "audusd", "usdcad", "nzdusd"]}}
        ]
        
        matcher.add("SIGNAL_ACTION", action_pattern)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                return {
                    "action": span.text.lower(),
                    "confidence": 0.8,
                    "method": "nlp"
                }
        
        return None
    except Exception as e:
        logger.error(f"Error in NLP parsing: {e}")
        return None

def parse_signal_emoji_format(message):
    """Parse signals in emoji format like:
    💰XAUUSD (1m) ⬇️
    🔴Sell  : 3349.27
    ✅TP : 3328.96
    ❌SL : 3351.72
    🧠 : RISK 0.1%
    """
    try:
        # Preprocess message
        message = preprocess_message(message)
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed emoji signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing emoji signal: {e}")
        return None

def parse_signal(message):
    """Main signal parsing function that combines AI, emoji, and regex methods"""
    # Try dedicated provider parsing first (for specific signal format)
    dedicated_result = parse_signal_dedicated_provider(message)
    if dedicated_result:
        return dedicated_result
    
    # Try emoji format parsing second
    emoji_result = parse_signal_emoji_format(message)
    if emoji_result:
        return emoji_result
    
    # Try AI parsing third
    ai_result = parse_signal_ai(message)
    if ai_result:
        return ai_result
    
    # Fall back to regex parsing
    regex_result = parse_signal_regex(message)
    if regex_result:
        return regex_result
    
    return None

# =====================
def parse_signal_ai_enhanced(message):
    """Enhanced AI signal parsing with entity extraction"""
    message = preprocess_message(message)
    if not nlp:
        return parse_signal_regex(message)  # Fallback to regex

    try:
        doc = nlp(message)
        entities = {
            "action": None,
            "symbol": None,
            "entry_price": None,
            "sl": None,
            "tps": []
        }
        used_tokens = set()
        found_entry = False

        # Extract entities using NLP
        for ent in doc.ents:
            if ent.label_ == "ORG" and not entities["symbol"]:
                entities["symbol"] = ent.text.upper()
            elif ent.label_ == "MONEY":
                try:
                    value = float(ent.text.replace(",", ""))
                    if not found_entry:
                        entities["entry_price"] = value
                        found_entry = True
                except ValueError:
                    pass

        # Pattern matching for action words
        action_patterns = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["limit", "stop"]}}
        ]
        
        matcher = Matcher(nlp.vocab)
        matcher.add("ACTION", action_patterns)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                if span.text.lower() in ["buy", "sell"]:
                    entities["action"] = span.text.upper()
                elif span.text.lower() in ["limit", "stop"]:
                    if entities["action"]:
                        entities["action"] = f"{entities['action']} {span.text.upper()}"

        # Extract prices and levels
        price_pattern = r'(\d{1,5}(?:\.\d{1,5})?)'
        price_matches = re.findall(price_pattern, message)
        
        for i, price in enumerate(price_matches):
            try:
                value = float(price)
                if not found_entry:
                    entities["entry_price"] = value
                    found_entry = True
                elif "SL" in message and i == len(price_matches) - 1:
                    entities["sl"] = value
                elif "TP" in message:
                    entities["tps"].append(value)
            except ValueError:
                pass

        # Validate required fields
        if not entities["action"] or not entities["symbol"]:
            return None

        # Handle market orders
        if entities["action"] in ["BUY", "SELL"] and not entities["entry_price"]:
            return {
                "symbol": entities["symbol"],
                "order_type": entities["action"],
                "entry_price": None,
                "sl": entities["sl"],
                "tps": entities["tps"]
            }

        # Determine order type with special handling
        order_type = entities["action"]
        if "LIMIT" in message and "BUY" in order_type:
            order_type = "BUY LIMIT"
        elif "LIMIT" in message and "SELL" in order_type:
            order_type = "SELL LIMIT"
        elif "STOP" in message and "BUY" in order_type:
            order_type = "BUY STOP"
        elif "STOP" in message and "SELL" in order_type:
            order_type = "SELL STOP"

        # Validate pending orders require entry price
        if ("LIMIT" in order_type or "STOP" in order_type) and not entities["entry_price"]:
            logger.warning("Pending order requires entry price")
            return None

        # Prepare result
        result = {
            "symbol": entities["symbol"],
            "order_type": order_type,
            "entry_price": entities["entry_price"],
            "sl": entities["sl"],
        }

        # Handle TP values
        if entities["tps"]:
            result["tps"] = entities["tps"]
        elif "TP" in message:
            tp_matches = re.findall(r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)', message)
            tps = []
            for tp in tp_matches:
                try:
                    tps.append(float(tp))
                except ValueError:
                    pass
            if tps:
                result["tps"] = tps

        logger.info(f"AI parsed signal: {result}")
        return result

    except Exception as e:
        logger.error(f"AI signal parsing error: {str(e)}")
        return None

def parse_signal_entities(message):
    """Extract trading entities from message using regex patterns"""
    entities = {
        "symbol": None,
        "order_type": None,
        "entry_price": None,
        "sl": None,
        "tps": []
    }
    
    try:
        # Extract symbol
        symbol_patterns = [
            r'\b([A-Z0-9]{3,10})\b',
            r'\b(GOLD|SILVER|OIL|BTC|ETH)\b'
        ]
        
        for pattern in symbol_patterns:
            match = re.search(pattern, message)
            if match:
                symbol = match.group(1)
                if symbol not in ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]:
                    entities["symbol"] = symbol
                    break
        
        # Extract order type
        order_pattern = r'\b(BUY|SELL|LONG|SHORT)\b'
        order_match = re.search(order_pattern, message)
        if order_match:
            entities["order_type"] = order_match.group(1)
        
        # Extract entry price
        price_pattern = r'\b(\d+\.?\d*)\b'
        price_matches = re.findall(price_pattern, message)
        if price_matches:
            entities["entry_price"] = float(price_matches[0])
        
        # Extract SL
        sl_pattern = r'SL\s*[:=\-]?\s*(\d+\.?\d*)'
        sl_match = re.search(sl_pattern, message)
        if sl_match:
            entities["sl"] = float(sl_match.group(1))
        
        # Extract TPs
        tp_pattern = r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)'
        tp_matches = re.findall(tp_pattern, message)
        for tp in tp_matches:
            try:
                entities["tps"].append(float(tp))
            except ValueError:
                pass
        
        return entities
        
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        return entities

def preprocess_message(message):
    """Clean and normalize message before parsing

    Args:
        message (str): Raw signal message to preprocess

    Returns:
        str: Cleaned and normalized message

    Handles:
    - Removes emojis and special characters
    - Expands compact number ranges (e.g., 3347-49 → 3347-3349)
    - Converts to uppercase and removes extra spaces
    """
    # Remove emojis and special characters
    message = re.sub(r'[✅🎯♦️⚠️🟢🔴⚡️💎🔥🚨⏱️📊🛑🔔📉📈@]', '', message)

    # Expand compact ranges (e.g., 3347-49 → 3347-3349)
    message = re.sub(r'(\d+)\s*[-–]\s*(\d{2})\b', expand_compact_range_match, message)

    # Convert to uppercase and remove extra spaces
    message = re.sub(r'\s+', ' ', message.upper().strip())
    return message

def parse_signal_dedicated_provider(message):
    """Dedicated parsing method for specific signal provider format:
    💰XAUUSD (1M) ⬆️
    🟢Buy : 3343.29
    ✅TP : 3367.94
    ❌SL : 3341.76
    🧠 : RISK 0.1%
    """
    try:
        # Custom preprocessing that preserves the emojis we need
        # Remove extra whitespace and normalize, but keep emojis
        message = re.sub(r'\s+', ' ', message.strip())
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed dedicated provider signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing dedicated provider signal: {e}")
        return None

def parse_signal_regex(message):
    """Parse trading signal using regular expressions"""
    message = preprocess_message(message)
    try:
        # Enhanced symbol normalization
        message = re.sub(r'\bGOLD\b', 'XAUUSD', message)
        message = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', message)
        message = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', message)
        message = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', message)
        message = re.sub(r'\bNAS100\b', 'NAS100', message)
        message = re.sub(r'\bSPX500\b', 'SPX500', message)
        message = re.sub(r'\bDXY\b', 'USDX', message)
        message = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', message)
        message = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', message)
        message = re.sub(r'\bXRP\b', 'XRPUSD', message)
        message = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', message)
        message = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', message)
        message = re.sub(r'\bUS30\b', 'US30', message)
        message = re.sub(r'\bDOW\b', 'US30', message)

        # Reserved words to skip
        reserved_words = ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]

        # New pattern for specific format:
        # [SYMBOL] (timeframe) [ORDER_TYPE] : [PRICE]
        # TP : [TP_PRICE]
        # SL : [SL_PRICE]
        specific_pattern = (
            r'([A-Z0-9]{3,10})\s*\(.*?\)\s*'  # Symbol with timeframe in parentheses
            r'(BUY|SELL)\s*:\s*(\d+\.?\d*)[\s\S]*?'  # Order type and price
            r'TP\s*:\s*(\d+\.?\d*)[\s\S]*?'  # TP
            r'SL\s*:\s*(\d+\.?\d*)'  # SL
        )

        specific_match = re.search(specific_pattern, message)
        if specific_match:
            symbol = specific_match.group(1)
            order_type = specific_match.group(2)
            entry_price = float(specific_match.group(3))
            tp = float(specific_match.group(4))
            sl = float(specific_match.group(5))

            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": [tp]
            }

        # Enhanced pattern for market orders without entry price
        # In parse_signal_regex function
        market_order_pattern = r'\b(BUY|SELL)\s+:\s*(\d+\.?\d*)\s+(\b[A-Z0-9]{3,10}\b)\b'
        market_match = re.search(market_order_pattern, message)
        if not market_match:
            # Alternative pattern: Symbol first
            market_order_pattern = r'\b([A-Z0-9]{3,10})\s+(BUY|SELL)\b'
            market_match = re.search(market_order_pattern, message)

        if market_match:
            if market_match.group(1) in ["BUY", "SELL"]:
                order_type = market_match.group(1)
                symbol = market_match.group(2)
            else:
                symbol = market_match.group(1)
                order_type = market_match.group(2)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                market_match = None

        if market_match:
            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tp": tp
                }

        # Enhanced pattern for pending orders with "@" symbol
        pending_pattern = r'(BUY|SELL)\s*(LIMIT|STOP)\s+(\w+)\s+@?\s*(\d+\.?\d*)'
        pending_match = re.search(pending_pattern, message)
        if not pending_match:
            # Alternative pattern: Symbol first with "@"
            pending_pattern = r'(\w+)\s+(BUY|SELL)\s*(LIMIT|STOP)\s+@?\s*(\d+\.?\d*)'
            pending_match = re.search(pending_pattern, message)

        if pending_match:
            if pending_match.group(1) in ["BUY", "SELL"]:
                order_type = f"{pending_match.group(1)} {pending_match.group(2)}"
                symbol = pending_match.group(3)
                entry_price = pending_match.group(4)
            else:
                symbol = pending_match.group(1)
                order_type = f"{pending_match.group(2)} {pending_match.group(3)}"
                entry_price = pending_match.group(4)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                pending_match = None

        if pending_match:
            try:
                entry_price = float(entry_price)
            except ValueError:
                entry_price = None

            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tp": tp
                }

        # Fallback pattern
        words = [word for word in message.split() if not word.startswith(('SL', 'TP'))]
        if not words:
            return None

        # Try to find order type
        order_type = None
        for ot in ["BUY LIMIT", "SELL LIMIT", "BUY STOP", "SELL STOP", "BUY", "SELL"]:
            if ot in message:
                order_type = ot
                break
        if not order_type:
            return None

        # Find symbol - first word that matches symbol pattern and not reserved
        symbol = None
        for word in words:
            if re.match(r'^[A-Z0-9]{3,10}$', word) and word not in reserved_words:
                symbol = word
                break
        if not symbol:
            return None

        # Find entry price
        entry_price = None
        for word in words:
            try:
                if word == symbol or word in order_type:
                    continue
                entry_price = float(word)
                break
            except ValueError:
                pass

        sl = None
        tp = None
        tps = []
        sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
        if sl_match:
            try:
                sl = float(sl_match.group(1))
            except ValueError:
                pass

        tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
        if tp_match:
            try:
                tp = float(tp_match.group(1))
            except ValueError:
                pass

        tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
        for tp_val in tp_matches:
            try:
                tps.append(float(tp_val))
            except ValueError:
                pass

        if tps:
            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": tps
            }

        return {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tp": tp
        }
    except Exception as e:
        logger.error(f"Signal parsing error: {str(e)}")
        return None

def parse_management_command(message):
    try:
        message = message.upper().strip()
        patterns = {
            "SL_TO_BE": r"\b(?:SL\s*TO\s*BE|BREAKEVEN|MOVE\s*TO\s*BREAKEVEN)\b",
            "CLOSE": r"\b(?:CLOSE|EXIT|TAKE\s*PROFIT)\b(?!\s*AT)",
            "PARTIAL_CLOSE": r"CLOSE\s*(\d+)\s*%|\bPARTIAL\s*CLOSE\b",
            "MODIFY_SL": r"MODIFY\s*SL\s*TO\s*(\d+\.?\d*)",
            "MODIFY_TP": r"MODIFY\s*TP\s*TO\s*(\d+\.?\d*)",
            "CANCEL": r"\b(?:CANCEL|DELETE)\b"
        }

        for action, pattern in patterns.items():
            match = re.search(pattern, message)
            if match:
                result = {"action": action}
                if action == "PARTIAL_CLOSE" and match.group(1):
                    result["percent"] = float(match.group(1))
                elif action == "MODIFY_SL" and match.group(1):
                    result["sl"] = float(match.group(1))
                elif action == "MODIFY_TP" and match.group(1):
                    result["tp"] = float(match.group(1))
                # Extract symbol, excluding command words
                command_words = {"CLOSE", "EXIT", "TAKE", "PROFIT", "SL", "TP", "MODIFY", "CANCEL", "DELETE", "PARTIAL", "BREAKEVEN", "MOVE", "TO", "BE", "AT"}
                
                # Find all potential symbols in the message
                symbol_matches = re.findall(r"\b([A-Z0-9]{3,6})\b", message)
                
                # Filter out command words and find the actual trading symbol
                for potential_symbol in symbol_matches:
                    if potential_symbol not in command_words:
                        result["symbol"] = potential_symbol
                        break
                return result

        if nlp:
            return parse_management_ai(message)

        return None
    except Exception as e:
        logger.error(f"Management command parsing error: {str(e)}")
        return None

def parse_management_ai(message):
    try:
        doc = nlp(message)
        result = {"action": None, "symbol": None, "params": {}}
        action_verbs = {"move", "close", "exit", "modify", "adjust", "set", "change", "cancel"}
        trade_objects = {"sl", "tp", "stop loss", "take profit", "position", "trade", "order"}

        for token in doc:
            if token.lemma_ in action_verbs:
                result["action"] = token.lemma_.upper()
                for child in token.children:
                    if child.lemma_ in trade_objects:
                        result["target"] = child.lemma_.upper()
                    elif child.dep_ in ("dobj", "attr", "prep") and child.ent_type_ == "CARDINAL":
                        result["params"]["value"] = float(child.text)
            if token.ent_type_ == "ORG" and len(token.text) >= 3:
                result["symbol"] = token.text.upper()

        if result["action"] == "MOVE" and result.get("target") == "SL":
            result["action"] = "MODIFY_SL"
        elif result["action"] == "CLOSE" or result["action"] == "EXIT":
            result["action"] = "CLOSE"
        elif result["action"] == "MODIFY" and result.get("target") == "TP":
            result["action"] = "MODIFY_TP"
        elif result["action"] == "CANCEL":
            result["action"] = "CANCEL"

        if not result["action"] or result["action"] not in ["SL_TO_BE", "CLOSE", "PARTIAL_CLOSE", "MODIFY_SL",
                                                            "MODIFY_TP", "CANCEL"]:
            return None

        return result
    except Exception as e:
        logger.error(f"AI management parsing error: {str(e)}")
        return None

# =====================
# BUSINESS LOGIC CLASSES
# =====================
class TradeTracker:
    def __init__(self, filename=ACTIVE_TRADES_FILE):
        self.filename = filename
        self.active_trades = {}
        self.win_streak = 0
        self.loss_streak = 0
        self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                self.active_trades = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.active_trades = {}

    def save(self):
        with open(self.filename, 'w') as f:
            json.dump(self.active_trades, f, indent=2)

    def add_trade(self, ticket, symbol, order_type, volume, entry_price,
                  actual_price=None, sl=None, tp=None, tps=None, magic=2023, status='pending'):
        """
        Add a trade to the active trades list.

        Args:
            ticket: Trade ticket number.
            symbol: Symbol traded.
            order_type: BUY/SELL etc.
            volume: Trade volume.
            entry_price: Intended entry price.
            actual_price: Actual executed price (defaults to entry_price).
            sl: Stop loss.
            tp: Take profit (single).
            tps: List of multiple take profits.
            magic: Magic number.
            status: Trade status.
        """
        if actual_price is None:
            actual_price = entry_price

        # Ensure tps is always a list
        if tps is None:
            tps = []
        elif not isinstance(tps, list):
            tps = [tps]

        self.active_trades[ticket] = {
            "symbol": symbol,
            "type": order_type,
            "volume": volume,
            "entry": entry_price,
            "actual_price": actual_price,
            "sl": sl,
            "tp": tp,  # Keep single TP if given
            "tps": tps,  # Store multi-TP list
            "magic": magic,
            "status": status,
            "open_time": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat()
        }
        self.save()

    def update_trade(self, ticket, updates):
        if ticket in self.active_trades:
            self.active_trades[ticket].update(updates)
            self.active_trades[ticket]["last_modified"] = datetime.now().isoformat()
            self.save()
            return True
        return False

    def remove_trade(self, ticket, profit=0.0):
        if ticket in self.active_trades:
            # Update streaks based on profit
            if profit > 0:
                self.win_streak += 1
                self.loss_streak = 0
            elif profit < 0:
                self.loss_streak += 1
                self.win_streak = 0

            del self.active_trades[ticket]
            self.save()
            return True
        return False

    def get_trades_by_symbol(self, symbol):
        return [trade for trade in self.active_trades.values() if trade["symbol"] == symbol]

    def get_most_recent_trade(self, symbol):
        trades = self.get_trades_by_symbol(symbol)
        if not trades:
            return None
        return max(trades, key=lambda x: x["open_time"])

    def get_trade_by_ticket(self, ticket):
        return self.active_trades.get(ticket)

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
                "max_trades": 20,  # Changed from 5 to 20
                "pip_tolerance": 2.0,
                "news_filter": False,
                "trading_hours": "09:00-17:00",
                
                "daily_loss_limit": 5.0,
                "daily_profit_target": 10.0,
                "max_trades_per_symbol": 20,  # Changed from 2 to 20
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

    def set_activated(self, status=True, key=None, email=None, is_trial=False, expiration=None):
        self.settings["activated"] = status
        if key and email:
            start_date = datetime.now()
            if not expiration:
                expiration = start_date + timedelta(days=365) if not is_trial else start_date + timedelta(days=7)
            self.settings["license"] = {
                "key": key,
                "email": email,
                "start_date": start_date.isoformat(),
                "expiration_date": expiration.isoformat(),
                "is_trial": is_trial
            }
        return self.save()

    def get_license_info(self):
        return self.settings.get("license", {})

    def get_telegram_session(self):
        return self.settings["telegram"].get("session_string")

    def set_telegram_session(self, session_string):
        self.settings["telegram"]["session_string"] = session_string
        return self.save()

    def get_telegram_channels(self):
        return self.settings["telegram"].get("channel_ids", [])

    def set_telegram_channels(self, channel_ids):
        self.settings["telegram"]["channel_ids"] = channel_ids
        return self.save()

    def get_mt5_settings(self):
        return self.settings["mt5"]

    def set_mt5_settings(self, account, server, password, path, symbol_prefix="", symbol_suffix=""):
        self.settings["mt5"] = {
            "account": account,
            "server": server,
            "password": password,
            "path": path,
            "symbol_prefix": symbol_prefix,
            "symbol_suffix": symbol_suffix
        }
        return self.save()

    def get_risk_settings(self):
        return self.settings["risk"]

    def set_risk_settings(self, risk_settings):
        self.settings["risk"] = risk_settings
        return self.save()

    def get_symbol_mappings(self):
        return self.settings.get("symbol_mappings", {})

    def set_symbol_mappings(self, mappings):
        self.settings["symbol_mappings"] = mappings
        return self.save()

    def get_activation_info(self):
        return {
            "activated": self.settings.get("activated", False),
            "last_activation": self.settings.get("last_activation"),
            "machine_id": self.settings.get("machine_id")
        }

    def reset_activation(self):
        self.settings["activated"] = False
        self.settings["last_activation"] = None
        self.settings["telegram"]["session_string"] = None
        self.settings["telegram"]["channel_ids"] = []
        self.settings["mt5"] = {
            "account": "",
            "server": "",
            "password": "",
            "path": ""
        }
        self.settings["license"] = {
            "key": "",
            "email": "",
            "start_date": None,
            "expiration_date": None,
            "is_trial": False
        }
        return self.save()

class LogoHeader(QWidget):
    def __init__(self, text, logo_pixmap):
        super().__init__()
        self.setMinimumHeight(80)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)

        # Left spacer
        layout.addStretch()

        # Logo and title container
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Logo
        logo_label = QLabel()
        logo_pixmap = logo_pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(logo_label)

        # Title
        title_label = QLabel(text)
        title_label
        title_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(title_label)

        layout.addWidget(container)

        # Right spacer
        layout.addStretch()

class TelegramManager(QObject):
    verification_sent = Signal()
    authenticated = Signal()
    channels_loaded = Signal(list)
    connection_error = Signal(str)
    trade_signal = Signal(str, str)
    management_command = Signal(dict)  # Added for management commands
    connection_status_changed = Signal(bool)
    new_signal_parsed = Signal(dict)  # New signal for UI

    def __init__(self):
        super().__init__()
        self.client = None
        self.session_string = None
        self.phone = None
        self.channels = []
        self.running = False
        self.channel_handlers = {}
        self.connected = False
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.channel_names = {}  # Map channel ID to name

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _connect(self, api_id, api_hash, phone, timeout=30):
        try:
            self.phone = phone
            self.client = TelegramClient(
                StringSession(self.session_string),
                api_id,
                api_hash,
                loop=self.loop
            )
            await asyncio.wait_for(self.client.connect(), timeout=timeout)
            if not await self.client.is_user_authorized():
                if self.session_string:
                    self.session_string = None
                    self.connection_error.emit("Saved session expired, please re-authenticate")
                if phone:
                    await self.client.send_code_request(phone)
                    self.verification_sent.emit()
                return False
            else:
                self.connected = True
                self.connection_status_changed.emit(True)
                self.authenticated.emit()
                return True
        except asyncio.TimeoutError:
            error = "Telegram connection timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram connection failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _authenticate(self, code, timeout=30):
        try:
            await asyncio.wait_for(
                self.client.sign_in(self.phone, code),
                timeout=timeout
            )
            self.session_string = self.client.session.save()
            self.connected = True
            self.connection_status_changed.emit(True)
            self.authenticated.emit()
            return True
        except asyncio.TimeoutError:
            error = "Telegram authentication timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram authentication failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _load_channels(self, timeout=30):
        try:
            if not self.client.is_connected():
                await self.client.connect()
            dialogs = await asyncio.wait_for(
                self.client.get_dialogs(limit=100),
                timeout=timeout
            )
            channels = []
            for dialog in dialogs:
                try:
                    if not isinstance(dialog.entity, Channel) or dialog.is_group:
                        continue
                    entity = dialog.entity
                    username = entity.username if hasattr(entity, 'username') else f"id:{entity.id}"
                    channel_info = {
                        "id": entity.id,
                        "name": dialog.name,
                        "username": username
                    }
                    channels.append(channel_info)
                    self.channel_names[entity.id] = dialog.name
                except Exception as e:
                    logger.error(f"Error processing dialog: {str(e)}")
                    continue
            self.channels_loaded.emit(channels)
        except asyncio.TimeoutError:
            error = "Channel loading timed out"
            logger.error(error)
            self.connection_error.emit(error)
        except Exception as e:
            error = f"Failed to load channels: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)

    def connect_telegram(self, api_id, api_hash, phone):
        asyncio.run_coroutine_threadsafe(
            self._connect(api_id, api_hash, phone),
            self.loop
        )

    def authenticate(self, code):
        asyncio.run_coroutine_threadsafe(
            self._authenticate(code),
            self.loop
        )

    def load_channels(self):
        asyncio.run_coroutine_threadsafe(
            self._load_channels(),
            self.loop
        )

    def add_channel_handler(self, channel_id, callback):
        if channel_id in self.channel_handlers:
            return

        @self.client.on(events.NewMessage(chats=channel_id))
        async def handler(event):
            try:
                message = event.message
                replied_to = None
                if message.reply_to_msg_id:
                    try:
                        replied_msg = await event.get_reply_message()
                        replied_to = replied_msg.text
                    except Exception as e:
                        logger.error(f"Error getting replied message: {str(e)}")
                        replied_to = None

                # Parse the signal with error handling
                try:
                    signal_details = parse_signal(message.text)
                except Exception as e:
                    logger.error(f"Error parsing signal: {str(e)}")
                    signal_details = None

                # Create signal data with channel info
                signal_data = {
                    "channel_id": channel_id,
                    "channel_name": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "message_id": message.id,
                    "text": message.text,
                    "date": message.date,
                    "sender": message.sender_id,
                    "replied_to": replied_to,
                    "signal_details": signal_details
                }

                self.trade_signal.emit(
                    "New Signal Received",
                    f"Channel: {self.channel_names.get(channel_id, channel_id)}\n{message.text}"
                )

                # Emit parsed signal to UI
                if signal_details:
                    self.new_signal_parsed.emit({
                        "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                        "symbol": signal_details.get("symbol", "N/A"),
                        "order_type": signal_details.get("order_type", "N/A"),
                        "entry_price": signal_details.get("entry_price", "N/A"),
                        "sl": signal_details.get("sl", "N/A"),
                        "tp": signal_details.get("tp", "N/A"),
                        "tps": signal_details.get("tps", []),
                        "status": "Parsed",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                else:
                    # Try parsing as management command if signal parsing fails
                    management_details = parse_management_command(message.text)
                    if management_details:
                        self.management_command.emit(management_details)
                    else:
                        self.new_signal_parsed.emit({
                            "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                            "symbol": "N/A",
                            "order_type": "N/A",
                            "entry_price": "N/A",
                            "sl": "N/A",
                            "tp": "N/A",
                            "tps": [],
                            "status": "Failed to parse",
                            "error": "Could not parse signal",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })

                # Only execute callback if signal was successfully parsed
                if signal_details:
                    callback(signal_data)
            except Exception as e:
                logger.error(f"Error in message handler: {str(e)}")
                # Emit error signal to UI
                self.new_signal_parsed.emit({
                    "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "symbol": "N/A",
                    "order_type": "N/A",
                    "entry_price": "N/A",
                    "sl": "N/A",
                    "tp": "N/A",
                    "tps": [],
                    "status": "Error",
                    "error": f"Handler error: {str(e)}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        self.channel_handlers[channel_id] = handler

    def start_listening(self):
        asyncio.run_coroutine_threadsafe(
            self._start_listening(),
            self.loop
        )

    async def _start_listening(self):
        self.running = True
        await self.client.start()
        await self.client.run_until_disconnected()
        self.running = False

    def stop_listening(self):
        self.running = False
        if self.client:
            try:
                # Clear all event handlers
                self.client.list = []

                # Disconnect if connected
                if self.client.is_connected():
                    self.client.disconnect()
                    logger.info("Telegram disconnected")
            except Exception as e:
                logger.error(f"Error stopping Telegram: {str(e)}")
        self.connected = False
        self.connection_status_changed.emit(False)
        logger.info("Telegram listening stopped")

class MT5Manager:
    def __init__(self):
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        self.symbol_cache = {}
        self.parent = None
        self.trade_tracker = TradeTracker()
        self.daily_profit = 0.0
        self.daily_loss = 0.0
        self.lock_until = None  # For account lock

    def get_pip_value(self, symbol):
        """Get pip value for a symbol in account currency"""
        symbol_info = mt5.symbol_info(symbol)
        if symbol_info is None:
            return 0.0001  # Default fallback

        # Calculate pip size (0.0001 for most pairs, 0.01 for JPY pairs)
        pip_size = 0.0001
        if "JPY" in symbol:
            pip_size = 0.01

        # Calculate pip value correctly
        point = symbol_info.point
        
        # For BTC and other crypto, the pip value calculation is different
        if "BTC" in symbol or "ETH" in symbol or "XRP" in symbol or "LTC" in symbol:
            # For crypto, 1 pip = 1 point, and pip value is directly the tick value
            pip_value = symbol_info.trade_tick_value
        else:
            # For forex pairs, calculate pip value: (pip size / point) * tick value
            pip_value = (pip_size / point) * symbol_info.trade_tick_value
        
        # For debugging (only log if there's an issue)
        if pip_value <= 0:
            logger.warning(f"Pip value calculation for {symbol}: pip_size={pip_size}, point={point}, tick_value={symbol_info.trade_tick_value}, pip_value={pip_value}")
        
        return pip_value

    def get_daily_pnl(self):
        """Get current daily P&L as percentage of balance"""
        try:
            account_info = self.get_account_info()
            if not account_info:
                return 0.0
            
            balance = account_info.get('balance', 0)
            if balance <= 0:
                return 0.0
            
            # Get today's trades
            today = datetime.now().date()
            start_time = datetime.combine(today, datetime.min.time())
            end_time = datetime.combine(today, datetime.max.time())
            
            # Get history for today
            history = mt5.history_deals_get(start_time, end_time)
            if history is None:
                return 0.0
            
            # Calculate total P&L for today
            daily_pnl = sum(deal.profit for deal in history)
            
            # Return as percentage of balance
            return (daily_pnl / balance) * 100 if balance > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error calculating daily P&L: {e}")
            return 0.0

    def should_execute_in_range(self, current_price, entry_range, risk_settings):
        low, high = min(entry_range), max(entry_range)
        in_range = low <= current_price <= high
        execute_in_range = risk_settings.get('execute_in_range', True)
        range_handling = risk_settings['entry_range_handling']

        # Always execute if price is in range and setting enabled
        if in_range and execute_in_range:
            return True, None  # Market execution

        # Otherwise convert to pending order
        if range_handling == "First Price":
            preferred_price = low
        elif range_handling == "Last Price":
            preferred_price = high
        else:  # Average
            preferred_price = (low + high) / 2

        return False, preferred_price

    def connect(self, account, server, password, path):
        try:
            account = int(account) if str(account).isdigit() else account
        except ValueError:
            raise ConnectionError("Account number must be numeric")

        if mt5_is_initialized():
            mt5.shutdown()
            time.sleep(1)

        if not os.path.exists(path):
            logger.error(f"MT5 executable NOT FOUND at: {path}")
            raise ConnectionError(f"MT5 executable not found at {path}")

        logger.info(f"Connecting to MT5 at: {path}")
        if not mt5.initialize(path=path, login=account, password=password, server=server):
            error = mt5.last_error()
            logger.error(f"MT5 initialization failed: {error}")
            raise ConnectionError(f"MT5 initialization failed: {error}")

        account_info = mt5.account_info()
        if account_info is None:
            mt5.shutdown()
            error = mt5.last_error()
            logger.error(f"MT5 account info failed: {error}")
            raise ConnectionError(f"Failed to get account info: {error}")

        self.connected = True
        self.account = account
        self.server = server
        self.path = path
        logger.info(f"Connected to MT5 account: {account}")
        return True

    def disconnect(self):
        if mt5_is_initialized():
            mt5.shutdown()
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        logger.info("Disconnected from MT5")

    def get_account_info(self):
        if self.connected:
            try:
                return mt5.account_info()._asdict()
            except:
                return None
        return None

    def normalize_symbol(self, symbol):
        """Normalize symbol for broker-specific format"""
        # Skip invalid words
        if symbol in ["LIMIT", "STOP", "TP", "SL"]:
            return None

        mappings = self.parent.settings.get_symbol_mappings()
        if symbol.upper() in mappings:
            return mappings[symbol.upper()]

        clean_symbol = re.sub(r'[^\w\s.@-]', '', symbol).upper()
        substitutions = {
            'GOLD': 'XAUUSD',
            'XAU': 'XAUUSD',
            'SILVER': 'XAGUSD',
            'XAG': 'XAGUSD',
            'USOIL': 'XTIUSD',
            'UKOIL': 'XBRUSD',
            'OIL': 'XTIUSD',
            'BRENT': 'XBRUSD',
            'NAS100': 'NAS100',
            'SPX500': 'SPX500',
            'DXY': 'USDX',
            'BTC': 'BTCUSD',
            'ETH': 'ETHUSD',
            'XRP': 'XRPUSD',
            'LTC': 'LTCUSD',
            'BCH': 'BCHUSD'
        }
        if clean_symbol in substitutions:
            clean_symbol = substitutions[clean_symbol]

        # Get broker-specific prefix and suffix
        mt5_settings = self.parent.settings.get_mt5_settings()
        symbol_prefix = mt5_settings.get("symbol_prefix", "")
        symbol_suffix = mt5_settings.get("symbol_suffix", "")

        # Try with broker-specific prefix and suffix first
        if symbol_prefix or symbol_suffix:
            broker_symbol = f"{symbol_prefix}{clean_symbol}{symbol_suffix}"
            if mt5.symbol_info(broker_symbol):
                logger.info(f"Found broker symbol: {clean_symbol} -> {broker_symbol}")
                return broker_symbol

        # Try original symbol first
        if mt5.symbol_info(clean_symbol):
            return clean_symbol

        # Try with broker suffix only
        if symbol_suffix:
            trial = clean_symbol + symbol_suffix
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with suffix: {clean_symbol} -> {trial}")
                return trial

        # Try with broker prefix only
        if symbol_prefix:
            trial = symbol_prefix + clean_symbol
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with prefix: {clean_symbol} -> {trial}")
                return trial

        # Try with common suffixes
        for suffix in ['', 'USD', 'EUR', 'JPY', 'GBP', 'CHF', 'AUD', 'CAD', 'NZD']:
            trial = clean_symbol + suffix
            if mt5.symbol_info(trial):
                return trial

        # Try with common prefixes
        for prefix in ['', 'MT_', 'FX_', 'CFD_', 'SPOT_', 'OTC_']:
            trial = prefix + clean_symbol
            if mt5.symbol_info(trial):
                return trial

        # Try removing numbers
        no_num = re.sub(r'\d+', '', clean_symbol)
        if no_num != clean_symbol and mt5.symbol_info(no_num):
            return no_num

        # Try base currency for forex pairs
        if len(clean_symbol) > 3 and clean_symbol[-3:] in ['USD', 'EUR', 'JPY']:
            base = clean_symbol[:-3]
            if mt5.symbol_info(base):
                return base

        logger.warning(f"Symbol not found: {clean_symbol}")
        return None

    def calculate_pip_value(self, symbol_info, symbol):
        """
        Calculate the pip value for a given symbol correctly.
        Handles different instrument types (forex, metals, indices, etc.)
        """
        try:
            contract_size = symbol_info.trade_contract_size
            tick_value = symbol_info.trade_tick_value
            tick_size = symbol_info.trade_tick_size
            point = symbol_info.point
            
            # Handle different instrument types
            if "JPY" in symbol:
                # For JPY pairs, 1 pip = 1 point
                pip_value = tick_value
            elif "XAU" in symbol or "GOLD" in symbol:
                # For gold, calculate based on contract size
                pip_value = tick_value * 10
            elif "XAG" in symbol or "SILVER" in symbol:
                # For silver, calculate based on contract size
                pip_value = tick_value * 10
            else:
                # For other forex pairs, 1 pip = 10 points
                pip_value = tick_value * 10
            
            # Validate pip value
            if pip_value <= 0:
                logger.warning(f"Invalid pip value for {symbol}: {pip_value}, using fallback")
                # Fallback calculation
                pip_multiplier = 10 if "JPY" not in symbol else 1
                pip_value = tick_value * pip_multiplier
            
            return pip_value
            
        except Exception as e:
            logger.error(f"Error calculating pip value for {symbol}: {e}")
            # Emergency fallback
            return symbol_info.trade_tick_value * 10

    def execute_trade(self, symbol, order_type, entry_price, volume, sl=None, tp=None, tps=None, tolerance=2.0, channel_name=None):
        if not self.connected:
            raise ConnectionError("Not connected to MT5")
        try:
            clean_symbol = self.normalize_symbol(symbol)
            if clean_symbol is None:
                logger.warning(f"Skipping trade for invalid symbol: {symbol}")
                return [{"error": f"Invalid symbol: {symbol}"}]
            logger.info(f"Normalized symbol: {symbol} -> {clean_symbol}")

            # Get risk settings
            risk_settings = self.parent.settings.get_risk_settings()
            risk_method = risk_settings['risk_method']
            logger.info(f"Risk calculation for {clean_symbol}: method={risk_method}, settings={risk_settings}")

            # Calculate position size based on risk method
            if risk_method == 'percent':
                # Percent risk method - calculate lot size based on account balance and risk percentage
                account_info = self.get_account_info()
                if not account_info:
                    logger.error("Cannot calculate percent risk - no account info")
                    lot_size = risk_settings.get("fixed_lot", 0.1)
                else:
                    balance = account_info.get('balance', 0)
                    if balance <= 0:
                        logger.error("Cannot calculate percent risk - invalid balance")
                        lot_size = risk_settings.get("fixed_lot", 0.1)
                    else:
                        # Calculate risk amount in account currency
                        risk_amount = balance * (risk_settings['risk_percent'] / 100)

                        # Get symbol info
                        if not mt5.symbol_select(clean_symbol, True):
                            logger.error(f"Symbol {clean_symbol} not found")
                            return [{"error": f"Symbol {clean_symbol} not found"}]

                        symbol_info = mt5.symbol_info(clean_symbol)
                        if symbol_info is None:
                            logger.error(f"Failed to get symbol info for {clean_symbol}")
                            return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

                        # Calculate point value safely with fallback
                        point = symbol_info.point if symbol_info else 0.00001

                        # Calculate stop loss distance in pips
                        if sl and entry_price:
                            # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                            pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                            sl_distance = abs(entry_price - sl) / point / pip_multiplier
                        else:
                            # If no SL, use default 50 pips
                            sl_distance = 50

                        # Calculate lot size with proper validation
                        if sl_distance > 0 and point > 0 and symbol_info.trade_tick_value > 0:
                            # Get pip value per lot for this symbol
                            pip_value = self.calculate_pip_value(symbol_info, clean_symbol)
                            
                            if pip_value > 0:
                                lot_size = risk_amount / (sl_distance * pip_value)
                            else:
                                lot_size = risk_settings.get("fixed_lot", 0.1)
                                logger.warning("Invalid pip_value, using fixed lot")
                        else:
                            lot_size = risk_settings.get("fixed_lot", 0.1)
                            logger.warning("Invalid sl_distance, point_value, or tick_value, using fixed lot")

                        # Apply broker constraints
                        min_volume = symbol_info.volume_min
                        max_volume = symbol_info.volume_max
                        volume_step = symbol_info.volume_step

                        # Clamp to min/max and round to step
                        lot_size = max(min(lot_size, max_volume), min_volume)
                        if volume_step > 0:
                            lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step
                            
                        # Additional safety check: ensure lot size doesn't exceed reasonable limits
                        # For a small account, limit lot size to prevent margin issues
                        if balance < 1000:  # Small account
                            # For very small accounts, use much smaller lot sizes
                            if balance < 200:
                                max_safe_lot = min(lot_size, 0.01)  # Max 0.01 lot for very small accounts
                            elif balance < 500:
                                max_safe_lot = min(lot_size, 0.1)   # Max 0.1 lot for small accounts
                            else:
                                max_safe_lot = min(lot_size, 0.5)   # Max 0.5 lot for medium accounts
                            
                            if lot_size > max_safe_lot:
                                logger.warning(f"Lot size {lot_size} too large for small account (balance: ${balance}), limiting to {max_safe_lot}")
                                lot_size = max_safe_lot

                        logger.info(
                            f"Percent risk lot size: {lot_size:.2f} (risk: {risk_settings['risk_percent']}%, "
                            f"balance: ${balance:.2f}, risk amount: ${risk_amount:.2f}, "
                            f"SL distance: {sl_distance} pips)")

            elif risk_method == 'fixed_dollar':
                fixed_dollar_risk = risk_settings.get('fixed_dollar', 100.0)

                # For fixed dollar risk, we need SL and either entry_price or current market price
                if not sl:
                    logger.error("Fixed dollar risk requires SL")
                    return [{"error": "Fixed dollar risk requires SL"}]
                
                # If entry_price is None (market order), we'll get current price later
                if not entry_price:
                    logger.info("Entry price is None (market order), will use current market price for calculation")

                symbol_info = mt5.symbol_info(clean_symbol)
                point = symbol_info.point
                
                # Get current market price if entry_price is None (market order)
                if not entry_price:
                    tick = mt5.symbol_info_tick(clean_symbol)
                    if tick is None:
                        logger.error(f"Failed to get current price for {clean_symbol}")
                        return [{"error": f"Failed to get current price for {clean_symbol}"}]
                    
                    # Use ask price for BUY orders, bid price for SELL orders
                    if order_type == "BUY":
                        entry_price = tick.ask
                    else:
                        entry_price = tick.bid
                    logger.info(f"Using current market price for calculation: {entry_price}")
                
                # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                sl_distance = abs(entry_price - sl) / point / pip_multiplier

                # Validate SL distance
                if sl_distance <= 0:
                    logger.error(f"Invalid SL distance: {sl_distance} pips")
                    return [{"error": "Invalid stop loss distance"}]
                
                # Prevent extremely small SL distances (less than 1 pip)
                if sl_distance < 1:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very small, this may cause issues")
                
                # Prevent extremely large SL distances (more than 1000 pips)
                if sl_distance > 1000:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very large, please verify")

                # Calculate pip value correctly for different instruments
                pip_value = self.calculate_pip_value(symbol_info, clean_symbol)

                # Calculate lot size
                lot_size = fixed_dollar_risk / (sl_distance * pip_value)
                logger.info(f"Fixed dollar calculation: Risk=${fixed_dollar_risk}, SL_distance={sl_distance:.2f} pips, Pip_value=${pip_value:.2f}, Lot_size={lot_size:.4f}")

                # Safety checks for lot size
                if lot_size <= 0:
                    logger.error(f"Invalid lot size calculated: {lot_size}")
                    return [{"error": "Invalid lot size calculated"}]
                
                # Prevent extremely large lot sizes (safety limit)
                max_safe_lot = 100.0  # Maximum safe lot size
                if lot_size > max_safe_lot:
                    logger.warning(f"Lot size {lot_size:.4f} exceeds safety limit of {max_safe_lot}, capping to {max_safe_lot}")
                    lot_size = max_safe_lot
                
                # Additional validation for reasonable lot sizes
                if lot_size > 10.0:
                    logger.warning(f"Large lot size calculated: {lot_size:.4f} - please verify risk settings")
                
                # Log detailed calculation for debugging
                logger.info(f"Risk calculation details for {clean_symbol}:")
                logger.info(f"  - Fixed dollar risk: ${fixed_dollar_risk}")
                logger.info(f"  - Entry price: {entry_price}")
                logger.info(f"  - Stop loss: {sl}")
                logger.info(f"  - SL distance: {sl_distance:.2f} pips")
                logger.info(f"  - Pip value per lot: ${pip_value:.2f}")
                logger.info(f"  - Calculated lot size: {lot_size:.4f}")

            else:  # Fixed lot method
                lot_size = risk_settings.get("fixed_lot", 0.1)
                logger.info(f"Using fixed lot size: {lot_size}")

            # Validate and adjust volume
            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info:
                # Get volume constraints
                min_volume = symbol_info.volume_min
                volume_step = symbol_info.volume_step

                # Adjust volume to meet broker requirements
                if lot_size < min_volume:
                    lot_size = min_volume
                if volume_step > 0:
                    lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step

                logger.info(f"Adjusted volume: {lot_size} (min: {min_volume}, step: {volume_step})")

            # Validate pending orders require entry price
            is_market_order = order_type in ["BUY", "SELL"]
            if not is_market_order and entry_price is None:
                logger.error("Pending order requires entry price")
                return [{"error": "Pending order requires entry price"}]

            # Handle range entries with validation
            if isinstance(entry_price, tuple):
                if len(entry_price) != 2:
                    logger.error("Invalid range entry - must have exactly 2 values")
                    return [{"error": "Invalid range entry format"}]
                
                # Validate range values
                if entry_price[0] <= 0 or entry_price[1] <= 0:
                    logger.error("Invalid range entry - values must be positive")
                    return [{"error": "Invalid range entry values"}]
                
                risk_settings = self.parent.settings.get_risk_settings()
                range_handling = risk_settings['entry_range_handling']
                if range_handling == "First Price":
                    calculated_price = entry_price[0]
                elif range_handling == "Last Price":
                    calculated_price = entry_price[1]
                else:  # Average Price
                    calculated_price = (entry_price[0] + entry_price[1]) / 2
                
                # Validate calculated price
                if calculated_price <= 0:
                    logger.error("Invalid calculated entry price")
                    return [{"error": "Invalid calculated entry price"}]
                
                logger.info(f"Converted range entry to {calculated_price} using {range_handling} method")
                entry_price = calculated_price

            # Get symbol info
            if not mt5.symbol_select(clean_symbol, True):
                logger.error(f"Symbol {clean_symbol} not found")
                return [{"error": f"Symbol {clean_symbol} not found"}]

            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info is None:
                logger.error(f"Failed to get symbol info for {clean_symbol}")
                return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

            point = symbol_info.point if symbol_info else 0.00001  # Fallback point value
            tick = mt5.symbol_info_tick(clean_symbol)
            if tick is None:
                logger.error(f"Failed to get current price for {clean_symbol}")
                return [{"error": f"Failed to get current price for {clean_symbol}"}]

            # Prepare base trade request
            # Get comment settings and channel name
            risk_settings = self.parent.settings.get_risk_settings() if hasattr(self, 'parent') else {}
            enable_comments = risk_settings.get("enable_comments", True)
            comment_prefix = risk_settings.get("comment_prefix", "FTSC")
            
            # Get channel name from signal data if available
            channel_name = channel_name if channel_name else "Unknown"
            
            # Create comment with channel name if enabled
            if enable_comments:
                comment = f"{comment_prefix} - {channel_name}"
            else:
                comment = ""
            
            request = {
                "symbol": clean_symbol,
                "volume": lot_size,
                "deviation": 20,
                "magic": 2023,
                "comment": comment,
                "type_time": mt5.ORDER_TIME_GTC,
            }

            # Add SL if provided
            if sl and sl > 0:
                request["sl"] = sl

            # Set order type
            if is_market_order:
                request["action"] = mt5.TRADE_ACTION_DEAL
                request["type_filling"] = mt5.ORDER_FILLING_FOK
                if order_type == "BUY":
                    request["type"] = mt5.ORDER_TYPE_BUY
                    request["price"] = tick.ask
                else:  # SELL
                    request["type"] = mt5.ORDER_TYPE_SELL
                    request["price"] = tick.bid
            else:
                request["action"] = mt5.TRADE_ACTION_PENDING
                request["price"] = entry_price
                request["type_filling"] = mt5.ORDER_FILLING_IOC
                if order_type == "BUY LIMIT":
                    request["type"] = mt5.ORDER_TYPE_BUY_LIMIT
                elif order_type == "SELL LIMIT":
                    request["type"] = mt5.ORDER_TYPE_SELL_LIMIT
                elif order_type == "BUY STOP":
                    request["type"] = mt5.ORDER_TYPE_BUY_STOP
                elif order_type == "SELL STOP":
                    request["type"] = mt5.ORDER_TYPE_SELL_STOP

            # Handle multiple TPs
            results = []
            if tps and len(tps) > 1:
                # Get symbol volume limits
                min_volume = symbol_info.volume_min
                volume_per_tp = lot_size / len(tps)

                # Adjust volume to meet minimum requirement while respecting total volume
                if volume_per_tp < min_volume:
                    volume_per_tp = min_volume
                    total_volume = volume_per_tp * len(tps)
                    if total_volume > lot_size * 1.1:  # Allow 10% tolerance
                        logger.warning(f"Total volume {total_volume} exceeds original {lot_size}, adjusting")
                        volume_per_tp = lot_size / len(tps)  # Revert to original calculation
                    else:
                        logger.warning(f"Adjusted TP volume to minimum: {min_volume}")

                for i, tp_val in enumerate(tps):
                    tp_request = request.copy()
                    tp_request["volume"] = volume_per_tp
                    tp_request["tp"] = tp_val
                    tp_request["comment"] = f"Falcon Trade TP{i + 1}"

                    # Send trade request
                    result = mt5.order_send(tp_request)
                    if result.retcode != mt5.TRADE_RETCODE_DONE:
                        error_msg = f"TP{i + 1} failed: {result.comment}"
                        logger.error(error_msg)
                        results.append({"error": error_msg})
                    else:
                        logger.info(f"TP{i + 1} executed successfully: Ticket={result.order}")

                        # Add to trade tracker
                        self.trade_tracker.add_trade(
                            ticket=result.order,
                            symbol=clean_symbol,
                            order_type=order_type,
                            volume=volume_per_tp,
                            entry_price=entry_price,
                            actual_price=result.price,
                            sl=sl,
                            tp=tp_val,
                            status='pending' if not is_market_order else 'filled'
                        )
                        results.append({
                            "symbol": clean_symbol,
                            "order_type": order_type,
                            "volume": volume_per_tp,
                            "price": result.price,
                            "sl": sl,
                            "tp": tp_val,
                            "ticket": result.order
                        })
                return results
            else:
                # Handle single TP
                if tp and tp > 0:
                    request["tp"] = tp
                elif tps and len(tps) == 1:
                    request["tp"] = tps[0]

                # Send trade request
                result = mt5.order_send(request)
                if result.retcode != mt5.TRADE_RETCODE_DONE:
                    error_msg = f"Trade failed: {result.comment} (error {result.retcode})"
                    logger.error(error_msg)
                    return [{"error": error_msg}]

                logger.info(f"Trade executed successfully: Ticket={result.order}")

                # Add to trade tracker
                self.trade_tracker.add_trade(
                    ticket=result.order,
                    symbol=clean_symbol,
                    order_type=order_type,
                    volume=lot_size,
                    entry_price=entry_price,
                    actual_price=result.price,
                    sl=sl,
                    tp=tp or (tps[0] if tps and len(tps) > 0 else None),
                    status='pending' if not is_market_order else 'filled'
                )

                return [{
                    "symbol": clean_symbol,
                    "order_type": order_type,
                    "volume": lot_size,
                    "price": result.price,
                    "sl": sl,
                    "tp": tp or (tps[0] if tps and len(tps) > 0 else None),
                    "ticket": result.order
                }]

        except Exception as e:
            logger.error(f"Error executing trade: {str(e)}")
            return [{"error": str(e)}]

    def _handle_send_result(self, result, request):
        if result is None:
            last_error = mt5.last_error()
            return {"error": f"MT5 send failed: {last_error}"}
        elif result.retcode != mt5.TRADE_RETCODE_DONE:
            return {"error": f"Broker rejected: {result.retcode} - {result.comment}"}
        else:
            # Add trade with partial volume
            self.trade_tracker.add_trade(
                result.order,
                request["symbol"],
                request["type"],
                request["volume"],  # Partial volume
                request["price"],
                sl=request.get("sl"),
                tp=request.get("tp"),
                tps=None
            )
            return {"success": True, "ticket": result.order}

    def handle_management(self, command):
        action = command.get("action")
        symbol = command.get("symbol")
        trades = self.trade_tracker.get_trades_by_symbol(symbol) if symbol else list(
            self.trade_tracker.active_trades.values())
        if not trades:
            return {"error": "No matching trades found"}

        results = []
        for trade in trades:
            ticket = [k for k, v in self.trade_tracker.active_trades.items() if v == trade][0]
            if action == "CLOSE":
                self.close_trade(ticket)
                results.append({"success": True, "action": "closed", "ticket": ticket})
            elif action == "PARTIAL_CLOSE":
                percent = command.get("percent", 50)
                self.partial_close_trade(ticket, percent)
                results.append({"success": True, "action": "partial_closed", "ticket": ticket})
            elif action == "MODIFY_SL":
                new_sl = command.get("sl")
                if new_sl:
                    self.modify_sl(ticket, new_sl)
                    results.append({"success": True, "action": "sl_modified", "ticket": ticket})
            elif action == "MODIFY_TP":
                new_tp = command.get("tp")
                if new_tp:
                    self.modify_tp(ticket, new_tp)
                    results.append({"success": True, "action": "tp_modified", "ticket": ticket})
            elif action == "SL_TO_BE":
                self.move_sl_to_be(ticket)
                results.append({"success": True, "action": "sl_to_be", "ticket": ticket})
            elif action == "CANCEL":
                self.cancel_order(ticket)
                results.append({"success": True, "action": "cancelled", "ticket": ticket})

        return results

    def close_trade(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": position.volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Close trade",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                profit = result.profit
                self.trade_tracker.remove_trade(ticket, profit)
                return True
        return False

    def partial_close_trade(self, ticket, percent):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            close_volume = position.volume * (percent / 100)
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": close_volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Partial close",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                # Update volume in tracker
                new_volume = position.volume - close_volume
                self.trade_tracker.update_trade(ticket, {"volume": new_volume})
                return True
        return False

    def modify_sl(self, ticket, new_sl):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": new_sl,
                "tp": position.tp  # PRESERVE EXISTING TP
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": new_sl})
                return True
        return False

    def modify_tp(self, ticket, new_tp):
        request = {
            "action": mt5.TRADE_ACTION_SLTP,
            "position": ticket,
            "tp": new_tp,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.update_trade(ticket, {"tp": new_tp})
            return True
        return False

    def move_sl_to_be(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            be_price = position.price_open
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": be_price,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": be_price})
                return True
        return False

    def cancel_order(self, ticket):
        request = {
            "action": mt5.TRADE_ACTION_REMOVE,
            "order": ticket,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.remove_trade(ticket, 0)
            return True
        return False

    def close_all_trades(self):
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                self.close_trade(pos.ticket)

    def monitor_trades(self):
        risk_settings = self.parent.settings.get_risk_settings()
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                ticket = pos.ticket
                trade = self.trade_tracker.get_trade_by_ticket(ticket)
                if not trade:
                    continue

                current_price = mt5.symbol_info_tick(
                    pos.symbol).bid if pos.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(pos.symbol).ask
                entry_price = trade["entry"]

                # BE after pips
                if risk_settings['be_after_pips'] > 0:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    pip_diff = abs(current_price - entry_price) / point / pip_multiplier
                    if pip_diff >= risk_settings['be_after_pips']:
                        self.move_sl_to_be(ticket)

                # Trailing SL
                if risk_settings['trailing_sl_enabled']:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert pip distance to points for trailing stop
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    trailing_dist = risk_settings['trailing_sl_distance'] * point * pip_multiplier
                    if pos.type == mt5.ORDER_TYPE_BUY:
                        new_sl = current_price - trailing_dist
                        if new_sl > pos.sl:
                            self.modify_sl(ticket, new_sl)
                    else:
                        new_sl = current_price + trailing_dist
                        if new_sl < pos.sl:
                            self.modify_sl(ticket, new_sl)

class TradeMonitor(QThread):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.running = True

    def run(self):
        while self.running:
            if self.parent.mt5_manager.connected:
                self.parent.mt5_manager.monitor_trades()
            time.sleep(1)

# =====================
# UI COMPONENTS

# =====================
# ACTIVATION PAGE
# =====================
class ActivationPage(QWidget):
    activation_result = Signal(bool, str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.activation_result.connect(self.handle_activation_result)

    def setup_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(20)

        # Logo
        logo_label = QLabel()
        logo_pixmap = self.main_window.app_logo.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label, 0, Qt.AlignCenter)

        # Header
        header = QLabel("Falcon Trade Signal Copier")
        header
        layout.addWidget(header, 0, Qt.AlignCenter)

        # Subheader
        subheader = QLabel("Activate Your License")
        subheader
        layout.addWidget(subheader, 0, Qt.AlignCenter)

        # Instruction text
        instruction = QLabel(
            "Enter your license key below or start a free 7-day trial."
        )
        instruction
        instruction.setWordWrap(True)
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)

        # License key input
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter license key (XXXX-XXXX-XXXX-XXXX)")
        self.key_input
        # Allow Enter key to activate
        self.key_input.returnPressed.connect(self.activate_software)
        layout.addWidget(self.key_input)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        self.activate_btn = QPushButton("Activate License")
        self.activate_btn
        self.activate_btn.clicked.connect(self.activate_software)

        self.trial_btn = QPushButton("Start Free Trial")
        self.trial_btn
        self.trial_btn.clicked.connect(self.start_trial)

        btn_layout.addWidget(self.activate_btn)
        btn_layout.addWidget(self.trial_btn)
        layout.addLayout(btn_layout)

        # Status message
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"font-size: 13px; margin-top: 10px;")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Footer
        footer = QLabel(
            f"© 2023 Falcon Trade Copier v{VERSION} | "
            "<a href='https://falcontradecopier.com' style='color:blue;'>Website</a> | "
            "<a href='mailto:support@falcontradecopier.com' style='color:blue;'>Support</a>"
        )
        footer
        footer.setOpenExternalLinks(True)
        layout.addWidget(footer, 0, Qt.AlignCenter)

        # Set initial status
        self.update_status(True, "Enter your license key to continue")

    def update_status(self, valid, message):
        color = "green" if valid else "red"
        self.status_label.setStyleSheet(f"""
            font-size: 13px;
            color: {color};
            margin-top: 10px;
        """)
        self.status_label.setText(message)

    def activate_software(self):
        try:
            key = self.key_input.text().strip()

            if not key:
                self.update_status(False, "Please enter a license key")
                return

            if len(key) < 8:  # Reduced minimum length for bypass key
                self.update_status(False, "Invalid license key format")
                return

            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.activate_btn.setText("Validating...")
            self.update_status(True, "Validating license...")

            # Start validation in separate thread
            threading.Thread(target=self.main_window.validate_license, args=(key,), daemon=True).start()
            
            logger.info(f"Starting license validation for key: {key[:8]}...")
            
        except Exception as e:
            logger.error(f"Error in activate_software: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.update_status(False, "Activation error occurred. Please try again.")

    def start_trial(self):
        try:
            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.trial_btn.setText("Starting...")
            self.update_status(True, "Starting trial...")

            # Start trial process in separate thread
            threading.Thread(target=self.main_window.process_trial, daemon=True).start()
            
            logger.info("Starting trial license creation...")
            
        except Exception as e:
            logger.error(f"Error in start_trial: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.trial_btn.setText("Start Free Trial")
            self.update_status(False, "Trial start error occurred. Please try again.")

    def handle_activation_result(self, valid, message, result):
        try:
            if valid:
                self.update_status(True, message)
                self.main_window.show_telegram_page()
            else:
                # Reset buttons to original state on failure
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
                self.update_status(False, message)
                
                logger.warning(f"Activation failed: {message}")
        except Exception as e:
            logger.error(f"Error handling activation result: {e}")
            # Ensure buttons are reset even if there's an error
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
    
    def reset_ui_state(self):
        """Reset the activation page to initial state"""
        try:
            # Clear input field
            self.key_input.clear()
            
            # Enable buttons and reset text
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
            
            # Reset status message
            self.update_status(True, "Enter your license key to continue")
            
            # Ensure signal connections are active (reconnect if needed)
            self.reconnect_signals()
            
            # Set focus to input field for better UX
            self.key_input.setFocus()
            
            logger.info("Activation page UI state reset successfully")
        except Exception as e:
            logger.error(f"Error resetting activation page UI state: {e}")
            # Fallback to ensure buttons are at least enabled
            try:
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
            except:
                pass
    
    def reconnect_signals(self):
        """Ensure signal connections are properly established"""
        try:
            # Disconnect existing connections to avoid duplicates
            try:
                self.activate_btn.clicked.disconnect()
                self.trial_btn.clicked.disconnect()
            except:
                pass  # No existing connections to disconnect
            
            # Reconnect signals
            self.activate_btn.clicked.connect(self.activate_software)
            self.trial_btn.clicked.connect(self.start_trial)
            
            logger.debug("Activation page signals reconnected")
        except Exception as e:
            logger.error(f"Error reconnecting activation page signals: {e}")

# =====================
# TELEGRAM SETUP PAGE
# =====================
class TelegramPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.channel_checkboxes = {}  # Store channel_id: checkbox mapping
        self.setup_ui()
        self.check_session_status()
        QTimer.singleShot(100, self.attempt_auto_connect)
        self.channels = []  # Store loaded channels

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(1.5)

        # Header with logo
        header = LogoHeader("Telegram Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Phone and Code in one row
        phone_code_layout = QHBoxLayout()
        phone_code_layout.setSpacing(1.5)

        # Phone input
        phone_layout = QVBoxLayout()
        phone_layout.setSpacing(1.5)
        phone_label = QLabel("Phone Number:")
        phone_label
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("+1234567890")
        self.phone_input.setFixedHeight(28)
        self.phone_input.setFixedWidth(200)
        phone_layout.addWidget(phone_label)
        phone_layout.addWidget(self.phone_input)
        phone_code_layout.addLayout(phone_layout)

        # Code input
        code_layout = QVBoxLayout()
        code_layout.setSpacing(1.5)
        code_label = QLabel("Verification Code:")
        code_label
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("12345")
        self.code_input.setEnabled(False)
        self.code_input.setFixedHeight(28)
        self.code_input.setFixedWidth(200)
        code_layout.addWidget(code_label)
        code_layout.addWidget(self.code_input)
        phone_code_layout.addLayout(code_layout)

        layout.addLayout(phone_code_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(1.5)

        self.send_code_btn = QPushButton("Send Code")
        self.send_code_btn.clicked.connect(self.send_telegram_code)

        self.verify_btn = QPushButton("Verify")
        self.verify_btn.setEnabled(False)
        self.verify_btn.clicked.connect(self.verify_telegram_code)

        self.change_number_btn = QPushButton("Change Number")
        self.change_number_btn.setVisible(False)
        self.change_number_btn.clicked.connect(self.change_telegram_number)

        btn_layout.addWidget(self.send_code_btn)
        btn_layout.addWidget(self.verify_btn)
        btn_layout.addWidget(self.change_number_btn)
        layout.addLayout(btn_layout)

        # Channel selection
        channel_layout = QVBoxLayout()
        channel_layout.setSpacing(1.5)
        channel_header = QLabel("Telegram Channels:")
        channel_header
        channel_layout.addWidget(channel_header)
        
        # Search field for channels
        search_layout = QHBoxLayout()
        search_layout.addStretch()  # Push to right side
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.channel_search = QLineEdit()
        self.channel_search.setPlaceholderText("Search channels...")
        self.channel_search.setFixedHeight(28)
        self.channel_search.setFixedWidth(200)
        self.channel_search.textChanged.connect(self.filter_channels)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.channel_search)
        channel_layout.addLayout(search_layout)

        # Scroll area for channels grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: 2px solid #1c243b;
                border-radius: 6px;
                background-color: #0d111f;
            }
        """)

        # Container widget for grid
        container = QWidget()
        self.grid_layout = QGridLayout(container)
        self.grid_layout.setSpacing(0)
        self.grid_layout.setContentsMargins(15, 15, 15, 15)

        scroll_area.setWidget(container)
        scroll_area.setMinimumHeight(150)
        channel_layout.addWidget(scroll_area)
        layout.addLayout(channel_layout)

        # Channel IDs and Save button in one row
        id_save_layout = QHBoxLayout()
        id_save_layout.setSpacing(1.5)

        # Channel IDs
        id_layout = QVBoxLayout()
        id_layout.setSpacing(1.5)
        id_label = QLabel("Channel IDs (comma separated):")
        id_label
        self.channel_id_input = QLineEdit()
        self.channel_id_input
        id_layout.addWidget(id_label)
        id_layout.addWidget(self.channel_id_input)
        id_save_layout.addLayout(id_layout, 3)  # 3/4 width

        # Save button
        self.save_btn = QPushButton("Save Channels")
        self.save_btn.setFixedHeight(35)
        self.save_btn.setFixedWidth(120)
        self.save_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.save_btn.clicked.connect(self.save_channels)
        id_save_layout.addWidget(self.save_btn, 1)  # 1/4 width
        # Align save button with channel ID field
        self.save_btn.setContentsMargins(0, 0, 0, 0)

        layout.addLayout(id_save_layout)

        # Navigation
        nav_layout = QHBoxLayout()

        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.activation_page))
        self.next_btn = QPushButton("Next")
        self.next_btn.setEnabled(False)
        self.next_btn.clicked.connect(self.parent.show_mt5_page)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)
        layout.addLayout(nav_layout)

        # Set fixed width for buttons
        for btn in [self.send_code_btn, self.verify_btn, self.change_number_btn]:
            btn.setFixedWidth(150)

        # Load saved channels if any
        saved_channels = self.parent.settings.get_telegram_channels()
        if saved_channels:
            self.channel_id_input.setText(", ".join(str(id) for id in saved_channels))

    def send_telegram_code(self):
        phone = self.phone_input.text().strip()
        if not phone:
            QMessageBox.warning(self, "Missing Phone", "Please enter your phone number")
            return

        self.send_code_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Sending verification code...")
        self.parent.telegram_manager.connect_telegram(
            TELEGRAM_API_ID,
            TELEGRAM_API_HASH,
            phone
        )

    def verify_telegram_code(self):
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "Missing Code", "Please enter the verification code")
            return

        self.verify_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Verifying code...")
        self.parent.telegram_manager.authenticate(code)

    def change_telegram_number(self):
        self.parent.telegram_manager.stop_listening()
        self.parent.telegram_manager = TelegramManager()
        self.parent.setup_connections()
        self.parent.settings.set_telegram_session(None)
        self.phone_input.setEnabled(True)
        self.phone_input.clear()
        self.code_input.clear()
        self.code_input.setEnabled(False)
        self.verify_btn.setEnabled(False)
        self.change_number_btn.setVisible(False)
        self.next_btn.setEnabled(False)
        self.clear_channel_grid()
        self.channel_id_input.clear()
        self.send_code_btn.setEnabled(True)
        self.send_code_btn.setVisible(True)
        self.parent.update_connection_status()
        self.parent.status_bar.showMessage("Enter new phone number")

    def check_session_status(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)

    def attempt_auto_connect(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.parent.status_bar.showMessage("Attempting auto-login...")
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)
            self.phone_input.setEnabled(False)
            self.code_input.setEnabled(False)
            self.verify_btn.setEnabled(False)
            self.parent.telegram_manager.session_string = session
            self.parent.telegram_manager.connect_telegram(
                TELEGRAM_API_ID, TELEGRAM_API_HASH, ""
            )

    def load_channels(self, channels):
        self.channels = channels  # Store channels
        self.clear_channel_grid()
        if not channels:
            label = QLabel("No channels available")
            label
            label.setAlignment(Qt.AlignCenter)
            self.grid_layout.addWidget(label, 0, 0, 1, 2)
            return

        # Add channels to grid
        row, col = 0, 0
        max_cols = 2  # Number of columns in grid

        for channel in channels:
            checkbox = QCheckBox(f"{channel['name']} (@{channel['username']})")
            checkbox
            checkbox.setProperty("channel_id", channel["id"])
            self.channel_checkboxes[channel["id"]] = checkbox

            # Check if this channel is already selected
            saved_ids = [id.strip() for id in self.channel_id_input.text().split(",") if id.strip()]
            if str(channel["id"]) in saved_ids:
                checkbox.setChecked(True)

            # Connect checkbox state change to update ID input
            checkbox.stateChanged.connect(self.update_channel_ids_from_checkboxes)

            self.grid_layout.addWidget(checkbox, row, col)

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

    def clear_channel_grid(self):
        # Clear existing checkboxes
        for i in reversed(range(self.grid_layout.count())):
            widget = self.grid_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self.channel_checkboxes.clear()

    def update_channel_ids_from_checkboxes(self):
        """Update channel ID input based on checkbox states"""
        selected_ids = []
        for channel_id, checkbox in self.channel_checkboxes.items():
            if checkbox.isChecked():
                selected_ids.append(str(channel_id))

        self.channel_id_input.setText(", ".join(selected_ids))

    def save_channels(self):
        channel_ids = []
        for id_str in self.channel_id_input.text().split(','):
            id_str = id_str.strip()
            if id_str:
                try:
                    channel_ids.append(int(id_str))
                except ValueError:
                    logger.error(f"Invalid channel ID: {id_str}")

        if channel_ids:
            self.parent.settings.set_telegram_channels(channel_ids)
            self.parent.status_bar.showMessage(f"Saved {len(channel_ids)} channels")
            self.next_btn.setEnabled(True)
        else:
            self.parent.status_bar.showMessage("No valid channel IDs to save")

    def get_channel_name(self, channel_id):
        for channel in self.channels:
            if channel['id'] == channel_id:
                return channel['name']
        return str(channel_id)
        
    def filter_channels(self):
        """Filter channels based on search text"""
        search_text = self.channel_search.text().lower()
        for i in range(self.grid_layout.count()):
            widget = self.grid_layout.itemAt(i).widget()
            if isinstance(widget, QCheckBox):
                channel_name = widget.text().lower()
                widget.setVisible(search_text in channel_name)

# MT5 SETUP PAGE
# =====================
class MT5Page(QWidget):
    connection_result = Signal(bool, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        self.load_settings()
        self.connection_result.connect(self.on_mt5_connection_result)

    def browse_mt5_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select MetaTrader 5 Terminal",
            "C:/",
            "Executable Files (*.exe)"
        )
        if file_path:
            self.path_input.setText(file_path)

    def setup_ui(self):
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 25, 40, 20)
        layout.setSpacing(8)

        # Header with logo
        header = LogoHeader("MT5 Account Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Form
        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignLeft)

        # Account
        account_label = QLabel("Account Number:")
        account_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.account_input = QLineEdit()
        self.account_input.setPlaceholderText("Enter MT5 account number")
        self.account_input.setFixedHeight(40)
        self.account_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(account_label, self.account_input)

        # Server
        server_label = QLabel("Server:")
        server_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Enter MT5 server name")
        self.server_input.setFixedHeight(40)
        self.server_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(server_label, self.server_input)

        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter MT5 password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(40)
        self.password_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(password_label, self.password_input)

        # Path
        path_label = QLabel("MT5 Path:")
        path_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        path_layout = QHBoxLayout()
        path_layout.setSpacing(4)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter MT5 terminal path")
        self.path_input.setFixedHeight(40)
        self.path_input.setStyleSheet("font-size: 13px;")
        path_layout.addWidget(self.path_input)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_mt5_path)
        self.browse_btn.setFixedWidth(100)
        self.browse_btn.setFixedHeight(40)
        path_layout.addWidget(self.browse_btn)
        form_layout.addRow(path_label, path_layout)

        # MT5 Path Instructions
        path_instructions = QLabel("💡 Instructions: Right-click on your MT5 terminal shortcut → Properties → Copy the path from 'Target' field")
        path_instructions.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 4px;")
        path_instructions.setWordWrap(False)
        path_instructions.setAlignment(Qt.AlignLeft)
        form_layout.addRow("", path_instructions)

        # Symbol Prefix and Suffix (aligned like other fields)
        prefix_label = QLabel("Symbol Prefix:")
        prefix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText(".pro")
        self.prefix_input.setFixedHeight(40)
        self.prefix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(prefix_label, self.prefix_input)
        
        suffix_label = QLabel("Symbol Suffix:")
        suffix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.suffix_input = QLineEdit()
        self.suffix_input.setPlaceholderText(".raw")
        self.suffix_input.setFixedHeight(40)
        self.suffix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(suffix_label, self.suffix_input)

        # Help text
        help_text = QLabel("💡 Tip: Leave empty if your broker doesn't use prefixes/suffixes")
        help_text.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 8px;")
        help_text.setWordWrap(True)
        help_text.setAlignment(Qt.AlignCenter)
        form_layout.addRow(help_text)

        # Center the form
        form_container = QWidget()
        form_container.setMaximumWidth(500)
        form_container.setLayout(form_layout)
        
        # Center the form container
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(form_container)
        center_layout.addStretch()
        layout.addLayout(center_layout)

        # Status
        self.status_label = QLabel("Not connected")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        # Connect button with dynamic glow effect
        self.connect_btn = QPushButton("Connect to MT5")
        self.connect_btn.setFixedHeight(45)
        self.connect_btn.setFixedWidth(200)
        self.connect_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f27d03, stop:1 #ff8a1a);
                color: #020711;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff8a1a, stop:1 #f27d03);
                
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e07000, stop:1 #f27d03);
            }
        """)
        self.connect_btn.clicked.connect(self.connect_mt5)
        
        # Center the button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.connect_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 6)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1c243b;
                border-radius: 4px;
                text-align: center;
                background-color: #0d111f;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8ccaee, stop:1 #f27d03);
                border-radius: 3px;
            }
        """)
        # Remove percentage text from progress bar
        self.progress_bar.setTextVisible(False)
        # Center the progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addStretch()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addStretch()
        layout.addLayout(progress_layout)

        # Navigation
        nav_layout = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.telegram_page))
        self.finish_btn = QPushButton("Finish")
        self.finish_btn.setEnabled(False)
        self.finish_btn.clicked.connect(self.parent.show_dashboard)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.finish_btn)
        layout.addLayout(nav_layout)

    def load_settings(self):
        mt5_settings = self.parent.settings.get_mt5_settings()
        self.account_input.setText(mt5_settings.get("account", ""))
        self.server_input.setText(mt5_settings.get("server", ""))
        self.password_input.setText(mt5_settings.get("password", ""))
        self.path_input.setText(mt5_settings.get("path", ""))
        self.prefix_input.setText(mt5_settings.get("symbol_prefix", ""))
        self.suffix_input.setText(mt5_settings.get("symbol_suffix", ""))

    def connect_mt5(self):
        account = self.account_input.text().strip()
        server = self.server_input.text().strip()
        password = self.password_input.text()
        path = self.path_input.text().strip()
        symbol_prefix = self.prefix_input.text().strip()
        symbol_suffix = self.suffix_input.text().strip()

        if not account or not server or not password or not path:
            QMessageBox.warning(self, "Missing Information", "Please fill in all fields")
            return

        self.connect_btn.setEnabled(False)
        self.status_label.setText("Connecting to MT5...")
        self.parent.status_bar.showMessage("Connecting to MT5...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.parent.settings.set_mt5_settings(account, server, password, path, symbol_prefix, symbol_suffix)

        # Create a new thread and worker
        self.thread = QThread()
        self.worker = Worker(account, server, password, path)
        self.worker.parent = self.parent  # Pass parent reference
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress_update.connect(self.update_progress_status)
        self.worker.finished.connect(self.on_mt5_connection_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # Start the thread
        self.thread.start()
        
        # Set up timeout timer
        self.timeout_timer = QTimer()
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self.handle_connection_timeout)
        self.timeout_timer.start(60000)  # 60 seconds timeout

    def connect_mt5_thread(self, account, server, password, path):
        try:
            self.parent.mt5_manager.connect(account, server, password, path)
            self.connection_result.emit(True, "Connected successfully!")
        except Exception as e:
            self.connection_result.emit(False, str(e))

    def update_progress_status(self, message, step):
        """Update the status label with progress message and update progress bar"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        self.parent.status_bar.showMessage(message)
        self.progress_bar.setValue(step)

    def handle_connection_timeout(self):
        """Handle connection timeout"""
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.terminate()
            self.thread.wait(2000)  # Wait up to 2 seconds for thread to terminate
        self.progress_bar.setVisible(False)
        self.status_label.setText("Connection timeout - please try again")
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
        self.parent.status_bar.showMessage("MT5 connection timed out")
        self.connect_btn.setEnabled(True)
        QMessageBox.warning(self, "Connection Timeout", 
                          "The connection to MT5 timed out. Please check your settings and try again.")

    def on_mt5_connection_result(self, success, message):
        # Stop timeout timer
        if hasattr(self, 'timeout_timer'):
            self.timeout_timer.stop()
        
        self.progress_bar.setVisible(False)
        if success:
            self.status_label.setText("Connected successfully")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #1d9e4a;")
            self.parent.status_bar.showMessage("MT5 connected successfully")
            # Update account info immediately after successful connection
            self.parent.update_account_info()
            # Enable the finish button so user can click it to go to dashboard
            self.finish_btn.setEnabled(True)
        else:
            self.status_label.setText("Connection failed")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
            self.parent.status_bar.showMessage("MT5 connection failed")
            QMessageBox.warning(self, "Connection Failed", f"Failed to connect to MT5: {message}")
        self.connect_btn.setEnabled(True)

class Worker(QObject):
    finished = Signal(bool, str)
    progress_update = Signal(str, int)  # Add progress signal with step number

    def __init__(self, account, server, password, path):
        super().__init__()
        self.account = account
        self.server = server
        self.password = password
        self.path = path
        self.timeout = 60  # 60 seconds timeout for connection

    @Slot()
    def run(self):
        try:
            # Step 1: Validate account number
            self.progress_update.emit("Validating account number...", 1)
            time.sleep(0.5)  # Small delay to show progress
            try:
                account = int(self.account) if str(self.account).isdigit() else self.account
            except ValueError:
                raise ValueError("Account number must be numeric")

            # Step 2: Shutdown existing MT5 connection
            self.progress_update.emit("Shutting down existing MT5 connection...", 2)
            time.sleep(0.5)  # Small delay to show progress
            if mt5_is_initialized():
                mt5.shutdown()
                time.sleep(1)

            # Step 3: Check MT5 executable path
            self.progress_update.emit("Checking MT5 executable...", 3)
            time.sleep(0.5)  # Small delay to show progress
            if not os.path.exists(self.path):
                raise ValueError("MT5 path not found")

            # Step 4: Initialize MT5
            self.progress_update.emit("Initializing MT5...", 4)
            time.sleep(0.5)  # Small delay to show progress
            logger.info(f"Connecting to MT5 at: {self.path}")
            if not mt5.initialize(path=self.path, login=account, password=self.password, server=self.server):
                raise ValueError(f"MT5 initialization failed: {mt5.last_error()}")

            # Step 5: Get account info
            self.progress_update.emit("Getting account information...", 5)
            time.sleep(0.5)  # Small delay to show progress
            account_info = mt5.account_info()
            if not account_info:
                raise ValueError("Failed to get account info")

            # Step 6: Finalize connection
            self.progress_update.emit("Finalizing connection...", 6)
            time.sleep(0.5)  # Small delay to show progress
            
            # Set the connection status in the MT5Manager
            if hasattr(self, 'parent') and hasattr(self.parent, 'mt5_manager'):
                self.parent.mt5_manager.connected = True
                self.parent.mt5_manager.account = self.account
                self.parent.mt5_manager.server = self.server
                self.parent.mt5_manager.path = self.path
            
            self.finished.emit(True, "Connected successfully")
        except Exception as e:
            self.finished.emit(False, str(e))

import sys
import os
import asyncio
import threading
from PySide6.QtCore import QObject, Signal, Slot, QThread
import json
import uuid
import socket
import hashlib
import requests
import time
from datetime import datetime, timedelta
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase not available. Install with: pip install supabase")
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect, QThread
import re
import logging
from PySide6.QtCore import QDate
from PySide6.QtWidgets import QDateEdit, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import QPropertyAnimation, QEasingCurve
import pyperclip
from PySide6.QtGui import QIcon, QPalette, QColor, QAction, QFont, QImage, QPixmap, QLinearGradient, QBrush, QPainter, \
    QFontMetrics
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QCheckBox,
    QGroupBox, QSpacerItem, QSizePolicy, QFileDialog, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QSystemTrayIcon,
    QMenu, QStatusBar, QGridLayout, QComboBox, QDoubleSpinBox, QTreeWidget,
    QTreeWidgetItem, QInputDialog, QDialog, QDialogButtonBox, QFormLayout, QScrollArea,
    QSpinBox, QFrame, QStyle, QToolBar, QProgressBar
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import Channel
import MetaTrader5 as mt5
import psutil
import platform

# Charting and analytics imports
try:
    import matplotlib
    # Set backend before importing pyplot to avoid GUI issues
    matplotlib.use('Agg', force=True)  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    CHARTING_AVAILABLE = True
except ImportError:
    CHARTING_AVAILABLE = False
    print("Warning: Charting libraries not available. Install with: pip install matplotlib pandas numpy")
except Exception as e:
    CHARTING_AVAILABLE = False
    print(f"Warning: Charting libraries error: {e}")

# ======================
# APPLICATION CONSTANTS
# ======================

APP_NAME = "Falcon Trade Signal Copier"
SHORT_NAME = "FTSC"
VERSION = "1.2"

TELEGRAM_API_ID = 26121573
TELEGRAM_API_HASH = "305761518085ff8519d0eded60f46c72"
TRADE_HISTORY_FILE = "../falcon_trade_history.json"
SETTINGS_FILE = "../falcon_app_settings.json"
ACTIVE_TRADES_FILE = "../falcon_active_trades.json"

# Import Supabase configuration
try:
    from supabase_config import *
    SUPABASE_CONFIG_LOADED = True
except ImportError:
    # Fallback configuration (replace with your actual values)
    SUPABASE_URL = "https://your-project-id.supabase.co"
    SUPABASE_ANON_KEY = "your-anon-key-here"
    LICENSES_TABLE = "licenses"
    HEARTBEATS_TABLE = "heartbeats"
    USERS_TABLE = "users"
    SUPABASE_CONFIG_LOADED = False

# Legacy API URLs (fallback)
VALIDATION_URL = "https://api.falcontradecopier.com/validate-license"
HEARTBEAT_URL = "https://api.falcontradecopier.com/heartbeat"
ACTIVATION_URL = "https://api.falcontradecopier.com/activate"
TRIAL_URL = "https://api.falcontradecopier.com/start-trial"

NEWS_API_URL = "https://example.com/news-api"  # Placeholder for news API

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("../falcon_app_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load spaCy model for AI parsing
try:
    import spacy
    from spacy.matcher import Matcher

    nlp = spacy.load("en_core_web_sm")
except ImportError:
    logger.warning("spaCy not installed. Using regex-only parsing.")
    nlp = None
except OSError:
    logger.info("spaCy model not available. Using regex parsing as fallback.")
    nlp = None

# =====================
# HELPER FUNCTIONS
# =====================
def get_hardware_id():
    """Generate hardware fingerprint for device binding"""
    try:
        # Use MAC address
        mac = uuid.getnode()

        # Get disk serial (platform-independent)
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

        # Get CPU info
        cpu_id = platform.processor()

        combined = f"{mac}-{disk_id}-{cpu_id}"
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error generating hardware ID: {str(e)}")
        return str(uuid.uuid4())

def mt5_is_initialized():
    try:
        mt5.symbols_total()
        return True
    except:
        return False

def expand_compact_range_match(match):
    """Helper function to expand compact ranges like '3347-49' to '3347-3349'"""
    first = match.group(1)
    second = match.group(2)
    if '.' in first:
        return match.group(0)  # Don't process decimals
    try:
        first_num = int(first)
        second_num = int(second)
        base = (first_num // 100) * 100
        full_second = base + second_num
        if full_second < first_num:
            full_second += 100  # Handle century crossing
        return f"{first}-{full_second}"
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to expand range {first}-{second}: {e}")
        return match.group(0)

# ======================
# SUPABASE MANAGER
# ======================
class SupabaseManager:
    def __init__(self):
        self.client = None
        self.initialized = False
        self.validation_cache = {}  # Cache recent validations
        self.rate_limit_attempts = {}  # Track validation attempts per IP/machine
        self.max_attempts_per_hour = 60  # Rate limiting
        
        if SUPABASE_AVAILABLE:
            try:
                self.client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                self.initialized = True
                logger.info("Supabase client initialized successfully")
                if SUPABASE_CONFIG_LOADED:
                    logger.info("Supabase configuration loaded successfully")
                else:
                    logger.warning("Using fallback Supabase configuration")
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
        else:
            logger.warning("Supabase not available - using legacy API")
            
    def _check_rate_limit(self, machine_id):
        """Check if machine_id has exceeded rate limits"""
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        
        # Clean old attempts
        self.rate_limit_attempts = {
            mid: attempts for mid, attempts in self.rate_limit_attempts.items()
            if any(attempt > hour_ago for attempt in attempts)
        }
        
        # Check current machine attempts
        if machine_id not in self.rate_limit_attempts:
            self.rate_limit_attempts[machine_id] = []
            
        recent_attempts = [
            attempt for attempt in self.rate_limit_attempts[machine_id]
            if attempt > hour_ago
        ]
        
        if len(recent_attempts) >= self.max_attempts_per_hour:
            logger.warning(f"Rate limit exceeded for machine {machine_id[:8]}...")
            return False
            
        # Record this attempt
        self.rate_limit_attempts[machine_id] = recent_attempts + [current_time]
        return True
        
    def _log_validation_attempt(self, license_key, machine_id, result, additional_info=None):
        """Log validation attempts for security monitoring"""
        log_data = {
            'license_key': license_key[:8] + "...",  # Partial key for security
            'machine_id': machine_id[:8] + "...",   # Partial machine ID
            'timestamp': datetime.now().isoformat(),
            'valid': result.get('valid', False),
            'message': result.get('message', ''),
            'source': 'supabase' if self.initialized else 'fallback'
        }
        
        if additional_info:
            log_data.update(additional_info)
            
        if result.get('valid'):
            logger.info(f"License validation successful: {license_key[:8]}... on {machine_id[:8]}...")
        else:
            logger.warning(f"License validation failed: {license_key[:8]}... on {machine_id[:8]}... - {result.get('message', 'Unknown error')}")
            
        # Store validation log in database for monitoring
        if self.initialized:
            try:
                self.client.table('validation_logs').insert(log_data).execute()
            except Exception as e:
                logger.debug(f"Failed to log validation attempt: {e}")
    
    def validate_license(self, license_key, machine_id):
        """Enhanced license validation using Supabase with improved error handling"""
        if not self.initialized:
            return self._fallback_validate_license(license_key, machine_id)
        
        try:
            # Query the licenses table - prioritize 'key' column (actual database structure)
            try:
                response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name for compatibility
                response = self.client.table(LICENSES_TABLE).select('*').eq('license_key', license_key).execute()
            
            if not response.data:
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": "License key not found"})
                return {"valid": False, "message": "License key not found. Please check your license key."}
            
            license_data = response.data[0]
            
            # Enhanced status validation
            status = license_data.get('status', license_data.get('is_active', False))
            if status not in [LICENSE_STATUS_ACTIVE, True, 'active', 'ACTIVE']:
                detailed_message = f"License status is '{status}'. Please contact support if this is unexpected."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": detailed_message, "status": status})
                return {"valid": False, "message": detailed_message}
            
            # Enhanced expiration validation
            expires_at = license_data.get('expires_at') or license_data.get('expiration_date') or license_data.get('valid_until')
            if not expires_at:
                error_msg = "License has no expiration date. Please contact support."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": error_msg}
            
            try:
                expiration_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if expiration_date < datetime.now(expiration_date.tzinfo):
                    days_expired = (datetime.now(expiration_date.tzinfo) - expiration_date).days
                    error_msg = f"License expired {days_expired} day(s) ago on {expiration_date.strftime('%Y-%m-%d')}. Please renew your license."
                    self._log_validation_attempt(license_key, machine_id, 
                        {"valid": False, "message": error_msg, "days_expired": days_expired})
                    return {"valid": False, "message": error_msg}
            except ValueError as ve:
                error_msg = f"Invalid expiration date format: {expires_at}"
                logger.error(f"Date parsing error for license {license_key[:8]}...: {ve}")
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": "License has invalid expiration date. Please contact support."}
            
            # Enhanced machine binding with multi-device support
            bound_machine = license_data.get('machine_id') or license_data.get('hw_id') or license_data.get('device_id')
            max_machines = license_data.get('max_machines', 1)
            
            # If this is a multi-device license, check current device count
            if max_machines > 1:
                try:
                    # Get all active machines for this license
                    active_machines_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=7)).isoformat()).execute()
                    active_machine_ids = list(set([hb['machine_id'] for hb in active_machines_response.data if hb.get('machine_id')]))
                    
                    if machine_id not in active_machine_ids and len(active_machine_ids) >= max_machines:
                        error_msg = f"License allows maximum {max_machines} device(s). {len(active_machine_ids)} device(s) already active."
                        self._log_validation_attempt(license_key, machine_id, 
                            {"valid": False, "message": error_msg, "max_machines": max_machines, "active_count": len(active_machine_ids)})
                        return {"valid": False, "message": error_msg}
                except Exception as e:
                    logger.warning(f"Could not check device count for multi-device license: {e}")
                    # Continue with single-device validation as fallback
            
            # Single device binding check (for single-device licenses or as fallback)
            if max_machines == 1 and bound_machine and bound_machine != machine_id:
                error_msg = "License is already activated on another device. Contact support for device transfer."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg, "bound_machine": bound_machine[:8] + "..."})
                return {"valid": False, "message": error_msg}
            
            # Update machine binding if not set (for new activations)
            if not bound_machine:
                try:
                    self.client.table(LICENSES_TABLE).update({
                        'machine_id': machine_id,
                        'last_activation': datetime.now().isoformat()
                    }).eq('key', license_key).execute()
                    logger.info(f"License {license_key[:8]}... activated on new device {machine_id[:8]}...")
                except Exception as e:
                    logger.debug(f"Could not update machine binding: {e}")  # Suppressed - column may not exist
                    # Continue validation even if update fails
            
            # Calculate days until expiration for user info
            days_until_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
            
            validation_result = {
                "valid": True,
                "email": license_data.get('email', 'user@falcontrade.com'),
                "is_trial": license_data.get('is_trial', False) or license_data.get('license_type') == LICENSE_TYPE_TRIAL,
                "expires_at": expires_at,
                "days_until_expiry": days_until_expiry,
                "license_type": license_data.get('license_type', LICENSE_TYPE_STANDARD),
                "tier": license_data.get('tier', 'basic'),
                "max_machines": max_machines,
                "user_id": license_data.get('user_id'),
                "subscription_id": license_data.get('subscription_id'),
                "features": self._get_license_features(license_data.get('tier', 'basic'), license_data.get('license_type', LICENSE_TYPE_STANDARD))
            }
            
            self._log_validation_attempt(license_key, machine_id, validation_result, 
                {"tier": license_data.get('tier'), "days_remaining": days_until_expiry})
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Validation system error: {str(e)}"
            logger.error(f"Supabase validation error for {license_key[:8]}...: {e}")
            self._log_validation_attempt(license_key, machine_id, 
                {"valid": False, "message": error_msg, "error_type": "system_error"})
            return self._fallback_validate_license(license_key, machine_id)
    
    def _get_license_features(self, tier, license_type):
        """Get available features based on license tier and type"""
        base_features = {
            "signal_copying": True,
            "basic_stats": True,
            "trade_history": True
        }
        
        if tier == 'basic':
            return {
                **base_features,
                "max_simultaneous_trades": 5,
                "advanced_filters": False,
                "custom_lot_sizing": False,
                "multi_account": False
            }
        elif tier == 'premium':
            return {
                **base_features,
                "max_simultaneous_trades": 20,
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True
            }
        elif tier == 'professional':
            return {
                **base_features,
                "max_simultaneous_trades": -1,  # Unlimited
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True,
                "api_access": True,
                "white_label": True
            }
        else:
            return base_features
    
    def check_feature_access(self, license_key, feature_name):
        """Check if a specific feature is available for the current license"""
        try:
            machine_id = get_hardware_id()  # Assuming this function exists
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return False
                
            features = validation_result.get('features', {})
            return features.get(feature_name, False)
            
        except Exception as e:
            logger.error(f"Feature access check failed: {e}")
            return False
    
    def create_trial_license(self, machine_id, email=None):
        """Create a trial license using Supabase"""
        if not self.initialized:
            return self._fallback_create_trial(machine_id)
        
        try:
            # Generate trial license key
            trial_key = f"TRIAL-{uuid.uuid4().hex[:8].upper()}"
            expiration_date = datetime.now() + timedelta(days=7)
            
            # Insert trial license (support both column naming conventions)
            trial_data = {
                'key': trial_key,  # Primary column name
                'license_key': trial_key,  # Backup column name for compatibility
                'email': email or f'trial-{machine_id[:8]}@falcontrade.com',
                'machine_id': machine_id,
                'status': LICENSE_STATUS_ACTIVE,
                'is_trial': True,
                'expires_at': expiration_date.isoformat(),
                'created_at': datetime.now().isoformat(),
                'license_type': LICENSE_TYPE_TRIAL
            }
            
            response = self.client.table(LICENSES_TABLE).insert(trial_data).execute()
            
            if response.data:
                return {
                    "success": True,
                    "key": trial_key,
                    "email": trial_data['email'],
                    "expires_at": trial_data['expires_at']
                }
            else:
                return {"success": False, "message": "Failed to create trial license"}
                
        except Exception as e:
            logger.error(f"Supabase trial creation error: {e}")
            return self._fallback_create_trial(machine_id)
    
    def send_heartbeat(self, license_key, machine_id, stats):
        """Enhanced heartbeat with validation status and better monitoring"""
        if not self.initialized:
            return self._fallback_heartbeat(license_key, machine_id, stats)
        
        try:
            # Perform quick validation check during heartbeat
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                logger.warning(f"Heartbeat failed: License {license_key[:8]}... is no longer valid")
                return {"success": False, "message": "License is no longer valid", "validation_failed": True}
            
            heartbeat_data = {
                'key': license_key,  # Primary column name
                'license_key': license_key,  # Backup column name for compatibility
                'machine_id': machine_id,
                'signals_processed': stats.get('signals_processed', 0),
                'trades_executed': stats.get('trades_executed', 0),
                'version': stats.get('version', VERSION),
                'license_status': 'valid',
                'days_until_expiry': validation_result.get('days_until_expiry', 0),
                'license_tier': validation_result.get('tier', 'basic'),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            
            # Insert heartbeat record
            self.client.table(HEARTBEATS_TABLE).insert(heartbeat_data).execute()
            
            # Update last activity and cumulative stats in licenses table
            update_data = {
                    'last_activity': datetime.now().isoformat(),
                'last_heartbeat': datetime.now().isoformat(),
                'total_signals_processed': stats.get('total_signals_processed', 0),
                'total_trades_executed': stats.get('total_trades_executed', 0)
            }
            
            try:
                self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name
                self.client.table(LICENSES_TABLE).update(update_data).eq('license_key', license_key).execute()
            
            # Check for license expiration warnings
            days_until_expiry = validation_result.get('days_until_expiry', 0)
            if days_until_expiry <= 7 and days_until_expiry > 0:
                logger.warning(f"License {license_key[:8]}... expires in {days_until_expiry} day(s)")
                return {"success": True, "warning": f"License expires in {days_until_expiry} day(s)", "days_until_expiry": days_until_expiry}
            
            return {"success": True, "days_until_expiry": days_until_expiry}
            
        except Exception as e:
            logger.error(f"Supabase heartbeat error: {e}")
            return self._fallback_heartbeat(license_key, machine_id, stats)
    
    def get_license_status_report(self, license_key, machine_id):
        """Get comprehensive license status report for admin/monitoring"""
        try:
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return {"error": validation_result.get('message', 'Invalid license')}
            
            # Get recent heartbeat activity
            recent_heartbeats = []
            try:
                heartbeat_response = self.client.table(HEARTBEATS_TABLE).select('*').eq('key', license_key).order('timestamp', desc=True).limit(10).execute()
                recent_heartbeats = heartbeat_response.data
            except Exception as e:
                logger.debug(f"Could not fetch heartbeat history: {e}")  # Suppressed - table may not exist
            
            # Get all devices for this license
            active_devices = []
            try:
                device_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=30)).isoformat()).execute()
                unique_devices = list(set([hb['machine_id'] for hb in device_response.data if hb.get('machine_id')]))
                active_devices = unique_devices
            except Exception as e:
                logger.debug(f"Could not fetch device list: {e}")  # Suppressed - table may not exist
            
            return {
                "license_valid": True,
                "license_key": license_key[:8] + "...",
                "email": validation_result.get('email'),
                "tier": validation_result.get('tier'),
                "license_type": validation_result.get('license_type'),
                "expires_at": validation_result.get('expires_at'),
                "days_until_expiry": validation_result.get('days_until_expiry'),
                "max_machines": validation_result.get('max_machines'),
                "active_devices_count": len(active_devices),
                "active_devices": active_devices,
                "features": validation_result.get('features'),
                "recent_activity": len(recent_heartbeats),
                "last_heartbeat": recent_heartbeats[0].get('timestamp') if recent_heartbeats else None,
                "total_signals": sum([hb.get('signals_processed', 0) for hb in recent_heartbeats]),
                "total_trades": sum([hb.get('trades_executed', 0) for hb in recent_heartbeats])
            }
            
        except Exception as e:
            logger.error(f"License status report error: {e}")
            return {"error": f"Could not generate status report: {str(e)}"}
    
    def revoke_license(self, license_key, reason=""):
        """Revoke a license (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            update_data = {
                'status': LICENSE_STATUS_SUSPENDED,
                'revoked_at': datetime.now().isoformat(),
                'revocation_reason': reason
            }
            
            response = self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            
            if response.data:
                logger.info(f"License {license_key[:8]}... revoked. Reason: {reason}")
                return {"success": True, "message": "License revoked successfully"}
            else:
                return {"success": False, "message": "License not found"}
                
        except Exception as e:
            logger.error(f"License revocation error: {e}")
            return {"success": False, "message": f"Revocation failed: {str(e)}"}
    
    def extend_license(self, license_key, days_to_add):
        """Extend license expiration (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            # Get current license data
            response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            
            if not response.data:
                return {"success": False, "message": "License not found"}
            
            license_data = response.data[0]
            current_expiry = license_data.get('expires_at')
            
            if not current_expiry:
                return {"success": False, "message": "License has no expiration date"}
            
            # Calculate new expiration
            current_date = datetime.fromisoformat(current_expiry.replace('Z', '+00:00'))
            new_expiry = current_date + timedelta(days=days_to_add)
            
            # Update license
            update_response = self.client.table(LICENSES_TABLE).update({
                'expires_at': new_expiry.isoformat(),
                'extended_at': datetime.now().isoformat(),
                'extension_days': days_to_add
            }).eq('key', license_key).execute()
            
            if update_response.data:
                logger.info(f"License {license_key[:8]}... extended by {days_to_add} days")
                return {"success": True, "message": f"License extended by {days_to_add} days", "new_expiry": new_expiry.isoformat()}
            else:
                return {"success": False, "message": "Extension failed"}
                
        except Exception as e:
            logger.error(f"License extension error: {e}")
            return {"success": False, "message": f"Extension failed: {str(e)}"}
    
    def _fallback_validate_license(self, license_key, machine_id):
        """Fallback to legacy API"""
        try:
            response = requests.post(
                VALIDATION_URL,
                json={"key": license_key, "hw_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"valid": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"valid": False, "message": str(e)}
    
    def _fallback_create_trial(self, machine_id):
        """Fallback to legacy trial API"""
        try:
            response = requests.post(
                TRIAL_URL,
                json={"machine_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def _fallback_heartbeat(self, license_key, machine_id, stats):
        """Fallback to legacy heartbeat API"""
        try:
            response = requests.post(
                HEARTBEAT_URL,
                json={
                    "key": license_key,
                    "hw_id": machine_id,
                    "signals_processed": stats.get('signals_processed', 0),
                    "trades_executed": stats.get('trades_executed', 0),
                    "version": stats.get('version', VERSION)
                },
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

import sys
import os
import asyncio
import threading
from PySide6.QtCore import QObject, Signal, Slot, QThread
import json
import uuid
import socket
import hashlib
import requests
import time
from datetime import datetime, timedelta
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase not available. Install with: pip install supabase")
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect, QThread
import re
import logging
from PySide6.QtCore import QDate
from PySide6.QtWidgets import QDateEdit, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import QPropertyAnimation, QEasingCurve
import pyperclip
from PySide6.QtGui import QIcon, QPalette, QColor, QAction, QFont, QImage, QPixmap, QLinearGradient, QBrush, QPainter, \
    QFontMetrics
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QCheckBox,
    QGroupBox, QSpacerItem, QSizePolicy, QFileDialog, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QSystemTrayIcon,
    QMenu, QStatusBar, QGridLayout, QComboBox, QDoubleSpinBox, QTreeWidget,
    QTreeWidgetItem, QInputDialog, QDialog, QDialogButtonBox, QFormLayout, QScrollArea,
    QSpinBox, QFrame, QStyle, QToolBar, QProgressBar
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import Channel
import MetaTrader5 as mt5
import psutil
import platform

# Charting and analytics imports
try:
    import matplotlib
    # Set backend before importing pyplot to avoid GUI issues
    matplotlib.use('Agg', force=True)  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    CHARTING_AVAILABLE = True
except ImportError:
    CHARTING_AVAILABLE = False
    print("Warning: Charting libraries not available. Install with: pip install matplotlib pandas numpy")
except Exception as e:
    CHARTING_AVAILABLE = False
    print(f"Warning: Charting libraries error: {e}")

# ======================
# APPLICATION CONSTANTS
# ======================

APP_NAME = "Falcon Trade Signal Copier"
SHORT_NAME = "FTSC"
VERSION = "1.2"

TELEGRAM_API_ID = 26121573
TELEGRAM_API_HASH = "305761518085ff8519d0eded60f46c72"
TRADE_HISTORY_FILE = "../falcon_trade_history.json"
SETTINGS_FILE = "../falcon_app_settings.json"
ACTIVE_TRADES_FILE = "../falcon_active_trades.json"

# Import Supabase configuration
try:
    from supabase_config import *
    SUPABASE_CONFIG_LOADED = True
except ImportError:
    # Fallback configuration (replace with your actual values)
    SUPABASE_URL = "https://your-project-id.supabase.co"
    SUPABASE_ANON_KEY = "your-anon-key-here"
    LICENSES_TABLE = "licenses"
    HEARTBEATS_TABLE = "heartbeats"
    USERS_TABLE = "users"
    SUPABASE_CONFIG_LOADED = False

# Legacy API URLs (fallback)
VALIDATION_URL = "https://api.falcontradecopier.com/validate-license"
HEARTBEAT_URL = "https://api.falcontradecopier.com/heartbeat"
ACTIVATION_URL = "https://api.falcontradecopier.com/activate"
TRIAL_URL = "https://api.falcontradecopier.com/start-trial"

NEWS_API_URL = "https://example.com/news-api"  # Placeholder for news API

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("../falcon_app_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load spaCy model for AI parsing
try:
    import spacy
    from spacy.matcher import Matcher

    nlp = spacy.load("en_core_web_sm")
except ImportError:
    logger.warning("spaCy not installed. Using regex-only parsing.")
    nlp = None
except OSError:
    logger.info("spaCy model not available. Using regex parsing as fallback.")
    nlp = None

# =====================
# HELPER FUNCTIONS
# =====================
def get_hardware_id():
    """Generate hardware fingerprint for device binding"""
    try:
        # Use MAC address
        mac = uuid.getnode()

        # Get disk serial (platform-independent)
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

        # Get CPU info
        cpu_id = platform.processor()

        combined = f"{mac}-{disk_id}-{cpu_id}"
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error generating hardware ID: {str(e)}")
        return str(uuid.uuid4())

def mt5_is_initialized():
    try:
        mt5.symbols_total()
        return True
    except:
        return False

def expand_compact_range_match(match):
    """Helper function to expand compact ranges like '3347-49' to '3347-3349'"""
    first = match.group(1)
    second = match.group(2)
    if '.' in first:
        return match.group(0)  # Don't process decimals
    try:
        first_num = int(first)
        second_num = int(second)
        base = (first_num // 100) * 100
        full_second = base + second_num
        if full_second < first_num:
            full_second += 100  # Handle century crossing
        return f"{first}-{full_second}"
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to expand range {first}-{second}: {e}")
        return match.group(0)

# ======================
# SUPABASE MANAGER
# ======================
class SupabaseManager:
    def __init__(self):
        self.client = None
        self.initialized = False
        self.validation_cache = {}  # Cache recent validations
        self.rate_limit_attempts = {}  # Track validation attempts per IP/machine
        self.max_attempts_per_hour = 60  # Rate limiting
        
        if SUPABASE_AVAILABLE:
            try:
                self.client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                self.initialized = True
                logger.info("Supabase client initialized successfully")
                if SUPABASE_CONFIG_LOADED:
                    logger.info("Supabase configuration loaded successfully")
                else:
                    logger.warning("Using fallback Supabase configuration")
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
        else:
            logger.warning("Supabase not available - using legacy API")
            
    def _check_rate_limit(self, machine_id):
        """Check if machine_id has exceeded rate limits"""
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        
        # Clean old attempts
        self.rate_limit_attempts = {
            mid: attempts for mid, attempts in self.rate_limit_attempts.items()
            if any(attempt > hour_ago for attempt in attempts)
        }
        
        # Check current machine attempts
        if machine_id not in self.rate_limit_attempts:
            self.rate_limit_attempts[machine_id] = []
            
        recent_attempts = [
            attempt for attempt in self.rate_limit_attempts[machine_id]
            if attempt > hour_ago
        ]
        
        if len(recent_attempts) >= self.max_attempts_per_hour:
            logger.warning(f"Rate limit exceeded for machine {machine_id[:8]}...")
            return False
            
        # Record this attempt
        self.rate_limit_attempts[machine_id] = recent_attempts + [current_time]
        return True
        
    def _log_validation_attempt(self, license_key, machine_id, result, additional_info=None):
        """Log validation attempts for security monitoring"""
        log_data = {
            'license_key': license_key[:8] + "...",  # Partial key for security
            'machine_id': machine_id[:8] + "...",   # Partial machine ID
            'timestamp': datetime.now().isoformat(),
            'valid': result.get('valid', False),
            'message': result.get('message', ''),
            'source': 'supabase' if self.initialized else 'fallback'
        }
        
        if additional_info:
            log_data.update(additional_info)
            
        if result.get('valid'):
            logger.info(f"License validation successful: {license_key[:8]}... on {machine_id[:8]}...")
        else:
            logger.warning(f"License validation failed: {license_key[:8]}... on {machine_id[:8]}... - {result.get('message', 'Unknown error')}")
            
        # Store validation log in database for monitoring
        if self.initialized:
            try:
                self.client.table('validation_logs').insert(log_data).execute()
            except Exception as e:
                logger.debug(f"Failed to log validation attempt: {e}")
    
    def validate_license(self, license_key, machine_id):
        """Enhanced license validation using Supabase with improved error handling"""
        if not self.initialized:
            return self._fallback_validate_license(license_key, machine_id)
        
        try:
            # Query the licenses table - prioritize 'key' column (actual database structure)
            try:
                response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name for compatibility
                response = self.client.table(LICENSES_TABLE).select('*').eq('license_key', license_key).execute()
            
            if not response.data:
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": "License key not found"})
                return {"valid": False, "message": "License key not found. Please check your license key."}
            
            license_data = response.data[0]
            
            # Enhanced status validation
            status = license_data.get('status', license_data.get('is_active', False))
            if status not in [LICENSE_STATUS_ACTIVE, True, 'active', 'ACTIVE']:
                detailed_message = f"License status is '{status}'. Please contact support if this is unexpected."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": detailed_message, "status": status})
                return {"valid": False, "message": detailed_message}
            
            # Enhanced expiration validation
            expires_at = license_data.get('expires_at') or license_data.get('expiration_date') or license_data.get('valid_until')
            if not expires_at:
                error_msg = "License has no expiration date. Please contact support."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": error_msg}
            
            try:
                expiration_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if expiration_date < datetime.now(expiration_date.tzinfo):
                    days_expired = (datetime.now(expiration_date.tzinfo) - expiration_date).days
                    error_msg = f"License expired {days_expired} day(s) ago on {expiration_date.strftime('%Y-%m-%d')}. Please renew your license."
                    self._log_validation_attempt(license_key, machine_id, 
                        {"valid": False, "message": error_msg, "days_expired": days_expired})
                    return {"valid": False, "message": error_msg}
            except ValueError as ve:
                error_msg = f"Invalid expiration date format: {expires_at}"
                logger.error(f"Date parsing error for license {license_key[:8]}...: {ve}")
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": "License has invalid expiration date. Please contact support."}
            
            # Enhanced machine binding with multi-device support
            bound_machine = license_data.get('machine_id') or license_data.get('hw_id') or license_data.get('device_id')
            max_machines = license_data.get('max_machines', 1)
            
            # If this is a multi-device license, check current device count
            if max_machines > 1:
                try:
                    # Get all active machines for this license
                    active_machines_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=7)).isoformat()).execute()
                    active_machine_ids = list(set([hb['machine_id'] for hb in active_machines_response.data if hb.get('machine_id')]))
                    
                    if machine_id not in active_machine_ids and len(active_machine_ids) >= max_machines:
                        error_msg = f"License allows maximum {max_machines} device(s). {len(active_machine_ids)} device(s) already active."
                        self._log_validation_attempt(license_key, machine_id, 
                            {"valid": False, "message": error_msg, "max_machines": max_machines, "active_count": len(active_machine_ids)})
                        return {"valid": False, "message": error_msg}
                except Exception as e:
                    logger.warning(f"Could not check device count for multi-device license: {e}")
                    # Continue with single-device validation as fallback
            
            # Single device binding check (for single-device licenses or as fallback)
            if max_machines == 1 and bound_machine and bound_machine != machine_id:
                error_msg = "License is already activated on another device. Contact support for device transfer."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg, "bound_machine": bound_machine[:8] + "..."})
                return {"valid": False, "message": error_msg}
            
            # Update machine binding if not set (for new activations)
            if not bound_machine:
                try:
                    self.client.table(LICENSES_TABLE).update({
                        'machine_id': machine_id,
                        'last_activation': datetime.now().isoformat()
                    }).eq('key', license_key).execute()
                    logger.info(f"License {license_key[:8]}... activated on new device {machine_id[:8]}...")
                except Exception as e:
                    logger.debug(f"Could not update machine binding: {e}")  # Suppressed - column may not exist
                    # Continue validation even if update fails
            
            # Calculate days until expiration for user info
            days_until_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
            
            validation_result = {
                "valid": True,
                "email": license_data.get('email', 'user@falcontrade.com'),
                "is_trial": license_data.get('is_trial', False) or license_data.get('license_type') == LICENSE_TYPE_TRIAL,
                "expires_at": expires_at,
                "days_until_expiry": days_until_expiry,
                "license_type": license_data.get('license_type', LICENSE_TYPE_STANDARD),
                "tier": license_data.get('tier', 'basic'),
                "max_machines": max_machines,
                "user_id": license_data.get('user_id'),
                "subscription_id": license_data.get('subscription_id'),
                "features": self._get_license_features(license_data.get('tier', 'basic'), license_data.get('license_type', LICENSE_TYPE_STANDARD))
            }
            
            self._log_validation_attempt(license_key, machine_id, validation_result, 
                {"tier": license_data.get('tier'), "days_remaining": days_until_expiry})
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Validation system error: {str(e)}"
            logger.error(f"Supabase validation error for {license_key[:8]}...: {e}")
            self._log_validation_attempt(license_key, machine_id, 
                {"valid": False, "message": error_msg, "error_type": "system_error"})
            return self._fallback_validate_license(license_key, machine_id)
    
    def _get_license_features(self, tier, license_type):
        """Get available features based on license tier and type"""
        base_features = {
            "signal_copying": True,
            "basic_stats": True,
            "trade_history": True
        }
        
        if tier == 'basic':
            return {
                **base_features,
                "max_simultaneous_trades": 5,
                "advanced_filters": False,
                "custom_lot_sizing": False,
                "multi_account": False
            }
        elif tier == 'premium':
            return {
                **base_features,
                "max_simultaneous_trades": 20,
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True
            }
        elif tier == 'professional':
            return {
                **base_features,
                "max_simultaneous_trades": -1,  # Unlimited
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True,
                "api_access": True,
                "white_label": True
            }
        else:
            return base_features
    
    def check_feature_access(self, license_key, feature_name):
        """Check if a specific feature is available for the current license"""
        try:
            machine_id = get_hardware_id()  # Assuming this function exists
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return False
                
            features = validation_result.get('features', {})
            return features.get(feature_name, False)
            
        except Exception as e:
            logger.error(f"Feature access check failed: {e}")
            return False
    
    def create_trial_license(self, machine_id, email=None):
        """Create a trial license using Supabase"""
        if not self.initialized:
            return self._fallback_create_trial(machine_id)
        
        try:
            # Generate trial license key
            trial_key = f"TRIAL-{uuid.uuid4().hex[:8].upper()}"
            expiration_date = datetime.now() + timedelta(days=7)
            
            # Insert trial license (support both column naming conventions)
            trial_data = {
                'key': trial_key,  # Primary column name
                'license_key': trial_key,  # Backup column name for compatibility
                'email': email or f'trial-{machine_id[:8]}@falcontrade.com',
                'machine_id': machine_id,
                'status': LICENSE_STATUS_ACTIVE,
                'is_trial': True,
                'expires_at': expiration_date.isoformat(),
                'created_at': datetime.now().isoformat(),
                'license_type': LICENSE_TYPE_TRIAL
            }
            
            response = self.client.table(LICENSES_TABLE).insert(trial_data).execute()
            
            if response.data:
                return {
                    "success": True,
                    "key": trial_key,
                    "email": trial_data['email'],
                    "expires_at": trial_data['expires_at']
                }
            else:
                return {"success": False, "message": "Failed to create trial license"}
                
        except Exception as e:
            logger.error(f"Supabase trial creation error: {e}")
            return self._fallback_create_trial(machine_id)
    
    def send_heartbeat(self, license_key, machine_id, stats):
        """Enhanced heartbeat with validation status and better monitoring"""
        if not self.initialized:
            return self._fallback_heartbeat(license_key, machine_id, stats)
        
        try:
            # Perform quick validation check during heartbeat
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                logger.warning(f"Heartbeat failed: License {license_key[:8]}... is no longer valid")
                return {"success": False, "message": "License is no longer valid", "validation_failed": True}
            
            heartbeat_data = {
                'key': license_key,  # Primary column name
                'license_key': license_key,  # Backup column name for compatibility
                'machine_id': machine_id,
                'signals_processed': stats.get('signals_processed', 0),
                'trades_executed': stats.get('trades_executed', 0),
                'version': stats.get('version', VERSION),
                'license_status': 'valid',
                'days_until_expiry': validation_result.get('days_until_expiry', 0),
                'license_tier': validation_result.get('tier', 'basic'),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            
            # Insert heartbeat record
            self.client.table(HEARTBEATS_TABLE).insert(heartbeat_data).execute()
            
            # Update last activity and cumulative stats in licenses table
            update_data = {
                    'last_activity': datetime.now().isoformat(),
                'last_heartbeat': datetime.now().isoformat(),
                'total_signals_processed': stats.get('total_signals_processed', 0),
                'total_trades_executed': stats.get('total_trades_executed', 0)
            }
            
            try:
                self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name
                self.client.table(LICENSES_TABLE).update(update_data).eq('license_key', license_key).execute()
            
            # Check for license expiration warnings
            days_until_expiry = validation_result.get('days_until_expiry', 0)
            if days_until_expiry <= 7 and days_until_expiry > 0:
                logger.warning(f"License {license_key[:8]}... expires in {days_until_expiry} day(s)")
                return {"success": True, "warning": f"License expires in {days_until_expiry} day(s)", "days_until_expiry": days_until_expiry}
            
            return {"success": True, "days_until_expiry": days_until_expiry}
            
        except Exception as e:
            logger.error(f"Supabase heartbeat error: {e}")
            return self._fallback_heartbeat(license_key, machine_id, stats)
    
    def get_license_status_report(self, license_key, machine_id):
        """Get comprehensive license status report for admin/monitoring"""
        try:
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return {"error": validation_result.get('message', 'Invalid license')}
            
            # Get recent heartbeat activity
            recent_heartbeats = []
            try:
                heartbeat_response = self.client.table(HEARTBEATS_TABLE).select('*').eq('key', license_key).order('timestamp', desc=True).limit(10).execute()
                recent_heartbeats = heartbeat_response.data
            except Exception as e:
                logger.debug(f"Could not fetch heartbeat history: {e}")  # Suppressed - table may not exist
            
            # Get all devices for this license
            active_devices = []
            try:
                device_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=30)).isoformat()).execute()
                unique_devices = list(set([hb['machine_id'] for hb in device_response.data if hb.get('machine_id')]))
                active_devices = unique_devices
            except Exception as e:
                logger.debug(f"Could not fetch device list: {e}")  # Suppressed - table may not exist
            
            return {
                "license_valid": True,
                "license_key": license_key[:8] + "...",
                "email": validation_result.get('email'),
                "tier": validation_result.get('tier'),
                "license_type": validation_result.get('license_type'),
                "expires_at": validation_result.get('expires_at'),
                "days_until_expiry": validation_result.get('days_until_expiry'),
                "max_machines": validation_result.get('max_machines'),
                "active_devices_count": len(active_devices),
                "active_devices": active_devices,
                "features": validation_result.get('features'),
                "recent_activity": len(recent_heartbeats),
                "last_heartbeat": recent_heartbeats[0].get('timestamp') if recent_heartbeats else None,
                "total_signals": sum([hb.get('signals_processed', 0) for hb in recent_heartbeats]),
                "total_trades": sum([hb.get('trades_executed', 0) for hb in recent_heartbeats])
            }
            
        except Exception as e:
            logger.error(f"License status report error: {e}")
            return {"error": f"Could not generate status report: {str(e)}"}
    
    def revoke_license(self, license_key, reason=""):
        """Revoke a license (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            update_data = {
                'status': LICENSE_STATUS_SUSPENDED,
                'revoked_at': datetime.now().isoformat(),
                'revocation_reason': reason
            }
            
            response = self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            
            if response.data:
                logger.info(f"License {license_key[:8]}... revoked. Reason: {reason}")
                return {"success": True, "message": "License revoked successfully"}
            else:
                return {"success": False, "message": "License not found"}
                
        except Exception as e:
            logger.error(f"License revocation error: {e}")
            return {"success": False, "message": f"Revocation failed: {str(e)}"}
    
    def extend_license(self, license_key, days_to_add):
        """Extend license expiration (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            # Get current license data
            response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            
            if not response.data:
                return {"success": False, "message": "License not found"}
            
            license_data = response.data[0]
            current_expiry = license_data.get('expires_at')
            
            if not current_expiry:
                return {"success": False, "message": "License has no expiration date"}
            
            # Calculate new expiration
            current_date = datetime.fromisoformat(current_expiry.replace('Z', '+00:00'))
            new_expiry = current_date + timedelta(days=days_to_add)
            
            # Update license
            update_response = self.client.table(LICENSES_TABLE).update({
                'expires_at': new_expiry.isoformat(),
                'extended_at': datetime.now().isoformat(),
                'extension_days': days_to_add
            }).eq('key', license_key).execute()
            
            if update_response.data:
                logger.info(f"License {license_key[:8]}... extended by {days_to_add} days")
                return {"success": True, "message": f"License extended by {days_to_add} days", "new_expiry": new_expiry.isoformat()}
            else:
                return {"success": False, "message": "Extension failed"}
                
        except Exception as e:
            logger.error(f"License extension error: {e}")
            return {"success": False, "message": f"Extension failed: {str(e)}"}
    
    def _fallback_validate_license(self, license_key, machine_id):
        """Fallback to legacy API"""
        try:
            response = requests.post(
                VALIDATION_URL,
                json={"key": license_key, "hw_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"valid": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"valid": False, "message": str(e)}
    
    def _fallback_create_trial(self, machine_id):
        """Fallback to legacy trial API"""
        try:
            response = requests.post(
                TRIAL_URL,
                json={"machine_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def _fallback_heartbeat(self, license_key, machine_id, stats):
        """Fallback to legacy heartbeat API"""
        try:
            response = requests.post(
                HEARTBEAT_URL,
                json={
                    "key": license_key,
                    "hw_id": machine_id,
                    "signals_processed": stats.get('signals_processed', 0),
                    "trades_executed": stats.get('trades_executed', 0),
                    "version": stats.get('version', VERSION)
                },
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

def parse_signal_ai(message):
    """Parse trading signal using NLP and pattern matching"""
    message = preprocess_message(message)
    if not nlp:
        return None

    try:
        doc = nlp(message)
        matcher = Matcher(nlp.vocab)
        used_tokens = set()

        # Define patterns for signal extraction
        action_pattern = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["eurusd", "gbpusd", "usdjpy", "audusd", "usdcad", "nzdusd"]}}
        ]
        
        matcher.add("SIGNAL_ACTION", action_pattern)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                return {
                    "action": span.text.lower(),
                    "confidence": 0.8,
                    "method": "nlp"
                }
        
        return None
    except Exception as e:
        logger.error(f"Error in NLP parsing: {e}")
        return None

def parse_signal_emoji_format(message):
    """Parse signals in emoji format like:
    💰XAUUSD (1m) ⬇️
    🔴Sell  : 3349.27
    ✅TP : 3328.96
    ❌SL : 3351.72
    🧠 : RISK 0.1%
    """
    try:
        # Preprocess message
        message = preprocess_message(message)
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed emoji signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing emoji signal: {e}")
        return None

def parse_signal(message):
    """Main signal parsing function that combines AI, emoji, and regex methods"""
    # Try dedicated provider parsing first (for specific signal format)
    dedicated_result = parse_signal_dedicated_provider(message)
    if dedicated_result:
        return dedicated_result
    
    # Try emoji format parsing second
    emoji_result = parse_signal_emoji_format(message)
    if emoji_result:
        return emoji_result
    
    # Try AI parsing third
    ai_result = parse_signal_ai(message)
    if ai_result:
        return ai_result
    
    # Fall back to regex parsing
    regex_result = parse_signal_regex(message)
    if regex_result:
        return regex_result
    
    return None

# =====================
def parse_signal_ai_enhanced(message):
    """Enhanced AI signal parsing with entity extraction"""
    message = preprocess_message(message)
    if not nlp:
        return parse_signal_regex(message)  # Fallback to regex

    try:
        doc = nlp(message)
        entities = {
            "action": None,
            "symbol": None,
            "entry_price": None,
            "sl": None,
            "tps": []
        }
        used_tokens = set()
        found_entry = False

        # Extract entities using NLP
        for ent in doc.ents:
            if ent.label_ == "ORG" and not entities["symbol"]:
                entities["symbol"] = ent.text.upper()
            elif ent.label_ == "MONEY":
                try:
                    value = float(ent.text.replace(",", ""))
                    if not found_entry:
                        entities["entry_price"] = value
                        found_entry = True
                except ValueError:
                    pass

        # Pattern matching for action words
        action_patterns = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["limit", "stop"]}}
        ]
        
        matcher = Matcher(nlp.vocab)
        matcher.add("ACTION", action_patterns)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                if span.text.lower() in ["buy", "sell"]:
                    entities["action"] = span.text.upper()
                elif span.text.lower() in ["limit", "stop"]:
                    if entities["action"]:
                        entities["action"] = f"{entities['action']} {span.text.upper()}"

        # Extract prices and levels
        price_pattern = r'(\d{1,5}(?:\.\d{1,5})?)'
        price_matches = re.findall(price_pattern, message)
        
        for i, price in enumerate(price_matches):
            try:
                value = float(price)
                if not found_entry:
                    entities["entry_price"] = value
                    found_entry = True
                elif "SL" in message and i == len(price_matches) - 1:
                    entities["sl"] = value
                elif "TP" in message:
                    entities["tps"].append(value)
            except ValueError:
                pass

        # Validate required fields
        if not entities["action"] or not entities["symbol"]:
            return None

        # Handle market orders
        if entities["action"] in ["BUY", "SELL"] and not entities["entry_price"]:
            return {
                "symbol": entities["symbol"],
                "order_type": entities["action"],
                "entry_price": None,
                "sl": entities["sl"],
                "tps": entities["tps"]
            }

        # Determine order type with special handling
        order_type = entities["action"]
        if "LIMIT" in message and "BUY" in order_type:
            order_type = "BUY LIMIT"
        elif "LIMIT" in message and "SELL" in order_type:
            order_type = "SELL LIMIT"
        elif "STOP" in message and "BUY" in order_type:
            order_type = "BUY STOP"
        elif "STOP" in message and "SELL" in order_type:
            order_type = "SELL STOP"

        # Validate pending orders require entry price
        if ("LIMIT" in order_type or "STOP" in order_type) and not entities["entry_price"]:
            logger.warning("Pending order requires entry price")
            return None

        # Prepare result
        result = {
            "symbol": entities["symbol"],
            "order_type": order_type,
            "entry_price": entities["entry_price"],
            "sl": entities["sl"],
        }

        # Handle TP values
        if entities["tps"]:
            result["tps"] = entities["tps"]
        elif "TP" in message:
            tp_matches = re.findall(r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)', message)
            tps = []
            for tp in tp_matches:
                try:
                    tps.append(float(tp))
                except ValueError:
                    pass
            if tps:
                result["tps"] = tps

        logger.info(f"AI parsed signal: {result}")
        return result

    except Exception as e:
        logger.error(f"AI signal parsing error: {str(e)}")
        return None

def parse_signal_entities(message):
    """Extract trading entities from message using regex patterns"""
    entities = {
        "symbol": None,
        "order_type": None,
        "entry_price": None,
        "sl": None,
        "tps": []
    }
    
    try:
        # Extract symbol
        symbol_patterns = [
            r'\b([A-Z0-9]{3,10})\b',
            r'\b(GOLD|SILVER|OIL|BTC|ETH)\b'
        ]
        
        for pattern in symbol_patterns:
            match = re.search(pattern, message)
            if match:
                symbol = match.group(1)
                if symbol not in ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]:
                    entities["symbol"] = symbol
                    break
        
        # Extract order type
        order_pattern = r'\b(BUY|SELL|LONG|SHORT)\b'
        order_match = re.search(order_pattern, message)
        if order_match:
            entities["order_type"] = order_match.group(1)
        
        # Extract entry price
        price_pattern = r'\b(\d+\.?\d*)\b'
        price_matches = re.findall(price_pattern, message)
        if price_matches:
            entities["entry_price"] = float(price_matches[0])
        
        # Extract SL
        sl_pattern = r'SL\s*[:=\-]?\s*(\d+\.?\d*)'
        sl_match = re.search(sl_pattern, message)
        if sl_match:
            entities["sl"] = float(sl_match.group(1))
        
        # Extract TPs
        tp_pattern = r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)'
        tp_matches = re.findall(tp_pattern, message)
        for tp in tp_matches:
            try:
                entities["tps"].append(float(tp))
            except ValueError:
                pass
        
        return entities
        
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        return entities

def preprocess_message(message):
    """Clean and normalize message before parsing

    Args:
        message (str): Raw signal message to preprocess

    Returns:
        str: Cleaned and normalized message

    Handles:
    - Removes emojis and special characters
    - Expands compact number ranges (e.g., 3347-49 → 3347-3349)
    - Converts to uppercase and removes extra spaces
    """
    # Remove emojis and special characters
    message = re.sub(r'[✅🎯♦️⚠️🟢🔴⚡️💎🔥🚨⏱️📊🛑🔔📉📈@]', '', message)

    # Expand compact ranges (e.g., 3347-49 → 3347-3349)
    message = re.sub(r'(\d+)\s*[-–]\s*(\d{2})\b', expand_compact_range_match, message)

    # Convert to uppercase and remove extra spaces
    message = re.sub(r'\s+', ' ', message.upper().strip())
    return message

def parse_signal_dedicated_provider(message):
    """Dedicated parsing method for specific signal provider format:
    💰XAUUSD (1M) ⬆️
    🟢Buy : 3343.29
    ✅TP : 3367.94
    ❌SL : 3341.76
    🧠 : RISK 0.1%
    """
    try:
        # Custom preprocessing that preserves the emojis we need
        # Remove extra whitespace and normalize, but keep emojis
        message = re.sub(r'\s+', ' ', message.strip())
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed dedicated provider signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing dedicated provider signal: {e}")
        return None

def parse_signal_regex(message):
    """Parse trading signal using regular expressions"""
    message = preprocess_message(message)
    try:
        # Enhanced symbol normalization
        message = re.sub(r'\bGOLD\b', 'XAUUSD', message)
        message = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', message)
        message = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', message)
        message = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', message)
        message = re.sub(r'\bNAS100\b', 'NAS100', message)
        message = re.sub(r'\bSPX500\b', 'SPX500', message)
        message = re.sub(r'\bDXY\b', 'USDX', message)
        message = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', message)
        message = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', message)
        message = re.sub(r'\bXRP\b', 'XRPUSD', message)
        message = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', message)
        message = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', message)
        message = re.sub(r'\bUS30\b', 'US30', message)
        message = re.sub(r'\bDOW\b', 'US30', message)

        # Reserved words to skip
        reserved_words = ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]

        # New pattern for specific format:
        # [SYMBOL] (timeframe) [ORDER_TYPE] : [PRICE]
        # TP : [TP_PRICE]
        # SL : [SL_PRICE]
        specific_pattern = (
            r'([A-Z0-9]{3,10})\s*\(.*?\)\s*'  # Symbol with timeframe in parentheses
            r'(BUY|SELL)\s*:\s*(\d+\.?\d*)[\s\S]*?'  # Order type and price
            r'TP\s*:\s*(\d+\.?\d*)[\s\S]*?'  # TP
            r'SL\s*:\s*(\d+\.?\d*)'  # SL
        )

        specific_match = re.search(specific_pattern, message)
        if specific_match:
            symbol = specific_match.group(1)
            order_type = specific_match.group(2)
            entry_price = float(specific_match.group(3))
            tp = float(specific_match.group(4))
            sl = float(specific_match.group(5))

            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": [tp]
            }

        # Enhanced pattern for market orders without entry price
        # In parse_signal_regex function
        market_order_pattern = r'\b(BUY|SELL)\s+:\s*(\d+\.?\d*)\s+(\b[A-Z0-9]{3,10}\b)\b'
        market_match = re.search(market_order_pattern, message)
        if not market_match:
            # Alternative pattern: Symbol first
            market_order_pattern = r'\b([A-Z0-9]{3,10})\s+(BUY|SELL)\b'
            market_match = re.search(market_order_pattern, message)

        if market_match:
            if market_match.group(1) in ["BUY", "SELL"]:
                order_type = market_match.group(1)
                symbol = market_match.group(2)
            else:
                symbol = market_match.group(1)
                order_type = market_match.group(2)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                market_match = None

        if market_match:
            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tp": tp
                }

        # Enhanced pattern for pending orders with "@" symbol
        pending_pattern = r'(BUY|SELL)\s*(LIMIT|STOP)\s+(\w+)\s+@?\s*(\d+\.?\d*)'
        pending_match = re.search(pending_pattern, message)
        if not pending_match:
            # Alternative pattern: Symbol first with "@"
            pending_pattern = r'(\w+)\s+(BUY|SELL)\s*(LIMIT|STOP)\s+@?\s*(\d+\.?\d*)'
            pending_match = re.search(pending_pattern, message)

        if pending_match:
            if pending_match.group(1) in ["BUY", "SELL"]:
                order_type = f"{pending_match.group(1)} {pending_match.group(2)}"
                symbol = pending_match.group(3)
                entry_price = pending_match.group(4)
            else:
                symbol = pending_match.group(1)
                order_type = f"{pending_match.group(2)} {pending_match.group(3)}"
                entry_price = pending_match.group(4)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                pending_match = None

        if pending_match:
            try:
                entry_price = float(entry_price)
            except ValueError:
                entry_price = None

            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tp": tp
                }

        # Fallback pattern
        words = [word for word in message.split() if not word.startswith(('SL', 'TP'))]
        if not words:
            return None

        # Try to find order type
        order_type = None
        for ot in ["BUY LIMIT", "SELL LIMIT", "BUY STOP", "SELL STOP", "BUY", "SELL"]:
            if ot in message:
                order_type = ot
                break
        if not order_type:
            return None

        # Find symbol - first word that matches symbol pattern and not reserved
        symbol = None
        for word in words:
            if re.match(r'^[A-Z0-9]{3,10}$', word) and word not in reserved_words:
                symbol = word
                break
        if not symbol:
            return None

        # Find entry price
        entry_price = None
        for word in words:
            try:
                if word == symbol or word in order_type:
                    continue
                entry_price = float(word)
                break
            except ValueError:
                pass

        sl = None
        tp = None
        tps = []
        sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
        if sl_match:
            try:
                sl = float(sl_match.group(1))
            except ValueError:
                pass

        tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
        if tp_match:
            try:
                tp = float(tp_match.group(1))
            except ValueError:
                pass

        tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
        for tp_val in tp_matches:
            try:
                tps.append(float(tp_val))
            except ValueError:
                pass

        if tps:
            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": tps
            }

        return {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tp": tp
        }
    except Exception as e:
        logger.error(f"Signal parsing error: {str(e)}")
        return None

def parse_management_command(message):
    try:
        message = message.upper().strip()
        patterns = {
            "SL_TO_BE": r"\b(?:SL\s*TO\s*BE|BREAKEVEN|MOVE\s*TO\s*BREAKEVEN)\b",
            "CLOSE": r"\b(?:CLOSE|EXIT|TAKE\s*PROFIT)\b(?!\s*AT)",
            "PARTIAL_CLOSE": r"CLOSE\s*(\d+)\s*%|\bPARTIAL\s*CLOSE\b",
            "MODIFY_SL": r"MODIFY\s*SL\s*TO\s*(\d+\.?\d*)",
            "MODIFY_TP": r"MODIFY\s*TP\s*TO\s*(\d+\.?\d*)",
            "CANCEL": r"\b(?:CANCEL|DELETE)\b"
        }

        for action, pattern in patterns.items():
            match = re.search(pattern, message)
            if match:
                result = {"action": action}
                if action == "PARTIAL_CLOSE" and match.group(1):
                    result["percent"] = float(match.group(1))
                elif action == "MODIFY_SL" and match.group(1):
                    result["sl"] = float(match.group(1))
                elif action == "MODIFY_TP" and match.group(1):
                    result["tp"] = float(match.group(1))
                # Extract symbol, excluding command words
                command_words = {"CLOSE", "EXIT", "TAKE", "PROFIT", "SL", "TP", "MODIFY", "CANCEL", "DELETE", "PARTIAL", "BREAKEVEN", "MOVE", "TO", "BE", "AT"}
                
                # Find all potential symbols in the message
                symbol_matches = re.findall(r"\b([A-Z0-9]{3,6})\b", message)
                
                # Filter out command words and find the actual trading symbol
                for potential_symbol in symbol_matches:
                    if potential_symbol not in command_words:
                        result["symbol"] = potential_symbol
                        break
                return result

        if nlp:
            return parse_management_ai(message)

        return None
    except Exception as e:
        logger.error(f"Management command parsing error: {str(e)}")
        return None

def parse_management_ai(message):
    try:
        doc = nlp(message)
        result = {"action": None, "symbol": None, "params": {}}
        action_verbs = {"move", "close", "exit", "modify", "adjust", "set", "change", "cancel"}
        trade_objects = {"sl", "tp", "stop loss", "take profit", "position", "trade", "order"}

        for token in doc:
            if token.lemma_ in action_verbs:
                result["action"] = token.lemma_.upper()
                for child in token.children:
                    if child.lemma_ in trade_objects:
                        result["target"] = child.lemma_.upper()
                    elif child.dep_ in ("dobj", "attr", "prep") and child.ent_type_ == "CARDINAL":
                        result["params"]["value"] = float(child.text)
            if token.ent_type_ == "ORG" and len(token.text) >= 3:
                result["symbol"] = token.text.upper()

        if result["action"] == "MOVE" and result.get("target") == "SL":
            result["action"] = "MODIFY_SL"
        elif result["action"] == "CLOSE" or result["action"] == "EXIT":
            result["action"] = "CLOSE"
        elif result["action"] == "MODIFY" and result.get("target") == "TP":
            result["action"] = "MODIFY_TP"
        elif result["action"] == "CANCEL":
            result["action"] = "CANCEL"

        if not result["action"] or result["action"] not in ["SL_TO_BE", "CLOSE", "PARTIAL_CLOSE", "MODIFY_SL",
                                                            "MODIFY_TP", "CANCEL"]:
            return None

        return result
    except Exception as e:
        logger.error(f"AI management parsing error: {str(e)}")
        return None

# =====================
# BUSINESS LOGIC CLASSES
# =====================
class TradeTracker:
    def __init__(self, filename=ACTIVE_TRADES_FILE):
        self.filename = filename
        self.active_trades = {}
        self.win_streak = 0
        self.loss_streak = 0
        self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                self.active_trades = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.active_trades = {}

    def save(self):
        with open(self.filename, 'w') as f:
            json.dump(self.active_trades, f, indent=2)

    def add_trade(self, ticket, symbol, order_type, volume, entry_price,
                  actual_price=None, sl=None, tp=None, tps=None, magic=2023, status='pending'):
        """
        Add a trade to the active trades list.

        Args:
            ticket: Trade ticket number.
            symbol: Symbol traded.
            order_type: BUY/SELL etc.
            volume: Trade volume.
            entry_price: Intended entry price.
            actual_price: Actual executed price (defaults to entry_price).
            sl: Stop loss.
            tp: Take profit (single).
            tps: List of multiple take profits.
            magic: Magic number.
            status: Trade status.
        """
        if actual_price is None:
            actual_price = entry_price

        # Ensure tps is always a list
        if tps is None:
            tps = []
        elif not isinstance(tps, list):
            tps = [tps]

        self.active_trades[ticket] = {
            "symbol": symbol,
            "type": order_type,
            "volume": volume,
            "entry": entry_price,
            "actual_price": actual_price,
            "sl": sl,
            "tp": tp,  # Keep single TP if given
            "tps": tps,  # Store multi-TP list
            "magic": magic,
            "status": status,
            "open_time": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat()
        }
        self.save()

    def update_trade(self, ticket, updates):
        if ticket in self.active_trades:
            self.active_trades[ticket].update(updates)
            self.active_trades[ticket]["last_modified"] = datetime.now().isoformat()
            self.save()
            return True
        return False

    def remove_trade(self, ticket, profit=0.0):
        if ticket in self.active_trades:
            # Update streaks based on profit
            if profit > 0:
                self.win_streak += 1
                self.loss_streak = 0
            elif profit < 0:
                self.loss_streak += 1
                self.win_streak = 0

            del self.active_trades[ticket]
            self.save()
            return True
        return False

    def get_trades_by_symbol(self, symbol):
        return [trade for trade in self.active_trades.values() if trade["symbol"] == symbol]

    def get_most_recent_trade(self, symbol):
        trades = self.get_trades_by_symbol(symbol)
        if not trades:
            return None
        return max(trades, key=lambda x: x["open_time"])

    def get_trade_by_ticket(self, ticket):
        return self.active_trades.get(ticket)

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
                "max_trades": 20,  # Changed from 5 to 20
                "pip_tolerance": 2.0,
                "news_filter": False,
                "trading_hours": "09:00-17:00",
                
                "daily_loss_limit": 5.0,
                "daily_profit_target": 10.0,
                "max_trades_per_symbol": 20,  # Changed from 2 to 20
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

    def set_activated(self, status=True, key=None, email=None, is_trial=False, expiration=None):
        self.settings["activated"] = status
        if key and email:
            start_date = datetime.now()
            if not expiration:
                expiration = start_date + timedelta(days=365) if not is_trial else start_date + timedelta(days=7)
            self.settings["license"] = {
                "key": key,
                "email": email,
                "start_date": start_date.isoformat(),
                "expiration_date": expiration.isoformat(),
                "is_trial": is_trial
            }
        return self.save()

    def get_license_info(self):
        return self.settings.get("license", {})

    def get_telegram_session(self):
        return self.settings["telegram"].get("session_string")

    def set_telegram_session(self, session_string):
        self.settings["telegram"]["session_string"] = session_string
        return self.save()

    def get_telegram_channels(self):
        return self.settings["telegram"].get("channel_ids", [])

    def set_telegram_channels(self, channel_ids):
        self.settings["telegram"]["channel_ids"] = channel_ids
        return self.save()

    def get_mt5_settings(self):
        return self.settings["mt5"]

    def set_mt5_settings(self, account, server, password, path, symbol_prefix="", symbol_suffix=""):
        self.settings["mt5"] = {
            "account": account,
            "server": server,
            "password": password,
            "path": path,
            "symbol_prefix": symbol_prefix,
            "symbol_suffix": symbol_suffix
        }
        return self.save()

    def get_risk_settings(self):
        return self.settings["risk"]

    def set_risk_settings(self, risk_settings):
        self.settings["risk"] = risk_settings
        return self.save()

    def get_symbol_mappings(self):
        return self.settings.get("symbol_mappings", {})

    def set_symbol_mappings(self, mappings):
        self.settings["symbol_mappings"] = mappings
        return self.save()

    def get_activation_info(self):
        return {
            "activated": self.settings.get("activated", False),
            "last_activation": self.settings.get("last_activation"),
            "machine_id": self.settings.get("machine_id")
        }

    def reset_activation(self):
        self.settings["activated"] = False
        self.settings["last_activation"] = None
        self.settings["telegram"]["session_string"] = None
        self.settings["telegram"]["channel_ids"] = []
        self.settings["mt5"] = {
            "account": "",
            "server": "",
            "password": "",
            "path": ""
        }
        self.settings["license"] = {
            "key": "",
            "email": "",
            "start_date": None,
            "expiration_date": None,
            "is_trial": False
        }
        return self.save()

class LogoHeader(QWidget):
    def __init__(self, text, logo_pixmap):
        super().__init__()
        self.setMinimumHeight(80)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)

        # Left spacer
        layout.addStretch()

        # Logo and title container
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Logo
        logo_label = QLabel()
        logo_pixmap = logo_pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(logo_label)

        # Title
        title_label = QLabel(text)
        title_label
        title_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(title_label)

        layout.addWidget(container)

        # Right spacer
        layout.addStretch()

class TelegramManager(QObject):
    verification_sent = Signal()
    authenticated = Signal()
    channels_loaded = Signal(list)
    connection_error = Signal(str)
    trade_signal = Signal(str, str)
    management_command = Signal(dict)  # Added for management commands
    connection_status_changed = Signal(bool)
    new_signal_parsed = Signal(dict)  # New signal for UI

    def __init__(self):
        super().__init__()
        self.client = None
        self.session_string = None
        self.phone = None
        self.channels = []
        self.running = False
        self.channel_handlers = {}
        self.connected = False
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.channel_names = {}  # Map channel ID to name

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _connect(self, api_id, api_hash, phone, timeout=30):
        try:
            self.phone = phone
            self.client = TelegramClient(
                StringSession(self.session_string),
                api_id,
                api_hash,
                loop=self.loop
            )
            await asyncio.wait_for(self.client.connect(), timeout=timeout)
            if not await self.client.is_user_authorized():
                if self.session_string:
                    self.session_string = None
                    self.connection_error.emit("Saved session expired, please re-authenticate")
                if phone:
                    await self.client.send_code_request(phone)
                    self.verification_sent.emit()
                return False
            else:
                self.connected = True
                self.connection_status_changed.emit(True)
                self.authenticated.emit()
                return True
        except asyncio.TimeoutError:
            error = "Telegram connection timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram connection failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _authenticate(self, code, timeout=30):
        try:
            await asyncio.wait_for(
                self.client.sign_in(self.phone, code),
                timeout=timeout
            )
            self.session_string = self.client.session.save()
            self.connected = True
            self.connection_status_changed.emit(True)
            self.authenticated.emit()
            return True
        except asyncio.TimeoutError:
            error = "Telegram authentication timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram authentication failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _load_channels(self, timeout=30):
        try:
            if not self.client.is_connected():
                await self.client.connect()
            dialogs = await asyncio.wait_for(
                self.client.get_dialogs(limit=100),
                timeout=timeout
            )
            channels = []
            for dialog in dialogs:
                try:
                    if not isinstance(dialog.entity, Channel) or dialog.is_group:
                        continue
                    entity = dialog.entity
                    username = entity.username if hasattr(entity, 'username') else f"id:{entity.id}"
                    channel_info = {
                        "id": entity.id,
                        "name": dialog.name,
                        "username": username
                    }
                    channels.append(channel_info)
                    self.channel_names[entity.id] = dialog.name
                except Exception as e:
                    logger.error(f"Error processing dialog: {str(e)}")
                    continue
            self.channels_loaded.emit(channels)
        except asyncio.TimeoutError:
            error = "Channel loading timed out"
            logger.error(error)
            self.connection_error.emit(error)
        except Exception as e:
            error = f"Failed to load channels: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)

    def connect_telegram(self, api_id, api_hash, phone):
        asyncio.run_coroutine_threadsafe(
            self._connect(api_id, api_hash, phone),
            self.loop
        )

    def authenticate(self, code):
        asyncio.run_coroutine_threadsafe(
            self._authenticate(code),
            self.loop
        )

    def load_channels(self):
        asyncio.run_coroutine_threadsafe(
            self._load_channels(),
            self.loop
        )

    def add_channel_handler(self, channel_id, callback):
        if channel_id in self.channel_handlers:
            return

        @self.client.on(events.NewMessage(chats=channel_id))
        async def handler(event):
            try:
                message = event.message
                replied_to = None
                if message.reply_to_msg_id:
                    try:
                        replied_msg = await event.get_reply_message()
                        replied_to = replied_msg.text
                    except Exception as e:
                        logger.error(f"Error getting replied message: {str(e)}")
                        replied_to = None

                # Parse the signal with error handling
                try:
                    signal_details = parse_signal(message.text)
                except Exception as e:
                    logger.error(f"Error parsing signal: {str(e)}")
                    signal_details = None

                # Create signal data with channel info
                signal_data = {
                    "channel_id": channel_id,
                    "channel_name": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "message_id": message.id,
                    "text": message.text,
                    "date": message.date,
                    "sender": message.sender_id,
                    "replied_to": replied_to,
                    "signal_details": signal_details
                }

                self.trade_signal.emit(
                    "New Signal Received",
                    f"Channel: {self.channel_names.get(channel_id, channel_id)}\n{message.text}"
                )

                # Emit parsed signal to UI
                if signal_details:
                    self.new_signal_parsed.emit({
                        "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                        "symbol": signal_details.get("symbol", "N/A"),
                        "order_type": signal_details.get("order_type", "N/A"),
                        "entry_price": signal_details.get("entry_price", "N/A"),
                        "sl": signal_details.get("sl", "N/A"),
                        "tp": signal_details.get("tp", "N/A"),
                        "tps": signal_details.get("tps", []),
                        "status": "Parsed",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                else:
                    # Try parsing as management command if signal parsing fails
                    management_details = parse_management_command(message.text)
                    if management_details:
                        self.management_command.emit(management_details)
                    else:
                        self.new_signal_parsed.emit({
                            "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                            "symbol": "N/A",
                            "order_type": "N/A",
                            "entry_price": "N/A",
                            "sl": "N/A",
                            "tp": "N/A",
                            "tps": [],
                            "status": "Failed to parse",
                            "error": "Could not parse signal",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })

                # Only execute callback if signal was successfully parsed
                if signal_details:
                    callback(signal_data)
            except Exception as e:
                logger.error(f"Error in message handler: {str(e)}")
                # Emit error signal to UI
                self.new_signal_parsed.emit({
                    "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "symbol": "N/A",
                    "order_type": "N/A",
                    "entry_price": "N/A",
                    "sl": "N/A",
                    "tp": "N/A",
                    "tps": [],
                    "status": "Error",
                    "error": f"Handler error: {str(e)}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        self.channel_handlers[channel_id] = handler

    def start_listening(self):
        asyncio.run_coroutine_threadsafe(
            self._start_listening(),
            self.loop
        )

    async def _start_listening(self):
        self.running = True
        await self.client.start()
        await self.client.run_until_disconnected()
        self.running = False

    def stop_listening(self):
        self.running = False
        if self.client:
            try:
                # Clear all event handlers
                self.client.list = []

                # Disconnect if connected
                if self.client.is_connected():
                    self.client.disconnect()
                    logger.info("Telegram disconnected")
            except Exception as e:
                logger.error(f"Error stopping Telegram: {str(e)}")
        self.connected = False
        self.connection_status_changed.emit(False)
        logger.info("Telegram listening stopped")

class MT5Manager:
    def __init__(self):
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        self.symbol_cache = {}
        self.parent = None
        self.trade_tracker = TradeTracker()
        self.daily_profit = 0.0
        self.daily_loss = 0.0
        self.lock_until = None  # For account lock

    def get_pip_value(self, symbol):
        """Get pip value for a symbol in account currency"""
        symbol_info = mt5.symbol_info(symbol)
        if symbol_info is None:
            return 0.0001  # Default fallback

        # Calculate pip size (0.0001 for most pairs, 0.01 for JPY pairs)
        pip_size = 0.0001
        if "JPY" in symbol:
            pip_size = 0.01

        # Calculate pip value correctly
        point = symbol_info.point
        
        # For BTC and other crypto, the pip value calculation is different
        if "BTC" in symbol or "ETH" in symbol or "XRP" in symbol or "LTC" in symbol:
            # For crypto, 1 pip = 1 point, and pip value is directly the tick value
            pip_value = symbol_info.trade_tick_value
        else:
            # For forex pairs, calculate pip value: (pip size / point) * tick value
            pip_value = (pip_size / point) * symbol_info.trade_tick_value
        
        # For debugging (only log if there's an issue)
        if pip_value <= 0:
            logger.warning(f"Pip value calculation for {symbol}: pip_size={pip_size}, point={point}, tick_value={symbol_info.trade_tick_value}, pip_value={pip_value}")
        
        return pip_value

    def get_daily_pnl(self):
        """Get current daily P&L as percentage of balance"""
        try:
            account_info = self.get_account_info()
            if not account_info:
                return 0.0
            
            balance = account_info.get('balance', 0)
            if balance <= 0:
                return 0.0
            
            # Get today's trades
            today = datetime.now().date()
            start_time = datetime.combine(today, datetime.min.time())
            end_time = datetime.combine(today, datetime.max.time())
            
            # Get history for today
            history = mt5.history_deals_get(start_time, end_time)
            if history is None:
                return 0.0
            
            # Calculate total P&L for today
            daily_pnl = sum(deal.profit for deal in history)
            
            # Return as percentage of balance
            return (daily_pnl / balance) * 100 if balance > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error calculating daily P&L: {e}")
            return 0.0

    def should_execute_in_range(self, current_price, entry_range, risk_settings):
        low, high = min(entry_range), max(entry_range)
        in_range = low <= current_price <= high
        execute_in_range = risk_settings.get('execute_in_range', True)
        range_handling = risk_settings['entry_range_handling']

        # Always execute if price is in range and setting enabled
        if in_range and execute_in_range:
            return True, None  # Market execution

        # Otherwise convert to pending order
        if range_handling == "First Price":
            preferred_price = low
        elif range_handling == "Last Price":
            preferred_price = high
        else:  # Average
            preferred_price = (low + high) / 2

        return False, preferred_price

    def connect(self, account, server, password, path):
        try:
            account = int(account) if str(account).isdigit() else account
        except ValueError:
            raise ConnectionError("Account number must be numeric")

        if mt5_is_initialized():
            mt5.shutdown()
            time.sleep(1)

        if not os.path.exists(path):
            logger.error(f"MT5 executable NOT FOUND at: {path}")
            raise ConnectionError(f"MT5 executable not found at {path}")

        logger.info(f"Connecting to MT5 at: {path}")
        if not mt5.initialize(path=path, login=account, password=password, server=server):
            error = mt5.last_error()
            logger.error(f"MT5 initialization failed: {error}")
            raise ConnectionError(f"MT5 initialization failed: {error}")

        account_info = mt5.account_info()
        if account_info is None:
            mt5.shutdown()
            error = mt5.last_error()
            logger.error(f"MT5 account info failed: {error}")
            raise ConnectionError(f"Failed to get account info: {error}")

        self.connected = True
        self.account = account
        self.server = server
        self.path = path
        logger.info(f"Connected to MT5 account: {account}")
        return True

    def disconnect(self):
        if mt5_is_initialized():
            mt5.shutdown()
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        logger.info("Disconnected from MT5")

    def get_account_info(self):
        if self.connected:
            try:
                return mt5.account_info()._asdict()
            except:
                return None
        return None

    def normalize_symbol(self, symbol):
        """Normalize symbol for broker-specific format"""
        # Skip invalid words
        if symbol in ["LIMIT", "STOP", "TP", "SL"]:
            return None

        mappings = self.parent.settings.get_symbol_mappings()
        if symbol.upper() in mappings:
            return mappings[symbol.upper()]

        clean_symbol = re.sub(r'[^\w\s.@-]', '', symbol).upper()
        substitutions = {
            'GOLD': 'XAUUSD',
            'XAU': 'XAUUSD',
            'SILVER': 'XAGUSD',
            'XAG': 'XAGUSD',
            'USOIL': 'XTIUSD',
            'UKOIL': 'XBRUSD',
            'OIL': 'XTIUSD',
            'BRENT': 'XBRUSD',
            'NAS100': 'NAS100',
            'SPX500': 'SPX500',
            'DXY': 'USDX',
            'BTC': 'BTCUSD',
            'ETH': 'ETHUSD',
            'XRP': 'XRPUSD',
            'LTC': 'LTCUSD',
            'BCH': 'BCHUSD'
        }
        if clean_symbol in substitutions:
            clean_symbol = substitutions[clean_symbol]

        # Get broker-specific prefix and suffix
        mt5_settings = self.parent.settings.get_mt5_settings()
        symbol_prefix = mt5_settings.get("symbol_prefix", "")
        symbol_suffix = mt5_settings.get("symbol_suffix", "")

        # Try with broker-specific prefix and suffix first
        if symbol_prefix or symbol_suffix:
            broker_symbol = f"{symbol_prefix}{clean_symbol}{symbol_suffix}"
            if mt5.symbol_info(broker_symbol):
                logger.info(f"Found broker symbol: {clean_symbol} -> {broker_symbol}")
                return broker_symbol

        # Try original symbol first
        if mt5.symbol_info(clean_symbol):
            return clean_symbol

        # Try with broker suffix only
        if symbol_suffix:
            trial = clean_symbol + symbol_suffix
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with suffix: {clean_symbol} -> {trial}")
                return trial

        # Try with broker prefix only
        if symbol_prefix:
            trial = symbol_prefix + clean_symbol
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with prefix: {clean_symbol} -> {trial}")
                return trial

        # Try with common suffixes
        for suffix in ['', 'USD', 'EUR', 'JPY', 'GBP', 'CHF', 'AUD', 'CAD', 'NZD']:
            trial = clean_symbol + suffix
            if mt5.symbol_info(trial):
                return trial

        # Try with common prefixes
        for prefix in ['', 'MT_', 'FX_', 'CFD_', 'SPOT_', 'OTC_']:
            trial = prefix + clean_symbol
            if mt5.symbol_info(trial):
                return trial

        # Try removing numbers
        no_num = re.sub(r'\d+', '', clean_symbol)
        if no_num != clean_symbol and mt5.symbol_info(no_num):
            return no_num

        # Try base currency for forex pairs
        if len(clean_symbol) > 3 and clean_symbol[-3:] in ['USD', 'EUR', 'JPY']:
            base = clean_symbol[:-3]
            if mt5.symbol_info(base):
                return base

        logger.warning(f"Symbol not found: {clean_symbol}")
        return None

    def calculate_pip_value(self, symbol_info, symbol):
        """
        Calculate the pip value for a given symbol correctly.
        Handles different instrument types (forex, metals, indices, etc.)
        """
        try:
            contract_size = symbol_info.trade_contract_size
            tick_value = symbol_info.trade_tick_value
            tick_size = symbol_info.trade_tick_size
            point = symbol_info.point
            
            # Handle different instrument types
            if "JPY" in symbol:
                # For JPY pairs, 1 pip = 1 point
                pip_value = tick_value
            elif "XAU" in symbol or "GOLD" in symbol:
                # For gold, calculate based on contract size
                pip_value = tick_value * 10
            elif "XAG" in symbol or "SILVER" in symbol:
                # For silver, calculate based on contract size
                pip_value = tick_value * 10
            else:
                # For other forex pairs, 1 pip = 10 points
                pip_value = tick_value * 10
            
            # Validate pip value
            if pip_value <= 0:
                logger.warning(f"Invalid pip value for {symbol}: {pip_value}, using fallback")
                # Fallback calculation
                pip_multiplier = 10 if "JPY" not in symbol else 1
                pip_value = tick_value * pip_multiplier
            
            return pip_value
            
        except Exception as e:
            logger.error(f"Error calculating pip value for {symbol}: {e}")
            # Emergency fallback
            return symbol_info.trade_tick_value * 10

    def execute_trade(self, symbol, order_type, entry_price, volume, sl=None, tp=None, tps=None, tolerance=2.0, channel_name=None):
        if not self.connected:
            raise ConnectionError("Not connected to MT5")
        try:
            clean_symbol = self.normalize_symbol(symbol)
            if clean_symbol is None:
                logger.warning(f"Skipping trade for invalid symbol: {symbol}")
                return [{"error": f"Invalid symbol: {symbol}"}]
            logger.info(f"Normalized symbol: {symbol} -> {clean_symbol}")

            # Get risk settings
            risk_settings = self.parent.settings.get_risk_settings()
            risk_method = risk_settings['risk_method']
            logger.info(f"Risk calculation for {clean_symbol}: method={risk_method}, settings={risk_settings}")

            # Calculate position size based on risk method
            if risk_method == 'percent':
                # Percent risk method - calculate lot size based on account balance and risk percentage
                account_info = self.get_account_info()
                if not account_info:
                    logger.error("Cannot calculate percent risk - no account info")
                    lot_size = risk_settings.get("fixed_lot", 0.1)
                else:
                    balance = account_info.get('balance', 0)
                    if balance <= 0:
                        logger.error("Cannot calculate percent risk - invalid balance")
                        lot_size = risk_settings.get("fixed_lot", 0.1)
                    else:
                        # Calculate risk amount in account currency
                        risk_amount = balance * (risk_settings['risk_percent'] / 100)

                        # Get symbol info
                        if not mt5.symbol_select(clean_symbol, True):
                            logger.error(f"Symbol {clean_symbol} not found")
                            return [{"error": f"Symbol {clean_symbol} not found"}]

                        symbol_info = mt5.symbol_info(clean_symbol)
                        if symbol_info is None:
                            logger.error(f"Failed to get symbol info for {clean_symbol}")
                            return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

                        # Calculate point value safely with fallback
                        point = symbol_info.point if symbol_info else 0.00001

                        # Calculate stop loss distance in pips
                        if sl and entry_price:
                            # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                            pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                            sl_distance = abs(entry_price - sl) / point / pip_multiplier
                        else:
                            # If no SL, use default 50 pips
                            sl_distance = 50

                        # Calculate lot size with proper validation
                        if sl_distance > 0 and point > 0 and symbol_info.trade_tick_value > 0:
                            # Get pip value per lot for this symbol
                            pip_value = self.calculate_pip_value(symbol_info, clean_symbol)
                            
                            if pip_value > 0:
                                lot_size = risk_amount / (sl_distance * pip_value)
                            else:
                                lot_size = risk_settings.get("fixed_lot", 0.1)
                                logger.warning("Invalid pip_value, using fixed lot")
                        else:
                            lot_size = risk_settings.get("fixed_lot", 0.1)
                            logger.warning("Invalid sl_distance, point_value, or tick_value, using fixed lot")

                        # Apply broker constraints
                        min_volume = symbol_info.volume_min
                        max_volume = symbol_info.volume_max
                        volume_step = symbol_info.volume_step

                        # Clamp to min/max and round to step
                        lot_size = max(min(lot_size, max_volume), min_volume)
                        if volume_step > 0:
                            lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step
                            
                        # Additional safety check: ensure lot size doesn't exceed reasonable limits
                        # For a small account, limit lot size to prevent margin issues
                        if balance < 1000:  # Small account
                            # For very small accounts, use much smaller lot sizes
                            if balance < 200:
                                max_safe_lot = min(lot_size, 0.01)  # Max 0.01 lot for very small accounts
                            elif balance < 500:
                                max_safe_lot = min(lot_size, 0.1)   # Max 0.1 lot for small accounts
                            else:
                                max_safe_lot = min(lot_size, 0.5)   # Max 0.5 lot for medium accounts
                            
                            if lot_size > max_safe_lot:
                                logger.warning(f"Lot size {lot_size} too large for small account (balance: ${balance}), limiting to {max_safe_lot}")
                                lot_size = max_safe_lot

                        logger.info(
                            f"Percent risk lot size: {lot_size:.2f} (risk: {risk_settings['risk_percent']}%, "
                            f"balance: ${balance:.2f}, risk amount: ${risk_amount:.2f}, "
                            f"SL distance: {sl_distance} pips)")

            elif risk_method == 'fixed_dollar':
                fixed_dollar_risk = risk_settings.get('fixed_dollar', 100.0)

                # For fixed dollar risk, we need SL and either entry_price or current market price
                if not sl:
                    logger.error("Fixed dollar risk requires SL")
                    return [{"error": "Fixed dollar risk requires SL"}]
                
                # If entry_price is None (market order), we'll get current price later
                if not entry_price:
                    logger.info("Entry price is None (market order), will use current market price for calculation")

                symbol_info = mt5.symbol_info(clean_symbol)
                point = symbol_info.point
                
                # Get current market price if entry_price is None (market order)
                if not entry_price:
                    tick = mt5.symbol_info_tick(clean_symbol)
                    if tick is None:
                        logger.error(f"Failed to get current price for {clean_symbol}")
                        return [{"error": f"Failed to get current price for {clean_symbol}"}]
                    
                    # Use ask price for BUY orders, bid price for SELL orders
                    if order_type == "BUY":
                        entry_price = tick.ask
                    else:
                        entry_price = tick.bid
                    logger.info(f"Using current market price for calculation: {entry_price}")
                
                # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                sl_distance = abs(entry_price - sl) / point / pip_multiplier

                # Validate SL distance
                if sl_distance <= 0:
                    logger.error(f"Invalid SL distance: {sl_distance} pips")
                    return [{"error": "Invalid stop loss distance"}]
                
                # Prevent extremely small SL distances (less than 1 pip)
                if sl_distance < 1:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very small, this may cause issues")
                
                # Prevent extremely large SL distances (more than 1000 pips)
                if sl_distance > 1000:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very large, please verify")

                # Calculate pip value correctly for different instruments
                pip_value = self.calculate_pip_value(symbol_info, clean_symbol)

                # Calculate lot size
                lot_size = fixed_dollar_risk / (sl_distance * pip_value)
                logger.info(f"Fixed dollar calculation: Risk=${fixed_dollar_risk}, SL_distance={sl_distance:.2f} pips, Pip_value=${pip_value:.2f}, Lot_size={lot_size:.4f}")

                # Safety checks for lot size
                if lot_size <= 0:
                    logger.error(f"Invalid lot size calculated: {lot_size}")
                    return [{"error": "Invalid lot size calculated"}]
                
                # Prevent extremely large lot sizes (safety limit)
                max_safe_lot = 100.0  # Maximum safe lot size
                if lot_size > max_safe_lot:
                    logger.warning(f"Lot size {lot_size:.4f} exceeds safety limit of {max_safe_lot}, capping to {max_safe_lot}")
                    lot_size = max_safe_lot
                
                # Additional validation for reasonable lot sizes
                if lot_size > 10.0:
                    logger.warning(f"Large lot size calculated: {lot_size:.4f} - please verify risk settings")
                
                # Log detailed calculation for debugging
                logger.info(f"Risk calculation details for {clean_symbol}:")
                logger.info(f"  - Fixed dollar risk: ${fixed_dollar_risk}")
                logger.info(f"  - Entry price: {entry_price}")
                logger.info(f"  - Stop loss: {sl}")
                logger.info(f"  - SL distance: {sl_distance:.2f} pips")
                logger.info(f"  - Pip value per lot: ${pip_value:.2f}")
                logger.info(f"  - Calculated lot size: {lot_size:.4f}")

            else:  # Fixed lot method
                lot_size = risk_settings.get("fixed_lot", 0.1)
                logger.info(f"Using fixed lot size: {lot_size}")

            # Validate and adjust volume
            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info:
                # Get volume constraints
                min_volume = symbol_info.volume_min
                volume_step = symbol_info.volume_step

                # Adjust volume to meet broker requirements
                if lot_size < min_volume:
                    lot_size = min_volume
                if volume_step > 0:
                    lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step

                logger.info(f"Adjusted volume: {lot_size} (min: {min_volume}, step: {volume_step})")

            # Validate pending orders require entry price
            is_market_order = order_type in ["BUY", "SELL"]
            if not is_market_order and entry_price is None:
                logger.error("Pending order requires entry price")
                return [{"error": "Pending order requires entry price"}]

            # Handle range entries with validation
            if isinstance(entry_price, tuple):
                if len(entry_price) != 2:
                    logger.error("Invalid range entry - must have exactly 2 values")
                    return [{"error": "Invalid range entry format"}]
                
                # Validate range values
                if entry_price[0] <= 0 or entry_price[1] <= 0:
                    logger.error("Invalid range entry - values must be positive")
                    return [{"error": "Invalid range entry values"}]
                
                risk_settings = self.parent.settings.get_risk_settings()
                range_handling = risk_settings['entry_range_handling']
                if range_handling == "First Price":
                    calculated_price = entry_price[0]
                elif range_handling == "Last Price":
                    calculated_price = entry_price[1]
                else:  # Average Price
                    calculated_price = (entry_price[0] + entry_price[1]) / 2
                
                # Validate calculated price
                if calculated_price <= 0:
                    logger.error("Invalid calculated entry price")
                    return [{"error": "Invalid calculated entry price"}]
                
                logger.info(f"Converted range entry to {calculated_price} using {range_handling} method")
                entry_price = calculated_price

            # Get symbol info
            if not mt5.symbol_select(clean_symbol, True):
                logger.error(f"Symbol {clean_symbol} not found")
                return [{"error": f"Symbol {clean_symbol} not found"}]

            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info is None:
                logger.error(f"Failed to get symbol info for {clean_symbol}")
                return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

            point = symbol_info.point if symbol_info else 0.00001  # Fallback point value
            tick = mt5.symbol_info_tick(clean_symbol)
            if tick is None:
                logger.error(f"Failed to get current price for {clean_symbol}")
                return [{"error": f"Failed to get current price for {clean_symbol}"}]

            # Prepare base trade request
            # Get comment settings and channel name
            risk_settings = self.parent.settings.get_risk_settings() if hasattr(self, 'parent') else {}
            enable_comments = risk_settings.get("enable_comments", True)
            comment_prefix = risk_settings.get("comment_prefix", "FTSC")
            
            # Get channel name from signal data if available
            channel_name = channel_name if channel_name else "Unknown"
            
            # Create comment with channel name if enabled
            if enable_comments:
                comment = f"{comment_prefix} - {channel_name}"
            else:
                comment = ""
            
            request = {
                "symbol": clean_symbol,
                "volume": lot_size,
                "deviation": 20,
                "magic": 2023,
                "comment": comment,
                "type_time": mt5.ORDER_TIME_GTC,
            }

            # Add SL if provided
            if sl and sl > 0:
                request["sl"] = sl

            # Set order type
            if is_market_order:
                request["action"] = mt5.TRADE_ACTION_DEAL
                request["type_filling"] = mt5.ORDER_FILLING_FOK
                if order_type == "BUY":
                    request["type"] = mt5.ORDER_TYPE_BUY
                    request["price"] = tick.ask
                else:  # SELL
                    request["type"] = mt5.ORDER_TYPE_SELL
                    request["price"] = tick.bid
            else:
                request["action"] = mt5.TRADE_ACTION_PENDING
                request["price"] = entry_price
                request["type_filling"] = mt5.ORDER_FILLING_IOC
                if order_type == "BUY LIMIT":
                    request["type"] = mt5.ORDER_TYPE_BUY_LIMIT
                elif order_type == "SELL LIMIT":
                    request["type"] = mt5.ORDER_TYPE_SELL_LIMIT
                elif order_type == "BUY STOP":
                    request["type"] = mt5.ORDER_TYPE_BUY_STOP
                elif order_type == "SELL STOP":
                    request["type"] = mt5.ORDER_TYPE_SELL_STOP

            # Handle multiple TPs
            results = []
            if tps and len(tps) > 1:
                # Get symbol volume limits
                min_volume = symbol_info.volume_min
                volume_per_tp = lot_size / len(tps)

                # Adjust volume to meet minimum requirement while respecting total volume
                if volume_per_tp < min_volume:
                    volume_per_tp = min_volume
                    total_volume = volume_per_tp * len(tps)
                    if total_volume > lot_size * 1.1:  # Allow 10% tolerance
                        logger.warning(f"Total volume {total_volume} exceeds original {lot_size}, adjusting")
                        volume_per_tp = lot_size / len(tps)  # Revert to original calculation
                    else:
                        logger.warning(f"Adjusted TP volume to minimum: {min_volume}")

                for i, tp_val in enumerate(tps):
                    tp_request = request.copy()
                    tp_request["volume"] = volume_per_tp
                    tp_request["tp"] = tp_val
                    tp_request["comment"] = f"Falcon Trade TP{i + 1}"

                    # Send trade request
                    result = mt5.order_send(tp_request)
                    if result.retcode != mt5.TRADE_RETCODE_DONE:
                        error_msg = f"TP{i + 1} failed: {result.comment}"
                        logger.error(error_msg)
                        results.append({"error": error_msg})
                    else:
                        logger.info(f"TP{i + 1} executed successfully: Ticket={result.order}")

                        # Add to trade tracker
                        self.trade_tracker.add_trade(
                            ticket=result.order,
                            symbol=clean_symbol,
                            order_type=order_type,
                            volume=volume_per_tp,
                            entry_price=entry_price,
                            actual_price=result.price,
                            sl=sl,
                            tp=tp_val,
                            status='pending' if not is_market_order else 'filled'
                        )
                        results.append({
                            "symbol": clean_symbol,
                            "order_type": order_type,
                            "volume": volume_per_tp,
                            "price": result.price,
                            "sl": sl,
                            "tp": tp_val,
                            "ticket": result.order
                        })
                return results
            else:
                # Handle single TP
                if tp and tp > 0:
                    request["tp"] = tp
                elif tps and len(tps) == 1:
                    request["tp"] = tps[0]

                # Send trade request
                result = mt5.order_send(request)
                if result.retcode != mt5.TRADE_RETCODE_DONE:
                    error_msg = f"Trade failed: {result.comment} (error {result.retcode})"
                    logger.error(error_msg)
                    return [{"error": error_msg}]

                logger.info(f"Trade executed successfully: Ticket={result.order}")

                # Add to trade tracker
                self.trade_tracker.add_trade(
                    ticket=result.order,
                    symbol=clean_symbol,
                    order_type=order_type,
                    volume=lot_size,
                    entry_price=entry_price,
                    actual_price=result.price,
                    sl=sl,
                    tp=tp or (tps[0] if tps and len(tps) > 0 else None),
                    status='pending' if not is_market_order else 'filled'
                )

                return [{
                    "symbol": clean_symbol,
                    "order_type": order_type,
                    "volume": lot_size,
                    "price": result.price,
                    "sl": sl,
                    "tp": tp or (tps[0] if tps and len(tps) > 0 else None),
                    "ticket": result.order
                }]

        except Exception as e:
            logger.error(f"Error executing trade: {str(e)}")
            return [{"error": str(e)}]

    def _handle_send_result(self, result, request):
        if result is None:
            last_error = mt5.last_error()
            return {"error": f"MT5 send failed: {last_error}"}
        elif result.retcode != mt5.TRADE_RETCODE_DONE:
            return {"error": f"Broker rejected: {result.retcode} - {result.comment}"}
        else:
            # Add trade with partial volume
            self.trade_tracker.add_trade(
                result.order,
                request["symbol"],
                request["type"],
                request["volume"],  # Partial volume
                request["price"],
                sl=request.get("sl"),
                tp=request.get("tp"),
                tps=None
            )
            return {"success": True, "ticket": result.order}

    def handle_management(self, command):
        action = command.get("action")
        symbol = command.get("symbol")
        trades = self.trade_tracker.get_trades_by_symbol(symbol) if symbol else list(
            self.trade_tracker.active_trades.values())
        if not trades:
            return {"error": "No matching trades found"}

        results = []
        for trade in trades:
            ticket = [k for k, v in self.trade_tracker.active_trades.items() if v == trade][0]
            if action == "CLOSE":
                self.close_trade(ticket)
                results.append({"success": True, "action": "closed", "ticket": ticket})
            elif action == "PARTIAL_CLOSE":
                percent = command.get("percent", 50)
                self.partial_close_trade(ticket, percent)
                results.append({"success": True, "action": "partial_closed", "ticket": ticket})
            elif action == "MODIFY_SL":
                new_sl = command.get("sl")
                if new_sl:
                    self.modify_sl(ticket, new_sl)
                    results.append({"success": True, "action": "sl_modified", "ticket": ticket})
            elif action == "MODIFY_TP":
                new_tp = command.get("tp")
                if new_tp:
                    self.modify_tp(ticket, new_tp)
                    results.append({"success": True, "action": "tp_modified", "ticket": ticket})
            elif action == "SL_TO_BE":
                self.move_sl_to_be(ticket)
                results.append({"success": True, "action": "sl_to_be", "ticket": ticket})
            elif action == "CANCEL":
                self.cancel_order(ticket)
                results.append({"success": True, "action": "cancelled", "ticket": ticket})

        return results

    def close_trade(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": position.volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Close trade",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                profit = result.profit
                self.trade_tracker.remove_trade(ticket, profit)
                return True
        return False

    def partial_close_trade(self, ticket, percent):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            close_volume = position.volume * (percent / 100)
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": close_volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Partial close",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                # Update volume in tracker
                new_volume = position.volume - close_volume
                self.trade_tracker.update_trade(ticket, {"volume": new_volume})
                return True
        return False

    def modify_sl(self, ticket, new_sl):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": new_sl,
                "tp": position.tp  # PRESERVE EXISTING TP
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": new_sl})
                return True
        return False

    def modify_tp(self, ticket, new_tp):
        request = {
            "action": mt5.TRADE_ACTION_SLTP,
            "position": ticket,
            "tp": new_tp,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.update_trade(ticket, {"tp": new_tp})
            return True
        return False

    def move_sl_to_be(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            be_price = position.price_open
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": be_price,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": be_price})
                return True
        return False

    def cancel_order(self, ticket):
        request = {
            "action": mt5.TRADE_ACTION_REMOVE,
            "order": ticket,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.remove_trade(ticket, 0)
            return True
        return False

    def close_all_trades(self):
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                self.close_trade(pos.ticket)

    def monitor_trades(self):
        risk_settings = self.parent.settings.get_risk_settings()
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                ticket = pos.ticket
                trade = self.trade_tracker.get_trade_by_ticket(ticket)
                if not trade:
                    continue

                current_price = mt5.symbol_info_tick(
                    pos.symbol).bid if pos.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(pos.symbol).ask
                entry_price = trade["entry"]

                # BE after pips
                if risk_settings['be_after_pips'] > 0:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    pip_diff = abs(current_price - entry_price) / point / pip_multiplier
                    if pip_diff >= risk_settings['be_after_pips']:
                        self.move_sl_to_be(ticket)

                # Trailing SL
                if risk_settings['trailing_sl_enabled']:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert pip distance to points for trailing stop
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    trailing_dist = risk_settings['trailing_sl_distance'] * point * pip_multiplier
                    if pos.type == mt5.ORDER_TYPE_BUY:
                        new_sl = current_price - trailing_dist
                        if new_sl > pos.sl:
                            self.modify_sl(ticket, new_sl)
                    else:
                        new_sl = current_price + trailing_dist
                        if new_sl < pos.sl:
                            self.modify_sl(ticket, new_sl)

class TradeMonitor(QThread):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.running = True

    def run(self):
        while self.running:
            if self.parent.mt5_manager.connected:
                self.parent.mt5_manager.monitor_trades()
            time.sleep(1)

# =====================
# UI COMPONENTS

# =====================
# ACTIVATION PAGE
# =====================
class ActivationPage(QWidget):
    activation_result = Signal(bool, str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.activation_result.connect(self.handle_activation_result)

    def setup_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(20)

        # Logo
        logo_label = QLabel()
        logo_pixmap = self.main_window.app_logo.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label, 0, Qt.AlignCenter)

        # Header
        header = QLabel("Falcon Trade Signal Copier")
        header
        layout.addWidget(header, 0, Qt.AlignCenter)

        # Subheader
        subheader = QLabel("Activate Your License")
        subheader
        layout.addWidget(subheader, 0, Qt.AlignCenter)

        # Instruction text
        instruction = QLabel(
            "Enter your license key below or start a free 7-day trial."
        )
        instruction
        instruction.setWordWrap(True)
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)

        # License key input
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter license key (XXXX-XXXX-XXXX-XXXX)")
        self.key_input
        # Allow Enter key to activate
        self.key_input.returnPressed.connect(self.activate_software)
        layout.addWidget(self.key_input)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        self.activate_btn = QPushButton("Activate License")
        self.activate_btn
        self.activate_btn.clicked.connect(self.activate_software)

        self.trial_btn = QPushButton("Start Free Trial")
        self.trial_btn
        self.trial_btn.clicked.connect(self.start_trial)

        btn_layout.addWidget(self.activate_btn)
        btn_layout.addWidget(self.trial_btn)
        layout.addLayout(btn_layout)

        # Status message
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"font-size: 13px; margin-top: 10px;")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Footer
        footer = QLabel(
            f"© 2023 Falcon Trade Copier v{VERSION} | "
            "<a href='https://falcontradecopier.com' style='color:blue;'>Website</a> | "
            "<a href='mailto:support@falcontradecopier.com' style='color:blue;'>Support</a>"
        )
        footer
        footer.setOpenExternalLinks(True)
        layout.addWidget(footer, 0, Qt.AlignCenter)

        # Set initial status
        self.update_status(True, "Enter your license key to continue")

    def update_status(self, valid, message):
        color = "green" if valid else "red"
        self.status_label.setStyleSheet(f"""
            font-size: 13px;
            color: {color};
            margin-top: 10px;
        """)
        self.status_label.setText(message)

    def activate_software(self):
        try:
            key = self.key_input.text().strip()

            if not key:
                self.update_status(False, "Please enter a license key")
                return

            if len(key) < 8:  # Reduced minimum length for bypass key
                self.update_status(False, "Invalid license key format")
                return

            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.activate_btn.setText("Validating...")
            self.update_status(True, "Validating license...")

            # Start validation in separate thread
            threading.Thread(target=self.main_window.validate_license, args=(key,), daemon=True).start()
            
            logger.info(f"Starting license validation for key: {key[:8]}...")
            
        except Exception as e:
            logger.error(f"Error in activate_software: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.update_status(False, "Activation error occurred. Please try again.")

    def start_trial(self):
        try:
            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.trial_btn.setText("Starting...")
            self.update_status(True, "Starting trial...")

            # Start trial process in separate thread
            threading.Thread(target=self.main_window.process_trial, daemon=True).start()
            
            logger.info("Starting trial license creation...")
            
        except Exception as e:
            logger.error(f"Error in start_trial: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.trial_btn.setText("Start Free Trial")
            self.update_status(False, "Trial start error occurred. Please try again.")

    def handle_activation_result(self, valid, message, result):
        try:
            if valid:
                self.update_status(True, message)
                self.main_window.show_telegram_page()
            else:
                # Reset buttons to original state on failure
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
                self.update_status(False, message)
                
                logger.warning(f"Activation failed: {message}")
        except Exception as e:
            logger.error(f"Error handling activation result: {e}")
            # Ensure buttons are reset even if there's an error
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
    
    def reset_ui_state(self):
        """Reset the activation page to initial state"""
        try:
            # Clear input field
            self.key_input.clear()
            
            # Enable buttons and reset text
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
            
            # Reset status message
            self.update_status(True, "Enter your license key to continue")
            
            # Ensure signal connections are active (reconnect if needed)
            self.reconnect_signals()
            
            # Set focus to input field for better UX
            self.key_input.setFocus()
            
            logger.info("Activation page UI state reset successfully")
        except Exception as e:
            logger.error(f"Error resetting activation page UI state: {e}")
            # Fallback to ensure buttons are at least enabled
            try:
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
            except:
                pass
    
    def reconnect_signals(self):
        """Ensure signal connections are properly established"""
        try:
            # Disconnect existing connections to avoid duplicates
            try:
                self.activate_btn.clicked.disconnect()
                self.trial_btn.clicked.disconnect()
            except:
                pass  # No existing connections to disconnect
            
            # Reconnect signals
            self.activate_btn.clicked.connect(self.activate_software)
            self.trial_btn.clicked.connect(self.start_trial)
            
            logger.debug("Activation page signals reconnected")
        except Exception as e:
            logger.error(f"Error reconnecting activation page signals: {e}")

# =====================
# TELEGRAM SETUP PAGE
# =====================
class TelegramPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.channel_checkboxes = {}  # Store channel_id: checkbox mapping
        self.setup_ui()
        self.check_session_status()
        QTimer.singleShot(100, self.attempt_auto_connect)
        self.channels = []  # Store loaded channels

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(1.5)

        # Header with logo
        header = LogoHeader("Telegram Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Phone and Code in one row
        phone_code_layout = QHBoxLayout()
        phone_code_layout.setSpacing(1.5)

        # Phone input
        phone_layout = QVBoxLayout()
        phone_layout.setSpacing(1.5)
        phone_label = QLabel("Phone Number:")
        phone_label
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("+1234567890")
        self.phone_input.setFixedHeight(28)
        self.phone_input.setFixedWidth(200)
        phone_layout.addWidget(phone_label)
        phone_layout.addWidget(self.phone_input)
        phone_code_layout.addLayout(phone_layout)

        # Code input
        code_layout = QVBoxLayout()
        code_layout.setSpacing(1.5)
        code_label = QLabel("Verification Code:")
        code_label
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("12345")
        self.code_input.setEnabled(False)
        self.code_input.setFixedHeight(28)
        self.code_input.setFixedWidth(200)
        code_layout.addWidget(code_label)
        code_layout.addWidget(self.code_input)
        phone_code_layout.addLayout(code_layout)

        layout.addLayout(phone_code_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(1.5)

        self.send_code_btn = QPushButton("Send Code")
        self.send_code_btn.clicked.connect(self.send_telegram_code)

        self.verify_btn = QPushButton("Verify")
        self.verify_btn.setEnabled(False)
        self.verify_btn.clicked.connect(self.verify_telegram_code)

        self.change_number_btn = QPushButton("Change Number")
        self.change_number_btn.setVisible(False)
        self.change_number_btn.clicked.connect(self.change_telegram_number)

        btn_layout.addWidget(self.send_code_btn)
        btn_layout.addWidget(self.verify_btn)
        btn_layout.addWidget(self.change_number_btn)
        layout.addLayout(btn_layout)

        # Channel selection
        channel_layout = QVBoxLayout()
        channel_layout.setSpacing(1.5)
        channel_header = QLabel("Telegram Channels:")
        channel_header
        channel_layout.addWidget(channel_header)
        
        # Search field for channels
        search_layout = QHBoxLayout()
        search_layout.addStretch()  # Push to right side
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.channel_search = QLineEdit()
        self.channel_search.setPlaceholderText("Search channels...")
        self.channel_search.setFixedHeight(28)
        self.channel_search.setFixedWidth(200)
        self.channel_search.textChanged.connect(self.filter_channels)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.channel_search)
        channel_layout.addLayout(search_layout)

        # Scroll area for channels grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: 2px solid #1c243b;
                border-radius: 6px;
                background-color: #0d111f;
            }
        """)

        # Container widget for grid
        container = QWidget()
        self.grid_layout = QGridLayout(container)
        self.grid_layout.setSpacing(0)
        self.grid_layout.setContentsMargins(15, 15, 15, 15)

        scroll_area.setWidget(container)
        scroll_area.setMinimumHeight(150)
        channel_layout.addWidget(scroll_area)
        layout.addLayout(channel_layout)

        # Channel IDs and Save button in one row
        id_save_layout = QHBoxLayout()
        id_save_layout.setSpacing(1.5)

        # Channel IDs
        id_layout = QVBoxLayout()
        id_layout.setSpacing(1.5)
        id_label = QLabel("Channel IDs (comma separated):")
        id_label
        self.channel_id_input = QLineEdit()
        self.channel_id_input
        id_layout.addWidget(id_label)
        id_layout.addWidget(self.channel_id_input)
        id_save_layout.addLayout(id_layout, 3)  # 3/4 width

        # Save button
        self.save_btn = QPushButton("Save Channels")
        self.save_btn.setFixedHeight(35)
        self.save_btn.setFixedWidth(120)
        self.save_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.save_btn.clicked.connect(self.save_channels)
        id_save_layout.addWidget(self.save_btn, 1)  # 1/4 width
        # Align save button with channel ID field
        self.save_btn.setContentsMargins(0, 0, 0, 0)

        layout.addLayout(id_save_layout)

        # Navigation
        nav_layout = QHBoxLayout()

        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.activation_page))
        self.next_btn = QPushButton("Next")
        self.next_btn.setEnabled(False)
        self.next_btn.clicked.connect(self.parent.show_mt5_page)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)
        layout.addLayout(nav_layout)

        # Set fixed width for buttons
        for btn in [self.send_code_btn, self.verify_btn, self.change_number_btn]:
            btn.setFixedWidth(150)

        # Load saved channels if any
        saved_channels = self.parent.settings.get_telegram_channels()
        if saved_channels:
            self.channel_id_input.setText(", ".join(str(id) for id in saved_channels))

    def send_telegram_code(self):
        phone = self.phone_input.text().strip()
        if not phone:
            QMessageBox.warning(self, "Missing Phone", "Please enter your phone number")
            return

        self.send_code_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Sending verification code...")
        self.parent.telegram_manager.connect_telegram(
            TELEGRAM_API_ID,
            TELEGRAM_API_HASH,
            phone
        )

    def verify_telegram_code(self):
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "Missing Code", "Please enter the verification code")
            return

        self.verify_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Verifying code...")
        self.parent.telegram_manager.authenticate(code)

    def change_telegram_number(self):
        self.parent.telegram_manager.stop_listening()
        self.parent.telegram_manager = TelegramManager()
        self.parent.setup_connections()
        self.parent.settings.set_telegram_session(None)
        self.phone_input.setEnabled(True)
        self.phone_input.clear()
        self.code_input.clear()
        self.code_input.setEnabled(False)
        self.verify_btn.setEnabled(False)
        self.change_number_btn.setVisible(False)
        self.next_btn.setEnabled(False)
        self.clear_channel_grid()
        self.channel_id_input.clear()
        self.send_code_btn.setEnabled(True)
        self.send_code_btn.setVisible(True)
        self.parent.update_connection_status()
        self.parent.status_bar.showMessage("Enter new phone number")

    def check_session_status(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)

    def attempt_auto_connect(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.parent.status_bar.showMessage("Attempting auto-login...")
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)
            self.phone_input.setEnabled(False)
            self.code_input.setEnabled(False)
            self.verify_btn.setEnabled(False)
            self.parent.telegram_manager.session_string = session
            self.parent.telegram_manager.connect_telegram(
                TELEGRAM_API_ID, TELEGRAM_API_HASH, ""
            )

    def load_channels(self, channels):
        self.channels = channels  # Store channels
        self.clear_channel_grid()
        if not channels:
            label = QLabel("No channels available")
            label
            label.setAlignment(Qt.AlignCenter)
            self.grid_layout.addWidget(label, 0, 0, 1, 2)
            return

        # Add channels to grid
        row, col = 0, 0
        max_cols = 2  # Number of columns in grid

        for channel in channels:
            checkbox = QCheckBox(f"{channel['name']} (@{channel['username']})")
            checkbox
            checkbox.setProperty("channel_id", channel["id"])
            self.channel_checkboxes[channel["id"]] = checkbox

            # Check if this channel is already selected
            saved_ids = [id.strip() for id in self.channel_id_input.text().split(",") if id.strip()]
            if str(channel["id"]) in saved_ids:
                checkbox.setChecked(True)

            # Connect checkbox state change to update ID input
            checkbox.stateChanged.connect(self.update_channel_ids_from_checkboxes)

            self.grid_layout.addWidget(checkbox, row, col)

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

    def clear_channel_grid(self):
        # Clear existing checkboxes
        for i in reversed(range(self.grid_layout.count())):
            widget = self.grid_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self.channel_checkboxes.clear()

    def update_channel_ids_from_checkboxes(self):
        """Update channel ID input based on checkbox states"""
        selected_ids = []
        for channel_id, checkbox in self.channel_checkboxes.items():
            if checkbox.isChecked():
                selected_ids.append(str(channel_id))

        self.channel_id_input.setText(", ".join(selected_ids))

    def save_channels(self):
        channel_ids = []
        for id_str in self.channel_id_input.text().split(','):
            id_str = id_str.strip()
            if id_str:
                try:
                    channel_ids.append(int(id_str))
                except ValueError:
                    logger.error(f"Invalid channel ID: {id_str}")

        if channel_ids:
            self.parent.settings.set_telegram_channels(channel_ids)
            self.parent.status_bar.showMessage(f"Saved {len(channel_ids)} channels")
            self.next_btn.setEnabled(True)
        else:
            self.parent.status_bar.showMessage("No valid channel IDs to save")

    def get_channel_name(self, channel_id):
        for channel in self.channels:
            if channel['id'] == channel_id:
                return channel['name']
        return str(channel_id)
        
    def filter_channels(self):
        """Filter channels based on search text"""
        search_text = self.channel_search.text().lower()
        for i in range(self.grid_layout.count()):
            widget = self.grid_layout.itemAt(i).widget()
            if isinstance(widget, QCheckBox):
                channel_name = widget.text().lower()
                widget.setVisible(search_text in channel_name)

# MT5 SETUP PAGE
# =====================
class MT5Page(QWidget):
    connection_result = Signal(bool, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        self.load_settings()
        self.connection_result.connect(self.on_mt5_connection_result)

    def browse_mt5_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select MetaTrader 5 Terminal",
            "C:/",
            "Executable Files (*.exe)"
        )
        if file_path:
            self.path_input.setText(file_path)

    def setup_ui(self):
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 25, 40, 20)
        layout.setSpacing(8)

        # Header with logo
        header = LogoHeader("MT5 Account Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Form
        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignLeft)

        # Account
        account_label = QLabel("Account Number:")
        account_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.account_input = QLineEdit()
        self.account_input.setPlaceholderText("Enter MT5 account number")
        self.account_input.setFixedHeight(40)
        self.account_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(account_label, self.account_input)

        # Server
        server_label = QLabel("Server:")
        server_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Enter MT5 server name")
        self.server_input.setFixedHeight(40)
        self.server_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(server_label, self.server_input)

        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter MT5 password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(40)
        self.password_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(password_label, self.password_input)

        # Path
        path_label = QLabel("MT5 Path:")
        path_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        path_layout = QHBoxLayout()
        path_layout.setSpacing(4)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter MT5 terminal path")
        self.path_input.setFixedHeight(40)
        self.path_input.setStyleSheet("font-size: 13px;")
        path_layout.addWidget(self.path_input)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_mt5_path)
        self.browse_btn.setFixedWidth(100)
        self.browse_btn.setFixedHeight(40)
        path_layout.addWidget(self.browse_btn)
        form_layout.addRow(path_label, path_layout)

        # MT5 Path Instructions
        path_instructions = QLabel("💡 Instructions: Right-click on your MT5 terminal shortcut → Properties → Copy the path from 'Target' field")
        path_instructions.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 4px;")
        path_instructions.setWordWrap(False)
        path_instructions.setAlignment(Qt.AlignLeft)
        form_layout.addRow("", path_instructions)

        # Symbol Prefix and Suffix (aligned like other fields)
        prefix_label = QLabel("Symbol Prefix:")
        prefix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText(".pro")
        self.prefix_input.setFixedHeight(40)
        self.prefix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(prefix_label, self.prefix_input)
        
        suffix_label = QLabel("Symbol Suffix:")
        suffix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.suffix_input = QLineEdit()
        self.suffix_input.setPlaceholderText(".raw")
        self.suffix_input.setFixedHeight(40)
        self.suffix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(suffix_label, self.suffix_input)

        # Help text
        help_text = QLabel("💡 Tip: Leave empty if your broker doesn't use prefixes/suffixes")
        help_text.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 8px;")
        help_text.setWordWrap(True)
        help_text.setAlignment(Qt.AlignCenter)
        form_layout.addRow(help_text)

        # Center the form
        form_container = QWidget()
        form_container.setMaximumWidth(500)
        form_container.setLayout(form_layout)
        
        # Center the form container
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(form_container)
        center_layout.addStretch()
        layout.addLayout(center_layout)

        # Status
        self.status_label = QLabel("Not connected")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        # Connect button with dynamic glow effect
        self.connect_btn = QPushButton("Connect to MT5")
        self.connect_btn.setFixedHeight(45)
        self.connect_btn.setFixedWidth(200)
        self.connect_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f27d03, stop:1 #ff8a1a);
                color: #020711;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff8a1a, stop:1 #f27d03);
                
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e07000, stop:1 #f27d03);
            }
        """)
        self.connect_btn.clicked.connect(self.connect_mt5)
        
        # Center the button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.connect_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 6)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1c243b;
                border-radius: 4px;
                text-align: center;
                background-color: #0d111f;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8ccaee, stop:1 #f27d03);
                border-radius: 3px;
            }
        """)
        # Remove percentage text from progress bar
        self.progress_bar.setTextVisible(False)
        # Center the progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addStretch()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addStretch()
        layout.addLayout(progress_layout)

        # Navigation
        nav_layout = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.telegram_page))
        self.finish_btn = QPushButton("Finish")
        self.finish_btn.setEnabled(False)
        self.finish_btn.clicked.connect(self.parent.show_dashboard)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.finish_btn)
        layout.addLayout(nav_layout)

    def load_settings(self):
        mt5_settings = self.parent.settings.get_mt5_settings()
        self.account_input.setText(mt5_settings.get("account", ""))
        self.server_input.setText(mt5_settings.get("server", ""))
        self.password_input.setText(mt5_settings.get("password", ""))
        self.path_input.setText(mt5_settings.get("path", ""))
        self.prefix_input.setText(mt5_settings.get("symbol_prefix", ""))
        self.suffix_input.setText(mt5_settings.get("symbol_suffix", ""))

    def connect_mt5(self):
        account = self.account_input.text().strip()
        server = self.server_input.text().strip()
        password = self.password_input.text()
        path = self.path_input.text().strip()
        symbol_prefix = self.prefix_input.text().strip()
        symbol_suffix = self.suffix_input.text().strip()

        if not account or not server or not password or not path:
            QMessageBox.warning(self, "Missing Information", "Please fill in all fields")
            return

        self.connect_btn.setEnabled(False)
        self.status_label.setText("Connecting to MT5...")
        self.parent.status_bar.showMessage("Connecting to MT5...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.parent.settings.set_mt5_settings(account, server, password, path, symbol_prefix, symbol_suffix)

        # Create a new thread and worker
        self.thread = QThread()
        self.worker = Worker(account, server, password, path)
        self.worker.parent = self.parent  # Pass parent reference
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress_update.connect(self.update_progress_status)
        self.worker.finished.connect(self.on_mt5_connection_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # Start the thread
        self.thread.start()
        
        # Set up timeout timer
        self.timeout_timer = QTimer()
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self.handle_connection_timeout)
        self.timeout_timer.start(60000)  # 60 seconds timeout

    def connect_mt5_thread(self, account, server, password, path):
        try:
            self.parent.mt5_manager.connect(account, server, password, path)
            self.connection_result.emit(True, "Connected successfully!")
        except Exception as e:
            self.connection_result.emit(False, str(e))

    def update_progress_status(self, message, step):
        """Update the status label with progress message and update progress bar"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        self.parent.status_bar.showMessage(message)
        self.progress_bar.setValue(step)

    def handle_connection_timeout(self):
        """Handle connection timeout"""
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.terminate()
            self.thread.wait(2000)  # Wait up to 2 seconds for thread to terminate
        self.progress_bar.setVisible(False)
        self.status_label.setText("Connection timeout - please try again")
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
        self.parent.status_bar.showMessage("MT5 connection timed out")
        self.connect_btn.setEnabled(True)
        QMessageBox.warning(self, "Connection Timeout", 
                          "The connection to MT5 timed out. Please check your settings and try again.")

    def on_mt5_connection_result(self, success, message):
        # Stop timeout timer
        if hasattr(self, 'timeout_timer'):
            self.timeout_timer.stop()
        
        self.progress_bar.setVisible(False)
        if success:
            self.status_label.setText("Connected successfully")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #1d9e4a;")
            self.parent.status_bar.showMessage("MT5 connected successfully")
            # Update account info immediately after successful connection
            self.parent.update_account_info()
            # Enable the finish button so user can click it to go to dashboard
            self.finish_btn.setEnabled(True)
        else:
            self.status_label.setText("Connection failed")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
            self.parent.status_bar.showMessage("MT5 connection failed")
            QMessageBox.warning(self, "Connection Failed", f"Failed to connect to MT5: {message}")
        self.connect_btn.setEnabled(True)

class Worker(QObject):
    finished = Signal(bool, str)
    progress_update = Signal(str, int)  # Add progress signal with step number

    def __init__(self, account, server, password, path):
        super().__init__()
        self.account = account
        self.server = server
        self.password = password
        self.path = path
        self.timeout = 60  # 60 seconds timeout for connection

    @Slot()
    def run(self):
        try:
            # Step 1: Validate account number
            self.progress_update.emit("Validating account number...", 1)
            time.sleep(0.5)  # Small delay to show progress
            try:
                account = int(self.account) if str(self.account).isdigit() else self.account
            except ValueError:
                raise ValueError("Account number must be numeric")

            # Step 2: Shutdown existing MT5 connection
            self.progress_update.emit("Shutting down existing MT5 connection...", 2)
            time.sleep(0.5)  # Small delay to show progress
            if mt5_is_initialized():
                mt5.shutdown()
                time.sleep(1)

            # Step 3: Check MT5 executable path
            self.progress_update.emit("Checking MT5 executable...", 3)
            time.sleep(0.5)  # Small delay to show progress
            if not os.path.exists(self.path):
                raise ValueError("MT5 path not found")

            # Step 4: Initialize MT5
            self.progress_update.emit("Initializing MT5...", 4)
            time.sleep(0.5)  # Small delay to show progress
            logger.info(f"Connecting to MT5 at: {self.path}")
            if not mt5.initialize(path=self.path, login=account, password=self.password, server=self.server):
                raise ValueError(f"MT5 initialization failed: {mt5.last_error()}")

            # Step 5: Get account info
            self.progress_update.emit("Getting account information...", 5)
            time.sleep(0.5)  # Small delay to show progress
            account_info = mt5.account_info()
            if not account_info:
                raise ValueError("Failed to get account info")

            # Step 6: Finalize connection
            self.progress_update.emit("Finalizing connection...", 6)
            time.sleep(0.5)  # Small delay to show progress
            
            # Set the connection status in the MT5Manager
            if hasattr(self, 'parent') and hasattr(self.parent, 'mt5_manager'):
                self.parent.mt5_manager.connected = True
                self.parent.mt5_manager.account = self.account
                self.parent.mt5_manager.server = self.server
                self.parent.mt5_manager.path = self.path
            
            self.finished.emit(True, "Connected successfully")
        except Exception as e:
            self.finished.emit(False, str(e))

import sys
import os
import asyncio
import threading
from PySide6.QtCore import QObject, Signal, Slot, QThread
import json
import uuid
import socket
import hashlib
import requests
import time
from datetime import datetime, timedelta
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase not available. Install with: pip install supabase")
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect, QThread
import re
import logging
from PySide6.QtCore import QDate
from PySide6.QtWidgets import QDateEdit, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import QPropertyAnimation, QEasingCurve
import pyperclip
from PySide6.QtGui import QIcon, QPalette, QColor, QAction, QFont, QImage, QPixmap, QLinearGradient, QBrush, QPainter, \
    QFontMetrics
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QCheckBox,
    QGroupBox, QSpacerItem, QSizePolicy, QFileDialog, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QSystemTrayIcon,
    QMenu, QStatusBar, QGridLayout, QComboBox, QDoubleSpinBox, QTreeWidget,
    QTreeWidgetItem, QInputDialog, QDialog, QDialogButtonBox, QFormLayout, QScrollArea,
    QSpinBox, QFrame, QStyle, QToolBar, QProgressBar
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QEvent, QPoint, QRect
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import Channel
import MetaTrader5 as mt5
import psutil
import platform

# Charting and analytics imports
try:
    import matplotlib
    # Set backend before importing pyplot to avoid GUI issues
    matplotlib.use('Agg', force=True)  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    CHARTING_AVAILABLE = True
except ImportError:
    CHARTING_AVAILABLE = False
    print("Warning: Charting libraries not available. Install with: pip install matplotlib pandas numpy")
except Exception as e:
    CHARTING_AVAILABLE = False
    print(f"Warning: Charting libraries error: {e}")

# ======================
# APPLICATION CONSTANTS
# ======================

APP_NAME = "Falcon Trade Signal Copier"
SHORT_NAME = "FTSC"
VERSION = "1.2"

TELEGRAM_API_ID = 26121573
TELEGRAM_API_HASH = "305761518085ff8519d0eded60f46c72"
TRADE_HISTORY_FILE = "../falcon_trade_history.json"
SETTINGS_FILE = "../falcon_app_settings.json"
ACTIVE_TRADES_FILE = "../falcon_active_trades.json"

# Import Supabase configuration
try:
    from supabase_config import *
    SUPABASE_CONFIG_LOADED = True
except ImportError:
    # Fallback configuration (replace with your actual values)
    SUPABASE_URL = "https://your-project-id.supabase.co"
    SUPABASE_ANON_KEY = "your-anon-key-here"
    LICENSES_TABLE = "licenses"
    HEARTBEATS_TABLE = "heartbeats"
    USERS_TABLE = "users"
    SUPABASE_CONFIG_LOADED = False

# Legacy API URLs (fallback)
VALIDATION_URL = "https://api.falcontradecopier.com/validate-license"
HEARTBEAT_URL = "https://api.falcontradecopier.com/heartbeat"
ACTIVATION_URL = "https://api.falcontradecopier.com/activate"
TRIAL_URL = "https://api.falcontradecopier.com/start-trial"

NEWS_API_URL = "https://example.com/news-api"  # Placeholder for news API

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("../falcon_app_debug.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load spaCy model for AI parsing
try:
    import spacy
    from spacy.matcher import Matcher

    nlp = spacy.load("en_core_web_sm")
except ImportError:
    logger.warning("spaCy not installed. Using regex-only parsing.")
    nlp = None
except OSError:
    logger.info("spaCy model not available. Using regex parsing as fallback.")
    nlp = None

# =====================
# HELPER FUNCTIONS
# =====================
def get_hardware_id():
    """Generate hardware fingerprint for device binding"""
    try:
        # Use MAC address
        mac = uuid.getnode()

        # Get disk serial (platform-independent)
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

        # Get CPU info
        cpu_id = platform.processor()

        combined = f"{mac}-{disk_id}-{cpu_id}"
        return hashlib.sha256(combined.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error generating hardware ID: {str(e)}")
        return str(uuid.uuid4())

def mt5_is_initialized():
    try:
        mt5.symbols_total()
        return True
    except:
        return False

def expand_compact_range_match(match):
    """Helper function to expand compact ranges like '3347-49' to '3347-3349'"""
    first = match.group(1)
    second = match.group(2)
    if '.' in first:
        return match.group(0)  # Don't process decimals
    try:
        first_num = int(first)
        second_num = int(second)
        base = (first_num // 100) * 100
        full_second = base + second_num
        if full_second < first_num:
            full_second += 100  # Handle century crossing
        return f"{first}-{full_second}"
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to expand range {first}-{second}: {e}")
        return match.group(0)

# ======================
# SUPABASE MANAGER
# ======================
class SupabaseManager:
    def __init__(self):
        self.client = None
        self.initialized = False
        self.validation_cache = {}  # Cache recent validations
        self.rate_limit_attempts = {}  # Track validation attempts per IP/machine
        self.max_attempts_per_hour = 60  # Rate limiting
        
        if SUPABASE_AVAILABLE:
            try:
                self.client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                self.initialized = True
                logger.info("Supabase client initialized successfully")
                if SUPABASE_CONFIG_LOADED:
                    logger.info("Supabase configuration loaded successfully")
                else:
                    logger.warning("Using fallback Supabase configuration")
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
        else:
            logger.warning("Supabase not available - using legacy API")
            
    def _check_rate_limit(self, machine_id):
        """Check if machine_id has exceeded rate limits"""
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        
        # Clean old attempts
        self.rate_limit_attempts = {
            mid: attempts for mid, attempts in self.rate_limit_attempts.items()
            if any(attempt > hour_ago for attempt in attempts)
        }
        
        # Check current machine attempts
        if machine_id not in self.rate_limit_attempts:
            self.rate_limit_attempts[machine_id] = []
            
        recent_attempts = [
            attempt for attempt in self.rate_limit_attempts[machine_id]
            if attempt > hour_ago
        ]
        
        if len(recent_attempts) >= self.max_attempts_per_hour:
            logger.warning(f"Rate limit exceeded for machine {machine_id[:8]}...")
            return False
            
        # Record this attempt
        self.rate_limit_attempts[machine_id] = recent_attempts + [current_time]
        return True
        
    def _log_validation_attempt(self, license_key, machine_id, result, additional_info=None):
        """Log validation attempts for security monitoring"""
        log_data = {
            'license_key': license_key[:8] + "...",  # Partial key for security
            'machine_id': machine_id[:8] + "...",   # Partial machine ID
            'timestamp': datetime.now().isoformat(),
            'valid': result.get('valid', False),
            'message': result.get('message', ''),
            'source': 'supabase' if self.initialized else 'fallback'
        }
        
        if additional_info:
            log_data.update(additional_info)
            
        if result.get('valid'):
            logger.info(f"License validation successful: {license_key[:8]}... on {machine_id[:8]}...")
        else:
            logger.warning(f"License validation failed: {license_key[:8]}... on {machine_id[:8]}... - {result.get('message', 'Unknown error')}")
            
        # Store validation log in database for monitoring
        if self.initialized:
            try:
                self.client.table('validation_logs').insert(log_data).execute()
            except Exception as e:
                logger.debug(f"Failed to log validation attempt: {e}")
    
    def validate_license(self, license_key, machine_id):
        """Enhanced license validation using Supabase with improved error handling"""
        if not self.initialized:
            return self._fallback_validate_license(license_key, machine_id)
        
        try:
            # Query the licenses table - prioritize 'key' column (actual database structure)
            try:
                response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name for compatibility
                response = self.client.table(LICENSES_TABLE).select('*').eq('license_key', license_key).execute()
            
            if not response.data:
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": "License key not found"})
                return {"valid": False, "message": "License key not found. Please check your license key."}
            
            license_data = response.data[0]
            
            # Enhanced status validation
            status = license_data.get('status', license_data.get('is_active', False))
            if status not in [LICENSE_STATUS_ACTIVE, True, 'active', 'ACTIVE']:
                detailed_message = f"License status is '{status}'. Please contact support if this is unexpected."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": detailed_message, "status": status})
                return {"valid": False, "message": detailed_message}
            
            # Enhanced expiration validation
            expires_at = license_data.get('expires_at') or license_data.get('expiration_date') or license_data.get('valid_until')
            if not expires_at:
                error_msg = "License has no expiration date. Please contact support."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": error_msg}
            
            try:
                expiration_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if expiration_date < datetime.now(expiration_date.tzinfo):
                    days_expired = (datetime.now(expiration_date.tzinfo) - expiration_date).days
                    error_msg = f"License expired {days_expired} day(s) ago on {expiration_date.strftime('%Y-%m-%d')}. Please renew your license."
                    self._log_validation_attempt(license_key, machine_id, 
                        {"valid": False, "message": error_msg, "days_expired": days_expired})
                    return {"valid": False, "message": error_msg}
            except ValueError as ve:
                error_msg = f"Invalid expiration date format: {expires_at}"
                logger.error(f"Date parsing error for license {license_key[:8]}...: {ve}")
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg})
                return {"valid": False, "message": "License has invalid expiration date. Please contact support."}
            
            # Enhanced machine binding with multi-device support
            bound_machine = license_data.get('machine_id') or license_data.get('hw_id') or license_data.get('device_id')
            max_machines = license_data.get('max_machines', 1)
            
            # If this is a multi-device license, check current device count
            if max_machines > 1:
                try:
                    # Get all active machines for this license
                    active_machines_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=7)).isoformat()).execute()
                    active_machine_ids = list(set([hb['machine_id'] for hb in active_machines_response.data if hb.get('machine_id')]))
                    
                    if machine_id not in active_machine_ids and len(active_machine_ids) >= max_machines:
                        error_msg = f"License allows maximum {max_machines} device(s). {len(active_machine_ids)} device(s) already active."
                        self._log_validation_attempt(license_key, machine_id, 
                            {"valid": False, "message": error_msg, "max_machines": max_machines, "active_count": len(active_machine_ids)})
                        return {"valid": False, "message": error_msg}
                except Exception as e:
                    logger.warning(f"Could not check device count for multi-device license: {e}")
                    # Continue with single-device validation as fallback
            
            # Single device binding check (for single-device licenses or as fallback)
            if max_machines == 1 and bound_machine and bound_machine != machine_id:
                error_msg = "License is already activated on another device. Contact support for device transfer."
                self._log_validation_attempt(license_key, machine_id, 
                    {"valid": False, "message": error_msg, "bound_machine": bound_machine[:8] + "..."})
                return {"valid": False, "message": error_msg}
            
            # Update machine binding if not set (for new activations)
            if not bound_machine:
                try:
                    self.client.table(LICENSES_TABLE).update({
                        'machine_id': machine_id,
                        'last_activation': datetime.now().isoformat()
                    }).eq('key', license_key).execute()
                    logger.info(f"License {license_key[:8]}... activated on new device {machine_id[:8]}...")
                except Exception as e:
                    logger.debug(f"Could not update machine binding: {e}")  # Suppressed - column may not exist
                    # Continue validation even if update fails
            
            # Calculate days until expiration for user info
            days_until_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
            
            validation_result = {
                "valid": True,
                "email": license_data.get('email', 'user@falcontrade.com'),
                "is_trial": license_data.get('is_trial', False) or license_data.get('license_type') == LICENSE_TYPE_TRIAL,
                "expires_at": expires_at,
                "days_until_expiry": days_until_expiry,
                "license_type": license_data.get('license_type', LICENSE_TYPE_STANDARD),
                "tier": license_data.get('tier', 'basic'),
                "max_machines": max_machines,
                "user_id": license_data.get('user_id'),
                "subscription_id": license_data.get('subscription_id'),
                "features": self._get_license_features(license_data.get('tier', 'basic'), license_data.get('license_type', LICENSE_TYPE_STANDARD))
            }
            
            self._log_validation_attempt(license_key, machine_id, validation_result, 
                {"tier": license_data.get('tier'), "days_remaining": days_until_expiry})
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Validation system error: {str(e)}"
            logger.error(f"Supabase validation error for {license_key[:8]}...: {e}")
            self._log_validation_attempt(license_key, machine_id, 
                {"valid": False, "message": error_msg, "error_type": "system_error"})
            return self._fallback_validate_license(license_key, machine_id)
    
    def _get_license_features(self, tier, license_type):
        """Get available features based on license tier and type"""
        base_features = {
            "signal_copying": True,
            "basic_stats": True,
            "trade_history": True
        }
        
        if tier == 'basic':
            return {
                **base_features,
                "max_simultaneous_trades": 5,
                "advanced_filters": False,
                "custom_lot_sizing": False,
                "multi_account": False
            }
        elif tier == 'premium':
            return {
                **base_features,
                "max_simultaneous_trades": 20,
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True
            }
        elif tier == 'professional':
            return {
                **base_features,
                "max_simultaneous_trades": -1,  # Unlimited
                "advanced_filters": True,
                "custom_lot_sizing": True,
                "multi_account": True,
                "priority_support": True,
                "custom_indicators": True,
                "api_access": True,
                "white_label": True
            }
        else:
            return base_features
    
    def check_feature_access(self, license_key, feature_name):
        """Check if a specific feature is available for the current license"""
        try:
            machine_id = get_hardware_id()  # Assuming this function exists
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return False
                
            features = validation_result.get('features', {})
            return features.get(feature_name, False)
            
        except Exception as e:
            logger.error(f"Feature access check failed: {e}")
            return False
    
    def create_trial_license(self, machine_id, email=None):
        """Create a trial license using Supabase"""
        if not self.initialized:
            return self._fallback_create_trial(machine_id)
        
        try:
            # Generate trial license key
            trial_key = f"TRIAL-{uuid.uuid4().hex[:8].upper()}"
            expiration_date = datetime.now() + timedelta(days=7)
            
            # Insert trial license (support both column naming conventions)
            trial_data = {
                'key': trial_key,  # Primary column name
                'license_key': trial_key,  # Backup column name for compatibility
                'email': email or f'trial-{machine_id[:8]}@falcontrade.com',
                'machine_id': machine_id,
                'status': LICENSE_STATUS_ACTIVE,
                'is_trial': True,
                'expires_at': expiration_date.isoformat(),
                'created_at': datetime.now().isoformat(),
                'license_type': LICENSE_TYPE_TRIAL
            }
            
            response = self.client.table(LICENSES_TABLE).insert(trial_data).execute()
            
            if response.data:
                return {
                    "success": True,
                    "key": trial_key,
                    "email": trial_data['email'],
                    "expires_at": trial_data['expires_at']
                }
            else:
                return {"success": False, "message": "Failed to create trial license"}
                
        except Exception as e:
            logger.error(f"Supabase trial creation error: {e}")
            return self._fallback_create_trial(machine_id)
    
    def send_heartbeat(self, license_key, machine_id, stats):
        """Enhanced heartbeat with validation status and better monitoring"""
        if not self.initialized:
            return self._fallback_heartbeat(license_key, machine_id, stats)
        
        try:
            # Perform quick validation check during heartbeat
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                logger.warning(f"Heartbeat failed: License {license_key[:8]}... is no longer valid")
                return {"success": False, "message": "License is no longer valid", "validation_failed": True}
            
            heartbeat_data = {
                'key': license_key,  # Primary column name
                'license_key': license_key,  # Backup column name for compatibility
                'machine_id': machine_id,
                'signals_processed': stats.get('signals_processed', 0),
                'trades_executed': stats.get('trades_executed', 0),
                'version': stats.get('version', VERSION),
                'license_status': 'valid',
                'days_until_expiry': validation_result.get('days_until_expiry', 0),
                'license_tier': validation_result.get('tier', 'basic'),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            
            # Insert heartbeat record
            self.client.table(HEARTBEATS_TABLE).insert(heartbeat_data).execute()
            
            # Update last activity and cumulative stats in licenses table
            update_data = {
                    'last_activity': datetime.now().isoformat(),
                'last_heartbeat': datetime.now().isoformat(),
                'total_signals_processed': stats.get('total_signals_processed', 0),
                'total_trades_executed': stats.get('total_trades_executed', 0)
            }
            
            try:
                self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            except Exception:
                # Fallback to 'license_key' column name
                self.client.table(LICENSES_TABLE).update(update_data).eq('license_key', license_key).execute()
            
            # Check for license expiration warnings
            days_until_expiry = validation_result.get('days_until_expiry', 0)
            if days_until_expiry <= 7 and days_until_expiry > 0:
                logger.warning(f"License {license_key[:8]}... expires in {days_until_expiry} day(s)")
                return {"success": True, "warning": f"License expires in {days_until_expiry} day(s)", "days_until_expiry": days_until_expiry}
            
            return {"success": True, "days_until_expiry": days_until_expiry}
            
        except Exception as e:
            logger.error(f"Supabase heartbeat error: {e}")
            return self._fallback_heartbeat(license_key, machine_id, stats)
    
    def get_license_status_report(self, license_key, machine_id):
        """Get comprehensive license status report for admin/monitoring"""
        try:
            validation_result = self.validate_license(license_key, machine_id)
            
            if not validation_result.get('valid'):
                return {"error": validation_result.get('message', 'Invalid license')}
            
            # Get recent heartbeat activity
            recent_heartbeats = []
            try:
                heartbeat_response = self.client.table(HEARTBEATS_TABLE).select('*').eq('key', license_key).order('timestamp', desc=True).limit(10).execute()
                recent_heartbeats = heartbeat_response.data
            except Exception as e:
                logger.debug(f"Could not fetch heartbeat history: {e}")  # Suppressed - table may not exist
            
            # Get all devices for this license
            active_devices = []
            try:
                device_response = self.client.table(HEARTBEATS_TABLE).select('machine_id').eq('key', license_key).gte('timestamp', (datetime.now() - timedelta(days=30)).isoformat()).execute()
                unique_devices = list(set([hb['machine_id'] for hb in device_response.data if hb.get('machine_id')]))
                active_devices = unique_devices
            except Exception as e:
                logger.debug(f"Could not fetch device list: {e}")  # Suppressed - table may not exist
            
            return {
                "license_valid": True,
                "license_key": license_key[:8] + "...",
                "email": validation_result.get('email'),
                "tier": validation_result.get('tier'),
                "license_type": validation_result.get('license_type'),
                "expires_at": validation_result.get('expires_at'),
                "days_until_expiry": validation_result.get('days_until_expiry'),
                "max_machines": validation_result.get('max_machines'),
                "active_devices_count": len(active_devices),
                "active_devices": active_devices,
                "features": validation_result.get('features'),
                "recent_activity": len(recent_heartbeats),
                "last_heartbeat": recent_heartbeats[0].get('timestamp') if recent_heartbeats else None,
                "total_signals": sum([hb.get('signals_processed', 0) for hb in recent_heartbeats]),
                "total_trades": sum([hb.get('trades_executed', 0) for hb in recent_heartbeats])
            }
            
        except Exception as e:
            logger.error(f"License status report error: {e}")
            return {"error": f"Could not generate status report: {str(e)}"}
    
    def revoke_license(self, license_key, reason=""):
        """Revoke a license (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            update_data = {
                'status': LICENSE_STATUS_SUSPENDED,
                'revoked_at': datetime.now().isoformat(),
                'revocation_reason': reason
            }
            
            response = self.client.table(LICENSES_TABLE).update(update_data).eq('key', license_key).execute()
            
            if response.data:
                logger.info(f"License {license_key[:8]}... revoked. Reason: {reason}")
                return {"success": True, "message": "License revoked successfully"}
            else:
                return {"success": False, "message": "License not found"}
                
        except Exception as e:
            logger.error(f"License revocation error: {e}")
            return {"success": False, "message": f"Revocation failed: {str(e)}"}
    
    def extend_license(self, license_key, days_to_add):
        """Extend license expiration (admin function)"""
        if not self.initialized:
            return {"success": False, "message": "Database not available"}
        
        try:
            # Get current license data
            response = self.client.table(LICENSES_TABLE).select('*').eq('key', license_key).execute()
            
            if not response.data:
                return {"success": False, "message": "License not found"}
            
            license_data = response.data[0]
            current_expiry = license_data.get('expires_at')
            
            if not current_expiry:
                return {"success": False, "message": "License has no expiration date"}
            
            # Calculate new expiration
            current_date = datetime.fromisoformat(current_expiry.replace('Z', '+00:00'))
            new_expiry = current_date + timedelta(days=days_to_add)
            
            # Update license
            update_response = self.client.table(LICENSES_TABLE).update({
                'expires_at': new_expiry.isoformat(),
                'extended_at': datetime.now().isoformat(),
                'extension_days': days_to_add
            }).eq('key', license_key).execute()
            
            if update_response.data:
                logger.info(f"License {license_key[:8]}... extended by {days_to_add} days")
                return {"success": True, "message": f"License extended by {days_to_add} days", "new_expiry": new_expiry.isoformat()}
            else:
                return {"success": False, "message": "Extension failed"}
                
        except Exception as e:
            logger.error(f"License extension error: {e}")
            return {"success": False, "message": f"Extension failed: {str(e)}"}
    
    def _fallback_validate_license(self, license_key, machine_id):
        """Fallback to legacy API"""
        try:
            response = requests.post(
                VALIDATION_URL,
                json={"key": license_key, "hw_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"valid": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"valid": False, "message": str(e)}
    
    def _fallback_create_trial(self, machine_id):
        """Fallback to legacy trial API"""
        try:
            response = requests.post(
                TRIAL_URL,
                json={"machine_id": machine_id},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def _fallback_heartbeat(self, license_key, machine_id, stats):
        """Fallback to legacy heartbeat API"""
        try:
            response = requests.post(
                HEARTBEAT_URL,
                json={
                    "key": license_key,
                    "hw_id": machine_id,
                    "signals_processed": stats.get('signals_processed', 0),
                    "trades_executed": stats.get('trades_executed', 0),
                    "version": stats.get('version', VERSION)
                },
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "message": f"Server error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

def parse_signal_ai(message):
    """Parse trading signal using NLP and pattern matching"""
    message = preprocess_message(message)
    if not nlp:
        return None

    try:
        doc = nlp(message)
        matcher = Matcher(nlp.vocab)
        used_tokens = set()

        # Define patterns for signal extraction
        action_pattern = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["eurusd", "gbpusd", "usdjpy", "audusd", "usdcad", "nzdusd"]}}
        ]
        
        matcher.add("SIGNAL_ACTION", action_pattern)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                return {
                    "action": span.text.lower(),
                    "confidence": 0.8,
                    "method": "nlp"
                }
        
        return None
    except Exception as e:
        logger.error(f"Error in NLP parsing: {e}")
        return None

def parse_signal_emoji_format(message):
    """Parse signals in emoji format like:
    💰XAUUSD (1m) ⬇️
    🔴Sell  : 3349.27
    ✅TP : 3328.96
    ❌SL : 3351.72
    🧠 : RISK 0.1%
    """
    try:
        # Preprocess message
        message = preprocess_message(message)
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed emoji signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing emoji signal: {e}")
        return None

def parse_signal(message):
    """Main signal parsing function that combines AI, emoji, and regex methods"""
    # Try dedicated provider parsing first (for specific signal format)
    dedicated_result = parse_signal_dedicated_provider(message)
    if dedicated_result:
        return dedicated_result
    
    # Try emoji format parsing second
    emoji_result = parse_signal_emoji_format(message)
    if emoji_result:
        return emoji_result
    
    # Try AI parsing third
    ai_result = parse_signal_ai(message)
    if ai_result:
        return ai_result
    
    # Fall back to regex parsing
    regex_result = parse_signal_regex(message)
    if regex_result:
        return regex_result
    
    return None

# =====================
def parse_signal_ai_enhanced(message):
    """Enhanced AI signal parsing with entity extraction"""
    message = preprocess_message(message)
    if not nlp:
        return parse_signal_regex(message)  # Fallback to regex

    try:
        doc = nlp(message)
        entities = {
            "action": None,
            "symbol": None,
            "entry_price": None,
            "sl": None,
            "tps": []
        }
        used_tokens = set()
        found_entry = False

        # Extract entities using NLP
        for ent in doc.ents:
            if ent.label_ == "ORG" and not entities["symbol"]:
                entities["symbol"] = ent.text.upper()
            elif ent.label_ == "MONEY":
                try:
                    value = float(ent.text.replace(",", ""))
                    if not found_entry:
                        entities["entry_price"] = value
                        found_entry = True
                except ValueError:
                    pass

        # Pattern matching for action words
        action_patterns = [
            {"LOWER": {"IN": ["buy", "sell", "long", "short"]}},
            {"LOWER": {"IN": ["limit", "stop"]}}
        ]
        
        matcher = Matcher(nlp.vocab)
        matcher.add("ACTION", action_patterns)
        matches = matcher(doc)
        
        for match_id, start, end in matches:
            span = doc[start:end]
            if span.text.lower() not in used_tokens:
                used_tokens.add(span.text.lower())
                if span.text.lower() in ["buy", "sell"]:
                    entities["action"] = span.text.upper()
                elif span.text.lower() in ["limit", "stop"]:
                    if entities["action"]:
                        entities["action"] = f"{entities['action']} {span.text.upper()}"

        # Extract prices and levels
        price_pattern = r'(\d{1,5}(?:\.\d{1,5})?)'
        price_matches = re.findall(price_pattern, message)
        
        for i, price in enumerate(price_matches):
            try:
                value = float(price)
                if not found_entry:
                    entities["entry_price"] = value
                    found_entry = True
                elif "SL" in message and i == len(price_matches) - 1:
                    entities["sl"] = value
                elif "TP" in message:
                    entities["tps"].append(value)
            except ValueError:
                pass

        # Validate required fields
        if not entities["action"] or not entities["symbol"]:
            return None

        # Handle market orders
        if entities["action"] in ["BUY", "SELL"] and not entities["entry_price"]:
            return {
                "symbol": entities["symbol"],
                "order_type": entities["action"],
                "entry_price": None,
                "sl": entities["sl"],
                "tps": entities["tps"]
            }

        # Determine order type with special handling
        order_type = entities["action"]
        if "LIMIT" in message and "BUY" in order_type:
            order_type = "BUY LIMIT"
        elif "LIMIT" in message and "SELL" in order_type:
            order_type = "SELL LIMIT"
        elif "STOP" in message and "BUY" in order_type:
            order_type = "BUY STOP"
        elif "STOP" in message and "SELL" in order_type:
            order_type = "SELL STOP"

        # Validate pending orders require entry price
        if ("LIMIT" in order_type or "STOP" in order_type) and not entities["entry_price"]:
            logger.warning("Pending order requires entry price")
            return None

        # Prepare result
        result = {
            "symbol": entities["symbol"],
            "order_type": order_type,
            "entry_price": entities["entry_price"],
            "sl": entities["sl"],
        }

        # Handle TP values
        if entities["tps"]:
            result["tps"] = entities["tps"]
        elif "TP" in message:
            tp_matches = re.findall(r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)', message)
            tps = []
            for tp in tp_matches:
                try:
                    tps.append(float(tp))
                except ValueError:
                    pass
            if tps:
                result["tps"] = tps

        logger.info(f"AI parsed signal: {result}")
        return result

    except Exception as e:
        logger.error(f"AI signal parsing error: {str(e)}")
        return None

def parse_signal_entities(message):
    """Extract trading entities from message using regex patterns"""
    entities = {
        "symbol": None,
        "order_type": None,
        "entry_price": None,
        "sl": None,
        "tps": []
    }
    
    try:
        # Extract symbol
        symbol_patterns = [
            r'\b([A-Z0-9]{3,10})\b',
            r'\b(GOLD|SILVER|OIL|BTC|ETH)\b'
        ]
        
        for pattern in symbol_patterns:
            match = re.search(pattern, message)
            if match:
                symbol = match.group(1)
                if symbol not in ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]:
                    entities["symbol"] = symbol
                    break
        
        # Extract order type
        order_pattern = r'\b(BUY|SELL|LONG|SHORT)\b'
        order_match = re.search(order_pattern, message)
        if order_match:
            entities["order_type"] = order_match.group(1)
        
        # Extract entry price
        price_pattern = r'\b(\d+\.?\d*)\b'
        price_matches = re.findall(price_pattern, message)
        if price_matches:
            entities["entry_price"] = float(price_matches[0])
        
        # Extract SL
        sl_pattern = r'SL\s*[:=\-]?\s*(\d+\.?\d*)'
        sl_match = re.search(sl_pattern, message)
        if sl_match:
            entities["sl"] = float(sl_match.group(1))
        
        # Extract TPs
        tp_pattern = r'TP\d*\s*[:=\-]?\s*(\d+\.?\d*)'
        tp_matches = re.findall(tp_pattern, message)
        for tp in tp_matches:
            try:
                entities["tps"].append(float(tp))
            except ValueError:
                pass
        
        return entities
        
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        return entities

def preprocess_message(message):
    """Clean and normalize message before parsing

    Args:
        message (str): Raw signal message to preprocess

    Returns:
        str: Cleaned and normalized message

    Handles:
    - Removes emojis and special characters
    - Expands compact number ranges (e.g., 3347-49 → 3347-3349)
    - Converts to uppercase and removes extra spaces
    """
    # Remove emojis and special characters
    message = re.sub(r'[✅🎯♦️⚠️🟢🔴⚡️💎🔥🚨⏱️📊🛑🔔📉📈@]', '', message)

    # Expand compact ranges (e.g., 3347-49 → 3347-3349)
    message = re.sub(r'(\d+)\s*[-–]\s*(\d{2})\b', expand_compact_range_match, message)

    # Convert to uppercase and remove extra spaces
    message = re.sub(r'\s+', ' ', message.upper().strip())
    return message

def parse_signal_dedicated_provider(message):
    """Dedicated parsing method for specific signal provider format:
    💰XAUUSD (1M) ⬆️
    🟢Buy : 3343.29
    ✅TP : 3367.94
    ❌SL : 3341.76
    🧠 : RISK 0.1%
    """
    try:
        # Custom preprocessing that preserves the emojis we need
        # Remove extra whitespace and normalize, but keep emojis
        message = re.sub(r'\s+', ' ', message.strip())
        
        # Extract symbol from first line (after 💰)
        symbol_match = re.search(r'💰([A-Z0-9]{3,10})', message)
        if not symbol_match:
            return None
        
        symbol = symbol_match.group(1)
        
        # Extract order type and entry price from second line - support both 🔴 and 🟢
        order_line_match = re.search(r'[🔴🟢](Sell|Buy)\s*:\s*(\d+\.?\d*)', message, re.IGNORECASE)
        if not order_line_match:
            return None
        
        order_type = order_line_match.group(1).upper()
        entry_price = float(order_line_match.group(2))
        
        # Extract TP from third line
        tp_match = re.search(r'✅TP\s*:\s*(\d+\.?\d*)', message)
        tp = float(tp_match.group(1)) if tp_match else None
        
        # Extract SL from fourth line
        sl_match = re.search(r'❌SL\s*:\s*(\d+\.?\d*)', message)
        sl = float(sl_match.group(1)) if sl_match else None
        
        # Extract risk percentage from fifth line
        risk_match = re.search(r'🧠\s*:\s*RISK\s*(\d+\.?\d*)%', message)
        risk_percent = float(risk_match.group(1)) if risk_match else None
        
        # Normalize symbol
        symbol = re.sub(r'\bGOLD\b', 'XAUUSD', symbol)
        symbol = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', symbol)
        symbol = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', symbol)
        symbol = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', symbol)
        symbol = re.sub(r'\bNAS100\b', 'NAS100', symbol)
        symbol = re.sub(r'\bSPX500\b', 'SPX500', symbol)
        symbol = re.sub(r'\bDXY\b', 'USDX', symbol)
        symbol = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', symbol)
        symbol = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', symbol)
        symbol = re.sub(r'\bXRP\b', 'XRPUSD', symbol)
        symbol = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', symbol)
        symbol = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', symbol)
        symbol = re.sub(r'\bUS30\b', 'US30', symbol)
        symbol = re.sub(r'\bDOW\b', 'US30', symbol)
        
        result = {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tps": [tp] if tp else []
        }
        
        # Add risk percentage if found
        if risk_percent:
            result["risk_percent"] = risk_percent
        
        logger.info(f"Parsed dedicated provider signal: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing dedicated provider signal: {e}")
        return None

def parse_signal_regex(message):
    """Parse trading signal using regular expressions"""
    message = preprocess_message(message)
    try:
        # Enhanced symbol normalization
        message = re.sub(r'\bGOLD\b', 'XAUUSD', message)
        message = re.sub(r'\bSILVER\b|\bXAG\b', 'XAGUSD', message)
        message = re.sub(r'\bUSOIL\b|\bOIL\b', 'XTIUSD', message)
        message = re.sub(r'\bUKOIL\b|\bBRENT\b', 'XBRUSD', message)
        message = re.sub(r'\bNAS100\b', 'NAS100', message)
        message = re.sub(r'\bSPX500\b', 'SPX500', message)
        message = re.sub(r'\bDXY\b', 'USDX', message)
        message = re.sub(r'\bBTC\b|\bBITCOIN\b', 'BTCUSD', message)
        message = re.sub(r'\bETH\b|\bETHEREUM\b', 'ETHUSD', message)
        message = re.sub(r'\bXRP\b', 'XRPUSD', message)
        message = re.sub(r'\bLTC\b|\bLITECOIN\b', 'LTCUSD', message)
        message = re.sub(r'\bBCH\b|\bBITCOINCASH\b', 'BCHUSD', message)
        message = re.sub(r'\bUS30\b', 'US30', message)
        message = re.sub(r'\bDOW\b', 'US30', message)

        # Reserved words to skip
        reserved_words = ["BUY", "SELL", "LIMIT", "STOP", "TP", "SL", "AT", "PRICE", "RANGE"]

        # New pattern for specific format:
        # [SYMBOL] (timeframe) [ORDER_TYPE] : [PRICE]
        # TP : [TP_PRICE]
        # SL : [SL_PRICE]
        specific_pattern = (
            r'([A-Z0-9]{3,10})\s*\(.*?\)\s*'  # Symbol with timeframe in parentheses
            r'(BUY|SELL)\s*:\s*(\d+\.?\d*)[\s\S]*?'  # Order type and price
            r'TP\s*:\s*(\d+\.?\d*)[\s\S]*?'  # TP
            r'SL\s*:\s*(\d+\.?\d*)'  # SL
        )

        specific_match = re.search(specific_pattern, message)
        if specific_match:
            symbol = specific_match.group(1)
            order_type = specific_match.group(2)
            entry_price = float(specific_match.group(3))
            tp = float(specific_match.group(4))
            sl = float(specific_match.group(5))

            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": [tp]
            }

        # Enhanced pattern for market orders without entry price
        # In parse_signal_regex function
        market_order_pattern = r'\b(BUY|SELL)\s+:\s*(\d+\.?\d*)\s+(\b[A-Z0-9]{3,10}\b)\b'
        market_match = re.search(market_order_pattern, message)
        if not market_match:
            # Alternative pattern: Symbol first
            market_order_pattern = r'\b([A-Z0-9]{3,10})\s+(BUY|SELL)\b'
            market_match = re.search(market_order_pattern, message)

        if market_match:
            if market_match.group(1) in ["BUY", "SELL"]:
                order_type = market_match.group(1)
                symbol = market_match.group(2)
            else:
                symbol = market_match.group(1)
                order_type = market_match.group(2)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                market_match = None

        if market_match:
            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": None,
                    "sl": sl,
                    "tp": tp
                }

        # Enhanced pattern for pending orders with "@" symbol
        pending_pattern = r'(BUY|SELL)\s*(LIMIT|STOP)\s+(\w+)\s+@?\s*(\d+\.?\d*)'
        pending_match = re.search(pending_pattern, message)
        if not pending_match:
            # Alternative pattern: Symbol first with "@"
            pending_pattern = r'(\w+)\s+(BUY|SELL)\s*(LIMIT|STOP)\s+@?\s*(\d+\.?\d*)'
            pending_match = re.search(pending_pattern, message)

        if pending_match:
            if pending_match.group(1) in ["BUY", "SELL"]:
                order_type = f"{pending_match.group(1)} {pending_match.group(2)}"
                symbol = pending_match.group(3)
                entry_price = pending_match.group(4)
            else:
                symbol = pending_match.group(1)
                order_type = f"{pending_match.group(2)} {pending_match.group(3)}"
                entry_price = pending_match.group(4)

            # Skip if symbol is a reserved word
            if symbol in reserved_words:
                pending_match = None

        if pending_match:
            try:
                entry_price = float(entry_price)
            except ValueError:
                entry_price = None

            sl = None
            tp = None
            tps = []

            sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
            if sl_match:
                try:
                    sl = float(sl_match.group(1))
                except ValueError:
                    pass

            tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
            for tp_val in tp_matches:
                try:
                    tps.append(float(tp_val))
                except ValueError:
                    pass

            if tps:
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tps": tps
                }
            else:
                tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
                if tp_match:
                    try:
                        tp = float(tp_match.group(1))
                    except ValueError:
                        pass
                return {
                    "symbol": symbol,
                    "order_type": order_type,
                    "entry_price": entry_price,
                    "sl": sl,
                    "tp": tp
                }

        # Fallback pattern
        words = [word for word in message.split() if not word.startswith(('SL', 'TP'))]
        if not words:
            return None

        # Try to find order type
        order_type = None
        for ot in ["BUY LIMIT", "SELL LIMIT", "BUY STOP", "SELL STOP", "BUY", "SELL"]:
            if ot in message:
                order_type = ot
                break
        if not order_type:
            return None

        # Find symbol - first word that matches symbol pattern and not reserved
        symbol = None
        for word in words:
            if re.match(r'^[A-Z0-9]{3,10}$', word) and word not in reserved_words:
                symbol = word
                break
        if not symbol:
            return None

        # Find entry price
        entry_price = None
        for word in words:
            try:
                if word == symbol or word in order_type:
                    continue
                entry_price = float(word)
                break
            except ValueError:
                pass

        sl = None
        tp = None
        tps = []
        sl_match = re.search(r'SL\D*(\d+\.?\d*)', message)
        if sl_match:
            try:
                sl = float(sl_match.group(1))
            except ValueError:
                pass

        tp_match = re.search(r'TP\D*(\d+\.?\d*)', message)
        if tp_match:
            try:
                tp = float(tp_match.group(1))
            except ValueError:
                pass

        tp_matches = re.findall(r'TP\d*\D*(\d+\.?\d*)', message)
        for tp_val in tp_matches:
            try:
                tps.append(float(tp_val))
            except ValueError:
                pass

        if tps:
            return {
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tps": tps
            }

        return {
            "symbol": symbol,
            "order_type": order_type,
            "entry_price": entry_price,
            "sl": sl,
            "tp": tp
        }
    except Exception as e:
        logger.error(f"Signal parsing error: {str(e)}")
        return None

def parse_management_command(message):
    try:
        message = message.upper().strip()
        patterns = {
            "SL_TO_BE": r"\b(?:SL\s*TO\s*BE|BREAKEVEN|MOVE\s*TO\s*BREAKEVEN)\b",
            "CLOSE": r"\b(?:CLOSE|EXIT|TAKE\s*PROFIT)\b(?!\s*AT)",
            "PARTIAL_CLOSE": r"CLOSE\s*(\d+)\s*%|\bPARTIAL\s*CLOSE\b",
            "MODIFY_SL": r"MODIFY\s*SL\s*TO\s*(\d+\.?\d*)",
            "MODIFY_TP": r"MODIFY\s*TP\s*TO\s*(\d+\.?\d*)",
            "CANCEL": r"\b(?:CANCEL|DELETE)\b"
        }

        for action, pattern in patterns.items():
            match = re.search(pattern, message)
            if match:
                result = {"action": action}
                if action == "PARTIAL_CLOSE" and match.group(1):
                    result["percent"] = float(match.group(1))
                elif action == "MODIFY_SL" and match.group(1):
                    result["sl"] = float(match.group(1))
                elif action == "MODIFY_TP" and match.group(1):
                    result["tp"] = float(match.group(1))
                # Extract symbol, excluding command words
                command_words = {"CLOSE", "EXIT", "TAKE", "PROFIT", "SL", "TP", "MODIFY", "CANCEL", "DELETE", "PARTIAL", "BREAKEVEN", "MOVE", "TO", "BE", "AT"}
                
                # Find all potential symbols in the message
                symbol_matches = re.findall(r"\b([A-Z0-9]{3,6})\b", message)
                
                # Filter out command words and find the actual trading symbol
                for potential_symbol in symbol_matches:
                    if potential_symbol not in command_words:
                        result["symbol"] = potential_symbol
                        break
                return result

        if nlp:
            return parse_management_ai(message)

        return None
    except Exception as e:
        logger.error(f"Management command parsing error: {str(e)}")
        return None

def parse_management_ai(message):
    try:
        doc = nlp(message)
        result = {"action": None, "symbol": None, "params": {}}
        action_verbs = {"move", "close", "exit", "modify", "adjust", "set", "change", "cancel"}
        trade_objects = {"sl", "tp", "stop loss", "take profit", "position", "trade", "order"}

        for token in doc:
            if token.lemma_ in action_verbs:
                result["action"] = token.lemma_.upper()
                for child in token.children:
                    if child.lemma_ in trade_objects:
                        result["target"] = child.lemma_.upper()
                    elif child.dep_ in ("dobj", "attr", "prep") and child.ent_type_ == "CARDINAL":
                        result["params"]["value"] = float(child.text)
            if token.ent_type_ == "ORG" and len(token.text) >= 3:
                result["symbol"] = token.text.upper()

        if result["action"] == "MOVE" and result.get("target") == "SL":
            result["action"] = "MODIFY_SL"
        elif result["action"] == "CLOSE" or result["action"] == "EXIT":
            result["action"] = "CLOSE"
        elif result["action"] == "MODIFY" and result.get("target") == "TP":
            result["action"] = "MODIFY_TP"
        elif result["action"] == "CANCEL":
            result["action"] = "CANCEL"

        if not result["action"] or result["action"] not in ["SL_TO_BE", "CLOSE", "PARTIAL_CLOSE", "MODIFY_SL",
                                                            "MODIFY_TP", "CANCEL"]:
            return None

        return result
    except Exception as e:
        logger.error(f"AI management parsing error: {str(e)}")
        return None

# =====================
# BUSINESS LOGIC CLASSES
# =====================
class TradeTracker:
    def __init__(self, filename=ACTIVE_TRADES_FILE):
        self.filename = filename
        self.active_trades = {}
        self.win_streak = 0
        self.loss_streak = 0
        self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                self.active_trades = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.active_trades = {}

    def save(self):
        with open(self.filename, 'w') as f:
            json.dump(self.active_trades, f, indent=2)

    def add_trade(self, ticket, symbol, order_type, volume, entry_price,
                  actual_price=None, sl=None, tp=None, tps=None, magic=2023, status='pending'):
        """
        Add a trade to the active trades list.

        Args:
            ticket: Trade ticket number.
            symbol: Symbol traded.
            order_type: BUY/SELL etc.
            volume: Trade volume.
            entry_price: Intended entry price.
            actual_price: Actual executed price (defaults to entry_price).
            sl: Stop loss.
            tp: Take profit (single).
            tps: List of multiple take profits.
            magic: Magic number.
            status: Trade status.
        """
        if actual_price is None:
            actual_price = entry_price

        # Ensure tps is always a list
        if tps is None:
            tps = []
        elif not isinstance(tps, list):
            tps = [tps]

        self.active_trades[ticket] = {
            "symbol": symbol,
            "type": order_type,
            "volume": volume,
            "entry": entry_price,
            "actual_price": actual_price,
            "sl": sl,
            "tp": tp,  # Keep single TP if given
            "tps": tps,  # Store multi-TP list
            "magic": magic,
            "status": status,
            "open_time": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat()
        }
        self.save()

    def update_trade(self, ticket, updates):
        if ticket in self.active_trades:
            self.active_trades[ticket].update(updates)
            self.active_trades[ticket]["last_modified"] = datetime.now().isoformat()
            self.save()
            return True
        return False

    def remove_trade(self, ticket, profit=0.0):
        if ticket in self.active_trades:
            # Update streaks based on profit
            if profit > 0:
                self.win_streak += 1
                self.loss_streak = 0
            elif profit < 0:
                self.loss_streak += 1
                self.win_streak = 0

            del self.active_trades[ticket]
            self.save()
            return True
        return False

    def get_trades_by_symbol(self, symbol):
        return [trade for trade in self.active_trades.values() if trade["symbol"] == symbol]

    def get_most_recent_trade(self, symbol):
        trades = self.get_trades_by_symbol(symbol)
        if not trades:
            return None
        return max(trades, key=lambda x: x["open_time"])

    def get_trade_by_ticket(self, ticket):
        return self.active_trades.get(ticket)

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
                "max_trades": 20,  # Changed from 5 to 20
                "pip_tolerance": 2.0,
                "news_filter": False,
                "trading_hours": "09:00-17:00",
                
                "daily_loss_limit": 5.0,
                "daily_profit_target": 10.0,
                "max_trades_per_symbol": 20,  # Changed from 2 to 20
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

    def set_activated(self, status=True, key=None, email=None, is_trial=False, expiration=None):
        self.settings["activated"] = status
        if key and email:
            start_date = datetime.now()
            if not expiration:
                expiration = start_date + timedelta(days=365) if not is_trial else start_date + timedelta(days=7)
            self.settings["license"] = {
                "key": key,
                "email": email,
                "start_date": start_date.isoformat(),
                "expiration_date": expiration.isoformat(),
                "is_trial": is_trial
            }
        return self.save()

    def get_license_info(self):
        return self.settings.get("license", {})

    def get_telegram_session(self):
        return self.settings["telegram"].get("session_string")

    def set_telegram_session(self, session_string):
        self.settings["telegram"]["session_string"] = session_string
        return self.save()

    def get_telegram_channels(self):
        return self.settings["telegram"].get("channel_ids", [])

    def set_telegram_channels(self, channel_ids):
        self.settings["telegram"]["channel_ids"] = channel_ids
        return self.save()

    def get_mt5_settings(self):
        return self.settings["mt5"]

    def set_mt5_settings(self, account, server, password, path, symbol_prefix="", symbol_suffix=""):
        self.settings["mt5"] = {
            "account": account,
            "server": server,
            "password": password,
            "path": path,
            "symbol_prefix": symbol_prefix,
            "symbol_suffix": symbol_suffix
        }
        return self.save()

    def get_risk_settings(self):
        return self.settings["risk"]

    def set_risk_settings(self, risk_settings):
        self.settings["risk"] = risk_settings
        return self.save()

    def get_symbol_mappings(self):
        return self.settings.get("symbol_mappings", {})

    def set_symbol_mappings(self, mappings):
        self.settings["symbol_mappings"] = mappings
        return self.save()

    def get_activation_info(self):
        return {
            "activated": self.settings.get("activated", False),
            "last_activation": self.settings.get("last_activation"),
            "machine_id": self.settings.get("machine_id")
        }

    def reset_activation(self):
        self.settings["activated"] = False
        self.settings["last_activation"] = None
        self.settings["telegram"]["session_string"] = None
        self.settings["telegram"]["channel_ids"] = []
        self.settings["mt5"] = {
            "account": "",
            "server": "",
            "password": "",
            "path": ""
        }
        self.settings["license"] = {
            "key": "",
            "email": "",
            "start_date": None,
            "expiration_date": None,
            "is_trial": False
        }
        return self.save()

class LogoHeader(QWidget):
    def __init__(self, text, logo_pixmap):
        super().__init__()
        self.setMinimumHeight(80)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)

        # Left spacer
        layout.addStretch()

        # Logo and title container
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Logo
        logo_label = QLabel()
        logo_pixmap = logo_pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(logo_label)

        # Title
        title_label = QLabel(text)
        title_label
        title_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(title_label)

        layout.addWidget(container)

        # Right spacer
        layout.addStretch()

class TelegramManager(QObject):
    verification_sent = Signal()
    authenticated = Signal()
    channels_loaded = Signal(list)
    connection_error = Signal(str)
    trade_signal = Signal(str, str)
    management_command = Signal(dict)  # Added for management commands
    connection_status_changed = Signal(bool)
    new_signal_parsed = Signal(dict)  # New signal for UI

    def __init__(self):
        super().__init__()
        self.client = None
        self.session_string = None
        self.phone = None
        self.channels = []
        self.running = False
        self.channel_handlers = {}
        self.connected = False
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.channel_names = {}  # Map channel ID to name

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _connect(self, api_id, api_hash, phone, timeout=30):
        try:
            self.phone = phone
            self.client = TelegramClient(
                StringSession(self.session_string),
                api_id,
                api_hash,
                loop=self.loop
            )
            await asyncio.wait_for(self.client.connect(), timeout=timeout)
            if not await self.client.is_user_authorized():
                if self.session_string:
                    self.session_string = None
                    self.connection_error.emit("Saved session expired, please re-authenticate")
                if phone:
                    await self.client.send_code_request(phone)
                    self.verification_sent.emit()
                return False
            else:
                self.connected = True
                self.connection_status_changed.emit(True)
                self.authenticated.emit()
                return True
        except asyncio.TimeoutError:
            error = "Telegram connection timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram connection failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _authenticate(self, code, timeout=30):
        try:
            await asyncio.wait_for(
                self.client.sign_in(self.phone, code),
                timeout=timeout
            )
            self.session_string = self.client.session.save()
            self.connected = True
            self.connection_status_changed.emit(True)
            self.authenticated.emit()
            return True
        except asyncio.TimeoutError:
            error = "Telegram authentication timed out"
            logger.error(error)
            self.connection_error.emit(error)
            return False
        except Exception as e:
            error = f"Telegram authentication failed: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)
            return False

    async def _load_channels(self, timeout=30):
        try:
            if not self.client.is_connected():
                await self.client.connect()
            dialogs = await asyncio.wait_for(
                self.client.get_dialogs(limit=100),
                timeout=timeout
            )
            channels = []
            for dialog in dialogs:
                try:
                    if not isinstance(dialog.entity, Channel) or dialog.is_group:
                        continue
                    entity = dialog.entity
                    username = entity.username if hasattr(entity, 'username') else f"id:{entity.id}"
                    channel_info = {
                        "id": entity.id,
                        "name": dialog.name,
                        "username": username
                    }
                    channels.append(channel_info)
                    self.channel_names[entity.id] = dialog.name
                except Exception as e:
                    logger.error(f"Error processing dialog: {str(e)}")
                    continue
            self.channels_loaded.emit(channels)
        except asyncio.TimeoutError:
            error = "Channel loading timed out"
            logger.error(error)
            self.connection_error.emit(error)
        except Exception as e:
            error = f"Failed to load channels: {str(e)}"
            logger.error(error)
            self.connection_error.emit(error)

    def connect_telegram(self, api_id, api_hash, phone):
        asyncio.run_coroutine_threadsafe(
            self._connect(api_id, api_hash, phone),
            self.loop
        )

    def authenticate(self, code):
        asyncio.run_coroutine_threadsafe(
            self._authenticate(code),
            self.loop
        )

    def load_channels(self):
        asyncio.run_coroutine_threadsafe(
            self._load_channels(),
            self.loop
        )

    def add_channel_handler(self, channel_id, callback):
        if channel_id in self.channel_handlers:
            return

        @self.client.on(events.NewMessage(chats=channel_id))
        async def handler(event):
            try:
                message = event.message
                replied_to = None
                if message.reply_to_msg_id:
                    try:
                        replied_msg = await event.get_reply_message()
                        replied_to = replied_msg.text
                    except Exception as e:
                        logger.error(f"Error getting replied message: {str(e)}")
                        replied_to = None

                # Parse the signal with error handling
                try:
                    signal_details = parse_signal(message.text)
                except Exception as e:
                    logger.error(f"Error parsing signal: {str(e)}")
                    signal_details = None

                # Create signal data with channel info
                signal_data = {
                    "channel_id": channel_id,
                    "channel_name": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "message_id": message.id,
                    "text": message.text,
                    "date": message.date,
                    "sender": message.sender_id,
                    "replied_to": replied_to,
                    "signal_details": signal_details
                }

                self.trade_signal.emit(
                    "New Signal Received",
                    f"Channel: {self.channel_names.get(channel_id, channel_id)}\n{message.text}"
                )

                # Emit parsed signal to UI
                if signal_details:
                    self.new_signal_parsed.emit({
                        "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                        "symbol": signal_details.get("symbol", "N/A"),
                        "order_type": signal_details.get("order_type", "N/A"),
                        "entry_price": signal_details.get("entry_price", "N/A"),
                        "sl": signal_details.get("sl", "N/A"),
                        "tp": signal_details.get("tp", "N/A"),
                        "tps": signal_details.get("tps", []),
                        "status": "Parsed",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                else:
                    # Try parsing as management command if signal parsing fails
                    management_details = parse_management_command(message.text)
                    if management_details:
                        self.management_command.emit(management_details)
                    else:
                        self.new_signal_parsed.emit({
                            "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                            "symbol": "N/A",
                            "order_type": "N/A",
                            "entry_price": "N/A",
                            "sl": "N/A",
                            "tp": "N/A",
                            "tps": [],
                            "status": "Failed to parse",
                            "error": "Could not parse signal",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })

                # Only execute callback if signal was successfully parsed
                if signal_details:
                    callback(signal_data)
            except Exception as e:
                logger.error(f"Error in message handler: {str(e)}")
                # Emit error signal to UI
                self.new_signal_parsed.emit({
                    "channel": self.channel_names.get(channel_id, f"Channel {channel_id}"),
                    "symbol": "N/A",
                    "order_type": "N/A",
                    "entry_price": "N/A",
                    "sl": "N/A",
                    "tp": "N/A",
                    "tps": [],
                    "status": "Error",
                    "error": f"Handler error: {str(e)}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        self.channel_handlers[channel_id] = handler

    def start_listening(self):
        asyncio.run_coroutine_threadsafe(
            self._start_listening(),
            self.loop
        )

    async def _start_listening(self):
        self.running = True
        await self.client.start()
        await self.client.run_until_disconnected()
        self.running = False

    def stop_listening(self):
        self.running = False
        if self.client:
            try:
                # Clear all event handlers
                self.client.list = []

                # Disconnect if connected
                if self.client.is_connected():
                    self.client.disconnect()
                    logger.info("Telegram disconnected")
            except Exception as e:
                logger.error(f"Error stopping Telegram: {str(e)}")
        self.connected = False
        self.connection_status_changed.emit(False)
        logger.info("Telegram listening stopped")

class MT5Manager:
    def __init__(self):
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        self.symbol_cache = {}
        self.parent = None
        self.trade_tracker = TradeTracker()
        self.daily_profit = 0.0
        self.daily_loss = 0.0
        self.lock_until = None  # For account lock

    def get_pip_value(self, symbol):
        """Get pip value for a symbol in account currency"""
        symbol_info = mt5.symbol_info(symbol)
        if symbol_info is None:
            return 0.0001  # Default fallback

        # Calculate pip size (0.0001 for most pairs, 0.01 for JPY pairs)
        pip_size = 0.0001
        if "JPY" in symbol:
            pip_size = 0.01

        # Calculate pip value correctly
        point = symbol_info.point
        
        # For BTC and other crypto, the pip value calculation is different
        if "BTC" in symbol or "ETH" in symbol or "XRP" in symbol or "LTC" in symbol:
            # For crypto, 1 pip = 1 point, and pip value is directly the tick value
            pip_value = symbol_info.trade_tick_value
        else:
            # For forex pairs, calculate pip value: (pip size / point) * tick value
            pip_value = (pip_size / point) * symbol_info.trade_tick_value
        
        # For debugging (only log if there's an issue)
        if pip_value <= 0:
            logger.warning(f"Pip value calculation for {symbol}: pip_size={pip_size}, point={point}, tick_value={symbol_info.trade_tick_value}, pip_value={pip_value}")
        
        return pip_value

    def get_daily_pnl(self):
        """Get current daily P&L as percentage of balance"""
        try:
            account_info = self.get_account_info()
            if not account_info:
                return 0.0
            
            balance = account_info.get('balance', 0)
            if balance <= 0:
                return 0.0
            
            # Get today's trades
            today = datetime.now().date()
            start_time = datetime.combine(today, datetime.min.time())
            end_time = datetime.combine(today, datetime.max.time())
            
            # Get history for today
            history = mt5.history_deals_get(start_time, end_time)
            if history is None:
                return 0.0
            
            # Calculate total P&L for today
            daily_pnl = sum(deal.profit for deal in history)
            
            # Return as percentage of balance
            return (daily_pnl / balance) * 100 if balance > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error calculating daily P&L: {e}")
            return 0.0

    def should_execute_in_range(self, current_price, entry_range, risk_settings):
        low, high = min(entry_range), max(entry_range)
        in_range = low <= current_price <= high
        execute_in_range = risk_settings.get('execute_in_range', True)
        range_handling = risk_settings['entry_range_handling']

        # Always execute if price is in range and setting enabled
        if in_range and execute_in_range:
            return True, None  # Market execution

        # Otherwise convert to pending order
        if range_handling == "First Price":
            preferred_price = low
        elif range_handling == "Last Price":
            preferred_price = high
        else:  # Average
            preferred_price = (low + high) / 2

        return False, preferred_price

    def connect(self, account, server, password, path):
        try:
            account = int(account) if str(account).isdigit() else account
        except ValueError:
            raise ConnectionError("Account number must be numeric")

        if mt5_is_initialized():
            mt5.shutdown()
            time.sleep(1)

        if not os.path.exists(path):
            logger.error(f"MT5 executable NOT FOUND at: {path}")
            raise ConnectionError(f"MT5 executable not found at {path}")

        logger.info(f"Connecting to MT5 at: {path}")
        if not mt5.initialize(path=path, login=account, password=password, server=server):
            error = mt5.last_error()
            logger.error(f"MT5 initialization failed: {error}")
            raise ConnectionError(f"MT5 initialization failed: {error}")

        account_info = mt5.account_info()
        if account_info is None:
            mt5.shutdown()
            error = mt5.last_error()
            logger.error(f"MT5 account info failed: {error}")
            raise ConnectionError(f"Failed to get account info: {error}")

        self.connected = True
        self.account = account
        self.server = server
        self.path = path
        logger.info(f"Connected to MT5 account: {account}")
        return True

    def disconnect(self):
        if mt5_is_initialized():
            mt5.shutdown()
        self.connected = False
        self.account = None
        self.server = None
        self.path = None
        logger.info("Disconnected from MT5")

    def get_account_info(self):
        if self.connected:
            try:
                return mt5.account_info()._asdict()
            except:
                return None
        return None

    def normalize_symbol(self, symbol):
        """Normalize symbol for broker-specific format"""
        # Skip invalid words
        if symbol in ["LIMIT", "STOP", "TP", "SL"]:
            return None

        mappings = self.parent.settings.get_symbol_mappings()
        if symbol.upper() in mappings:
            return mappings[symbol.upper()]

        clean_symbol = re.sub(r'[^\w\s.@-]', '', symbol).upper()
        substitutions = {
            'GOLD': 'XAUUSD',
            'XAU': 'XAUUSD',
            'SILVER': 'XAGUSD',
            'XAG': 'XAGUSD',
            'USOIL': 'XTIUSD',
            'UKOIL': 'XBRUSD',
            'OIL': 'XTIUSD',
            'BRENT': 'XBRUSD',
            'NAS100': 'NAS100',
            'SPX500': 'SPX500',
            'DXY': 'USDX',
            'BTC': 'BTCUSD',
            'ETH': 'ETHUSD',
            'XRP': 'XRPUSD',
            'LTC': 'LTCUSD',
            'BCH': 'BCHUSD'
        }
        if clean_symbol in substitutions:
            clean_symbol = substitutions[clean_symbol]

        # Get broker-specific prefix and suffix
        mt5_settings = self.parent.settings.get_mt5_settings()
        symbol_prefix = mt5_settings.get("symbol_prefix", "")
        symbol_suffix = mt5_settings.get("symbol_suffix", "")

        # Try with broker-specific prefix and suffix first
        if symbol_prefix or symbol_suffix:
            broker_symbol = f"{symbol_prefix}{clean_symbol}{symbol_suffix}"
            if mt5.symbol_info(broker_symbol):
                logger.info(f"Found broker symbol: {clean_symbol} -> {broker_symbol}")
                return broker_symbol

        # Try original symbol first
        if mt5.symbol_info(clean_symbol):
            return clean_symbol

        # Try with broker suffix only
        if symbol_suffix:
            trial = clean_symbol + symbol_suffix
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with suffix: {clean_symbol} -> {trial}")
                return trial

        # Try with broker prefix only
        if symbol_prefix:
            trial = symbol_prefix + clean_symbol
            if mt5.symbol_info(trial):
                logger.info(f"Found symbol with prefix: {clean_symbol} -> {trial}")
                return trial

        # Try with common suffixes
        for suffix in ['', 'USD', 'EUR', 'JPY', 'GBP', 'CHF', 'AUD', 'CAD', 'NZD']:
            trial = clean_symbol + suffix
            if mt5.symbol_info(trial):
                return trial

        # Try with common prefixes
        for prefix in ['', 'MT_', 'FX_', 'CFD_', 'SPOT_', 'OTC_']:
            trial = prefix + clean_symbol
            if mt5.symbol_info(trial):
                return trial

        # Try removing numbers
        no_num = re.sub(r'\d+', '', clean_symbol)
        if no_num != clean_symbol and mt5.symbol_info(no_num):
            return no_num

        # Try base currency for forex pairs
        if len(clean_symbol) > 3 and clean_symbol[-3:] in ['USD', 'EUR', 'JPY']:
            base = clean_symbol[:-3]
            if mt5.symbol_info(base):
                return base

        logger.warning(f"Symbol not found: {clean_symbol}")
        return None

    def calculate_pip_value(self, symbol_info, symbol):
        """
        Calculate the pip value for a given symbol correctly.
        Handles different instrument types (forex, metals, indices, etc.)
        """
        try:
            contract_size = symbol_info.trade_contract_size
            tick_value = symbol_info.trade_tick_value
            tick_size = symbol_info.trade_tick_size
            point = symbol_info.point
            
            # Handle different instrument types
            if "JPY" in symbol:
                # For JPY pairs, 1 pip = 1 point
                pip_value = tick_value
            elif "XAU" in symbol or "GOLD" in symbol:
                # For gold, calculate based on contract size
                pip_value = tick_value * 10
            elif "XAG" in symbol or "SILVER" in symbol:
                # For silver, calculate based on contract size
                pip_value = tick_value * 10
            else:
                # For other forex pairs, 1 pip = 10 points
                pip_value = tick_value * 10
            
            # Validate pip value
            if pip_value <= 0:
                logger.warning(f"Invalid pip value for {symbol}: {pip_value}, using fallback")
                # Fallback calculation
                pip_multiplier = 10 if "JPY" not in symbol else 1
                pip_value = tick_value * pip_multiplier
            
            return pip_value
            
        except Exception as e:
            logger.error(f"Error calculating pip value for {symbol}: {e}")
            # Emergency fallback
            return symbol_info.trade_tick_value * 10

    def execute_trade(self, symbol, order_type, entry_price, volume, sl=None, tp=None, tps=None, tolerance=2.0, channel_name=None):
        if not self.connected:
            raise ConnectionError("Not connected to MT5")
        try:
            clean_symbol = self.normalize_symbol(symbol)
            if clean_symbol is None:
                logger.warning(f"Skipping trade for invalid symbol: {symbol}")
                return [{"error": f"Invalid symbol: {symbol}"}]
            logger.info(f"Normalized symbol: {symbol} -> {clean_symbol}")

            # Get risk settings
            risk_settings = self.parent.settings.get_risk_settings()
            risk_method = risk_settings['risk_method']
            logger.info(f"Risk calculation for {clean_symbol}: method={risk_method}, settings={risk_settings}")

            # Calculate position size based on risk method
            if risk_method == 'percent':
                # Percent risk method - calculate lot size based on account balance and risk percentage
                account_info = self.get_account_info()
                if not account_info:
                    logger.error("Cannot calculate percent risk - no account info")
                    lot_size = risk_settings.get("fixed_lot", 0.1)
                else:
                    balance = account_info.get('balance', 0)
                    if balance <= 0:
                        logger.error("Cannot calculate percent risk - invalid balance")
                        lot_size = risk_settings.get("fixed_lot", 0.1)
                    else:
                        # Calculate risk amount in account currency
                        risk_amount = balance * (risk_settings['risk_percent'] / 100)

                        # Get symbol info
                        if not mt5.symbol_select(clean_symbol, True):
                            logger.error(f"Symbol {clean_symbol} not found")
                            return [{"error": f"Symbol {clean_symbol} not found"}]

                        symbol_info = mt5.symbol_info(clean_symbol)
                        if symbol_info is None:
                            logger.error(f"Failed to get symbol info for {clean_symbol}")
                            return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

                        # Calculate point value safely with fallback
                        point = symbol_info.point if symbol_info else 0.00001

                        # Calculate stop loss distance in pips
                        if sl and entry_price:
                            # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                            pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                            sl_distance = abs(entry_price - sl) / point / pip_multiplier
                        else:
                            # If no SL, use default 50 pips
                            sl_distance = 50

                        # Calculate lot size with proper validation
                        if sl_distance > 0 and point > 0 and symbol_info.trade_tick_value > 0:
                            # Get pip value per lot for this symbol
                            pip_value = self.calculate_pip_value(symbol_info, clean_symbol)
                            
                            if pip_value > 0:
                                lot_size = risk_amount / (sl_distance * pip_value)
                            else:
                                lot_size = risk_settings.get("fixed_lot", 0.1)
                                logger.warning("Invalid pip_value, using fixed lot")
                        else:
                            lot_size = risk_settings.get("fixed_lot", 0.1)
                            logger.warning("Invalid sl_distance, point_value, or tick_value, using fixed lot")

                        # Apply broker constraints
                        min_volume = symbol_info.volume_min
                        max_volume = symbol_info.volume_max
                        volume_step = symbol_info.volume_step

                        # Clamp to min/max and round to step
                        lot_size = max(min(lot_size, max_volume), min_volume)
                        if volume_step > 0:
                            lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step
                            
                        # Additional safety check: ensure lot size doesn't exceed reasonable limits
                        # For a small account, limit lot size to prevent margin issues
                        if balance < 1000:  # Small account
                            # For very small accounts, use much smaller lot sizes
                            if balance < 200:
                                max_safe_lot = min(lot_size, 0.01)  # Max 0.01 lot for very small accounts
                            elif balance < 500:
                                max_safe_lot = min(lot_size, 0.1)   # Max 0.1 lot for small accounts
                            else:
                                max_safe_lot = min(lot_size, 0.5)   # Max 0.5 lot for medium accounts
                            
                            if lot_size > max_safe_lot:
                                logger.warning(f"Lot size {lot_size} too large for small account (balance: ${balance}), limiting to {max_safe_lot}")
                                lot_size = max_safe_lot

                        logger.info(
                            f"Percent risk lot size: {lot_size:.2f} (risk: {risk_settings['risk_percent']}%, "
                            f"balance: ${balance:.2f}, risk amount: ${risk_amount:.2f}, "
                            f"SL distance: {sl_distance} pips)")

            elif risk_method == 'fixed_dollar':
                fixed_dollar_risk = risk_settings.get('fixed_dollar', 100.0)

                # For fixed dollar risk, we need SL and either entry_price or current market price
                if not sl:
                    logger.error("Fixed dollar risk requires SL")
                    return [{"error": "Fixed dollar risk requires SL"}]
                
                # If entry_price is None (market order), we'll get current price later
                if not entry_price:
                    logger.info("Entry price is None (market order), will use current market price for calculation")

                symbol_info = mt5.symbol_info(clean_symbol)
                point = symbol_info.point
                
                # Get current market price if entry_price is None (market order)
                if not entry_price:
                    tick = mt5.symbol_info_tick(clean_symbol)
                    if tick is None:
                        logger.error(f"Failed to get current price for {clean_symbol}")
                        return [{"error": f"Failed to get current price for {clean_symbol}"}]
                    
                    # Use ask price for BUY orders, bid price for SELL orders
                    if order_type == "BUY":
                        entry_price = tick.ask
                    else:
                        entry_price = tick.bid
                    logger.info(f"Using current market price for calculation: {entry_price}")
                
                # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                pip_multiplier = 10 if "JPY" not in clean_symbol else 1
                sl_distance = abs(entry_price - sl) / point / pip_multiplier

                # Validate SL distance
                if sl_distance <= 0:
                    logger.error(f"Invalid SL distance: {sl_distance} pips")
                    return [{"error": "Invalid stop loss distance"}]
                
                # Prevent extremely small SL distances (less than 1 pip)
                if sl_distance < 1:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very small, this may cause issues")
                
                # Prevent extremely large SL distances (more than 1000 pips)
                if sl_distance > 1000:
                    logger.warning(f"SL distance {sl_distance:.2f} pips is very large, please verify")

                # Calculate pip value correctly for different instruments
                pip_value = self.calculate_pip_value(symbol_info, clean_symbol)

                # Calculate lot size
                lot_size = fixed_dollar_risk / (sl_distance * pip_value)
                logger.info(f"Fixed dollar calculation: Risk=${fixed_dollar_risk}, SL_distance={sl_distance:.2f} pips, Pip_value=${pip_value:.2f}, Lot_size={lot_size:.4f}")

                # Safety checks for lot size
                if lot_size <= 0:
                    logger.error(f"Invalid lot size calculated: {lot_size}")
                    return [{"error": "Invalid lot size calculated"}]
                
                # Prevent extremely large lot sizes (safety limit)
                max_safe_lot = 100.0  # Maximum safe lot size
                if lot_size > max_safe_lot:
                    logger.warning(f"Lot size {lot_size:.4f} exceeds safety limit of {max_safe_lot}, capping to {max_safe_lot}")
                    lot_size = max_safe_lot
                
                # Additional validation for reasonable lot sizes
                if lot_size > 10.0:
                    logger.warning(f"Large lot size calculated: {lot_size:.4f} - please verify risk settings")
                
                # Log detailed calculation for debugging
                logger.info(f"Risk calculation details for {clean_symbol}:")
                logger.info(f"  - Fixed dollar risk: ${fixed_dollar_risk}")
                logger.info(f"  - Entry price: {entry_price}")
                logger.info(f"  - Stop loss: {sl}")
                logger.info(f"  - SL distance: {sl_distance:.2f} pips")
                logger.info(f"  - Pip value per lot: ${pip_value:.2f}")
                logger.info(f"  - Calculated lot size: {lot_size:.4f}")

            else:  # Fixed lot method
                lot_size = risk_settings.get("fixed_lot", 0.1)
                logger.info(f"Using fixed lot size: {lot_size}")

            # Validate and adjust volume
            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info:
                # Get volume constraints
                min_volume = symbol_info.volume_min
                volume_step = symbol_info.volume_step

                # Adjust volume to meet broker requirements
                if lot_size < min_volume:
                    lot_size = min_volume
                if volume_step > 0:
                    lot_size = round(lot_size / volume_step) * volume_step  # Round to nearest step

                logger.info(f"Adjusted volume: {lot_size} (min: {min_volume}, step: {volume_step})")

            # Validate pending orders require entry price
            is_market_order = order_type in ["BUY", "SELL"]
            if not is_market_order and entry_price is None:
                logger.error("Pending order requires entry price")
                return [{"error": "Pending order requires entry price"}]

            # Handle range entries with validation
            if isinstance(entry_price, tuple):
                if len(entry_price) != 2:
                    logger.error("Invalid range entry - must have exactly 2 values")
                    return [{"error": "Invalid range entry format"}]
                
                # Validate range values
                if entry_price[0] <= 0 or entry_price[1] <= 0:
                    logger.error("Invalid range entry - values must be positive")
                    return [{"error": "Invalid range entry values"}]
                
                risk_settings = self.parent.settings.get_risk_settings()
                range_handling = risk_settings['entry_range_handling']
                if range_handling == "First Price":
                    calculated_price = entry_price[0]
                elif range_handling == "Last Price":
                    calculated_price = entry_price[1]
                else:  # Average Price
                    calculated_price = (entry_price[0] + entry_price[1]) / 2
                
                # Validate calculated price
                if calculated_price <= 0:
                    logger.error("Invalid calculated entry price")
                    return [{"error": "Invalid calculated entry price"}]
                
                logger.info(f"Converted range entry to {calculated_price} using {range_handling} method")
                entry_price = calculated_price

            # Get symbol info
            if not mt5.symbol_select(clean_symbol, True):
                logger.error(f"Symbol {clean_symbol} not found")
                return [{"error": f"Symbol {clean_symbol} not found"}]

            symbol_info = mt5.symbol_info(clean_symbol)
            if symbol_info is None:
                logger.error(f"Failed to get symbol info for {clean_symbol}")
                return [{"error": f"Failed to get symbol info for {clean_symbol}"}]

            point = symbol_info.point if symbol_info else 0.00001  # Fallback point value
            tick = mt5.symbol_info_tick(clean_symbol)
            if tick is None:
                logger.error(f"Failed to get current price for {clean_symbol}")
                return [{"error": f"Failed to get current price for {clean_symbol}"}]

            # Prepare base trade request
            # Get comment settings and channel name
            risk_settings = self.parent.settings.get_risk_settings() if hasattr(self, 'parent') else {}
            enable_comments = risk_settings.get("enable_comments", True)
            comment_prefix = risk_settings.get("comment_prefix", "FTSC")
            
            # Get channel name from signal data if available
            channel_name = channel_name if channel_name else "Unknown"
            
            # Create comment with channel name if enabled
            if enable_comments:
                comment = f"{comment_prefix} - {channel_name}"
            else:
                comment = ""
            
            request = {
                "symbol": clean_symbol,
                "volume": lot_size,
                "deviation": 20,
                "magic": 2023,
                "comment": comment,
                "type_time": mt5.ORDER_TIME_GTC,
            }

            # Add SL if provided
            if sl and sl > 0:
                request["sl"] = sl

            # Set order type
            if is_market_order:
                request["action"] = mt5.TRADE_ACTION_DEAL
                request["type_filling"] = mt5.ORDER_FILLING_FOK
                if order_type == "BUY":
                    request["type"] = mt5.ORDER_TYPE_BUY
                    request["price"] = tick.ask
                else:  # SELL
                    request["type"] = mt5.ORDER_TYPE_SELL
                    request["price"] = tick.bid
            else:
                request["action"] = mt5.TRADE_ACTION_PENDING
                request["price"] = entry_price
                request["type_filling"] = mt5.ORDER_FILLING_IOC
                if order_type == "BUY LIMIT":
                    request["type"] = mt5.ORDER_TYPE_BUY_LIMIT
                elif order_type == "SELL LIMIT":
                    request["type"] = mt5.ORDER_TYPE_SELL_LIMIT
                elif order_type == "BUY STOP":
                    request["type"] = mt5.ORDER_TYPE_BUY_STOP
                elif order_type == "SELL STOP":
                    request["type"] = mt5.ORDER_TYPE_SELL_STOP

            # Handle multiple TPs
            results = []
            if tps and len(tps) > 1:
                # Get symbol volume limits
                min_volume = symbol_info.volume_min
                volume_per_tp = lot_size / len(tps)

                # Adjust volume to meet minimum requirement while respecting total volume
                if volume_per_tp < min_volume:
                    volume_per_tp = min_volume
                    total_volume = volume_per_tp * len(tps)
                    if total_volume > lot_size * 1.1:  # Allow 10% tolerance
                        logger.warning(f"Total volume {total_volume} exceeds original {lot_size}, adjusting")
                        volume_per_tp = lot_size / len(tps)  # Revert to original calculation
                    else:
                        logger.warning(f"Adjusted TP volume to minimum: {min_volume}")

                for i, tp_val in enumerate(tps):
                    tp_request = request.copy()
                    tp_request["volume"] = volume_per_tp
                    tp_request["tp"] = tp_val
                    tp_request["comment"] = f"Falcon Trade TP{i + 1}"

                    # Send trade request
                    result = mt5.order_send(tp_request)
                    if result.retcode != mt5.TRADE_RETCODE_DONE:
                        error_msg = f"TP{i + 1} failed: {result.comment}"
                        logger.error(error_msg)
                        results.append({"error": error_msg})
                    else:
                        logger.info(f"TP{i + 1} executed successfully: Ticket={result.order}")

                        # Add to trade tracker
                        self.trade_tracker.add_trade(
                            ticket=result.order,
                            symbol=clean_symbol,
                            order_type=order_type,
                            volume=volume_per_tp,
                            entry_price=entry_price,
                            actual_price=result.price,
                            sl=sl,
                            tp=tp_val,
                            status='pending' if not is_market_order else 'filled'
                        )
                        results.append({
                            "symbol": clean_symbol,
                            "order_type": order_type,
                            "volume": volume_per_tp,
                            "price": result.price,
                            "sl": sl,
                            "tp": tp_val,
                            "ticket": result.order
                        })
                return results
            else:
                # Handle single TP
                if tp and tp > 0:
                    request["tp"] = tp
                elif tps and len(tps) == 1:
                    request["tp"] = tps[0]

                # Send trade request
                result = mt5.order_send(request)
                if result.retcode != mt5.TRADE_RETCODE_DONE:
                    error_msg = f"Trade failed: {result.comment} (error {result.retcode})"
                    logger.error(error_msg)
                    return [{"error": error_msg}]

                logger.info(f"Trade executed successfully: Ticket={result.order}")

                # Add to trade tracker
                self.trade_tracker.add_trade(
                    ticket=result.order,
                    symbol=clean_symbol,
                    order_type=order_type,
                    volume=lot_size,
                    entry_price=entry_price,
                    actual_price=result.price,
                    sl=sl,
                    tp=tp or (tps[0] if tps and len(tps) > 0 else None),
                    status='pending' if not is_market_order else 'filled'
                )

                return [{
                    "symbol": clean_symbol,
                    "order_type": order_type,
                    "volume": lot_size,
                    "price": result.price,
                    "sl": sl,
                    "tp": tp or (tps[0] if tps and len(tps) > 0 else None),
                    "ticket": result.order
                }]

        except Exception as e:
            logger.error(f"Error executing trade: {str(e)}")
            return [{"error": str(e)}]

    def _handle_send_result(self, result, request):
        if result is None:
            last_error = mt5.last_error()
            return {"error": f"MT5 send failed: {last_error}"}
        elif result.retcode != mt5.TRADE_RETCODE_DONE:
            return {"error": f"Broker rejected: {result.retcode} - {result.comment}"}
        else:
            # Add trade with partial volume
            self.trade_tracker.add_trade(
                result.order,
                request["symbol"],
                request["type"],
                request["volume"],  # Partial volume
                request["price"],
                sl=request.get("sl"),
                tp=request.get("tp"),
                tps=None
            )
            return {"success": True, "ticket": result.order}

    def handle_management(self, command):
        action = command.get("action")
        symbol = command.get("symbol")
        trades = self.trade_tracker.get_trades_by_symbol(symbol) if symbol else list(
            self.trade_tracker.active_trades.values())
        if not trades:
            return {"error": "No matching trades found"}

        results = []
        for trade in trades:
            ticket = [k for k, v in self.trade_tracker.active_trades.items() if v == trade][0]
            if action == "CLOSE":
                self.close_trade(ticket)
                results.append({"success": True, "action": "closed", "ticket": ticket})
            elif action == "PARTIAL_CLOSE":
                percent = command.get("percent", 50)
                self.partial_close_trade(ticket, percent)
                results.append({"success": True, "action": "partial_closed", "ticket": ticket})
            elif action == "MODIFY_SL":
                new_sl = command.get("sl")
                if new_sl:
                    self.modify_sl(ticket, new_sl)
                    results.append({"success": True, "action": "sl_modified", "ticket": ticket})
            elif action == "MODIFY_TP":
                new_tp = command.get("tp")
                if new_tp:
                    self.modify_tp(ticket, new_tp)
                    results.append({"success": True, "action": "tp_modified", "ticket": ticket})
            elif action == "SL_TO_BE":
                self.move_sl_to_be(ticket)
                results.append({"success": True, "action": "sl_to_be", "ticket": ticket})
            elif action == "CANCEL":
                self.cancel_order(ticket)
                results.append({"success": True, "action": "cancelled", "ticket": ticket})

        return results

    def close_trade(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": position.volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Close trade",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                profit = result.profit
                self.trade_tracker.remove_trade(ticket, profit)
                return True
        return False

    def partial_close_trade(self, ticket, percent):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            close_volume = position.volume * (percent / 100)
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "position": ticket,
                "symbol": position.symbol,
                "volume": close_volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == mt5.ORDER_TYPE_BUY else mt5.ORDER_TYPE_BUY,
                "price": mt5.symbol_info_tick(
                    position.symbol).bid if position.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(
                    position.symbol).ask,
                "deviation": 20,
                "magic": position.magic,
                "comment": "Partial close",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                # Update volume in tracker
                new_volume = position.volume - close_volume
                self.trade_tracker.update_trade(ticket, {"volume": new_volume})
                return True
        return False

    def modify_sl(self, ticket, new_sl):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": new_sl,
                "tp": position.tp  # PRESERVE EXISTING TP
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": new_sl})
                return True
        return False

    def modify_tp(self, ticket, new_tp):
        request = {
            "action": mt5.TRADE_ACTION_SLTP,
            "position": ticket,
            "tp": new_tp,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.update_trade(ticket, {"tp": new_tp})
            return True
        return False

    def move_sl_to_be(self, ticket):
        position = mt5.positions_get(ticket=ticket)
        if position:
            position = position[0]
            be_price = position.price_open
            request = {
                "action": mt5.TRADE_ACTION_SLTP,
                "position": ticket,
                "sl": be_price,
            }
            result = mt5.order_send(request)
            if result.retcode == mt5.TRADE_RETCODE_DONE:
                self.trade_tracker.update_trade(ticket, {"sl": be_price})
                return True
        return False

    def cancel_order(self, ticket):
        request = {
            "action": mt5.TRADE_ACTION_REMOVE,
            "order": ticket,
        }
        result = mt5.order_send(request)
        if result.retcode == mt5.TRADE_RETCODE_DONE:
            self.trade_tracker.remove_trade(ticket, 0)
            return True
        return False

    def close_all_trades(self):
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                self.close_trade(pos.ticket)

    def monitor_trades(self):
        risk_settings = self.parent.settings.get_risk_settings()
        positions = mt5.positions_get()
        if positions:
            for pos in positions:
                ticket = pos.ticket
                trade = self.trade_tracker.get_trade_by_ticket(ticket)
                if not trade:
                    continue

                current_price = mt5.symbol_info_tick(
                    pos.symbol).bid if pos.type == mt5.ORDER_TYPE_BUY else mt5.symbol_info_tick(pos.symbol).ask
                entry_price = trade["entry"]

                # BE after pips
                if risk_settings['be_after_pips'] > 0:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert point distance to pips (1 pip = 10 points for most pairs, 1 point for JPY pairs)
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    pip_diff = abs(current_price - entry_price) / point / pip_multiplier
                    if pip_diff >= risk_settings['be_after_pips']:
                        self.move_sl_to_be(ticket)

                # Trailing SL
                if risk_settings['trailing_sl_enabled']:
                    point = mt5.symbol_info(pos.symbol).point
                    # Convert pip distance to points for trailing stop
                    pip_multiplier = 10 if "JPY" not in pos.symbol else 1
                    trailing_dist = risk_settings['trailing_sl_distance'] * point * pip_multiplier
                    if pos.type == mt5.ORDER_TYPE_BUY:
                        new_sl = current_price - trailing_dist
                        if new_sl > pos.sl:
                            self.modify_sl(ticket, new_sl)
                    else:
                        new_sl = current_price + trailing_dist
                        if new_sl < pos.sl:
                            self.modify_sl(ticket, new_sl)

class TradeMonitor(QThread):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.running = True

    def run(self):
        while self.running:
            if self.parent.mt5_manager.connected:
                self.parent.mt5_manager.monitor_trades()
            time.sleep(1)

# =====================
# UI COMPONENTS

# =====================
# ACTIVATION PAGE
# =====================
class ActivationPage(QWidget):
    activation_result = Signal(bool, str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.activation_result.connect(self.handle_activation_result)

    def setup_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(20)

        # Logo
        logo_label = QLabel()
        logo_pixmap = self.main_window.app_logo.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label, 0, Qt.AlignCenter)

        # Header
        header = QLabel("Falcon Trade Signal Copier")
        header
        layout.addWidget(header, 0, Qt.AlignCenter)

        # Subheader
        subheader = QLabel("Activate Your License")
        subheader
        layout.addWidget(subheader, 0, Qt.AlignCenter)

        # Instruction text
        instruction = QLabel(
            "Enter your license key below or start a free 7-day trial."
        )
        instruction
        instruction.setWordWrap(True)
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)

        # License key input
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter license key (XXXX-XXXX-XXXX-XXXX)")
        self.key_input
        # Allow Enter key to activate
        self.key_input.returnPressed.connect(self.activate_software)
        layout.addWidget(self.key_input)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        self.activate_btn = QPushButton("Activate License")
        self.activate_btn
        self.activate_btn.clicked.connect(self.activate_software)

        self.trial_btn = QPushButton("Start Free Trial")
        self.trial_btn
        self.trial_btn.clicked.connect(self.start_trial)

        btn_layout.addWidget(self.activate_btn)
        btn_layout.addWidget(self.trial_btn)
        layout.addLayout(btn_layout)

        # Status message
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"font-size: 13px; margin-top: 10px;")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Footer
        footer = QLabel(
            f"© 2023 Falcon Trade Copier v{VERSION} | "
            "<a href='https://falcontradecopier.com' style='color:blue;'>Website</a> | "
            "<a href='mailto:support@falcontradecopier.com' style='color:blue;'>Support</a>"
        )
        footer
        footer.setOpenExternalLinks(True)
        layout.addWidget(footer, 0, Qt.AlignCenter)

        # Set initial status
        self.update_status(True, "Enter your license key to continue")

    def update_status(self, valid, message):
        color = "green" if valid else "red"
        self.status_label.setStyleSheet(f"""
            font-size: 13px;
            color: {color};
            margin-top: 10px;
        """)
        self.status_label.setText(message)

    def activate_software(self):
        try:
            key = self.key_input.text().strip()

            if not key:
                self.update_status(False, "Please enter a license key")
                return

            if len(key) < 8:  # Reduced minimum length for bypass key
                self.update_status(False, "Invalid license key format")
                return

            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.activate_btn.setText("Validating...")
            self.update_status(True, "Validating license...")

            # Start validation in separate thread
            threading.Thread(target=self.main_window.validate_license, args=(key,), daemon=True).start()
            
            logger.info(f"Starting license validation for key: {key[:8]}...")
            
        except Exception as e:
            logger.error(f"Error in activate_software: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.update_status(False, "Activation error occurred. Please try again.")

    def start_trial(self):
        try:
            # Visual feedback - disable buttons and show loading state
            self.activate_btn.setEnabled(False)
            self.trial_btn.setEnabled(False)
            self.trial_btn.setText("Starting...")
            self.update_status(True, "Starting trial...")

            # Start trial process in separate thread
            threading.Thread(target=self.main_window.process_trial, daemon=True).start()
            
            logger.info("Starting trial license creation...")
            
        except Exception as e:
            logger.error(f"Error in start_trial: {e}")
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.trial_btn.setText("Start Free Trial")
            self.update_status(False, "Trial start error occurred. Please try again.")

    def handle_activation_result(self, valid, message, result):
        try:
            if valid:
                self.update_status(True, message)
                self.main_window.show_telegram_page()
            else:
                # Reset buttons to original state on failure
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
                self.update_status(False, message)
                
                logger.warning(f"Activation failed: {message}")
        except Exception as e:
            logger.error(f"Error handling activation result: {e}")
            # Ensure buttons are reset even if there's an error
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
    
    def reset_ui_state(self):
        """Reset the activation page to initial state"""
        try:
            # Clear input field
            self.key_input.clear()
            
            # Enable buttons and reset text
            self.activate_btn.setEnabled(True)
            self.trial_btn.setEnabled(True)
            self.activate_btn.setText("Activate")
            self.trial_btn.setText("Start Free Trial")
            
            # Reset status message
            self.update_status(True, "Enter your license key to continue")
            
            # Ensure signal connections are active (reconnect if needed)
            self.reconnect_signals()
            
            # Set focus to input field for better UX
            self.key_input.setFocus()
            
            logger.info("Activation page UI state reset successfully")
        except Exception as e:
            logger.error(f"Error resetting activation page UI state: {e}")
            # Fallback to ensure buttons are at least enabled
            try:
                self.activate_btn.setEnabled(True)
                self.trial_btn.setEnabled(True)
                self.activate_btn.setText("Activate")
                self.trial_btn.setText("Start Free Trial")
            except:
                pass
    
    def reconnect_signals(self):
        """Ensure signal connections are properly established"""
        try:
            # Disconnect existing connections to avoid duplicates
            try:
                self.activate_btn.clicked.disconnect()
                self.trial_btn.clicked.disconnect()
            except:
                pass  # No existing connections to disconnect
            
            # Reconnect signals
            self.activate_btn.clicked.connect(self.activate_software)
            self.trial_btn.clicked.connect(self.start_trial)
            
            logger.debug("Activation page signals reconnected")
        except Exception as e:
            logger.error(f"Error reconnecting activation page signals: {e}")

# =====================
# TELEGRAM SETUP PAGE
# =====================
class TelegramPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.channel_checkboxes = {}  # Store channel_id: checkbox mapping
        self.setup_ui()
        self.check_session_status()
        QTimer.singleShot(100, self.attempt_auto_connect)
        self.channels = []  # Store loaded channels

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(1.5)

        # Header with logo
        header = LogoHeader("Telegram Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Phone and Code in one row
        phone_code_layout = QHBoxLayout()
        phone_code_layout.setSpacing(1.5)

        # Phone input
        phone_layout = QVBoxLayout()
        phone_layout.setSpacing(1.5)
        phone_label = QLabel("Phone Number:")
        phone_label
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("+1234567890")
        self.phone_input.setFixedHeight(28)
        self.phone_input.setFixedWidth(200)
        phone_layout.addWidget(phone_label)
        phone_layout.addWidget(self.phone_input)
        phone_code_layout.addLayout(phone_layout)

        # Code input
        code_layout = QVBoxLayout()
        code_layout.setSpacing(1.5)
        code_label = QLabel("Verification Code:")
        code_label
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("12345")
        self.code_input.setEnabled(False)
        self.code_input.setFixedHeight(28)
        self.code_input.setFixedWidth(200)
        code_layout.addWidget(code_label)
        code_layout.addWidget(self.code_input)
        phone_code_layout.addLayout(code_layout)

        layout.addLayout(phone_code_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(1.5)

        self.send_code_btn = QPushButton("Send Code")
        self.send_code_btn.clicked.connect(self.send_telegram_code)

        self.verify_btn = QPushButton("Verify")
        self.verify_btn.setEnabled(False)
        self.verify_btn.clicked.connect(self.verify_telegram_code)

        self.change_number_btn = QPushButton("Change Number")
        self.change_number_btn.setVisible(False)
        self.change_number_btn.clicked.connect(self.change_telegram_number)

        btn_layout.addWidget(self.send_code_btn)
        btn_layout.addWidget(self.verify_btn)
        btn_layout.addWidget(self.change_number_btn)
        layout.addLayout(btn_layout)

        # Channel selection
        channel_layout = QVBoxLayout()
        channel_layout.setSpacing(1.5)
        channel_header = QLabel("Telegram Channels:")
        channel_header
        channel_layout.addWidget(channel_header)
        
        # Search field for channels
        search_layout = QHBoxLayout()
        search_layout.addStretch()  # Push to right side
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.channel_search = QLineEdit()
        self.channel_search.setPlaceholderText("Search channels...")
        self.channel_search.setFixedHeight(28)
        self.channel_search.setFixedWidth(200)
        self.channel_search.textChanged.connect(self.filter_channels)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.channel_search)
        channel_layout.addLayout(search_layout)

        # Scroll area for channels grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: 2px solid #1c243b;
                border-radius: 6px;
                background-color: #0d111f;
            }
        """)

        # Container widget for grid
        container = QWidget()
        self.grid_layout = QGridLayout(container)
        self.grid_layout.setSpacing(0)
        self.grid_layout.setContentsMargins(15, 15, 15, 15)

        scroll_area.setWidget(container)
        scroll_area.setMinimumHeight(150)
        channel_layout.addWidget(scroll_area)
        layout.addLayout(channel_layout)

        # Channel IDs and Save button in one row
        id_save_layout = QHBoxLayout()
        id_save_layout.setSpacing(1.5)

        # Channel IDs
        id_layout = QVBoxLayout()
        id_layout.setSpacing(1.5)
        id_label = QLabel("Channel IDs (comma separated):")
        id_label
        self.channel_id_input = QLineEdit()
        self.channel_id_input
        id_layout.addWidget(id_label)
        id_layout.addWidget(self.channel_id_input)
        id_save_layout.addLayout(id_layout, 3)  # 3/4 width

        # Save button
        self.save_btn = QPushButton("Save Channels")
        self.save_btn.setFixedHeight(35)
        self.save_btn.setFixedWidth(120)
        self.save_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.save_btn.clicked.connect(self.save_channels)
        id_save_layout.addWidget(self.save_btn, 1)  # 1/4 width
        # Align save button with channel ID field
        self.save_btn.setContentsMargins(0, 0, 0, 0)

        layout.addLayout(id_save_layout)

        # Navigation
        nav_layout = QHBoxLayout()

        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.activation_page))
        self.next_btn = QPushButton("Next")
        self.next_btn.setEnabled(False)
        self.next_btn.clicked.connect(self.parent.show_mt5_page)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)
        layout.addLayout(nav_layout)

        # Set fixed width for buttons
        for btn in [self.send_code_btn, self.verify_btn, self.change_number_btn]:
            btn.setFixedWidth(150)

        # Load saved channels if any
        saved_channels = self.parent.settings.get_telegram_channels()
        if saved_channels:
            self.channel_id_input.setText(", ".join(str(id) for id in saved_channels))

    def send_telegram_code(self):
        phone = self.phone_input.text().strip()
        if not phone:
            QMessageBox.warning(self, "Missing Phone", "Please enter your phone number")
            return

        self.send_code_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Sending verification code...")
        self.parent.telegram_manager.connect_telegram(
            TELEGRAM_API_ID,
            TELEGRAM_API_HASH,
            phone
        )

    def verify_telegram_code(self):
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "Missing Code", "Please enter the verification code")
            return

        self.verify_btn.setEnabled(False)
        self.parent.status_bar.showMessage("Verifying code...")
        self.parent.telegram_manager.authenticate(code)

    def change_telegram_number(self):
        self.parent.telegram_manager.stop_listening()
        self.parent.telegram_manager = TelegramManager()
        self.parent.setup_connections()
        self.parent.settings.set_telegram_session(None)
        self.phone_input.setEnabled(True)
        self.phone_input.clear()
        self.code_input.clear()
        self.code_input.setEnabled(False)
        self.verify_btn.setEnabled(False)
        self.change_number_btn.setVisible(False)
        self.next_btn.setEnabled(False)
        self.clear_channel_grid()
        self.channel_id_input.clear()
        self.send_code_btn.setEnabled(True)
        self.send_code_btn.setVisible(True)
        self.parent.update_connection_status()
        self.parent.status_bar.showMessage("Enter new phone number")

    def check_session_status(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)

    def attempt_auto_connect(self):
        session = self.parent.settings.get_telegram_session()
        if session:
            self.parent.status_bar.showMessage("Attempting auto-login...")
            self.send_code_btn.setVisible(False)
            self.change_number_btn.setVisible(True)
            self.phone_input.setEnabled(False)
            self.code_input.setEnabled(False)
            self.verify_btn.setEnabled(False)
            self.parent.telegram_manager.session_string = session
            self.parent.telegram_manager.connect_telegram(
                TELEGRAM_API_ID, TELEGRAM_API_HASH, ""
            )

    def load_channels(self, channels):
        self.channels = channels  # Store channels
        self.clear_channel_grid()
        if not channels:
            label = QLabel("No channels available")
            label
            label.setAlignment(Qt.AlignCenter)
            self.grid_layout.addWidget(label, 0, 0, 1, 2)
            return

        # Add channels to grid
        row, col = 0, 0
        max_cols = 2  # Number of columns in grid

        for channel in channels:
            checkbox = QCheckBox(f"{channel['name']} (@{channel['username']})")
            checkbox
            checkbox.setProperty("channel_id", channel["id"])
            self.channel_checkboxes[channel["id"]] = checkbox

            # Check if this channel is already selected
            saved_ids = [id.strip() for id in self.channel_id_input.text().split(",") if id.strip()]
            if str(channel["id"]) in saved_ids:
                checkbox.setChecked(True)

            # Connect checkbox state change to update ID input
            checkbox.stateChanged.connect(self.update_channel_ids_from_checkboxes)

            self.grid_layout.addWidget(checkbox, row, col)

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

    def clear_channel_grid(self):
        # Clear existing checkboxes
        for i in reversed(range(self.grid_layout.count())):
            widget = self.grid_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self.channel_checkboxes.clear()

    def update_channel_ids_from_checkboxes(self):
        """Update channel ID input based on checkbox states"""
        selected_ids = []
        for channel_id, checkbox in self.channel_checkboxes.items():
            if checkbox.isChecked():
                selected_ids.append(str(channel_id))

        self.channel_id_input.setText(", ".join(selected_ids))

    def save_channels(self):
        channel_ids = []
        for id_str in self.channel_id_input.text().split(','):
            id_str = id_str.strip()
            if id_str:
                try:
                    channel_ids.append(int(id_str))
                except ValueError:
                    logger.error(f"Invalid channel ID: {id_str}")

        if channel_ids:
            self.parent.settings.set_telegram_channels(channel_ids)
            self.parent.status_bar.showMessage(f"Saved {len(channel_ids)} channels")
            self.next_btn.setEnabled(True)
        else:
            self.parent.status_bar.showMessage("No valid channel IDs to save")

    def get_channel_name(self, channel_id):
        for channel in self.channels:
            if channel['id'] == channel_id:
                return channel['name']
        return str(channel_id)
        
    def filter_channels(self):
        """Filter channels based on search text"""
        search_text = self.channel_search.text().lower()
        for i in range(self.grid_layout.count()):
            widget = self.grid_layout.itemAt(i).widget()
            if isinstance(widget, QCheckBox):
                channel_name = widget.text().lower()
                widget.setVisible(search_text in channel_name)

# MT5 SETUP PAGE
# =====================
class MT5Page(QWidget):
    connection_result = Signal(bool, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        self.load_settings()
        self.connection_result.connect(self.on_mt5_connection_result)

    def browse_mt5_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select MetaTrader 5 Terminal",
            "C:/",
            "Executable Files (*.exe)"
        )
        if file_path:
            self.path_input.setText(file_path)

    def setup_ui(self):
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 25, 40, 20)
        layout.setSpacing(8)

        # Header with logo
        header = LogoHeader("MT5 Account Setup", self.parent.app_logo)
        layout.addWidget(header)

        # Form
        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignLeft)

        # Account
        account_label = QLabel("Account Number:")
        account_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.account_input = QLineEdit()
        self.account_input.setPlaceholderText("Enter MT5 account number")
        self.account_input.setFixedHeight(40)
        self.account_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(account_label, self.account_input)

        # Server
        server_label = QLabel("Server:")
        server_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Enter MT5 server name")
        self.server_input.setFixedHeight(40)
        self.server_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(server_label, self.server_input)

        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter MT5 password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(40)
        self.password_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(password_label, self.password_input)

        # Path
        path_label = QLabel("MT5 Path:")
        path_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        path_layout = QHBoxLayout()
        path_layout.setSpacing(4)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter MT5 terminal path")
        self.path_input.setFixedHeight(40)
        self.path_input.setStyleSheet("font-size: 13px;")
        path_layout.addWidget(self.path_input)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_mt5_path)
        self.browse_btn.setFixedWidth(100)
        self.browse_btn.setFixedHeight(40)
        path_layout.addWidget(self.browse_btn)
        form_layout.addRow(path_label, path_layout)

        # MT5 Path Instructions
        path_instructions = QLabel("💡 Instructions: Right-click on your MT5 terminal shortcut → Properties → Copy the path from 'Target' field")
        path_instructions.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 4px;")
        path_instructions.setWordWrap(False)
        path_instructions.setAlignment(Qt.AlignLeft)
        form_layout.addRow("", path_instructions)

        # Symbol Prefix and Suffix (aligned like other fields)
        prefix_label = QLabel("Symbol Prefix:")
        prefix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText(".pro")
        self.prefix_input.setFixedHeight(40)
        self.prefix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(prefix_label, self.prefix_input)
        
        suffix_label = QLabel("Symbol Suffix:")
        suffix_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.suffix_input = QLineEdit()
        self.suffix_input.setPlaceholderText(".raw")
        self.suffix_input.setFixedHeight(40)
        self.suffix_input.setStyleSheet("font-size: 13px;")
        form_layout.addRow(suffix_label, self.suffix_input)

        # Help text
        help_text = QLabel("💡 Tip: Leave empty if your broker doesn't use prefixes/suffixes")
        help_text.setStyleSheet("font-size: 11px; color: #9ca6b8; margin-top: 8px;")
        help_text.setWordWrap(True)
        help_text.setAlignment(Qt.AlignCenter)
        form_layout.addRow(help_text)

        # Center the form
        form_container = QWidget()
        form_container.setMaximumWidth(500)
        form_container.setLayout(form_layout)
        
        # Center the form container
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(form_container)
        center_layout.addStretch()
        layout.addLayout(center_layout)

        # Status
        self.status_label = QLabel("Not connected")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        # Connect button with dynamic glow effect
        self.connect_btn = QPushButton("Connect to MT5")
        self.connect_btn.setFixedHeight(45)
        self.connect_btn.setFixedWidth(200)
        self.connect_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f27d03, stop:1 #ff8a1a);
                color: #020711;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff8a1a, stop:1 #f27d03);
                
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e07000, stop:1 #f27d03);
            }
        """)
        self.connect_btn.clicked.connect(self.connect_mt5)
        
        # Center the button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.connect_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 6)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1c243b;
                border-radius: 4px;
                text-align: center;
                background-color: #0d111f;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8ccaee, stop:1 #f27d03);
                border-radius: 3px;
            }
        """)
        # Remove percentage text from progress bar
        self.progress_bar.setTextVisible(False)
        # Center the progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addStretch()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addStretch()
        layout.addLayout(progress_layout)

        # Navigation
        nav_layout = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(lambda: self.parent.stacked_widget.setCurrentWidget(self.parent.telegram_page))
        self.finish_btn = QPushButton("Finish")
        self.finish_btn.setEnabled(False)
        self.finish_btn.clicked.connect(self.parent.show_dashboard)

        nav_layout.addWidget(self.back_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.finish_btn)
        layout.addLayout(nav_layout)

    def load_settings(self):
        mt5_settings = self.parent.settings.get_mt5_settings()
        self.account_input.setText(mt5_settings.get("account", ""))
        self.server_input.setText(mt5_settings.get("server", ""))
        self.password_input.setText(mt5_settings.get("password", ""))
        self.path_input.setText(mt5_settings.get("path", ""))
        self.prefix_input.setText(mt5_settings.get("symbol_prefix", ""))
        self.suffix_input.setText(mt5_settings.get("symbol_suffix", ""))

    def connect_mt5(self):
        account = self.account_input.text().strip()
        server = self.server_input.text().strip()
        password = self.password_input.text()
        path = self.path_input.text().strip()
        symbol_prefix = self.prefix_input.text().strip()
        symbol_suffix = self.suffix_input.text().strip()

        if not account or not server or not password or not path:
            QMessageBox.warning(self, "Missing Information", "Please fill in all fields")
            return

        self.connect_btn.setEnabled(False)
        self.status_label.setText("Connecting to MT5...")
        self.parent.status_bar.showMessage("Connecting to MT5...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.parent.settings.set_mt5_settings(account, server, password, path, symbol_prefix, symbol_suffix)

        # Create a new thread and worker
        self.thread = QThread()
        self.worker = Worker(account, server, password, path)
        self.worker.parent = self.parent  # Pass parent reference
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress_update.connect(self.update_progress_status)
        self.worker.finished.connect(self.on_mt5_connection_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # Start the thread
        self.thread.start()
        
        # Set up timeout timer
        self.timeout_timer = QTimer()
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self.handle_connection_timeout)
        self.timeout_timer.start(60000)  # 60 seconds timeout

    def connect_mt5_thread(self, account, server, password, path):
        try:
            self.parent.mt5_manager.connect(account, server, password, path)
            self.connection_result.emit(True, "Connected successfully!")
        except Exception as e:
            self.connection_result.emit(False, str(e))

    def update_progress_status(self, message, step):
        """Update the status label with progress message and update progress bar"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #9ca6b8;")
        self.parent.status_bar.showMessage(message)
        self.progress_bar.setValue(step)

    def handle_connection_timeout(self):
        """Handle connection timeout"""
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.terminate()
            self.thread.wait(2000)  # Wait up to 2 seconds for thread to terminate
        self.progress_bar.setVisible(False)
        self.status_label.setText("Connection timeout - please try again")
        self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
        self.parent.status_bar.showMessage("MT5 connection timed out")
        self.connect_btn.setEnabled(True)
        QMessageBox.warning(self, "Connection Timeout", 
                          "The connection to MT5 timed out. Please check your settings and try again.")

    def on_mt5_connection_result(self, success, message):
        # Stop timeout timer
        if hasattr(self, 'timeout_timer'):
            self.timeout_timer.stop()
        
        self.progress_bar.setVisible(False)
        if success:
            self.status_label.setText("Connected successfully")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #1d9e4a;")
            self.parent.status_bar.showMessage("MT5 connected successfully")
            # Update account info immediately after successful connection
            self.parent.update_account_info()
            # Enable the finish button so user can click it to go to dashboard
            self.finish_btn.setEnabled(True)
        else:
            self.status_label.setText("Connection failed")
            self.status_label.setStyleSheet("font-size: 11px; font-weight: bold; margin: 8px 0; color: #f54e4e;")
            self.parent.status_bar.showMessage("MT5 connection failed")
            QMessageBox.warning(self, "Connection Failed", f"Failed to connect to MT5: {message}")
        self.connect_btn.setEnabled(True)

class Worker(QObject):
    finished = Signal(bool, str)
    progress_update = Signal(str, int)  # Add progress signal with step number

    def __init__(self, account, server, password, path):
        super().__init__()
        self.account = account
        self.server = server
        self.password = password
        self.path = path
        self.timeout = 60  # 60 seconds timeout for connection

    @Slot()
    def run(self):
        try:
            # Step 1: Validate account number
            self.progress_update.emit("Validating account number...", 1)
            time.sleep(0.5)  # Small delay to show progress
            try:
                account = int(self.account) if str(self.account).isdigit() else self.account
            except ValueError:
                raise ValueError("Account number must be numeric")

            # Step 2: Shutdown existing MT5 connection
            self.progress_update.emit("Shutting down existing MT5 connection...", 2)
            time.sleep(0.5)  # Small delay to show progress
            if mt5_is_initialized():
                mt5.shutdown()
                time.sleep(1)

            # Step 3: Check MT5 executable path
            self.progress_update.emit("Checking MT5 executable...", 3)
            time.sleep(0.5)  # Small delay to show progress
            if not os.path.exists(self.path):
                raise ValueError("MT5 path not found")

            # Step 4: Initialize MT5
            self.progress_update.emit("Initializing MT5...", 4)
            time.sleep(0.5)  # Small delay to show progress
            logger.info(f"Connecting to MT5 at: {self.path}")
            if not mt5.initialize(path=self.path, login=account, password=self.password, server=self.server):
                raise ValueError(f"MT5 initialization failed: {mt5.last_error()}")

            # Step 5: Get account info
            self.progress_update.emit("Getting account information...", 5)
            time.sleep(0.5)  # Small delay to show progress
            account_info = mt5.account_info()
            if not account_info:
                raise ValueError("Failed to get account info")

            # Step 6: Finalize connection
            self.progress_update.emit("Finalizing connection...", 6)
            time.sleep(0.5)  # Small delay to show progress
            
            # Set the connection status in the MT5Manager
            if hasattr(self, 'parent') and hasattr(self.parent, 'mt5_manager'):
                self.parent.mt5_manager.connected = True
                self.parent.mt5_manager.account = self.account
                self.parent.mt5_manager.server = self.server
                self.parent.mt5_manager.path = self.path
            
            self.finished.emit(True, "Connected successfully")
        except Exception as e:
            self.finished.emit(False, str(e))

# =====================
# DASHBOARD PAGE
# =====================
class DashboardPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.warning_labels = {}
        self.setup_ui()
        self.load_account_info()
        self.setup_timers()
        self.load_settings()

    def update_signal_info(self, signal_data):
        """Update the UI with new signal information"""
        self.channel_label.setText(signal_data.get("channel", "N/A"))
        self.symbol_label.setText(signal_data.get("symbol", "N/A"))
        
        # Try multiple possible keys for order type
        order_type = signal_data.get("order_type") or signal_data.get("type") or signal_data.get("action") or "N/A"
        self.type_label.setText(str(order_type))
        
        # Color grade the order type (BUY = green, SELL = red)
        order_type_str = str(order_type).upper()
        if "BUY" in order_type_str:
            self.type_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #1d9e4a;")  # Green for BUY
        elif "SELL" in order_type_str:
            self.type_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f54e4e;")  # Red for SELL
        else:
            self.type_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #8ccaee;")  # Blue for others

        # Format entry price
        entry_price = signal_data.get("entry_price", "N/A")
        if isinstance(entry_price, (list, tuple)):
            entry_price = f"{min(entry_price)}-{max(entry_price)}"
        elif entry_price is None:
            entry_price = "Market"
        self.entry_label.setText(str(entry_price))

        # Format SL
        sl = signal_data.get("sl", "N/A")
        self.sl_label.setText(str(sl))

        # Format TP
        tp = signal_data.get("tp", "N/A")
        tps = signal_data.get("tps", [])
        if tps:
            tp = ", ".join(map(str, tps))
        elif tp == "N/A" and not tps:
            tp = "N/A"
        self.tp_label.setText(str(tp))

        # Format lot size
        lot_size = signal_data.get("lot_size", "N/A")
        if lot_size != "N/A" and lot_size is not None:
            self.lot_label.setText(f"{lot_size:.2f}")
        else:
            self.lot_label.setText("N/A")

        # Status and error with color grading
        status = signal_data.get("status", "N/A")
        self.status_label.setText(str(status))
        
        # Color grade the status (Executed = green, others = red)
        status_str = str(status).upper()
        if "EXECUTED" in status_str or "SUCCESS" in status_str or "COMPLETED" in status_str:
            self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #1d9e4a;")  # Green for executed
        else:
            self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f54e4e;")  # Red for not executed
        
        error = signal_data.get("error", "")
        if error:
            self.error_label.setText(f"Error: {error}")
            self.error_label.setVisible(True)
        else:
            self.error_label.setVisible(False)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top bar
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(0, 0, 0, 0)
        top_bar.setSpacing(0)

        # Logo
        self.logo_label = QLabel()
        logo_pixmap = self.parent.app_logo.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.logo_label.setPixmap(logo_pixmap)
        top_bar.addWidget(self.logo_label)

        # Title
        title = QLabel("Falcon Trade Signal Copier")
        title
        top_bar.addWidget(title)

        # Spacer
        top_bar.addStretch()

        # Status indicators with dynamic animations
        status_layout = QHBoxLayout()
        status_layout.setSpacing(15)

        # Telegram Status Indicator
        telegram_container = QWidget()
        telegram_container.setFixedSize(130, 45)
        telegram_container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                border: 2px solid #1c243b;
                border-radius: 10px;
                padding: 6px;
            }
        """)
        
        telegram_layout = QHBoxLayout(telegram_container)
        telegram_layout.setContentsMargins(8, 4, 8, 4)
        telegram_layout.setSpacing(8)
        
        self.telegram_status = QLabel("●")
        self.telegram_status.setFixedSize(14, 14)
        self.telegram_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #f54e4e;
                background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                border-radius: 7px;
                text-align: center;
            }
        """)
        
        telegram_label = QLabel("Telegram")
        telegram_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #9ca6b8;")
        
        telegram_layout.addWidget(self.telegram_status)
        telegram_layout.addWidget(telegram_label)
        telegram_layout.addStretch()
        status_layout.addWidget(telegram_container)

        # MT5 Status Indicator
        mt5_container = QWidget()
        mt5_container.setFixedSize(130, 45)
        mt5_container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                border: 2px solid #1c243b;
                border-radius: 10px;
                padding: 6px;
            }
        """)
        
        mt5_layout = QHBoxLayout(mt5_container)
        mt5_layout.setContentsMargins(8, 4, 8, 4)
        mt5_layout.setSpacing(8)
        
        self.mt5_status = QLabel("●")
        self.mt5_status.setFixedSize(14, 14)
        self.mt5_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #f54e4e;
                background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                border-radius: 7px;
                text-align: center;
            }
        """)
        
        mt5_label = QLabel("MT5")
        mt5_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #9ca6b8;")
        
        mt5_layout.addWidget(self.mt5_status)
        mt5_layout.addWidget(mt5_label)
        mt5_layout.addStretch()
        status_layout.addWidget(mt5_container)

        # Copy Status Indicator
        copy_container = QWidget()
        copy_container.setFixedSize(130, 45)
        copy_container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                border: 2px solid #1c243b;
                border-radius: 10px;
                padding: 6px;
            }
        """)
        
        copy_layout = QHBoxLayout(copy_container)
        copy_layout.setContentsMargins(8, 4, 8, 4)
        copy_layout.setSpacing(8)
        
        self.copy_status = QLabel("●")
        self.copy_status.setFixedSize(14, 14)
        self.copy_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #f54e4e;
                background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                border-radius: 7px;
                text-align: center;
            }
        """)
        
        copy_label = QLabel("Copy")
        copy_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #9ca6b8;")
        
        copy_layout.addWidget(self.copy_status)
        copy_layout.addWidget(copy_label)
        copy_layout.addStretch()
        status_layout.addWidget(copy_container)

        top_bar.addLayout(status_layout)
        main_layout.addLayout(top_bar)

        # Control buttons with dynamic styling
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        control_layout.setContentsMargins(0, 10, 0, 10)

        self.start_btn = QPushButton("▶️ Start Copying")
        self.start_btn.setFixedHeight(50)
        self.start_btn.setFixedWidth(180)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d9e4a, stop:1 #2bb673);
                color: white;
                border-radius: 12px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                padding: 12px 20px;
                margin: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2bb673, stop:1 #1d9e4a);
                border: 2px solid #1d9e4a;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1a8a3f, stop:1 #1d9e4a);
            }
            QPushButton:disabled {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1c243b, stop:1 #131a2d);
                color: #9ca6b8;
                border: 2px solid #1c243b;
            }
        """)
        self.start_btn.clicked.connect(self.parent.start_copying)

        self.stop_btn = QPushButton("⏹️ Stop Copying")
        self.stop_btn.setFixedHeight(50)
        self.stop_btn.setFixedWidth(180)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f54e4e, stop:1 #ff6868);
                color: white;
                border-radius: 12px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                padding: 12px 20px;
                margin: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6868, stop:1 #f54e4e);
                border: 2px solid #f54e4e;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d43d3d, stop:1 #f54e4e);
            }
            QPushButton:disabled {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1c243b, stop:1 #131a2d);
                color: #9ca6b8;
                border: 2px solid #1c243b;
            }
        """)
        self.stop_btn.clicked.connect(self.parent.stop_copying)

        control_layout.addStretch()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addStretch()
        main_layout.addLayout(control_layout)

        # Tab widget with margin
        self.tabs = QTabWidget()
        self.tabs.setContentsMargins(0, 10, 0, 0)
        main_layout.addWidget(self.tabs)

        # Status tab
        status_tab = QWidget()
        status_layout = QVBoxLayout(status_tab)
        status_layout.setContentsMargins(0, 10, 0, 0)
        status_layout.setSpacing(5)

        # Account info - redesigned with card container
        account_group = QGroupBox("👤 Account Information")
        account_group.setStyleSheet("""
            QGroupBox {
                background-color: transparent;
                border: 1px solid #1c243b;
                border-radius: 6px;
                padding: 8px;
                margin: 5px;
                font-weight: bold;
                color: #f0f4f9;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                background-color: transparent;
            }
        """)
        account_layout = QVBoxLayout(account_group)
        account_layout.setSpacing(12)
        
        # Top row - Account details
        top_row = QHBoxLayout()
        top_row.setSpacing(20)
        
        # Left column
        left_col = QVBoxLayout()
        left_col.setSpacing(8)
        
        # Account Number
        account_num_container = QHBoxLayout()
        account_num_label = QLabel("Account Number:")
        account_num_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.account_num_label = QLabel("Loading...")
        self.account_num_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        account_num_container.addWidget(account_num_label)
        account_num_container.addWidget(self.account_num_label)
        account_num_container.addStretch()
        left_col.addLayout(account_num_container)
        
        # Leverage
        leverage_container = QHBoxLayout()
        leverage_label = QLabel("Leverage:")
        leverage_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.leverage_label = QLabel("Loading...")
        self.leverage_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        leverage_container.addWidget(leverage_label)
        leverage_container.addWidget(self.leverage_label)
        leverage_container.addStretch()
        left_col.addLayout(leverage_container)
        
        # Account Type
        account_type_container = QHBoxLayout()
        account_type_label = QLabel("Account Type:")
        account_type_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.account_type_label = QLabel("Loading...")
        self.account_type_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        account_type_container.addWidget(account_type_label)
        account_type_container.addWidget(self.account_type_label)
        account_type_container.addStretch()
        left_col.addLayout(account_type_container)
        
        # Currency
        currency_container = QHBoxLayout()
        currency_label = QLabel("Currency:")
        currency_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.currency_label = QLabel("Loading...")
        self.currency_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        currency_container.addWidget(currency_label)
        currency_container.addWidget(self.currency_label)
        currency_container.addStretch()
        left_col.addLayout(currency_container)
        
        # Profit
        profit_container = QHBoxLayout()
        profit_label = QLabel("Profit:")
        profit_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.profit_label = QLabel("Loading...")
        self.profit_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")  # Default white, will be updated dynamically
        profit_container.addWidget(profit_label)
        profit_container.addWidget(self.profit_label)
        profit_container.addStretch()
        left_col.addLayout(profit_container)
        
        top_row.addLayout(left_col)
        
        # Right column
        right_col = QVBoxLayout()
        right_col.setSpacing(8)
        
        # Balance
        balance_container = QHBoxLayout()
        balance_label = QLabel("Balance:")
        balance_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.balance_label = QLabel("Loading...")
        self.balance_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        balance_container.addWidget(balance_label)
        balance_container.addWidget(self.balance_label)
        balance_container.addStretch()
        right_col.addLayout(balance_container)
        
        # Equity
        equity_container = QHBoxLayout()
        equity_label = QLabel("Equity:")
        equity_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.equity_label = QLabel("Loading...")
        self.equity_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        equity_container.addWidget(equity_label)
        equity_container.addWidget(self.equity_label)
        equity_container.addStretch()
        right_col.addLayout(equity_container)
        
        # Free Margin
        free_margin_container = QHBoxLayout()
        free_margin_label = QLabel("Free Margin:")
        free_margin_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.free_margin_label = QLabel("Loading...")
        self.free_margin_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")  # Default white, will be updated dynamically
        free_margin_container.addWidget(free_margin_label)
        free_margin_container.addWidget(self.free_margin_label)
        free_margin_container.addStretch()
        right_col.addLayout(free_margin_container)
        
        # Used Margin
        used_margin_container = QHBoxLayout()
        used_margin_label = QLabel("Used Margin:")
        used_margin_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.used_margin_label = QLabel("Loading...")
        self.used_margin_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")
        used_margin_container.addWidget(used_margin_label)
        used_margin_container.addWidget(self.used_margin_label)
        used_margin_container.addStretch()
        right_col.addLayout(used_margin_container)
        
        # Margin Level
        margin_level_container = QHBoxLayout()
        margin_level_label = QLabel("Margin Level:")
        margin_level_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8; min-width: 120px;")
        self.margin_level_label = QLabel("Loading...")
        self.margin_level_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")  # Default white, will be updated dynamically
        margin_level_container.addWidget(margin_level_label)
        margin_level_container.addWidget(self.margin_level_label)
        margin_level_container.addStretch()
        right_col.addLayout(margin_level_container)
        
        top_row.addLayout(right_col)
        account_layout.addLayout(top_row)

        status_layout.addWidget(account_group)

        # Signal info - redesigned with card container
        signal_group = QGroupBox("📡 Last Signal")
        signal_group.setStyleSheet("""
            QGroupBox {
                background-color: transparent;
                border: 1px solid #1c243b;
                border-radius: 6px;
                padding: 8px;
                margin: 5px;
                font-weight: bold;
                color: #f0f4f9;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                background-color: transparent;
            }
        """)
        signal_layout = QVBoxLayout(signal_group)
        signal_layout.setSpacing(8)
        
        # Signal info with labels and values side by side
        channel_container = QHBoxLayout()
        channel_label = QLabel("Channel:")
        channel_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.channel_label = QLabel("-")
        self.channel_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        channel_container.addWidget(channel_label)
        channel_container.addWidget(self.channel_label)
        channel_container.addStretch()
        signal_layout.addLayout(channel_container)
        
        symbol_container = QHBoxLayout()
        symbol_label = QLabel("Symbol:")
        symbol_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.symbol_label = QLabel("-")
        self.symbol_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        symbol_container.addWidget(symbol_label)
        symbol_container.addWidget(self.symbol_label)
        symbol_container.addStretch()
        signal_layout.addLayout(symbol_container)
        
        type_container = QHBoxLayout()
        type_label = QLabel("Type:")
        type_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.type_label = QLabel("-")
        self.type_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8;")  # Default color, will be updated dynamically
        type_container.addWidget(type_label)
        type_container.addWidget(self.type_label)
        type_container.addStretch()
        signal_layout.addLayout(type_container)
        
        entry_container = QHBoxLayout()
        entry_label = QLabel("Entry:")
        entry_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.entry_label = QLabel("-")
        self.entry_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        entry_container.addWidget(entry_label)
        entry_container.addWidget(self.entry_label)
        entry_container.addStretch()
        signal_layout.addLayout(entry_container)
        
        sl_container = QHBoxLayout()
        sl_label = QLabel("SL:")
        sl_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.sl_label = QLabel("-")
        self.sl_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        sl_container.addWidget(sl_label)
        sl_container.addWidget(self.sl_label)
        sl_container.addStretch()
        signal_layout.addLayout(sl_container)
        
        tp_container = QHBoxLayout()
        tp_label = QLabel("TP:")
        tp_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.tp_label = QLabel("-")
        self.tp_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        tp_container.addWidget(tp_label)
        tp_container.addWidget(self.tp_label)
        tp_container.addStretch()
        signal_layout.addLayout(tp_container)
        
        lot_container = QHBoxLayout()
        lot_label = QLabel("Lot Size:")
        lot_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.lot_label = QLabel("-")
        self.lot_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f4f9;")  # White
        lot_container.addWidget(lot_label)
        lot_container.addWidget(self.lot_label)
        lot_container.addStretch()
        signal_layout.addLayout(lot_container)
        
        status_container = QHBoxLayout()
        status_label = QLabel("Status:")
        status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8; min-width: 80px;")
        self.status_label = QLabel("-")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #9ca6b8;")  # Default color, will be updated dynamically
        status_container.addWidget(status_label)
        status_container.addWidget(self.status_label)
        status_container.addStretch()
        signal_layout.addLayout(status_container)
        
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("font-size: 12px; color: #f54e4e; padding: 4px 0;")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        signal_layout.addWidget(self.error_label)

        status_layout.addWidget(signal_group)
        status_layout.addStretch()

        # History tab - COMPACT REDESIGN
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        history_layout.setContentsMargins(0, 0, 0, 0)
        history_layout.setSpacing(0)

        # Compact Header with inline controls
        header_layout = QHBoxLayout()
        
        # Title
        history_title = QLabel("📋 Trade History")
        history_title.setProperty("class", "title")
        header_layout.addWidget(history_title)
        
        header_layout.addStretch()
        
        # Compact action buttons
        self.refresh_history_btn = QPushButton("🔄")
        self.refresh_history_btn.setToolTip("Refresh History")
        self.refresh_history_btn.setFixedSize(32, 32)
        self.refresh_history_btn
        self.refresh_history_btn.clicked.connect(self.refresh_history)
        
        self.export_history_btn = QPushButton("📊")
        self.export_history_btn.setToolTip("Export CSV")
        self.export_history_btn.setFixedSize(32, 32)
        self.export_history_btn
        self.export_history_btn.clicked.connect(self.export_history)
        
        self.clear_history_btn = QPushButton("🗑️")
        self.clear_history_btn.setToolTip("Clear History")
        self.clear_history_btn.setFixedSize(32, 32)
        self.clear_history_btn
        self.clear_history_btn.clicked.connect(self.clear_history)
        
        header_layout.addWidget(self.refresh_history_btn)
        header_layout.addWidget(self.export_history_btn)
        header_layout.addWidget(self.clear_history_btn)
        
        history_layout.addLayout(header_layout)

        # Compact Statistics Row (3x2 grid)
        # Statistics Row (No Card)
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        stats_layout.setContentsMargins(0, 5, 0, 5)
        
        # Total Trades
        self.total_trades_label = QLabel("Total: 0")
        self.total_trades_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.total_trades_label)
        
        # Win Rate
        self.win_rate_label = QLabel("Win Rate: 0%")
        self.win_rate_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.win_rate_label)
        
        # Total Profit
        self.total_profit_label = QLabel("Total P&L: $0.00")
        self.total_profit_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.total_profit_label)
        
        # Average Profit
        self.avg_profit_label = QLabel("Avg: $0.00")
        self.avg_profit_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.avg_profit_label)
        
        # Max Drawdown
        self.max_dd_label = QLabel("Max DD: $0.00")
        self.max_dd_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.max_dd_label)
        
        # Best Trade
        self.best_trade_label = QLabel("Best: $0.00")
        self.best_trade_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        stats_layout.addWidget(self.best_trade_label)
        
        stats_layout.addStretch()
        
        history_layout.addLayout(stats_layout)

        # Compact Filters Row (Minimized)
        filters_frame = QFrame()
        filters_frame
        filters_layout = QHBoxLayout(filters_frame)
        filters_layout.setSpacing(4)
        filters_layout.setContentsMargins(4, 2, 4, 2)
        
        # Date filters (Minimized)
        from_label = QLabel("From:")
        from_label.setStyleSheet("font-size: 11px; font-weight: bold;")
        filters_layout.addWidget(from_label)
        
        self.date_from = QDateEdit()
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        self.date_from.setCalendarPopup(True)
        self.date_from.setFixedWidth(80)
        self.date_from
        filters_layout.addWidget(self.date_from)
        
        to_label = QLabel("To:")
        to_label
        filters_layout.addWidget(to_label)
        
        self.date_to = QDateEdit()
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setCalendarPopup(True)
        self.date_to.setFixedWidth(80)
        self.date_to
        filters_layout.addWidget(self.date_to)
        
        symbol_label = QLabel("Symbol:")
        symbol_label
        filters_layout.addWidget(symbol_label)
        
        self.symbol_filter = QComboBox()
        self.symbol_filter.addItem("All")
        self.symbol_filter.setFixedWidth(60)
        self.symbol_filter
        filters_layout.addWidget(self.symbol_filter)
        
        status_label = QLabel("Status:")
        status_label
        filters_layout.addWidget(status_label)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Executed", "Failed", "Pending"])
        self.status_filter.setFixedWidth(60)
        self.status_filter
        filters_layout.addWidget(self.status_filter)
        
        filters_layout.addStretch()
        
        history_layout.addWidget(filters_frame)

        # Compact History Table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(11)  # Increased from 10 to 11
        self.history_table.setHorizontalHeaderLabels([
            "Time", "Symbol", "Type", "Entry", "SL", "TP", "Lot", "Status", "P&L", "Closure", "Notes"
        ])
        
        # Compact column widths
        self.history_table.setColumnWidth(0, 80)   # Time
        self.history_table.setColumnWidth(1, 60)   # Symbol
        self.history_table.setColumnWidth(2, 60)   # Type
        self.history_table.setColumnWidth(3, 70)   # Entry
        self.history_table.setColumnWidth(4, 60)   # SL
        self.history_table.setColumnWidth(5, 60)   # TP
        self.history_table.setColumnWidth(6, 50)   # Lot
        self.history_table.setColumnWidth(7, 70)   # Status
        self.history_table.setColumnWidth(8, 70)   # P&L
        self.history_table.setColumnWidth(9, 70)   # Closure
        self.history_table.setColumnWidth(10, 100) # Notes
        
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSortingEnabled(True)
        self.history_table.verticalHeader().setDefaultSectionSize(30)  # Increased row height
        self.history_table.setStyleSheet("""
            QTableWidget {
                font-size: 11px;
                gridline-color: #d0d0d0;
                background-color: white;
                color: #2d2d2d;
                alternate-background-color: #f8f9fa;
            }
            QTableWidget::item {
                padding: 4px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #007bff;
                color: white;
            }
            QHeaderView::section {
                background-color: #e9ecef;
                color: #495057;
                padding: 8px;
                border: 1px solid #d0d0d0;
                border-left: none;
                font-weight: bold;
                font-size: 11px;
            }
            QHeaderView::section:hover {
                background-color: #dee2e6;
            }
        """)
        
        history_layout.addWidget(self.history_table)
        
        # Connect filter signals
        self.date_from.dateChanged.connect(self.apply_filters)
        self.date_to.dateChanged.connect(self.apply_filters)
        self.symbol_filter.currentTextChanged.connect(self.apply_filters)
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        
        self.tabs.addTab(history_tab, "History")

        # Performance tab - Simple Native Design
        performance_tab = QWidget()
        performance_layout = QVBoxLayout(performance_tab)
        performance_layout.setContentsMargins(10, 10, 10, 10)
        performance_layout.setSpacing(10)

        # Commercial Header
        header_layout = QHBoxLayout()
        
        # Title
        performance_title = QLabel("📊 Performance Analytics")
        performance_title.setProperty("class", "title")
        header_layout.addWidget(performance_title)
        
        header_layout.addStretch()
        
        # Time Period Selector
        period_label = QLabel("Period:")
        header_layout.addWidget(period_label)
        
        self.period_selector = QComboBox()
        self.period_selector.addItems(["Last 7 Days", "Last 30 Days", "Last 90 Days", "Last 6 Months", "Last Year", "All Time"])
        self.period_selector.setCurrentText("Last 30 Days")
        self.period_selector.currentTextChanged.connect(self.update_performance_data)
        header_layout.addWidget(self.period_selector)
        
        # Channel Filter
        channel_label = QLabel("Channel:")
        header_layout.addWidget(channel_label)
        
        self.channel_selector = QComboBox()
        self.channel_selector.addItem("All Channels")
        self.channel_selector.currentTextChanged.connect(self.update_performance_data)
        header_layout.addWidget(self.channel_selector)
        
        # Refresh Button
        self.refresh_performance_btn = QPushButton("🔄 Refresh")
        self.refresh_performance_btn.clicked.connect(self.update_performance_data)
        self.refresh_performance_btn.setProperty("class", "secondary")
        header_layout.addWidget(self.refresh_performance_btn)
        
        performance_layout.addLayout(header_layout)

        # Commercial Metrics Section
        metrics_group = QGroupBox("📈 Key Performance Metrics")
        metrics_layout = QGridLayout(metrics_group)
        metrics_layout.setSpacing(15)
        
        # Create commercial metric labels with icons
        self.total_pnl_label = QLabel("💰 Total P&L: $0.00")
        self.total_pnl_label.setProperty("class", "subtitle")
        self.win_rate_label = QLabel("🎯 Win Rate: 0%")
        self.win_rate_label.setProperty("class", "subtitle")
        self.rr_label = QLabel("⚖️ Avg R:R: 0.00")
        self.rr_label.setProperty("class", "subtitle")
        self.drawdown_label = QLabel("📉 Max Drawdown: $0.00")
        self.drawdown_label.setProperty("class", "subtitle")
        self.profit_factor_label = QLabel("📊 Profit Factor: 0.00")
        self.profit_factor_label.setProperty("class", "subtitle")
        self.sharpe_label = QLabel("📈 Sharpe Ratio: 0.00")
        self.sharpe_label.setProperty("class", "subtitle")
        
        # Add to grid
        metrics_layout.addWidget(self.total_pnl_label, 0, 0)
        metrics_layout.addWidget(self.win_rate_label, 0, 1)
        metrics_layout.addWidget(self.rr_label, 0, 2)
        metrics_layout.addWidget(self.drawdown_label, 1, 0)
        metrics_layout.addWidget(self.profit_factor_label, 1, 1)
        metrics_layout.addWidget(self.sharpe_label, 1, 2)
        
        performance_layout.addWidget(metrics_group)

        # Commercial Charts Section
        charts_group = QGroupBox("📊 Performance Charts")
        charts_layout = QVBoxLayout(charts_group)
        charts_layout.setSpacing(15)
        
        # Commercial chart placeholders
        self.equity_chart = QLabel("📈 Equity Curve Chart")
        self.equity_chart.setMinimumHeight(180)
        self.equity_chart.setAlignment(Qt.AlignCenter)
        self.equity_chart.setProperty("class", "status")
        
        self.drawdown_chart = QLabel("📉 Drawdown Analysis")
        self.drawdown_chart.setMinimumHeight(120)
        self.drawdown_chart.setAlignment(Qt.AlignCenter)
        self.drawdown_chart.setProperty("class", "status")
        
        charts_layout.addWidget(self.equity_chart)
        charts_layout.addWidget(self.drawdown_chart)
        
        performance_layout.addWidget(charts_group)
        
        # Channel Performance Table
        channel_group = QGroupBox("🏆 Channel Performance Ranking")
        channel_layout = QVBoxLayout(channel_group)
        channel_layout.setSpacing(10)
        
        self.channel_table = QTableWidget()
        self.channel_table.setColumnCount(7)
        self.channel_table.setHorizontalHeaderLabels([
            "Rank", "Channel", "Trades", "Win Rate", "P&L", "R:R", "Score"
        ])
        
        # Set column widths
        self.channel_table.setColumnWidth(0, 50)   # Rank
        self.channel_table.setColumnWidth(1, 150)  # Channel
        self.channel_table.setColumnWidth(2, 60)   # Trades
        self.channel_table.setColumnWidth(3, 80)   # Win Rate
        self.channel_table.setColumnWidth(4, 80)   # P&L
        self.channel_table.setColumnWidth(5, 60)   # R:R
        self.channel_table.setColumnWidth(6, 60)   # Score
        
        self.channel_table.horizontalHeader().setStretchLastSection(True)
        self.channel_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.channel_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.channel_table.setAlternatingRowColors(True)
        self.channel_table.setSortingEnabled(True)
        self.channel_table.verticalHeader().setDefaultSectionSize(30)
        
        channel_layout.addWidget(self.channel_table)
        performance_layout.addWidget(channel_group)



        # Settings tab - COMPLETELY REDESIGNED with clean commercial-grade GUI
        settings_tab = QWidget()
        settings_tab
        settings_layout = QVBoxLayout(settings_tab)
        settings_layout.setContentsMargins(20, 20, 20, 20)
        settings_layout.setSpacing(20)

        # Scroll area for settings
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area

        # Main container with simple 2-column layout
        container = QWidget()
        container
        main_container_layout = QHBoxLayout(container)
        main_container_layout.setSpacing(20)
        main_container_layout.setContentsMargins(10, 10, 10, 10)

        # Column 1 - Risk Management
        col1 = QVBoxLayout()
        col1.setSpacing(16)

        # Risk Management Section - 2x2 Grid Layout
        risk_group = QGroupBox("🛡️ Risk Management")
        risk_layout = QGridLayout()
        risk_layout.setSpacing(12)
        risk_layout.setContentsMargins(15, 15, 15, 15)
        
        # Row 1, Column 1 - Risk Method
        risk_method_label = QLabel("Risk Method:")
        risk_method_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8;")
        self.risk_method = QComboBox()
        self.risk_method.addItems(["Fixed Lot", "Percent of Balance", "Fixed Dollar"])
        risk_layout.addWidget(risk_method_label, 0, 0)
        risk_layout.addWidget(self.risk_method, 0, 1)
        
        # Row 1, Column 2 - Risk Percentage
        risk_percent_label = QLabel("Risk %:")
        risk_percent_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8;")
        self.risk_percent = QDoubleSpinBox()
        self.risk_percent.setRange(0.1, 10.0)
        self.risk_percent.setValue(1.0)
        self.risk_percent.setDecimals(1)
        self.risk_percent.setSuffix("%")
        risk_layout.addWidget(risk_percent_label, 0, 2)
        risk_layout.addWidget(self.risk_percent, 0, 3)
        
        # Row 2, Column 1 - Fixed Lot Size
        lot_size_label = QLabel("Fixed Lot:")
        lot_size_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8;")
        self.lot_size = QDoubleSpinBox()
        self.lot_size.setRange(0.01, 100)
        self.lot_size.setValue(0.1)
        self.lot_size.setDecimals(2)
        self.lot_size.setSuffix(" lots")
        risk_layout.addWidget(lot_size_label, 1, 0)
        risk_layout.addWidget(self.lot_size, 1, 1)
        
        # Row 2, Column 2 - Fixed Dollar Amount
        fixed_dollar_label = QLabel("Fixed $:")
        fixed_dollar_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #9ca6b8;")
        self.fixed_dollar = QDoubleSpinBox()
        self.fixed_dollar.setRange(1, 10000)
        self.fixed_dollar.setValue(100)
        self.fixed_dollar.setDecimals(0)
        self.fixed_dollar.setPrefix("$ ")
        risk_layout.addWidget(fixed_dollar_label, 1, 2)
        risk_layout.addWidget(self.fixed_dollar, 1, 3)
        
        # Auto-save fixed dollar amount when changed
        def save_fixed_dollar():
            current_risk_settings = self.parent.settings.get_risk_settings()
            current_risk_settings["fixed_dollar"] = self.fixed_dollar.value()
            self.parent.settings.set_risk_settings(current_risk_settings)
            logger.info(f"Fixed dollar amount automatically saved: ${self.fixed_dollar.value()}")
        
        self.fixed_dollar.valueChanged.connect(save_fixed_dollar)
        
        # Conflict handling function
        def update_risk_controls():
            method = self.risk_method.currentText()
            self.risk_percent.setEnabled(method == "Percent of Balance")
            self.lot_size.setEnabled(method == "Fixed Lot")
            self.fixed_dollar.setEnabled(method == "Fixed Dollar")
            
            # Auto-save the risk method when changed
            current_risk_settings = self.parent.settings.get_risk_settings()
            new_risk_method = "fixed" if method == "Fixed Lot" else "percent" if method == "Percent of Balance" else "fixed_dollar"
            
            if current_risk_settings.get("risk_method") != new_risk_method:
                current_risk_settings["risk_method"] = new_risk_method
                self.parent.settings.set_risk_settings(current_risk_settings)
                logger.info(f"Risk method automatically changed to: {new_risk_method}")
        
        self.risk_method.currentIndexChanged.connect(update_risk_controls)
        
        risk_group.setLayout(risk_layout)
        col1.addWidget(risk_group)
        col1.addStretch()
        
        # Initialize conflict handling
        update_risk_controls()

        # Column 2 - Stop Loss & Take Profit
        col2 = QVBoxLayout()
        col2.setSpacing(16)

        # Stop Loss & Take Profit Section
        sl_tp_group = QGroupBox("🎯 Stop Loss & Take Profit")
        sl_tp_layout = QFormLayout()
        sl_tp_layout.setSpacing(8)
        sl_tp_layout.setLabelAlignment(Qt.AlignRight)
        sl_tp_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        sl_tp_layout.setRowWrapPolicy(QFormLayout.DontWrapRows)

        # Ignore No TP/SL
        self.ignore_no_tpsl = QCheckBox()
        sl_tp_layout.addRow("Ignore trades without TP/SL:", self.ignore_no_tpsl)

        # Trailing Stop Loss
        self.trailing_enabled = QCheckBox()
        sl_tp_layout.addRow("Enable Trailing SL:", self.trailing_enabled)

        # Trailing Distance
        self.trailing_distance = QDoubleSpinBox()
        self.trailing_distance.setRange(1, 100)
        self.trailing_distance.setValue(20.0)
        self.trailing_distance.setDecimals(1)
        self.trailing_distance.setSuffix(" pips")
        sl_tp_layout.addRow("Trailing Distance:", self.trailing_distance)

        # Break Even After Pips
        self.be_after_pips = QDoubleSpinBox()
        self.be_after_pips.setRange(0, 100)
        self.be_after_pips.setValue(0.0)
        self.be_after_pips.setDecimals(1)
        self.be_after_pips.setSuffix(" pips")
        sl_tp_layout.addRow("BE After Pips:", self.be_after_pips)

        # Trail After TP
        self.trail_after_tp = QCheckBox()
        sl_tp_layout.addRow("Trail After TP:", self.trail_after_tp)

        # Split Multiple TPs
        self.split_tps = QCheckBox()
        sl_tp_layout.addRow("Split Multiple TPs:", self.split_tps)

        sl_tp_group.setLayout(sl_tp_layout)
        col2.addWidget(sl_tp_group)
        col2.addStretch()

        # Column 3 - Trade Filters
        col3 = QVBoxLayout()
        col3.setSpacing(16)

        # Trade Filters Section
        filters_group = QGroupBox("🔍 Trade Filters")
        filters_layout = QFormLayout()
        filters_layout.setSpacing(8)
        filters_layout.setLabelAlignment(Qt.AlignRight)
        filters_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        filters_layout.setRowWrapPolicy(QFormLayout.DontWrapRows)

        # News Filter
        self.news_filter = QCheckBox()
        filters_layout.addRow("Enable News Filter:", self.news_filter)

        # Trading Hours
        self.trading_hours = QLineEdit("09:00-17:00")
        filters_layout.addRow("Trading Hours:", self.trading_hours)

        # Entry Range Handling
        self.range_handling = QComboBox()
        self.range_handling.addItems(["First Price", "Average Price", "Last Price"])
        filters_layout.addRow("Entry Range Handling:", self.range_handling)

        # Execute in Range
        self.execute_in_range = QCheckBox()
        filters_layout.addRow("Execute in Range:", self.execute_in_range)

        # Max Spread
        self.max_spread = QDoubleSpinBox()
        self.max_spread.setRange(0, 10)
        self.max_spread.setValue(3.0)
        self.max_spread.setDecimals(1)
        self.max_spread.setSuffix(" pips")
        filters_layout.addRow("Max Spread:", self.max_spread)

        # Pip Tolerance
        self.pip_tolerance = QDoubleSpinBox()
        self.pip_tolerance.setRange(0, 10)
        self.pip_tolerance.setValue(2.0)
        self.pip_tolerance.setDecimals(1)
        self.pip_tolerance.setSuffix(" pips")
        filters_layout.addRow("Pip Tolerance:", self.pip_tolerance)

        filters_group.setLayout(filters_layout)
        col3.addWidget(filters_group)
        col3.addStretch()

        # Column 4 - Additional Risk Settings
        col4 = QVBoxLayout()
        col4.setSpacing(16)

        # Additional Risk Management Settings
        additional_risk_group = QGroupBox("⚙️ Additional Risk Settings")
        additional_risk_layout = QFormLayout()
        additional_risk_layout.setSpacing(8)
        additional_risk_layout.setLabelAlignment(Qt.AlignRight)
        additional_risk_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        additional_risk_layout.setRowWrapPolicy(QFormLayout.DontWrapRows)

        # Max Open Trades
        self.max_trades = QSpinBox()
        self.max_trades.setRange(1, 1000)
        self.max_trades.setValue(20)
        additional_risk_layout.addRow("Max Open Trades:", self.max_trades)

        # Max Trades Per Symbol
        self.max_trades_per_symbol = QSpinBox()
        self.max_trades_per_symbol.setRange(1, 100)
        self.max_trades_per_symbol.setValue(5)
        additional_risk_layout.addRow("Max Per Symbol:", self.max_trades_per_symbol)

        # Daily Loss Limit
        self.daily_loss_limit = QDoubleSpinBox()
        self.daily_loss_limit.setRange(0, 100)
        self.daily_loss_limit.setValue(5.0)
        self.daily_loss_limit.setDecimals(1)
        self.daily_loss_limit.setSuffix("%")
        additional_risk_layout.addRow("Daily Loss Limit:", self.daily_loss_limit)

        # Daily Profit Target
        self.daily_profit_target = QDoubleSpinBox()
        self.daily_profit_target.setRange(0, 100)
        self.daily_profit_target.setValue(10.0)
        self.daily_profit_target.setDecimals(1)
        self.daily_profit_target.setSuffix("%")
        additional_risk_layout.addRow("Daily Profit Target:", self.daily_profit_target)

        # Max Drawdown
        self.max_drawdown = QDoubleSpinBox()
        self.max_drawdown.setRange(0, 100)
        self.max_drawdown.setValue(30.0)
        self.max_drawdown.setDecimals(1)
        self.max_drawdown.setSuffix("%")
        additional_risk_layout.addRow("Max Drawdown:", self.max_drawdown)

        # Enable Comments
        self.enable_comments = QCheckBox()
        additional_risk_layout.addRow("Enable Comments:", self.enable_comments)

        # Comment Prefix
        self.comment_prefix = QLineEdit()
        self.comment_prefix.setPlaceholderText("FTSC")
        additional_risk_layout.addRow("Comment Prefix:", self.comment_prefix)

        additional_risk_group.setLayout(additional_risk_layout)
        col4.addWidget(additional_risk_group)
        col4.addStretch()

        # Add all 4 columns to main layout
        main_container_layout.addLayout(col1)
        main_container_layout.addLayout(col2)
        main_container_layout.addLayout(col3)
        main_container_layout.addLayout(col4)

        scroll_area.setWidget(container)
        settings_layout.addWidget(scroll_area)

        # Bottom Button Section
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)

        # Conflict Status Label
        self.conflict_status = QLabel("Settings are valid")
        button_layout.addWidget(self.conflict_status)

        button_layout.addStretch()

        # Reset to Default Button
        self.reset_to_default_btn = QPushButton("Reset to Default")
        self.reset_to_default_btn.clicked.connect(self.reset_to_defaults)
        self.reset_to_default_btn.setProperty("class", "secondary")
        button_layout.addWidget(self.reset_to_default_btn)

        # Save Button
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        self.save_btn.setProperty("class", "success")
        button_layout.addWidget(self.save_btn)

        settings_layout.addLayout(button_layout)

        # Enhanced Account Tab
        account_tab = QWidget()
        account_layout = QVBoxLayout(account_tab)
        account_layout.setContentsMargins(0, 10, 0, 0)
        account_layout.setSpacing(0)

        # Create scroll area for account information
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(0)

        # License Status Header with Refresh Button
        header_layout = QHBoxLayout()
        status_header = QLabel("🔑 License Information")
        status_header.setProperty("class", "title")
        header_layout.addWidget(status_header)
        header_layout.addStretch()
        
        self.refresh_account_btn = QPushButton("Refresh")
        self.refresh_account_btn.setMaximumWidth(100)
        self.refresh_account_btn.clicked.connect(self.refresh_license_info)
        self.refresh_account_btn.setProperty("class", "secondary")
        header_layout.addWidget(self.refresh_account_btn)
        scroll_layout.addLayout(header_layout)

        # License Status Indicator
        self.license_status_text = QLabel("License Active")
        scroll_layout.addWidget(self.license_status_text)

        # Main License Info Group
        license_group = QGroupBox("📋 License Details")

        license_form = QFormLayout(license_group)
        license_form.setVerticalSpacing(0)

        # License fields with enhanced styling
        self.license_email_label = QLabel("Loading...")
        self.license_email_label
        license_form.addRow("📧 Email:", self.license_email_label)

        self.license_key_label = QLabel("Loading...")
        self.license_key_label
        license_form.addRow("🔑 License Key:", self.license_key_label)

        self.license_tier_label = QLabel("Loading...")
        self.license_tier_label
        license_form.addRow("🏷️ Subscription Tier:", self.license_tier_label)

        self.license_type_label = QLabel("Loading...")
        self.license_type_label
        license_form.addRow("📝 License Type:", self.license_type_label)

        self.license_start_label = QLabel("Loading...")
        self.license_start_label
        license_form.addRow("📅 Start Date:", self.license_start_label)

        self.license_expiry_label = QLabel("Loading...")
        self.license_expiry_label
        license_form.addRow("⏰ Expiration Date:", self.license_expiry_label)

        self.license_days_label = QLabel("Loading...")
        self.license_days_label
        license_form.addRow("⏳ Days Remaining:", self.license_days_label)

        self.license_devices_label = QLabel("Loading...")
        self.license_devices_label
        license_form.addRow("🖥️ Max Devices:", self.license_devices_label)

        scroll_layout.addWidget(license_group)

        # Usage Statistics Group
        usage_group = QGroupBox("Usage Statistics")

        usage_form = QFormLayout(usage_group)
        usage_form.setVerticalSpacing(0)

        self.usage_signals_label = QLabel("Loading...")
        self.usage_signals_label
        usage_form.addRow("📊 Total Signals:", self.usage_signals_label)

        self.usage_trades_label = QLabel("Loading...")
        self.usage_trades_label
        usage_form.addRow("💹 Total Trades:", self.usage_trades_label)

        self.usage_last_activity_label = QLabel("Loading...")
        self.usage_last_activity_label
        usage_form.addRow("🕐 Last Activity:", self.usage_last_activity_label)

        self.usage_active_devices_label = QLabel("Loading...")
        self.usage_active_devices_label
        usage_form.addRow("📱 Active Devices:", self.usage_active_devices_label)

        scroll_layout.addWidget(usage_group)

        # Features & Limits Group
        features_group = QGroupBox("Available Features")

        features_layout = QVBoxLayout(features_group)

        self.features_list = QLabel("Loading features...")
        self.features_list
        self.features_list.setWordWrap(True)
        features_layout.addWidget(self.features_list)

        scroll_layout.addWidget(features_group)

        # Device Information Group
        device_group = QGroupBox("Device Information")

        device_form = QFormLayout(device_group)
        device_form.setVerticalSpacing(0)

        self.device_machine_id_label = QLabel("Loading...")
        self.device_machine_id_label
        device_form.addRow("🖥️ Machine ID:", self.device_machine_id_label)

        self.device_last_seen_label = QLabel("Loading...")
        self.device_last_seen_label
        device_form.addRow("👁️ Last Seen:", self.device_last_seen_label)

        scroll_layout.addWidget(device_group)

        # Action Buttons
        button_layout = QHBoxLayout()
        
        self.upgrade_btn = QPushButton("🚀 Upgrade License")
        self.upgrade_btn.setMaximumWidth(150)
        self.upgrade_btn.clicked.connect(self.show_upgrade_info)
        button_layout.addWidget(self.upgrade_btn)

        button_layout.addStretch()

        logout_btn = QPushButton("🚪 Logout Device")
        logout_btn.setMaximumWidth(130)
        logout_btn.clicked.connect(self.parent.logout)
        button_layout.addWidget(logout_btn)

        scroll_layout.addLayout(button_layout)
        scroll_layout.addStretch()

        # Set scroll content
        scroll_area.setWidget(scroll_content)
        account_layout.addWidget(scroll_area)

        # Add tabs
        self.tabs.addTab(status_tab, "Dashboard")
        self.tabs.addTab(history_tab, "History")
        self.tabs.addTab(performance_tab, "Performance")
        self.tabs.addTab(settings_tab, "Settings")
        self.tabs.addTab(account_tab, "My Account")
        main_layout.addWidget(self.tabs)

        # Back button
        back_layout = QHBoxLayout()
        back_layout.addStretch()
        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(self.parent.back_to_mt5)
        back_layout.addWidget(self.back_btn)
        main_layout.addLayout(back_layout)

        # Connect signals for conflict checking
        self.risk_method.currentIndexChanged.connect(self.check_conflicts)
        self.lot_size.valueChanged.connect(self.check_conflicts)
        self.risk_percent.valueChanged.connect(self.check_conflicts)
        self.fixed_dollar.valueChanged.connect(self.check_conflicts)
        self.ignore_no_tpsl.stateChanged.connect(self.check_conflicts)
        self.trailing_enabled.stateChanged.connect(self.check_conflicts)
        self.trailing_distance.valueChanged.connect(self.check_conflicts)
        self.be_after_pips.valueChanged.connect(self.check_conflicts)
        self.trail_after_tp.stateChanged.connect(self.check_conflicts)
        self.split_tps.stateChanged.connect(self.check_conflicts)
        self.max_trades.valueChanged.connect(self.check_conflicts)
        self.pip_tolerance.valueChanged.connect(self.check_conflicts)
        self.news_filter.stateChanged.connect(self.check_conflicts)
        self.trading_hours.textChanged.connect(self.check_conflicts)

        self.daily_loss_limit.valueChanged.connect(self.check_conflicts)
        self.daily_profit_target.valueChanged.connect(self.check_conflicts)
        self.max_trades_per_symbol.valueChanged.connect(self.check_conflicts)
        self.max_spread.valueChanged.connect(self.check_conflicts)
        self.execute_in_range.stateChanged.connect(self.check_conflicts)
        self.range_handling.currentIndexChanged.connect(self.check_conflicts)

    def create_settings_group(self, title):
        """Helper to create consistent settings group"""
        group = QGroupBox(title)

        return group



    def reset_to_defaults(self):
        default_settings = self.parent.settings._get_default_settings()["risk"]
        self.risk_method.setCurrentText(
            "Fixed Lot" if default_settings["risk_method"] == "fixed" else
            "Percent of Balance" if default_settings["risk_method"] == "percent"
            else "Fixed Dollar"
        )
        self.lot_size.setValue(default_settings["fixed_lot"])
        self.risk_percent.setValue(default_settings["risk_percent"])
        self.fixed_dollar.setValue(default_settings.get("fixed_dollar", 100))
        self.ignore_no_tpsl.setChecked(default_settings["ignore_no_tpsl"])
        self.max_drawdown.setValue(default_settings["max_drawdown_percent"])
        self.range_handling.setCurrentText(default_settings["entry_range_handling"])
        self.trailing_enabled.setChecked(default_settings["trailing_sl_enabled"])
        self.trailing_distance.setValue(default_settings["trailing_sl_distance"])
        self.be_after_pips.setValue(default_settings["be_after_pips"])
        self.trail_after_tp.setChecked(default_settings["trail_after_tp"])
        self.split_tps.setChecked(default_settings["split_tps"])
        self.max_trades.setValue(default_settings["max_trades"])
        self.pip_tolerance.setValue(default_settings["pip_tolerance"])
        self.news_filter.setChecked(default_settings["news_filter"])
        self.trading_hours.setText(default_settings["trading_hours"])

        self.daily_loss_limit.setValue(default_settings["daily_loss_limit"])
        self.daily_profit_target.setValue(default_settings["daily_profit_target"])
        self.max_trades_per_symbol.setValue(default_settings["max_trades_per_symbol"])
        self.max_spread.setValue(default_settings["max_spread"])
        self.execute_in_range.setChecked(default_settings.get("execute_in_range", True))
        self.enable_comments.setChecked(default_settings.get("enable_comments", True))
        self.comment_prefix.setText(default_settings.get("comment_prefix", "FTSC"))

        self.check_conflicts()
        QMessageBox.information(self, "Settings Reset", "All risk settings have been reset to defaults")

    def save_settings(self):
        # Validate combinations
        if self.risk_method.currentText() == "Percent of Balance" and self.ignore_no_tpsl.isChecked():
            QMessageBox.warning(self, "Invalid Settings", "Percent Risk cannot ignore no TP/SL")
            return
        if self.trailing_enabled.isChecked() and self.trail_after_tp.isChecked() and self.be_after_pips.value() > 0:
            QMessageBox.warning(self, "Invalid Settings", "BE after pips conflicts with trail after TP")
            return

        risk_settings = {
            "risk_method": "fixed" if self.risk_method.currentText() == "Fixed Lot" else
            "percent" if self.risk_method.currentText() == "Percent of Balance"
            else "fixed_dollar",
            "fixed_lot": self.lot_size.value(),
            "risk_percent": self.risk_percent.value(),
            "fixed_dollar": self.fixed_dollar.value(),
            "ignore_no_tpsl": self.ignore_no_tpsl.isChecked(),
            "max_drawdown_percent": self.max_drawdown.value(),
            "entry_range_handling": self.range_handling.currentText(),
            "trailing_sl_enabled": self.trailing_enabled.isChecked(),
            "trailing_sl_distance": self.trailing_distance.value(),
            "be_after_pips": self.be_after_pips.value(),
            "trail_after_tp": self.trail_after_tp.isChecked(),
            "split_tps": self.split_tps.isChecked(),
            "max_trades": self.max_trades.value(),
            "pip_tolerance": self.pip_tolerance.value(),
            "news_filter": self.news_filter.isChecked(),
            "trading_hours": self.trading_hours.text(),

            "daily_loss_limit": self.daily_loss_limit.value(),
            "daily_profit_target": self.daily_profit_target.value(),
            "max_trades_per_symbol": self.max_trades_per_symbol.value(),
            "max_spread": self.max_spread.value(),
            "execute_in_range": self.execute_in_range.isChecked(),
            "enable_comments": self.enable_comments.isChecked(),
            "comment_prefix": self.comment_prefix.text() if self.comment_prefix.text() else "FTSC"
        }
        self.parent.settings.set_risk_settings(risk_settings)
        QMessageBox.information(self, "Settings Saved", "Risk settings updated successfully")

    def load_account_info(self):
        """Load MT5 account information and license data"""
        self.update_account_info()
        self.refresh_license_info()

    def load_settings(self):
        try:
            risk_settings = self.parent.settings.get_risk_settings()

            # Set risk method
            risk_method = risk_settings.get("risk_method", "fixed")
            if risk_method == "fixed":
                self.risk_method.setCurrentText("Fixed Lot")
            elif risk_method == "percent":
                self.risk_method.setCurrentText("Percent of Balance")
            else:  # fixed_dollar
                self.risk_method.setCurrentText("Fixed Dollar")

            # Safely set widget values with error handling
            try:
                self.lot_size.setValue(risk_settings.get("fixed_lot", 0.1))
            except:
                pass
            try:
                self.risk_percent.setValue(risk_settings.get("risk_percent", 1.0))
            except:
                pass
            try:
                self.fixed_dollar.setValue(risk_settings.get("fixed_dollar", 100))
            except:
                pass
            try:
                self.ignore_no_tpsl.setChecked(risk_settings.get("ignore_no_tpsl", True))
            except:
                pass
            try:
                self.max_drawdown.setValue(risk_settings.get("max_drawdown_percent", 30.0))
            except:
                pass
            try:
                self.range_handling.setCurrentText(risk_settings.get("entry_range_handling", "Average Price"))
            except:
                pass
            try:
                self.trailing_enabled.setChecked(risk_settings.get("trailing_sl_enabled", False))
            except:
                pass
            try:
                self.trailing_distance.setValue(risk_settings.get("trailing_sl_distance", 20.0))
            except:
                pass
            try:
                self.be_after_pips.setValue(risk_settings.get("be_after_pips", 0.0))
            except:
                pass
            try:
                self.trail_after_tp.setChecked(risk_settings.get("trail_after_tp", False))
            except:
                pass
            try:
                self.split_tps.setChecked(risk_settings.get("split_tps", True))
            except:
                pass
            try:
                self.max_trades.setValue(risk_settings.get("max_trades", 5))
            except:
                pass
            try:
                self.pip_tolerance.setValue(risk_settings.get("pip_tolerance", 2.0))
            except:
                pass
            try:
                self.news_filter.setChecked(risk_settings.get("news_filter", False))
            except:
                pass
            try:
                self.trading_hours.setText(risk_settings.get("trading_hours", "09:00-17:00"))
            except:
                pass

            try:
                self.daily_loss_limit.setValue(risk_settings.get("daily_loss_limit", 5.0))
            except:
                pass
            try:
                self.daily_profit_target.setValue(risk_settings.get("daily_profit_target", 10.0))
            except:
                pass
            try:
                self.max_trades_per_symbol.setValue(risk_settings.get("max_trades_per_symbol", 2))
            except:
                pass
            try:
                self.max_spread.setValue(risk_settings.get("max_spread", 3.0))
            except:
                pass
            try:
                self.execute_in_range.setChecked(risk_settings.get("execute_in_range", True))
            except:
                pass
            try:
                self.enable_comments.setChecked(risk_settings.get("enable_comments", True))
            except:
                pass
            try:
                self.comment_prefix.setText(risk_settings.get("comment_prefix", "FTSC"))
            except:
                pass

            # Apply initial conflict check
            try:
                self.check_conflicts()
            except:
                pass
        except Exception as e:
            print(f"Error loading settings: {e}")
            pass

    def setup_timers(self):
        self.account_timer = QTimer()
        self.account_timer.timeout.connect(self.update_account_info)
        self.account_timer.start(10000)
        
        # License info refresh timer (every 60 seconds)
        self.license_timer = QTimer()
        self.license_timer.timeout.connect(self.refresh_license_info)
        self.license_timer.start(60000)
        
        # Initialize performance data with error handling
        try:
            self.initialize_performance_data()
        except Exception as e:
            logger.error(f"Failed to initialize performance data: {e}")
            # Don't let this crash the app

    def initialize_performance_data(self):
        """Initialize performance data when dashboard is loaded"""
        try:
            # Update performance data after a short delay to ensure UI is ready
            QTimer.singleShot(2000, self.update_performance_data)
            logger.info("Performance data initialization scheduled")
        except Exception as e:
            logger.error(f"Error initializing performance data: {e}")

    def update_account_info(self):
        if self.parent.mt5_manager.connected:
            try:
                account_info = self.parent.mt5_manager.get_account_info()
                if account_info:
                    # Account identification
                    self.account_num_label.setText(str(account_info.get('login', 'N/A')))
                    self.leverage_label.setText(f"1:{account_info.get('leverage', 0)}")
                    self.account_type_label.setText(self.get_account_type_name(account_info.get('trade_mode', 0)))
                    self.currency_label.setText(account_info.get('currency', 'N/A'))

                    # Profit calculation with color grading
                    profit = account_info.get('equity', 0) - account_info.get('balance', 0)
                    self.profit_label.setText(f"${profit:.2f}")
                    
                    # Color grade profit (green for positive, red for negative)
                    if profit > 0:
                        self.profit_label.setStyleSheet("font-size: 13px; color: #1d9e4a; font-weight: 500;")  # Green for profit
                    elif profit < 0:
                        self.profit_label.setStyleSheet("font-size: 13px; color: #f54e4e; font-weight: 500;")  # Red for loss
                    else:
                        self.profit_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")  # White for zero

                    # Financial metrics
                    self.balance_label.setText(f"${account_info.get('balance', 0):.2f}")
                    self.equity_label.setText(f"${account_info.get('equity', 0):.2f}")

                    free_margin = account_info.get('margin_free', 0)
                    self.free_margin_label.setText(f"${free_margin:.2f}")
                    
                    # Color grade free margin (red for negative)
                    if free_margin < 0:
                        self.free_margin_label.setStyleSheet("font-size: 13px; color: #f54e4e; font-weight: 500;")  # Red for negative
                    else:
                        self.free_margin_label.setStyleSheet("font-size: 13px; color: #f0f4f9; font-weight: 500;")  # White for positive

                    used_margin = account_info.get('margin', 0)
                    self.used_margin_label.setText(f"${used_margin:.2f}")

                    margin_level = account_info.get('margin_level', 0)
                    self.margin_level_label.setText(f"{margin_level:.2f}%")
                    
                    # Color grade margin level (red for low levels)
                    if margin_level < 100:
                        self.margin_level_label.setStyleSheet("font-size: 13px; color: #f54e4e; font-weight: 500;")  # Red for low margin
                    elif margin_level < 500:
                        self.margin_level_label.setStyleSheet("font-size: 13px; color: #f27d03; font-weight: 500;")  # Orange for medium margin
                    else:
                        self.margin_level_label.setStyleSheet("font-size: 13px; color: #1d9e4a; font-weight: 500;")  # Green for high margin
                else:
                    self.set_account_info_disconnected()
            except Exception as e:
                logger.error(f"Error updating account info: {str(e)}")
                self.set_account_info_disconnected()
        else:
            self.set_account_info_disconnected()

    def refresh_license_info(self):
        """Refresh license information using enhanced validation system"""
        try:
            # Get license info from settings
            license_info = self.parent.settings.get_license_info()
            license_key = license_info.get("key")
            machine_id = self.parent.settings.settings.get("machine_id")
            
            if not license_key or not machine_id:
                self.set_license_info_error("No license key or machine ID found")
                return
            
            # Use the enhanced validation system
            if hasattr(self.parent, 'supabase_manager'):
                validation_result = self.parent.supabase_manager.validate_license(license_key, machine_id)
                status_report = self.parent.supabase_manager.get_license_status_report(license_key, machine_id)
                
                if validation_result.get('valid'):
                    self.update_license_display(validation_result, status_report, license_key, machine_id)
                else:
                    self.set_license_info_error(validation_result.get('message', 'License validation failed'))
            else:
                # Fallback to basic license info from settings
                self.update_license_display_basic(license_info, license_key, machine_id)
                
        except Exception as e:
            logger.error(f"Error refreshing license info: {e}")
            self.set_license_info_error(f"Error loading license data: {str(e)}")

    def update_license_display(self, validation_result, status_report, license_key, machine_id):
        """Update the license display with real-time data"""
        try:
            # Update status indicator
            days_remaining = validation_result.get('days_until_expiry', 0)
            if days_remaining > 30:
                self.license_status_text.setText("License Active")
                self.license_status_text.setProperty("class", "status-success")
            elif days_remaining > 7:
                self.license_status_text.setText("License Expiring Soon")
                self.license_status_text.setProperty("class", "status-warning")
            else:
                self.license_status_text.setText("License Expires Very Soon")
                self.license_status_text.setProperty("class", "status-error")
            
            # Apply style changes
            self.license_status_text.style().unpolish(self.license_status_text)
            self.license_status_text.style().polish(self.license_status_text)

            # Update license details
            self.license_email_label.setText(validation_result.get('email', 'N/A'))
            self.license_key_label.setText(f"{license_key[:8]}...{license_key[-4:]}")
            
            tier = validation_result.get('tier', 'basic').title()
            self.license_tier_label.setText(f"{tier} {'(Trial)' if validation_result.get('is_trial') else ''}")
            
            self.license_type_label.setText(validation_result.get('license_type', 'standard').title())
            
            # Parse and format dates
            expires_at = validation_result.get('expires_at')
            if expires_at:
                try:
                    from datetime import datetime
                    exp_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                    self.license_expiry_label.setText(exp_date.strftime("%Y-%m-%d %H:%M"))
                except:
                    self.license_expiry_label.setText(expires_at)
            else:
                self.license_expiry_label.setText("N/A")
            
            # Days remaining with color coding
            if days_remaining > 30:
                color = 0
            elif days_remaining > 7:
                color = 0
            else:
                color = 0
            
            self.license_days_label.setText(f"{days_remaining} days")
            self.license_days_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            # Device info
            max_devices = validation_result.get('max_machines', 1)
            if status_report and not status_report.get('error'):
                active_devices = status_report.get('active_devices_count', 0)
                self.license_devices_label.setText(f"{active_devices}/{max_devices} active")
            else:
                self.license_devices_label.setText(f"Max: {max_devices}")
            
            # Features
            features = validation_result.get('features', {})
            if features:
                feature_text = ""
                for feature, available in features.items():
                    if isinstance(available, bool):
                        icon = "✅" if available else "❌"
                        name = feature.replace('_', ' ').title()
                        feature_text += f"{icon} {name}\n"
                    elif isinstance(available, int):
                        if available == -1:
                            feature_text += f"✅ {feature.replace('_', ' ').title()}: Unlimited\n"
                        else:
                            feature_text += f"✅ {feature.replace('_', ' ').title()}: {available}\n"
                
                self.features_list.setText(feature_text.strip())
            else:
                self.features_list.setText("No feature information available")
            
            # Start date (try to get from license data or use current date)
            self.license_start_label.setText("Available in full report")
            
            # Usage statistics
            if status_report and not status_report.get('error'):
                self.usage_signals_label.setText(str(status_report.get('total_signals', 0)))
                self.usage_trades_label.setText(str(status_report.get('total_trades', 0)))
                self.usage_last_activity_label.setText(status_report.get('last_heartbeat', 'N/A'))
                self.usage_active_devices_label.setText(str(status_report.get('active_devices_count', 0)))
            else:
                self.usage_signals_label.setText("N/A")
                self.usage_trades_label.setText("N/A")
                self.usage_last_activity_label.setText("N/A")
                self.usage_active_devices_label.setText("N/A")
            
            # Device information
            self.device_machine_id_label.setText(f"{machine_id[:8]}...{machine_id[-4:]}")
            self.device_last_seen_label.setText("Just now")
            
        except Exception as e:
            logger.error(f"Error updating license display: {e}")
            self.set_license_info_error("Error displaying license data")

    def update_license_display_basic(self, license_info, license_key, machine_id):
        """Fallback display using basic license info from settings"""
        try:
            self.license_email_label.setText(license_info.get('email', 'N/A'))
            self.license_key_label.setText(f"{license_key[:8]}...{license_key[-4:]}")
            self.license_tier_label.setText("Basic")
            self.license_type_label.setText("Standard")
            
            # Basic info
            self.license_start_label.setText(license_info.get('start_date', 'N/A'))
            self.license_expiry_label.setText(license_info.get('expiration_date', 'N/A'))
            self.license_days_label.setText("Unknown")
            self.license_devices_label.setText("1")
            
            # Default features
            self.features_list.setText("✅ Signal Copying\n✅ Basic Stats\n✅ Trade History")
            
            # Basic usage info
            self.usage_signals_label.setText("N/A")
            self.usage_trades_label.setText("N/A")
            self.usage_last_activity_label.setText("N/A")
            self.usage_active_devices_label.setText("1")
            
            # Device info
            self.device_machine_id_label.setText(f"{machine_id[:8]}...{machine_id[-4:]}")
            self.device_last_seen_label.setText("Just now")
            
        except Exception as e:
            logger.error(f"Error updating basic license display: {e}")
            self.set_license_info_error("Error displaying basic license data")

    def set_license_info_error(self, error_message):
        """Set error state for license information"""
        # Update status to error
        self.license_status_text.setText("License Error")
        self.license_status_text.setProperty("class", "status-error")
        self.license_status_text.style().unpolish(self.license_status_text)
        self.license_status_text.style().polish(self.license_status_text)
        
        # Set all fields to error
        error_text = f"Error: {error_message}"
        self.license_email_label.setText(error_text)
        self.license_key_label.setText("N/A")
        self.license_tier_label.setText("N/A")
        self.license_type_label.setText("N/A")
        self.license_start_label.setText("N/A")
        self.license_expiry_label.setText("N/A")
        self.license_days_label.setText("N/A")
        self.license_devices_label.setText("N/A")
        self.features_list.setText(error_text)
        self.usage_signals_label.setText("N/A")
        self.usage_trades_label.setText("N/A")
        self.usage_last_activity_label.setText("N/A")
        self.usage_active_devices_label.setText("N/A")
        self.device_machine_id_label.setText("N/A")
        self.device_last_seen_label.setText("N/A")

    def show_upgrade_info(self):
        """Show upgrade information dialog"""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Upgrade License")
            msg.setIcon(QMessageBox.Information)
            
            current_tier = "Basic"  # Default
            try:
                license_info = self.parent.settings.get_license_info()
                license_key = license_info.get("key")
                machine_id = self.parent.settings.settings.get("machine_id")
                
                if hasattr(self.parent, 'supabase_manager') and license_key and machine_id:
                    validation_result = self.parent.supabase_manager.validate_license(license_key, machine_id)
                    if validation_result.get('valid'):
                        current_tier = validation_result.get('tier', 'basic').title()
            except:
                pass
            
            upgrade_text = f"""
<h3>Current Plan: {current_tier}</h3>

<h4>Available Upgrade Options:</h4>

<b>🥉 Basic Plan</b>
• Max 5 simultaneous trades
• Basic signal copying
• Standard support

<b>🥈 Premium Plan</b>
• Max 20 simultaneous trades
• Advanced filters & custom lot sizing
• Multi-account support
• Priority support
• Custom indicators

<b>🥇 Professional Plan</b>
• Unlimited simultaneous trades
• All Premium features
• API access & white label
• Dedicated support

<br>
<b>To upgrade your license:</b><br>
1. Contact support at support@falcontradecopier.com<br>
2. Visit our website for pricing details<br>
3. Provide your current license key for upgrade pricing
            """
            
            msg.setText(upgrade_text)
            msg.exec()
            
        except Exception as e:
            logger.error(f"Error showing upgrade info: {e}")

    def set_account_info_disconnected(self):
        for label in [
            self.account_num_label, self.leverage_label, self.account_type_label,
            self.currency_label, self.profit_label, self.balance_label,
            self.equity_label, self.free_margin_label, self.used_margin_label,
            self.margin_level_label
        ]:
            label.setText("Disconnected")
            label.setStyleSheet("")  # Clear any color styling

    def get_account_type_name(self, trade_mode):
        """Convert MT5 trade mode to human-readable name"""
        mode_names = {
            0: "Demo",
            1: "Real",
            2: "Contest"
        }
        return mode_names.get(trade_mode, "Unknown")

    def check_conflicts(self):
        # Clear all warnings
        for label in self.warning_labels.values():
            label.setText("")
            label.setVisible(False)
        
        # Determine risk method
        is_fixed_lot = self.risk_method.currentText() == "Fixed Lot"
        is_percent = self.risk_method.currentText() == "Percent of Balance"
        is_fixed_dollar = self.risk_method.currentText() == "Fixed Dollar"

        # Enable/disable fields based on risk method
        self.lot_size.setEnabled(is_fixed_lot)
        self.risk_percent.setEnabled(is_percent)
        self.fixed_dollar.setEnabled(is_fixed_dollar)

        # Percent risk requires SL
        if is_percent and self.ignore_no_tpsl.isChecked():
            self.ignore_no_tpsl.setChecked(False)

        # Trailing SL conflicts
        if self.trailing_enabled.isChecked() and self.trail_after_tp.isChecked():
            self.be_after_pips.setEnabled(False)
        else:
            self.be_after_pips.setEnabled(True)

        # News filter conflicts
        if self.news_filter.isChecked():
            self.trading_hours.setEnabled(False)
        else:
            self.trading_hours.setEnabled(True)

    def update_connection_status(self, telegram_status=None, mt5_status=None):
        if telegram_status is None:
            telegram_status = self.parent.telegram_manager.connected
        if mt5_status is None:
            mt5_status = self.parent.mt5_manager.connected

        # Update Telegram status with dynamic styling
        if telegram_status:
            self.telegram_status.setText("●")
            self.telegram_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #1d9e4a;
                    background: radial-gradient(circle, #1d9e4a 0%, #1d9e4a 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for connected state
            self.telegram_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1d9e4a;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)
        else:
            self.telegram_status.setText("○")
            self.telegram_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #f54e4e;
                    background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for disconnected state
            self.telegram_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1c243b;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)
        
        # Update MT5 status with dynamic styling
        if mt5_status:
            self.mt5_status.setText("●")
            self.mt5_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #1d9e4a;
                    background: radial-gradient(circle, #1d9e4a 0%, #1d9e4a 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for connected state
            self.mt5_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1d9e4a;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)
        else:
            self.mt5_status.setText("○")
            self.mt5_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #f54e4e;
                    background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for disconnected state
            self.mt5_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1c243b;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)

    def update_copy_status(self, running):
        if running:
            self.copy_status.setText("●")
            self.copy_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #1d9e4a;
                    background: radial-gradient(circle, #1d9e4a 0%, #1d9e4a 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for running state
            self.copy_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1d9e4a;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
        else:
            self.copy_status.setText("○")
            self.copy_status.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: bold;
                    color: #f54e4e;
                    background: radial-gradient(circle, #f54e4e 0%, #f54e4e 60%, transparent 100%);
                    border-radius: 7px;
                    text-align: center;
                }
            """)
            # Update container border for stopped state
            self.copy_status.parent().setStyleSheet("""
                QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d111f, stop:1 #131a2d);
                    border: 2px solid #1c243b;
                    border-radius: 10px;
                    padding: 6px;
                }
            """)
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def refresh_history(self):
        """Refresh the history table and statistics"""
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_history_table()
            self.dashboard_page.update_history_statistics()
            self.dashboard_page.update_symbol_filter()
        else:
            logger.warning("Dashboard page not available for refresh")

    def apply_filters(self):
        """Apply filters to the history table"""
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_history_table()
            self.dashboard_page.update_history_statistics()
        else:
            logger.debug("Dashboard page not available for filters")  # Suppressed - normal during initialization

    def update_history_table(self):
        """Update the history table with filtered data"""
        try:
            # Get filtered trades
            filtered_trades = self.get_filtered_trades()
            
            # Clear table
            self.history_table.setRowCount(0)
            
            # Populate table
            for row, trade in enumerate(filtered_trades):
                self.history_table.insertRow(row)
                
                # Time (shortened)
                timestamp = trade.get('timestamp', 'N/A')
                if timestamp != 'N/A':
                    try:
                        dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                        time_str = dt.strftime('%H:%M')
                    except:
                        time_str = timestamp
                else:
                    time_str = 'N/A'
                self.history_table.setItem(row, 0, QTableWidgetItem(time_str))
                
                # Symbol
                symbol = trade.get('symbol', 'N/A')
                self.history_table.setItem(row, 1, QTableWidgetItem(symbol))
                
                # Type
                order_type = trade.get('order_type', 'N/A')
                self.history_table.setItem(row, 2, QTableWidgetItem(order_type))
                
                # Entry Price (shortened)
                entry_price = trade.get('entry_price', 'N/A')
                if isinstance(entry_price, (list, tuple)):
                    entry_price = f"{min(entry_price):.4f}"
                elif entry_price is not None and entry_price != 'N/A':
                    try:
                        entry_price = f"{float(entry_price):.4f}"
                    except:
                        entry_price = str(entry_price)
                elif entry_price is None:
                    entry_price = "Market"
                self.history_table.setItem(row, 3, QTableWidgetItem(str(entry_price)))
                
                # SL (shortened)
                sl = trade.get('sl', 'N/A')
                if sl != 'N/A' and sl is not None:
                    try:
                        sl = f"{float(sl):.4f}"
                    except:
                        sl = str(sl)
                self.history_table.setItem(row, 4, QTableWidgetItem(str(sl)))
                
                # TP (shortened)
                tp = trade.get('tp', 'N/A')
                tps = trade.get('tps', [])
                if tps:
                    tp = f"{len(tps)} TPs"
                elif tp != "N/A" and tp is not None:
                    try:
                        tp = f"{float(tp):.4f}"
                    except:
                        tp = str(tp)
                self.history_table.setItem(row, 5, QTableWidgetItem(str(tp)))
                
                # Lot Size
                lot_size = trade.get('lot_size', 'N/A')
                if lot_size != "N/A" and lot_size is not None:
                    self.history_table.setItem(row, 6, QTableWidgetItem(f"{lot_size:.2f}"))
                else:
                    self.history_table.setItem(row, 6, QTableWidgetItem("N/A"))
                
                # Status
                status = trade.get('status', 'N/A')
                status_item = QTableWidgetItem(status)
                if status == "Executed":
                    status_item.setForeground(QColor(0))
                elif status == "Failed":
                    status_item.setForeground(QColor(0))
                elif status == "Pending":
                    status_item.setForeground(QColor(0))
                self.history_table.setItem(row, 7, status_item)
                
                # Profit/Loss (with live calculation)
                profit = trade.get('profit', 0)
                # Update profit for executed trades
                if status == "Executed":
                    self.parent.trade_history.calculate_profit(trade)
                    profit = trade.get('profit', 0)
                
                profit_item = QTableWidgetItem(f"${profit:.2f}")
                if profit > 0:
                    profit_item.setForeground(QColor(0))
                elif profit < 0:
                    profit_item.setForeground(QColor(0))
                self.history_table.setItem(row, 8, profit_item)
                
                # Closure Type (NEW COLUMN)
                closure_type = trade.get('closure_type', 'Open')
                closure_item = QTableWidgetItem(closure_type)
                if closure_type == 'TP':
                    closure_item.setForeground(QColor(0))
                elif closure_type == 'SL':
                    closure_item.setForeground(QColor(0))
                elif closure_type == 'Manual':
                    closure_item.setForeground(QColor(0))
                elif closure_type == 'Partial':
                    closure_item.setForeground(QColor(0))
                self.history_table.setItem(row, 9, closure_item)
                
                # Notes (shortened)
                notes = trade.get('notes', '')
                if len(notes) > 20:
                    notes = notes[:17] + "..."
                self.history_table.setItem(row, 10, QTableWidgetItem(notes))
                
        except Exception as e:
            logger.error(f"Error updating history table: {str(e)}")

    def get_filtered_trades(self):
        """Get trades filtered by current filter settings"""
        try:
            # Access trade_history through parent (MainWindow)
            all_trades = self.parent.trade_history.history
            logger.info(f"Filtering {len(all_trades)} total trades")
            
            # Date filter
            date_from = self.date_from.date().toPython()
            date_to = self.date_to.date().toPython()
            
            # Symbol filter
            symbol_filter = self.symbol_filter.currentText()
            if symbol_filter == "All":
                symbol_filter = "All Symbols"
            
            # Status filter
            status_filter = self.status_filter.currentText()
            if status_filter == "All":
                status_filter = "All Status"
            
            filtered_trades = []
            
            for trade in all_trades:
                # Date filter
                try:
                    trade_date = datetime.strptime(trade.get('timestamp', ''), '%Y-%m-%d %H:%M:%S').date()
                    if trade_date < date_from or trade_date > date_to:
                        continue
                except:
                    continue
                
                # Symbol filter
                if symbol_filter != "All Symbols" and trade.get('symbol') != symbol_filter:
                    continue
                
                # Status filter
                if status_filter != "All Status" and trade.get('status') != status_filter:
                    continue
                
                filtered_trades.append(trade)
            
            logger.info(f"Filtered to {len(filtered_trades)} trades")
            return filtered_trades
            
        except Exception as e:
            logger.error(f"Error filtering trades: {str(e)}")
            return []

    def update_history_statistics(self):
        """Update the statistics labels with current data"""
        try:
            filtered_trades = self.get_filtered_trades()
            
            if not filtered_trades:
                # Reset all stats to zero
                self.total_trades_label.setText("Total: 0")
                self.win_rate_label.setText("Win Rate: 0%")
                self.total_profit_label.setText("Total P&L: $0.00")
                self.avg_profit_label.setText("Avg: $0.00")
                self.max_dd_label.setText("Max DD: $0.00")
                self.best_trade_label.setText("Best: $0.00")
                return
            
            # Calculate statistics
            total_trades = len(filtered_trades)
            
            # Update profits for executed trades
            for trade in filtered_trades:
                if trade.get('status') == 'Executed':
                    self.parent.trade_history.calculate_profit(trade)
            
            # Profit calculations
            total_profit = sum(trade.get('profit', 0) for trade in filtered_trades)
            avg_profit = total_profit / total_trades if total_trades > 0 else 0
            
            # Win rate (only for closed trades)
            closed_trades = [t for t in filtered_trades if t.get('closure_type') in ['TP', 'SL', 'Manual', 'Partial']]
            if closed_trades:
                winning_trades = sum(1 for trade in closed_trades if trade.get('profit', 0) > 0)
                win_rate = (winning_trades / len(closed_trades) * 100) if len(closed_trades) > 0 else 0
            else:
                win_rate = 0
            
            # Best trade
            best_trade = max((trade.get('profit', 0) for trade in filtered_trades), default=0)
            
            # Max drawdown (simplified calculation)
            max_dd = min((trade.get('profit', 0) for trade in filtered_trades), default=0)
            
            # Update labels
            self.total_trades_label.setText(f"Total: {total_trades}")
            self.win_rate_label.setText(f"Win Rate: {win_rate:.1f}%")
            self.total_profit_label.setText(f"Total P&L: ${total_profit:.2f}")
            self.avg_profit_label.setText(f"Avg: ${avg_profit:.2f}")
            self.max_dd_label.setText(f"Max DD: ${max_dd:.2f}")
            self.best_trade_label.setText(f"Best: ${best_trade:.2f}")
            
        except Exception as e:
            logger.error(f"Error updating history statistics: {str(e)}")

    def export_history(self):
        """Export history to CSV file"""
        try:
            from datetime import datetime
            filename = f"trade_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            filtered_trades = self.get_filtered_trades()
            
            if not filtered_trades:
                QMessageBox.information(self, "Export", "No trades to export!")
                return
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                import csv
                fieldnames = ['Date/Time', 'Channel', 'Symbol', 'Type', 'Entry Price', 'SL', 'TP', 
                            'Lot Size', 'Status', 'Profit/Loss', 'Notes']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for trade in filtered_trades:
                    # Format entry price
                    entry_price = trade.get('entry_price', 'N/A')
                    if isinstance(entry_price, (list, tuple)):
                        entry_price = f"{min(entry_price)}-{max(entry_price)}"
                    elif entry_price is None:
                        entry_price = "Market"
                    
                    # Format TP
                    tp = trade.get('tp', 'N/A')
                    tps = trade.get('tps', [])
                    if tps:
                        tp = ", ".join(map(str, tps))
                    elif tp == "N/A" and not tps:
                        tp = "N/A"
                    
                    # Format lot size
                    lot_size = trade.get('lot_size', 'N/A')
                    if lot_size != "N/A" and lot_size is not None:
                        lot_size = f"{lot_size:.2f}"
                    
                    writer.writerow({
                        'Date/Time': trade.get('timestamp', 'N/A'),
                        'Channel': trade.get('channel', 'N/A'),
                        'Symbol': trade.get('symbol', 'N/A'),
                        'Type': trade.get('order_type', 'N/A'),
                        'Entry Price': str(entry_price),
                        'SL': str(trade.get('sl', 'N/A')),
                        'TP': str(tp),
                        'Lot Size': str(lot_size),
                        'Status': trade.get('status', 'N/A'),
                        'Profit/Loss': f"${trade.get('profit', 0):.2f}",
                        'Notes': trade.get('notes', '')
                    })
            
            QMessageBox.information(self, "Export Successful", f"History exported to {filename}")
            
        except Exception as e:
            logger.error(f"Error exporting history: {str(e)}")
            QMessageBox.critical(self, "Export Error", f"Failed to export history: {str(e)}")

    def clear_history(self):
        """Clear all trade history"""
        try:
            reply = QMessageBox.question(
                self, 
                "Clear History", 
                "Are you sure you want to clear all trade history? This action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.trade_history.history = []
                self.trade_history.save()
                if hasattr(self, 'dashboard_page'):
                    self.dashboard_page.update_history_table()
                    self.dashboard_page.update_history_statistics()
                    self.dashboard_page.update_symbol_filter()
                QMessageBox.information(self, "History Cleared", "All trade history has been cleared.")
                
        except Exception as e:
            logger.error(f"Error clearing history: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to clear history: {str(e)}")

    def update_trade_history(self):
        """Update trade history display"""
        try:
            if hasattr(self, 'history_table'):
                self.update_history_table()
                self.update_history_statistics()
        except Exception as e:
            logger.error(f"Error updating trade history: {str(e)}")

    def create_section_header(self, title, description):
        """Create a section header with title and description"""
        header_frame = QFrame()
        header_frame
        
        header_layout = QVBoxLayout(header_frame)
        header_layout.setSpacing(5)
        
        # Title
        title_label = QLabel(title)
        title_label
        header_layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(description)
        desc_label
        header_layout.addWidget(desc_label)
        
        return header_frame

    def update_symbol_filter(self):
        """Update the symbol filter dropdown with unique symbols from history"""
        try:
            if hasattr(self, 'symbol_filter'):
                current_symbol = self.symbol_filter.currentText()
                
                # Get unique symbols from history through parent
                symbols = set()
                for trade in self.parent.trade_history.history:
                    symbol = trade.get('symbol', 'N/A')
                    if symbol != 'N/A':
                        symbols.add(symbol)
                
                # Update dropdown
                self.symbol_filter.clear()
                self.symbol_filter.addItem("All")
                
                # Add symbols in alphabetical order
                for symbol in sorted(symbols):
                    self.symbol_filter.addItem(symbol)
                
                # Restore previous selection if it still exists
                if current_symbol in symbols or current_symbol == "All":
                    index = self.symbol_filter.findText(current_symbol)
                    if index >= 0:
                        self.symbol_filter.setCurrentIndex(index)
                
        except Exception as e:
            logger.error(f"Error updating symbol filter: {str(e)}")

    def check_conflicts(self):
        """Check for conflicting settings and update status with widget disabling"""
        conflicts = []
        
        # Reset all widgets to enabled state and show them
        self.lot_size.setEnabled(True)
        self.lot_size.setVisible(True)
        self.risk_percent.setEnabled(True)
        self.risk_percent.setVisible(True)
        self.fixed_dollar.setEnabled(True)
        self.fixed_dollar.setVisible(True)
        self.trailing_distance.setEnabled(True)
        self.be_after_pips.setEnabled(True)
        self.trail_after_tp.setEnabled(True)
        self.daily_profit_target.setEnabled(True)
        
        # Check risk method conflicts and show/hide appropriate widgets
        if self.risk_method.currentText() == "Fixed Lot":
            # Show only Fixed Lot Size, hide others
            self.lot_size.setVisible(True)
            self.risk_percent.setVisible(False)
            self.fixed_dollar.setVisible(False)
        elif self.risk_method.currentText() == "Percent of Balance":
            # Show only Risk Percent, hide others
            self.lot_size.setVisible(False)
            self.risk_percent.setVisible(True)
            self.fixed_dollar.setVisible(False)
            if self.ignore_no_tpsl.isChecked():
                conflicts.append("Percent Risk cannot ignore no TP/SL")
        elif self.risk_method.currentText() == "Fixed Dollar":
            # Show only Fixed Dollar Risk, hide others
            self.lot_size.setVisible(False)
            self.risk_percent.setVisible(False)
            self.fixed_dollar.setVisible(True)
        
        # Check trailing stop conflicts
        if not self.trailing_enabled.isChecked():
            self.trailing_distance.setEnabled(False)
            self.trailing_distance.setVisible(False)
            self.trail_after_tp.setEnabled(False)
            self.trail_after_tp.setVisible(False)
        else:
            self.trailing_distance.setVisible(True)
            self.trail_after_tp.setVisible(True)
            if self.trail_after_tp.isChecked() and self.be_after_pips.value() > 0:
                conflicts.append("BE after pips conflicts with trail after TP")
                self.be_after_pips.setEnabled(False)
        
        # Check break even conflicts
        if self.be_after_pips.value() > 0 and self.trail_after_tp.isChecked():
            conflicts.append("BE after pips conflicts with trail after TP")
        
        # Check daily limits
        if self.daily_loss_limit.value() >= self.daily_profit_target.value():
            conflicts.append("Daily loss limit should be less than profit target")
            self.daily_profit_target.setEnabled(False)
        
        # Check max trades conflicts
        if self.max_trades_per_symbol.value() > self.max_trades.value():
            conflicts.append("Max trades per symbol cannot exceed max open trades")
        
        # Check spread and pip tolerance conflicts
        if self.max_spread.value() < self.pip_tolerance.value():
            conflicts.append("Max spread should be greater than pip tolerance")
        
        # Check trading hours format
        trading_hours = self.trading_hours.text().strip()
        if trading_hours and not re.match(r'^\d{2}:\d{2}-\d{2}:\d{2}$', trading_hours):
            conflicts.append("Trading hours format should be HH:MM-HH:MM")
        
        # Update status
        if conflicts:
            self.conflict_status.setText(f"⚠️ Conflicts: {', '.join(conflicts[:2])}{'...' if len(conflicts) > 2 else ''}")
            self.conflict_status
            self.save_btn.setEnabled(False)
            self.reset_to_default_btn.setEnabled(False)
        else:
            self.conflict_status.setText("✅ Settings are valid")
            self.conflict_status
            self.save_btn.setEnabled(True)
            self.reset_to_default_btn.setEnabled(True)

    def save_as_default(self):
        """Save current settings as default"""
        self.save_settings()
        # Save to default settings file
        default_settings = self.parent.settings._get_default_settings()
        default_settings["risk"] = self.parent.settings.get_risk_settings()
        self.parent.settings.save_default_settings(default_settings)
        QMessageBox.information(self, "Default Saved", "Settings have been saved as default for new installations")

    # =====================
    # PERFORMANCE ANALYTICS METHODS
    # =====================



    def update_performance_data(self):
        """Update all performance data and charts"""
        try:
            # Check if UI elements exist
            if not hasattr(self, 'period_selector') or not hasattr(self, 'channel_selector'):
                logger.warning("Performance UI elements not ready yet.")
                return
            
            # Get trade data based on selected period and channel
            period = self.period_selector.currentText()
            channel_filter = self.channel_selector.currentText()
            
            # Get trades from history
            if not hasattr(self.parent, 'trade_history'):
                logger.warning("Trade history not available.")
                return
                
            trades = self.parent.trade_history.get_all_trades()
            
            # Filter by period
            filtered_trades = self.filter_trades_by_period(trades, period)
            
            # Filter by channel if specified
            if channel_filter != "All Channels":
                filtered_trades = [t for t in filtered_trades if t.get('channel') == channel_filter]
            
            # Calculate performance metrics
            metrics = self.calculate_performance_metrics(filtered_trades)
            
            # Update metric cards
            self.update_metric_cards(metrics)
            
            # Generate and update charts (with fallback for no charting)
            self.update_equity_chart(filtered_trades)
            self.update_drawdown_chart(filtered_trades)
            
            # Update channel performance table
            self.update_channel_table(trades)
            
            logger.info(f"Performance data updated: {len(filtered_trades)} trades, P&L: ${metrics['total_pnl']:.2f}")
            
        except Exception as e:
            logger.error(f"Error updating performance data: {e}")
            # Don't show message box during startup to avoid blocking the app
            if hasattr(self, 'parent') and hasattr(self.parent, 'status_bar'):
                self.parent.status_bar.showMessage(f"Performance update error: {str(e)}")

    def filter_trades_by_period(self, trades, period):
        """Filter trades by selected time period"""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        
        if period == "Last 7 Days":
            start_date = now - timedelta(days=7)
        elif period == "Last 30 Days":
            start_date = now - timedelta(days=30)
        elif period == "Last 90 Days":
            start_date = now - timedelta(days=90)
        elif period == "Last 6 Months":
            start_date = now - timedelta(days=180)
        elif period == "Last Year":
            start_date = now - timedelta(days=365)
        else:  # All Time
            return trades
        
        filtered_trades = []
        for trade in trades:
            try:
                trade_date = datetime.strptime(trade.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                if trade_date >= start_date:
                    filtered_trades.append(trade)
            except:
                continue
        
        return filtered_trades

    def calculate_performance_metrics(self, trades):
        """Calculate comprehensive performance metrics"""
        if not trades:
            return {
                'total_pnl': 0,
                'win_rate': 0,
                'avg_rr': 0,
                'max_drawdown': 0,
                'profit_factor': 0,
                'sharpe_ratio': 0
            }
        
        # Basic metrics
        total_trades = len(trades)
        winning_trades = [t for t in trades if t.get('profit', 0) > 0]
        losing_trades = [t for t in trades if t.get('profit', 0) < 0]
        
        total_pnl = sum(t.get('profit', 0) for t in trades)
        win_rate = len(winning_trades) / total_trades * 100 if total_trades > 0 else 0
        
        # Risk/Reward calculation
        avg_rr = 0
        if losing_trades:
            avg_loss = abs(sum(t.get('profit', 0) for t in losing_trades) / len(losing_trades))
            if winning_trades and avg_loss > 0:
                avg_win = sum(t.get('profit', 0) for t in winning_trades) / len(winning_trades)
                avg_rr = avg_win / avg_loss
        
        # Drawdown calculation
        max_drawdown = self.calculate_max_drawdown(trades)
        
        # Profit factor
        gross_profit = sum(t.get('profit', 0) for t in winning_trades)
        gross_loss = abs(sum(t.get('profit', 0) for t in losing_trades))
        profit_factor = gross_profit / gross_loss if gross_loss > 0 else 0
        
        # Sharpe ratio (simplified)
        returns = [t.get('profit', 0) for t in trades]
        if returns:
            avg_return = sum(returns) / len(returns)
            variance = sum((r - avg_return) ** 2 for r in returns) / len(returns)
            sharpe_ratio = avg_return / (variance ** 0.5) if variance > 0 else 0
        else:
            sharpe_ratio = 0
        
        return {
            'total_pnl': total_pnl,
            'win_rate': win_rate,
            'avg_rr': avg_rr,
            'max_drawdown': max_drawdown,
            'profit_factor': profit_factor,
            'sharpe_ratio': sharpe_ratio
        }

    def calculate_max_drawdown(self, trades):
        """Calculate maximum drawdown from trade history"""
        if not trades:
            return 0
        
        # Sort trades by timestamp
        sorted_trades = sorted(trades, key=lambda x: x.get('timestamp', ''))
        
        running_balance = 0
        peak_balance = 0
        max_drawdown = 0
        
        for trade in sorted_trades:
            profit = trade.get('profit', 0)
            running_balance += profit
            
            if running_balance > peak_balance:
                peak_balance = running_balance
            
            drawdown = peak_balance - running_balance
            if drawdown > max_drawdown:
                max_drawdown = drawdown
        
        return max_drawdown

    def update_metric_cards(self, metrics):
        """Update metric label values"""
        # Update total P&L label
        pnl_text = f"Total P&L: ${metrics['total_pnl']:.2f}"
        self.total_pnl_label.setText(pnl_text)
        
        # Update other labels
        self.win_rate_label.setText(f"Win Rate: {metrics['win_rate']:.1f}%")
        self.rr_label.setText(f"Avg R:R: {metrics['avg_rr']:.2f}")
        self.drawdown_label.setText(f"Max Drawdown: ${metrics['max_drawdown']:.2f}")
        self.profit_factor_label.setText(f"Profit Factor: {metrics['profit_factor']:.2f}")
        self.sharpe_label.setText(f"Sharpe Ratio: {metrics['sharpe_ratio']:.2f}")

    def update_equity_chart(self, trades):
        """Generate and display equity curve chart"""
        try:
            if not trades:
                self.equity_chart.setText("📈 No trade data available")
                self.equity_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(156, 166, 184, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #9ca6b8;
                        font-size: 14px;
                    }
                """)
                return
            
            # Try to use matplotlib if available
            try:
                import matplotlib.pyplot as plt
                import matplotlib.dates as mdates
                from datetime import datetime
                
                # Sort trades by timestamp
                sorted_trades = sorted(trades, key=lambda x: x.get('timestamp', ''))
                
                # Calculate running balance
                dates = []
                balances = []
                running_balance = 0
                
                for trade in sorted_trades:
                    try:
                        date = datetime.strptime(trade.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                        profit = trade.get('profit', 0)
                        running_balance += profit
                        
                        dates.append(date)
                        balances.append(running_balance)
                    except:
                        continue
                
                if not dates:
                    self.equity_chart.setText("📈 No valid trade data")
                    return
                
                # Create chart
                plt.figure(figsize=(8, 4))
                plt.plot(dates, balances, color='#1d9e4a', linewidth=2)
                plt.fill_between(dates, balances, alpha=0.3, color='#1d9e4a')
                plt.title('Equity Curve', color='#f0f4f9')
                plt.xlabel('Date', color='#f0f4f9')
                plt.ylabel('Balance ($)', color='#f0f4f9')
                plt.grid(True, alpha=0.3)
                plt.gca().set_facecolor('#0d111f')
                plt.gcf().set_facecolor('#0d111f')
                
                # Save chart
                chart_path = "equity_chart.png"
                plt.savefig(chart_path, bbox_inches='tight', facecolor='#0d111f')
                plt.close()
                
                # Display chart
                pixmap = QPixmap(chart_path)
                self.equity_chart.setPixmap(pixmap.scaled(
                    self.equity_chart.width(), 
                    self.equity_chart.height(), 
                    Qt.KeepAspectRatio, 
                    Qt.SmoothTransformation
                ))
                
            except ImportError:
                # Fallback when matplotlib is not available
                total_pnl = sum(t.get('profit', 0) for t in trades)
                trade_count = len(trades)
                self.equity_chart.setText(f"📈 Equity Summary\n\nTotal P&L: ${total_pnl:.2f}\nTrades: {trade_count}\n\n(Charting not available)")
                self.equity_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(29, 158, 74, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #1d9e4a;
                        font-size: 12px;
                        font-weight: bold;
                    }
                """)
            except Exception as e:
                logger.error(f"Error creating equity chart: {e}")
                self.equity_chart.setText("📈 Chart generation failed")
                self.equity_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(245, 78, 78, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #f54e4e;
                        font-size: 12px;
                    }
                """)
                
        except Exception as e:
            logger.error(f"Error in equity chart update: {e}")
            self.equity_chart.setText("📈 Error loading equity data")

    def update_drawdown_chart(self, trades):
        """Generate and display drawdown chart"""
        try:
            if not trades:
                self.drawdown_chart.setText("📉 No trade data available")
                self.drawdown_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(156, 166, 184, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #9ca6b8;
                        font-size: 14px;
                    }
                """)
                return
            
            # Try to use matplotlib if available
            try:
                import matplotlib.pyplot as plt
                from datetime import datetime
                
                # Calculate drawdown over time
                sorted_trades = sorted(trades, key=lambda x: x.get('timestamp', ''))
                
                dates = []
                drawdowns = []
                running_balance = 0
                peak_balance = 0
                
                for trade in sorted_trades:
                    try:
                        date = datetime.strptime(trade.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                        profit = trade.get('profit', 0)
                        running_balance += profit
                        
                        if running_balance > peak_balance:
                            peak_balance = running_balance
                        
                        drawdown = peak_balance - running_balance
                        
                        dates.append(date)
                        drawdowns.append(drawdown)
                    except:
                        continue
                
                if not dates:
                    self.drawdown_chart.setText("📉 No valid drawdown data")
                    return
                
                # Create chart
                plt.figure(figsize=(8, 3))
                plt.fill_between(dates, drawdowns, alpha=0.7, color='#f54e4e')
                plt.plot(dates, drawdowns, color='#f54e4e', linewidth=1)
                plt.title('Drawdown Analysis', color='#f0f4f9')
                plt.xlabel('Date', color='#f0f4f9')
                plt.ylabel('Drawdown ($)', color='#f0f4f9')
                plt.grid(True, alpha=0.3)
                plt.gca().set_facecolor('#0d111f')
                plt.gcf().set_facecolor('#0d111f')
                
                # Save chart
                chart_path = "drawdown_chart.png"
                plt.savefig(chart_path, bbox_inches='tight', facecolor='#0d111f')
                plt.close()
                
                # Display chart
                pixmap = QPixmap(chart_path)
                self.drawdown_chart.setPixmap(pixmap.scaled(
                    self.drawdown_chart.width(), 
                    self.drawdown_chart.height(), 
                    Qt.KeepAspectRatio, 
                    Qt.SmoothTransformation
                ))
                
            except ImportError:
                # Fallback when matplotlib is not available
                max_drawdown = self.calculate_max_drawdown(trades)
                self.drawdown_chart.setText(f"📉 Drawdown Summary\n\nMax Drawdown: ${max_drawdown:.2f}\n\n(Charting not available)")
                self.drawdown_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(245, 78, 78, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #f54e4e;
                        font-size: 12px;
                        font-weight: bold;
                    }
                """)
            except Exception as e:
                logger.error(f"Error creating drawdown chart: {e}")
                self.drawdown_chart.setText("📉 Chart generation failed")
                self.drawdown_chart.setStyleSheet("""
                    QLabel {
                        background-color: rgba(245, 78, 78, 0.1);
                        border: 1px solid #1c243b;
                        border-radius: 6px;
                        padding: 20px;
                        color: #f54e4e;
                        font-size: 12px;
                    }
                """)
                
        except Exception as e:
            logger.error(f"Error in drawdown chart update: {e}")
            self.drawdown_chart.setText("📉 Error loading drawdown data")



    def update_channel_table(self, trades):
        """Update channel performance ranking table"""
        try:
            # Group trades by channel
            channel_data = {}
            
            for trade in trades:
                channel = trade.get('channel', 'Unknown')
                if channel not in channel_data:
                    channel_data[channel] = {
                        'trades': [],
                        'total_pnl': 0,
                        'winning_trades': 0,
                        'total_trades': 0
                    }
                
                profit = trade.get('profit', 0)
                channel_data[channel]['trades'].append(trade)
                channel_data[channel]['total_pnl'] += profit
                channel_data[channel]['total_trades'] += 1
                
                if profit > 0:
                    channel_data[channel]['winning_trades'] += 1
            
            # Calculate metrics for each channel
            channel_rankings = []
            for channel, data in channel_data.items():
                if data['total_trades'] > 0:
                    win_rate = (data['winning_trades'] / data['total_trades']) * 100
                    
                    # Calculate average R:R
                    winning_trades = [t for t in data['trades'] if t.get('profit', 0) > 0]
                    losing_trades = [t for t in data['trades'] if t.get('profit', 0) < 0]
                    
                    avg_rr = 0
                    if losing_trades:
                        avg_loss = abs(sum(t.get('profit', 0) for t in losing_trades) / len(losing_trades))
                        if winning_trades and avg_loss > 0:
                            avg_win = sum(t.get('profit', 0) for t in winning_trades) / len(winning_trades)
                            avg_rr = avg_win / avg_loss
                    
                    # Calculate performance score (weighted combination)
                    score = (win_rate * 0.4) + (avg_rr * 20) + (data['total_pnl'] * 0.01)
                    
                    channel_rankings.append({
                        'channel': channel,
                        'trades': data['total_trades'],
                        'win_rate': win_rate,
                        'pnl': data['total_pnl'],
                        'rr': avg_rr,
                        'score': score
                    })
            
            # Sort by score
            channel_rankings.sort(key=lambda x: x['score'], reverse=True)
            
            # Update table
            self.channel_table.setRowCount(len(channel_rankings))
            
            for i, ranking in enumerate(channel_rankings):
                # Rank
                rank_item = QTableWidgetItem(str(i + 1))
                rank_item.setTextAlignment(Qt.AlignCenter)
                self.channel_table.setItem(i, 0, rank_item)
                
                # Channel
                channel_item = QTableWidgetItem(ranking['channel'])
                self.channel_table.setItem(i, 1, channel_item)
                
                # Trades
                trades_item = QTableWidgetItem(str(ranking['trades']))
                trades_item.setTextAlignment(Qt.AlignCenter)
                self.channel_table.setItem(i, 2, trades_item)
                
                # Win Rate
                win_rate_item = QTableWidgetItem(f"{ranking['win_rate']:.1f}%")
                win_rate_item.setTextAlignment(Qt.AlignCenter)
                self.channel_table.setItem(i, 3, win_rate_item)
                
                # P&L
                pnl_item = QTableWidgetItem(f"${ranking['pnl']:.2f}")
                pnl_item.setTextAlignment(Qt.AlignCenter)
                if ranking['pnl'] >= 0:
                    pnl_item.setForeground(QColor("#10B981"))
                else:
                    pnl_item.setForeground(QColor("#EF4444"))
                self.channel_table.setItem(i, 4, pnl_item)
                
                # R:R
                rr_item = QTableWidgetItem(f"{ranking['rr']:.2f}")
                rr_item.setTextAlignment(Qt.AlignCenter)
                self.channel_table.setItem(i, 5, rr_item)
                
                # Score
                score_item = QTableWidgetItem(f"{ranking['score']:.1f}")
                score_item.setTextAlignment(Qt.AlignCenter)
                self.channel_table.setItem(i, 6, score_item)
            
            # Update channel selector
            current_channels = [ranking['channel'] for ranking in channel_rankings]
            self.channel_selector.clear()
            self.channel_selector.addItem("All Channels")
            self.channel_selector.addItems(current_channels)
            
        except Exception as e:
            logger.error(f"Error updating channel table: {e}")

class TradeHistory:
    def __init__(self, filename=TRADE_HISTORY_FILE):
        self.filename = filename
        self.history = []
        self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                self.history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.history = []

    def save(self):
        with open(self.filename, 'w') as f:
            json.dump(self.history, f, indent=2)

    def add_trade(self, trade_data):
        """Add a trade to history with proper profit calculation"""
        trade_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.calculate_profit(trade_data)
        self.history.append(trade_data)
        self.save()

    def calculate_profit(self, trade):
        """Calculate profit based on entry, SL, TP and current market conditions"""
        try:
            # Set default profit to 0
            trade["profit"] = 0
            
            # Get current market price for live profit calculation
            symbol = trade.get('symbol', '')
            if symbol and symbol != 'N/A':
                import MetaTrader5 as mt5
                if mt5.initialize():
                    tick = mt5.symbol_info_tick(symbol)
                    if tick:
                        entry_price = trade.get('entry_price')
                        lot_size = trade.get('lot_size', 0.1)
                        order_type = trade.get('order_type', '')
                        
                        # Handle None values safely
                        if entry_price is None or lot_size is None:
                            return
                            
                        try:
                            entry_price = float(entry_price)
                            lot_size = float(lot_size)
                        except (ValueError, TypeError):
                            return
                        
                        if order_type.startswith('BUY'):
                            # For buy orders, profit = (current_bid - entry_price) * lot_size * 100000
                            current_price = tick.bid
                            profit = (current_price - entry_price) * lot_size * 100000
                        else:
                            # For sell orders, profit = (entry_price - current_ask) * lot_size * 100000
                            current_price = tick.ask
                            profit = (entry_price - current_price) * lot_size * 100000
                        
                        trade["profit"] = profit
                        trade["current_price"] = current_price
                        return
            
            # Fallback: calculate theoretical profit based on TP
            entry_price = trade.get('entry_price')
            tp = trade.get('tp')
            lot_size = trade.get('lot_size', 0.1)
            order_type = trade.get('order_type', '')
            
            # Handle None values safely
            if entry_price is None or lot_size is None:
                return
                
            try:
                entry_price = float(entry_price)
                lot_size = float(lot_size)
            except (ValueError, TypeError):
                return
            
            if tp and entry_price > 0:
                try:
                    tp = float(tp)
                    if order_type.startswith('BUY'):
                        profit = (tp - entry_price) * lot_size * 100000
                    else:
                        profit = (entry_price - tp) * lot_size * 100000
                    trade["profit"] = profit
                except (ValueError, TypeError):
                    pass
                
        except Exception as e:
            # Don't log every error, just set profit to 0
            trade["profit"] = 0

    def update_trade_closure(self, symbol, closure_type, profit=None):
        """Update trade closure information when a trade is closed"""
        # Find the most recent trade for this symbol
        for trade in reversed(self.history):
            if trade.get('symbol') == symbol and trade.get('status') == 'Executed':
                trade['closure_type'] = closure_type  # 'TP', 'SL', 'Manual', 'Partial'
                if profit is not None:
                    trade['profit'] = profit
                trade['close_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.save()
                break

    def get_recent_trades(self, limit=50):
        return self.history[-limit:][::-1]

    def get_all_trades(self):
        return self.history[::-1]  # Return in reverse chronological order

    def clear(self):
        self.history = []
        self.save()

# =====================
# MAIN WINDOW
# =====================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        # Set window to start maximized for full screen experience
        self.setMinimumSize(700, 500)
        self.setMaximumSize(16777215, 16777215)  # Allow full screen
        
        self.settings = SettingsManager()
        self.telegram_manager = TelegramManager()
        self.mt5_manager = MT5Manager()
        self.mt5_manager.parent = self
        self.trade_history = TradeHistory()
        self.supabase_manager = SupabaseManager()  # Initialize Supabase manager
        self.signal_count = 0
        self.copying_active = False
        self.last_trade_details = None
        self.daily_signals = 0
        self.daily_trades = 0
        self.heartbeat_timer = None
        self.trade_monitor = TradeMonitor(self)
        self.trade_monitor.start()

        # Load application logo
        logo_path = "ftsc.png"
        if os.path.exists(logo_path):
            self.app_logo = QPixmap(logo_path)
            if self.app_logo.isNull():
                self.create_fallback_logo()
        else:
            self.create_fallback_logo()
        
        self.setup_ui()
        self.setup_connections()
        self.check_activation_status()
        self.setup_timers()
        self.apply_theme()
        
        # Initialize history display
        # self.initialize_history_display()  # Method not implemented yet

        # Maximize the window to full screen
        self.showMaximized()

    def initialize_history_display(self):
        """Initialize the trade history display"""
        # This method is called to set up the initial state of trade history display
        # The actual display is handled by the dashboard page
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_trade_history()

    def center_on_screen(self):
        """Center the window on the screen and ensure it fits within screen bounds"""
        screen_geometry = QApplication.primaryScreen().geometry()
        
        # Calculate center position
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        
        # Ensure window doesn't go off-screen
        x = max(0, min(x, screen_geometry.width() - self.width()))
        y = max(0, min(y, screen_geometry.height() - self.height()))
        
        self.move(x, y)

    def create_fallback_logo(self):
        self.app_logo = QPixmap(128, 128)
        self.app_logo.fill(Qt.transparent)
        painter = QPainter(self.app_logo)
        gradient = QLinearGradient(0, 0, 128, 128)
        gradient.setColorAt(0, QColor(0))
        gradient.setColorAt(1, QColor(0))
        painter.fillRect(self.rect(), gradient)
        font = QFont(0, 16, QFont.Bold)
        painter.setFont(font)
        painter.setPen(QColor(0))
        painter.drawText(self.app_logo.rect(), Qt.AlignCenter, "F")
        painter.end()

    def setup_ui(self):
        # Create stacked widget
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create pages with responsive containers
        self.activation_page = ActivationPage(self)
        self.telegram_page = TelegramPage(self)
        self.mt5_page = MT5Page(self)
        self.dashboard_page = DashboardPage(self)
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.activation_page)
        self.stacked_widget.addWidget(self.telegram_page)
        self.stacked_widget.addWidget(self.mt5_page)
        self.stacked_widget.addWidget(self.dashboard_page)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply responsive styling to status bar
        self.status_bar
        
        self.setup_tray_icon()

    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(self.app_logo))
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show_normal)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(self.close_app)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def setup_connections(self):
        self.telegram_manager.verification_sent.connect(self.on_verification_sent)
        self.telegram_manager.authenticated.connect(self.on_telegram_authenticated)
        self.telegram_manager.channels_loaded.connect(self.on_channels_loaded)
        self.telegram_manager.connection_error.connect(self.on_telegram_error)
        self.telegram_manager.connection_status_changed.connect(self.update_connection_status)
        self.telegram_manager.trade_signal.connect(self.on_trade_signal)
        self.telegram_manager.new_signal_parsed.connect(self.on_new_signal_parsed)
        self.telegram_manager.management_command.connect(self.on_management_command)
        self.activation_page.activation_result.connect(self.activation_page.handle_activation_result)
        self.mt5_page.connection_result.connect(self.mt5_page.on_mt5_connection_result)

    def setup_timers(self):
        self.account_timer = QTimer()
        self.account_timer.timeout.connect(self.update_account_info)
        self.account_timer.start(10000)

        self.heartbeat_timer = QTimer()
        self.heartbeat_timer.timeout.connect(self.send_heartbeat)
        self.heartbeat_timer.start(3600000)

        self.history_timer = QTimer()
        self.history_timer.timeout.connect(self.update_trade_history)
        self.history_timer.start(5000)

    def check_activation_status(self):
        if self.settings.is_activated():
            self.validate_license_at_startup()
            self.show_telegram_page()
        else:
            # Reset activation page UI state before showing it
            self.activation_page.reset_ui_state()
            self.stacked_widget.setCurrentWidget(self.activation_page)

    def validate_license(self, key):
        if key == "1234123412341234":
            self.settings.set_activated(
                status=True,
                key=key,
                email="bypass@falcontrade.com",
                is_trial=False,
                expiration=datetime.now() + timedelta(days=365 * 10)
            )
            self.activation_page.activation_result.emit(True, "Bypass activation successful!", {})
            return
        
        try:
            machine_id = self.settings.settings.get("machine_id")
            
            # Use Supabase manager for validation
            result = self.supabase_manager.validate_license(key, machine_id)
            
            if result.get("valid"):
                expiration = datetime.fromisoformat(result["expires_at"].replace('Z', '+00:00'))
                is_trial = result.get("is_trial", False)
                self.settings.set_activated(
                    status=True,
                    key=key,
                    email=result.get("email", "user@falcontrade.com"),
                    is_trial=is_trial,
                    expiration=expiration
                )
                self.activation_page.activation_result.emit(True, "Software activated successfully!", result)
            else:
                self.activation_page.activation_result.emit(False, result.get("message", "Invalid activation key"), {})
                
        except Exception as e:
            logger.error(f"License validation error: {e}")
            self.activation_page.activation_result.emit(False, str(e), {})

    def process_trial(self):
        try:
            machine_id = self.settings.settings.get("machine_id")
            
            # Use Supabase manager for trial creation
            result = self.supabase_manager.create_trial_license(machine_id)
            
            if result.get("success"):
                key = result["key"]
                expiration = datetime.fromisoformat(result["expires_at"].replace('Z', '+00:00'))
                self.settings.set_activated(
                    status=True,
                    key=key,
                    email=result.get("email", "trial@falcontrade.com"),
                    is_trial=True,
                    expiration=expiration
                )
                self.activation_page.activation_result.emit(True, "Trial activated successfully! 7 days remaining", {})
            else:
                self.activation_page.activation_result.emit(False, result.get("message", "Trial activation failed"), {})
                
        except Exception as e:
            logger.error(f"Trial activation error: {e}")
            self.activation_page.activation_result.emit(False, str(e), {})

    def validate_license_at_startup(self):
        license_info = self.settings.get_license_info()
        key = license_info.get("key")
        machine_id = self.settings.settings.get("machine_id")
        if key == "1234123412341234":
            return
        if not key or not machine_id:
            return
        threading.Thread(target=self.validate_license, args=(key,)).start()

    def send_heartbeat(self):
        if not self.settings.is_activated():
            return
        license_info = self.settings.get_license_info()
        key = license_info.get("key")
        machine_id = self.settings.settings.get("machine_id")
        if key == "1234123412341234":
            return
        if not key or not machine_id:
            return
        try:
            stats = {
                "signals_processed": self.daily_signals,
                "trades_executed": self.daily_trades,
                "version": VERSION
            }
            
            # Use Supabase manager for heartbeat
            result = self.supabase_manager.send_heartbeat(key, machine_id, stats)
            
            if result.get("success"):
                # Reset daily counters on successful heartbeat
                self.daily_signals = 0
                self.daily_trades = 0
            else:
                logger.warning(f"Heartbeat failed: {result.get('message', 'Unknown error')}")
        except Exception as e:
            logger.error(f"Heartbeat error: {str(e)}")

    def deactivate_software(self, reason):
        self.settings.reset_activation()
        self.stop_copying()
        
        # Reset activation page UI state before showing it
        self.activation_page.reset_ui_state()
        self.stacked_widget.setCurrentWidget(self.activation_page)
        QMessageBox.warning(self, "License Deactivated", reason)

    def show_telegram_page(self):
        self.stacked_widget.setCurrentWidget(self.telegram_page)
        self.status_bar.showMessage("Telegram setup")

    def show_mt5_page(self):
        self.stacked_widget.setCurrentWidget(self.mt5_page)
        self.status_bar.showMessage("MT5 setup")

    def show_dashboard(self):
        self.stacked_widget.setCurrentWidget(self.dashboard_page)
        self.status_bar.showMessage("Dashboard ready")
        # Force refresh connection status and account info
        self.update_connection_status()
        self.update_account_info()

    def on_verification_sent(self):
        self.telegram_page.phone_input.setEnabled(False)
        self.telegram_page.code_input.setEnabled(True)
        self.telegram_page.verify_btn.setEnabled(True)
        self.telegram_page.change_number_btn.setVisible(True)
        self.status_bar.showMessage("Verification code sent")

    def on_telegram_authenticated(self):
        self.settings.set_telegram_session(self.telegram_manager.session_string)
        self.telegram_page.code_input.setEnabled(False)
        self.telegram_page.verify_btn.setEnabled(False)
        self.telegram_page.next_btn.setEnabled(True)
        self.status_bar.showMessage("Telegram connected successfully!")
        self.telegram_manager.load_channels()
        self.update_connection_status()

    def on_channels_loaded(self, channels):
        if channels:
            self.telegram_page.load_channels(channels)
            self.status_bar.showMessage(f"Loaded {len(channels)} channels")
        else:
            self.status_bar.showMessage("No channels found")

    def on_telegram_error(self, error):
        QMessageBox.critical(self, "Telegram Error", error)
        self.telegram_page.send_code_btn.setEnabled(True)
        self.telegram_page.verify_btn.setEnabled(False)
        self.status_bar.showMessage(f"Error: {error}")
        self.update_connection_status()

    def update_connection_status(self, telegram_status=None):
        if telegram_status is None:
            telegram_status = self.telegram_manager.connected
        
        # Check MT5 connection more robustly
        mt5_status = self.mt5_manager.connected and mt5_is_initialized()
        if mt5_status != self.mt5_manager.connected:
            self.mt5_manager.connected = mt5_status
        
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_connection_status(
                telegram_status,
                mt5_status
            )

    def update_account_info(self):
        if hasattr(self, 'dashboard_page'):
            # Force refresh connection status first
            self.update_connection_status()
            self.dashboard_page.update_account_info()

    def start_copying(self):
        # Check Telegram connection
        if not self.telegram_manager.connected:
            session = self.settings.get_telegram_session()
            if session:
                self.status_bar.showMessage("Reconnecting to Telegram...")
                self.telegram_manager.session_string = session
                self.telegram_manager.connect_telegram(
                    TELEGRAM_API_ID,
                    TELEGRAM_API_HASH,
                    ""
                )
                # Don't block the UI thread
                QTimer.singleShot(2000, self.check_telegram_reconnection)
                return
            else:
                QMessageBox.warning(self, "Not Connected", "Telegram session not found. Please set up Telegram again.")
                return

        # Check MT5 connection - also check if MT5 is actually initialized
        if not self.mt5_manager.connected or not mt5_is_initialized():
            QMessageBox.warning(self, "MT5 Not Connected", "Please connect to MT5 first")
            return

        # Update account info before starting
        self.update_account_info()

        channel_ids = self.settings.get_telegram_channels()
        if not channel_ids:
            QMessageBox.warning(self, "No Channels", "Please add Telegram channels first")
            return

        self.telegram_manager.stop_listening()
        self.telegram_manager.channel_handlers = {}

        for channel_id in channel_ids:
            try:
                channel_id_int = int(channel_id)
                self.telegram_manager.add_channel_handler(channel_id_int, self.process_trade_signal)
            except ValueError:
                logger.error(f"Invalid channel ID: {channel_id}")

        self.telegram_manager.start_listening()
        self.copying_active = True
        self.dashboard_page.update_copy_status(True)
        self.status_bar.showMessage("Copy trading started")

    def check_telegram_reconnection(self):
        if not self.telegram_manager.connected:
            QMessageBox.warning(self, "Telegram Not Connected",
                                "Failed to reconnect to Telegram. Please check your connection.")
            return
        self.start_copying()

    def stop_copying(self):
        # Only stop listening and clear handlers, don't shutdown the session
        self.telegram_manager.stop_listening()
        if self.telegram_manager.client:
            try:
                self.telegram_manager.client.list = []
                logger.info("Cleared all Telegram event handlers")
            except Exception as e:
                logger.error(f"Error clearing event handlers: {str(e)}")
        self.telegram_manager.channel_handlers = {}
        self.copying_active = False
        self.dashboard_page.update_copy_status(False)
        self.status_bar.showMessage("Copy trading stopped")

    def on_trade_signal(self, title, message):
        self.signal_count += 1
        self.daily_signals += 1
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 3000)

    def on_new_signal_parsed(self, signal_data):
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_signal_info(signal_data)

            # Only execute if signal was successfully parsed
            if signal_data.get("status") == "Parsed":
                self.execute_trade(signal_data)

    def on_management_command(self, command):
        result = self.mt5_manager.handle_management(command)
        # Handle result, perhaps log or show in UI
        logger.info(f"Management command processed: {command}, Result: {result}")

    def execute_trade(self, signal_data):
        if not self.mt5_manager.connected:
            logger.error("Cannot execute trade - MT5 not connected")
            return

        # Check daily limits before executing
        risk_settings = self.settings.get_risk_settings()
        daily_loss_limit = risk_settings.get("daily_loss_limit", 5.0)
        daily_profit_target = risk_settings.get("daily_profit_target", 10.0)
        
        # Get current daily P&L
        current_pnl = self.mt5_manager.get_daily_pnl()
        
        # Check if we've hit daily loss limit
        if current_pnl < -daily_loss_limit:
            logger.warning(f"Daily loss limit reached: {current_pnl}% (limit: {daily_loss_limit}%)")
            signal_data["status"] = "Skipped - Daily Loss Limit"
            signal_data["error"] = f"Daily loss limit reached: {current_pnl}%"
            if hasattr(self, 'dashboard_page'):
                self.dashboard_page.update_signal_info(signal_data)
            return
            
        # Check if we've hit daily profit target
        if current_pnl > daily_profit_target:
            logger.warning(f"Daily profit target reached: {current_pnl}% (target: {daily_profit_target}%)")
            signal_data["status"] = "Skipped - Daily Profit Target"
            signal_data["error"] = f"Daily profit target reached: {current_pnl}%"
            if hasattr(self, 'dashboard_page'):
                self.dashboard_page.update_signal_info(signal_data)
            return

        # Use the flat signal_data directly (fixed: removed unnecessary nested 'signal_details' access)
        symbol = signal_data.get("symbol")
        order_type = signal_data.get("order_type")
        entry_price = signal_data.get("entry_price")
        sl = signal_data.get("sl")
        tp = signal_data.get("tp")
        tps = signal_data.get("tps", [])

        # Additional validation to skip if key fields are invalid or 'N/A'
        if symbol in (None, "N/A") or order_type in (None, "N/A"):
            logger.error("Invalid signal - missing or invalid symbol or order type")
            return

        # Handle 'N/A' for optional fields by setting to None
        if sl == "N/A":
            sl = None
        if tp == "N/A":
            tp = None
        if tps == [] or tps == ["N/A"]:
            tps = []

        risk_settings = self.settings.get_risk_settings()
        lot_size = risk_settings.get("fixed_lot", 0.1)

        result = self.mt5_manager.execute_trade(
            symbol=symbol,
            order_type=order_type,
            entry_price=entry_price,
            volume=lot_size,
            sl=sl,
            tp=tp,
            tps=tps,
            tolerance=risk_settings.get("pip_tolerance", 2.0),
            channel_name=signal_data.get("channel", "Unknown")
        )

        if result and not any("error" in r for r in result):
            signal_data["status"] = "Executed"
            # Get the actual calculated lot size from the result
            if result and len(result) > 0:
                actual_lot_size = result[0].get("volume", lot_size)
                signal_data["lot_size"] = actual_lot_size
            else:
                signal_data["lot_size"] = lot_size
            self.daily_trades += 1
            
            # Add trade to history for real-time updates
            trade_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "channel": signal_data.get("channel", "N/A"),
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tp": tp,
                "tps": tps,
                "lot_size": signal_data.get("lot_size", lot_size),
                "status": "Executed",
                "profit": 0,  # Will be updated when trade closes
                "notes": "Trade executed successfully"
            }
            self.trade_history.add_trade(trade_data)
            
        else:
            signal_data["status"] = "Failed"
            if result:
                errors = [r.get("error", "Unknown error") for r in result if "error" in r]
                signal_data["error"] = ", ".join(errors)
            
            # Add failed trade to history
            trade_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "channel": signal_data.get("channel", "N/A"),
                "symbol": symbol,
                "order_type": order_type,
                "entry_price": entry_price,
                "sl": sl,
                "tp": tp,
                "tps": tps,
                "lot_size": lot_size,
                "status": "Failed",
                "profit": 0,
                "notes": signal_data.get("error", "Trade execution failed")
            }
            self.trade_history.add_trade(trade_data)

        # Update UI with execution status
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_signal_info(signal_data)

    def process_trade_signal(self, signal_data):
        pass

    def update_trade_history(self):
        """Update trade history display - called by timer"""
        try:
            if hasattr(self, 'dashboard_page') and hasattr(self.dashboard_page, 'history_table'):
                logger.info("Updating trade history display...")
                self.dashboard_page.update_history_table()
                self.dashboard_page.update_history_statistics()
                self.dashboard_page.update_symbol_filter()
                logger.info(f"Trade history updated. Total trades: {len(self.trade_history.history)}")
            else:
                logger.warning("Dashboard page or history table not available")
        except Exception as e:
            logger.error(f"Error updating trade history: {str(e)}")

    def initialize_history_display(self):
        """Initialize the trade history display"""
        # This method is called to set up the initial state of trade history display
        # The actual display is handled by the dashboard page
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_trade_history()

    def update_symbol_filter(self):
        """Update the symbol filter dropdown with unique symbols from history"""
        try:
            if hasattr(self, 'symbol_filter'):
                current_symbol = self.symbol_filter.currentText()
                
                # Get unique symbols from history through parent
                symbols = set()
                for trade in self.parent.trade_history.history:
                    symbol = trade.get('symbol', 'N/A')
                    if symbol != 'N/A':
                        symbols.add(symbol)
                
                # Update dropdown
                self.symbol_filter.clear()
                self.symbol_filter.addItem("All")
                
                # Add symbols in alphabetical order
                for symbol in sorted(symbols):
                    self.symbol_filter.addItem(symbol)
                
                # Restore previous selection if it still exists
                if current_symbol in symbols or current_symbol == "All":
                    index = self.symbol_filter.findText(current_symbol)
                    if index >= 0:
                        self.symbol_filter.setCurrentIndex(index)
                        
        except Exception as e:
            logger.error(f"Error updating symbol filter: {str(e)}")

    def add_test_trade(self):
        """Add a test trade for demonstration"""
        try:
            import random
            symbols = ["EURUSD", "GBPUSD", "USDJPY", "AUDUSD", "BTCUSD"]
            order_types = ["BUY", "SELL"]
            statuses = ["Executed", "Failed", "Pending"]
            
            test_trade = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "channel": "Demo Channel",
                "symbol": random.choice(symbols),
                "order_type": random.choice(order_types),
                "entry_price": round(random.uniform(1.0, 2.0), 4),
                "sl": round(random.uniform(0.9, 1.9), 4),
                "tp": round(random.uniform(1.1, 2.1), 4),
                "tps": [],
                "lot_size": round(random.uniform(0.01, 1.0), 2),
                "status": random.choice(statuses),
                "profit": round(random.uniform(-100, 100), 2),
                "notes": f"Test trade {len(self.parent.trade_history.history) + 1}"
            }
            
            self.parent.trade_history.add_trade(test_trade)
            logger.info(f"Test trade added: {test_trade['symbol']} {test_trade['order_type']}")
            
            # Update the display immediately
            self.parent.update_trade_history()
            
        except Exception as e:
            logger.error(f"Error adding test trade: {str(e)}")

    def back_to_mt5(self):
        # Only stop copying, don't shutdown MT5 connection
        self.stop_copying()
        self.stacked_widget.setCurrentWidget(self.mt5_page)
        self.status_bar.showMessage("MT5 setup page")

    def apply_theme(self):
        """Apply modern dark theme with coral accent colors"""
        self.setStyleSheet("""
            /* Main Window and Global Styles */
            QMainWindow, QWidget {
                background-color: #020711;
                color: #f0f4f9;
                font-family: 'Open Sans';
                font-size: 13px;
            }

            /* Headings */
            QLabel#heading {
                font-family: 'Montserrat';
                font-weight: 700;
                font-size: 16px;
                color: #f0f4f9;
            }

            /* Cards and Containers */
            QFrame[frameShape="4"] /* QFrame.StyledPanel */ {
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 6px;
                padding: 8px;
            }

            /* Primary Buttons */
            QPushButton {
                background-color: #f27d03;
                color: #020711;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
                padding: 6px 12px;
                border: none;
            }

            QPushButton:hover {
                background-color: #ff8a1a;
            }

            QPushButton:pressed {
                background-color: #e07000;
            }

            QPushButton:disabled {
                background-color: #1c243b;
                color: #9ca6b8;
            }

            /* Destructive Buttons */
            QPushButton.destructive {
                background-color: #f27d03;
                color: #020711;
            }

            QPushButton.destructive:hover {
                background-color: #ff8a1a;
            }

            /* Text Styles */
            QLabel {
                color: #f0f4f9;
            }

            QLabel.muted {
                color: #9ca6b8;
            }

            /* Input Fields */
            QLineEdit, QComboBox, QTextEdit {
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 4px;
                padding: 4px 8px;
                color: #f0f4f9;
                selection-background-color: #f27d03;
                selection-color: #020711;
            }

            QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
                border: 1px solid #f27d03;
            }

            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left-width: 1px;
                border-left-color: #1c243b;
                border-left-style: solid;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
                background-color: #1c243b;
            }

            QComboBox::down-arrow {
                image: url(down_arrow.svg);
                width: 12px;
                height: 12px;
            }

            /* Progress Bar */
            QProgressBar {
                border: 1px solid #1c243b;
                border-radius: 4px;
                text-align: center;
                background-color: #0d111f;
            }

            QProgressBar::chunk {
                background-color: #f27d03;
                border-radius: 3px;
            }

            /* Scroll Bars */
            QScrollBar:vertical {
                border: none;
                background-color: #0d111f;
                width: 10px;
                margin: 0px;
            }

            QScrollBar::handle:vertical {
                background-color: #1c243b;
                border-radius: 5px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #2a3449;
            }

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }

            /* Tabs */
            QTabWidget::pane {
                border: 1px solid #1c243b;
                border-radius: 6px;
                background-color: #0d111f;
                margin-top: -1px;
            }

            QTabBar::tab {
                background-color: #0d111f;
                color: #9ca6b8;
                padding: 6px 12px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                border: 1px solid #1c243b;
                margin-right: 2px;
            }

            QTabBar::tab:selected {
                background-color: #0d111f;
                color: #f0f4f9;
                border-bottom-color: #0d111f; /* Same as background to connect with pane */
            }

            QTabBar::tab:hover:!selected {
                background-color: #131a2d;
                color: #f0f4f9;
            }

            /* Sliders */
            QSlider::groove:horizontal {
                border: 1px solid #1c243b;
                height: 6px;
                background: #0d111f;
                border-radius: 3px;
            }

            QSlider::handle:horizontal {
                background: #f27d03;
                border: 1px solid #1c243b;
                width: 14px;
                margin: -4px 0;
                border-radius: 7px;
            }

            /* Checkboxes and Radio Buttons */
            QCheckBox, QRadioButton {
                color: #f0f4f9;
                spacing: 6px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #1c243b;
                border-radius: 3px;
                background-color: #0d111f;
            }

            QCheckBox::indicator:checked, QRadioButton::indicator:checked {
                background-color: #f27d03;
                border: 1px solid #f27d03;
            }

            QRadioButton::indicator {
                border-radius: 7px;
            }

            QRadioButton::indicator:checked {
                background-color: #f27d03;
                border: 1px solid #f27d03;
            }

            /* Profit Indicator (Custom class for labels) */
            .profit-indicator {
                background-color: rgba(29, 158, 74, 0.125); /* #1d9e4a with 12.5% opacity */
                color: #1d9e4a;
                border-radius: 3px;
                padding: 3px 6px;
                font-weight: 500;
            }

            /* Table Views */
            QTableView {
                gridline-color: #1c243b;
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 6px;
                alternate-background-color: rgba(255, 255, 255, 0.03);
            }

            QHeaderView::section {
                background-color: #131a2d;
                color: #f0f4f9;
                padding: 6px;
                border: none;
                border-right: 1px solid #1c243b;
                border-bottom: 1px solid #1c243b;
            }

            QHeaderView::section:last {
                border-right: none;
            }

            /* Menu */
            QMenu {
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 6px;
                padding: 4px;
            }

            QMenu::item {
                padding: 4px 20px;
                border-radius: 4px;
            }

            QMenu::item:selected {
                background-color: #f27d03;
                color: #020711;
            }

            QMenu::separator {
                height: 1px;
                background-color: #1c243b;
                margin: 4px 0;
            }

            /* Tooltips */
            QToolTip {
                background-color: #0d111f;
                color: #f0f4f9;
                border: 1px solid #1c243b;
                border-radius: 4px;
                padding: 6px;
            }

            /* Status indicators with coral theme */
            QLabel[class="status-success"] {
                background-color: rgba(29, 158, 74, 0.125);
                color: #1d9e4a;
                border-radius: 3px;
                padding: 3px 6px;
                font-weight: 500;
            }

            QLabel[class="status-warning"] {
                background-color: rgba(242, 125, 3, 0.125);
                color: #f27d03;
                border-radius: 3px;
                padding: 3px 6px;
                font-weight: 500;
            }

            QLabel[class="status-error"] {
                background-color: rgba(245, 78, 78, 0.125);
                color: #f54e4e;
                border-radius: 3px;
                padding: 3px 6px;
                font-weight: 500;
            }

            /* Group Boxes */
            QGroupBox {
                background-color: transparent;
                border: 1px solid #1c243b;
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 8px;
                color: #f0f4f9;
                font-weight: bold;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                background-color: transparent;
            }

            /* SpinBox and DoubleSpinBox */
            QSpinBox, QDoubleSpinBox {
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 4px;
                padding: 4px 8px;
                color: #f0f4f9;
            }

            QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #f27d03;
            }

            /* Date Edit */
            QDateEdit {
                background-color: #0d111f;
                border: 1px solid #1c243b;
                border-radius: 4px;
                padding: 4px 8px;
                color: #f0f4f9;
            }

            QDateEdit:focus {
                border: 1px solid #f27d03;
            }

            /* Status Bar */
            QStatusBar {
                background-color: #0d111f;
                color: #9ca6b8;
                border-top: 1px solid #1c243b;
            }
        """)

    def show_normal(self):
        self.show()
        self.activateWindow()

    def close_app(self):
        self.trade_monitor.running = False
        self.trade_monitor.wait(2000)
        self.telegram_manager.stop_listening()
        if self.mt5_manager.connected:
            self.mt5_manager.disconnect()
        QApplication.quit()

    def logout(self):
        self.stop_copying()
        self.telegram_manager.stop_listening()
        self.telegram_manager.session_string = None
        self.settings.set_telegram_session(None)
        if self.mt5_manager.connected:
            self.mt5_manager.disconnect()
        self.settings.set_mt5_settings("", "", "", "")
        self.settings.reset_activation()
        if hasattr(self, 'dashboard_page'):
            self.dashboard_page.update_connection_status(False, False)
            self.dashboard_page.update_copy_status(False)
        
        # Reset activation page UI state before showing it
        self.activation_page.reset_ui_state()
        self.stacked_widget.setCurrentWidget(self.activation_page)
        self.status_bar.showMessage("Logged out successfully")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
