#!/usr/bin/env python3
"""
Test script for the Modern Dashboard GUI
This script tests the complete functionality of the Falcon Trade Signal Copier.
"""

import sys
import os

# Add the FTSC directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'FTSC'))

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from FTSC.gui.modern_dashboard import ModernDashboard, SettingsManager, TelegramManager, MT5Manager
        print("✓ All core classes imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_settings_manager():
    """Test the settings manager functionality"""
    print("\nTesting Settings Manager...")
    
    try:
        from FTSC.gui.modern_dashboard import SettingsManager
        
        # Create a test settings file
        test_settings = SettingsManager("test_settings.json")
        
        # Test default settings
        assert test_settings.settings is not None
        assert "risk" in test_settings.settings
        assert "telegram" in test_settings.settings
        assert "mt5" in test_settings.settings
        
        print("✓ Settings Manager created successfully")
        print("✓ Default settings loaded correctly")
        
        # Test risk settings
        risk_settings = test_settings.get_risk_settings()
        assert "fixed_lot" in risk_settings
        assert "max_trades" in risk_settings
        
        print("✓ Risk settings accessible")
        
        # Clean up test file
        if os.path.exists("test_settings.json"):
            os.remove("test_settings.json")
            
        return True
        
    except Exception as e:
        print(f"✗ Settings Manager test failed: {e}")
        return False

def test_managers():
    """Test the manager classes"""
    print("\nTesting Manager Classes...")
    
    try:
        from FTSC.gui.modern_dashboard import TelegramManager, MT5Manager
        
        # Test Telegram Manager
        telegram_manager = TelegramManager()
        assert telegram_manager is not None
        print("✓ Telegram Manager created successfully")
        
        # Test MT5 Manager
        mt5_manager = MT5Manager()
        assert mt5_manager is not None
        print("✓ MT5 Manager created successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Manager test failed: {e}")
        return False

def test_ui_creation():
    """Test UI creation without showing the window"""
    print("\nTesting UI Creation...")
    
    try:
        from PySide6.QtWidgets import QApplication
        from FTSC.gui.modern_dashboard import ModernDashboard
        
        # Create QApplication instance
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        # Create dashboard (don't show it)
        dashboard = ModernDashboard()
        assert dashboard is not None
        print("✓ Modern Dashboard created successfully")
        
        # Test basic UI components
        assert hasattr(dashboard, 'settings')
        assert hasattr(dashboard, 'telegram_manager')
        assert hasattr(dashboard, 'mt5_manager')
        assert hasattr(dashboard, 'supabase_manager')
        
        print("✓ All managers initialized")
        
        # Test UI components
        assert hasattr(dashboard, 'stacked_widget')
        assert hasattr(dashboard, 'signals_table')
        assert hasattr(dashboard, 'trades_table')
        
        print("✓ UI components created")
        
        return True
        
    except Exception as e:
        print(f"✗ UI creation test failed: {e}")
        return False

def test_functionality():
    """Test core functionality"""
    print("\nTesting Core Functionality...")
    
    try:
        from FTSC.gui.modern_dashboard import get_hardware_id
        
        # Test hardware ID generation
        hw_id = get_hardware_id()
        assert hw_id is not None
        assert len(hw_id) > 0
        print("✓ Hardware ID generation works")
        
        return True
        
    except Exception as e:
        print(f"✗ Functionality test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("Falcon Trade Signal Copier - Modern Dashboard Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_settings_manager,
        test_managers,
        test_ui_creation,
        test_functionality
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The modern dashboard is ready to use.")
        print("\nTo run the dashboard:")
        print("python run_modern_dashboard.py")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
    
    print("=" * 50)

if __name__ == "__main__":
    main()

