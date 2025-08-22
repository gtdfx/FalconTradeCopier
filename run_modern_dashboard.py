#!/usr/bin/env python3
"""
Launcher script for the Modern Dashboard GUI
Run this file to start the Falcon Trade Signal Copier with the new modern interface.
"""

import sys
import os

# Add the FTSC directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'FTSC'))

try:
    from FTSC.gui.modern_dashboard import main
    
    if __name__ == "__main__":
        print("Starting Falcon Trade Signal Copier - Modern Dashboard...")
        main()
        
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please make sure you have PySide6 installed:")
    print("pip install PySide6")
    sys.exit(1)
except Exception as e:
    print(f"Error starting application: {e}")
    sys.exit(1)

