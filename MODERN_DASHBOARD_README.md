# Modern Dashboard GUI

A sleek, modern dashboard interface for the Falcon Trade Signal Copier application, featuring a dark theme and intuitive navigation.

## Features

- **Complete Trading Application**: Full integration with all Falcon Trade Signal Copier functionality
- **Dark Theme**: Modern dark blue color scheme for better eye comfort
- **Sidebar Navigation**: Clean left sidebar with navigation buttons
- **Real-time Data Display**: Tables showing latest signals and active trades
- **Telegram Integration**: Built-in Telegram client for signal monitoring
- **MetaTrader 5 Integration**: Direct MT5 connection for trade execution
- **Risk Management**: Comprehensive risk management settings
- **License Management**: Built-in license validation and activation
- **Settings Management**: Persistent application settings
- **Responsive Design**: Adapts to different window sizes
- **Professional UI**: Clean, modern interface suitable for trading applications

## Screenshots

The dashboard includes:
- Left sidebar with navigation (Dashboard, Telegram, MetaTrader 5, etc.)
- Main content area with "Dashboard" title
- Latest Signals section with Buy/Sell data
- Active Trades section with trading pair information
- Create Signal button for manual signal creation

## Installation

1. Make sure you have the required dependencies:
   ```bash
   pip install PySide6
   ```

2. The modern dashboard is located at:
   ```
   FTSC/gui/modern_dashboard.py
   ```

## Usage

### Option 1: Run the launcher script
```bash
python run_modern_dashboard.py
```

### Option 2: Run directly
```bash
python FTSC/gui/modern_dashboard.py
```

### Option 3: Test the application
```bash
python test_modern_dashboard.py
```

### Option 4: Import and use in your code
```python
from FTSC.gui.modern_dashboard import ModernDashboard
from PySide6.QtWidgets import QApplication
import sys

app = QApplication(sys.argv)
dashboard = ModernDashboard()
dashboard.show()
sys.exit(app.exec())
```

## Interface Components

### Sidebar Navigation
- **Dashboard**: Main dashboard view with connection status, signals, and trades
- **Telegram**: Telegram integration settings and connection management
- **MetaTrader 5**: MT5 connection settings and account management
- **Risk Management**: Comprehensive risk management configuration
- **Settings**: Application settings and license management

### Dashboard Page
- **Connection Status**: Real-time status of Telegram, MT5, and license connections
- **Latest Signals**: Table showing recent trading signals
  - Buy/Sell column with color coding (blue for buy, red for sell)
  - Entry price column
  - Take Profit (TP) column
- **Active Trades**: Table showing currently active trades
  - Trading pair column
  - Entry price column
  - Take Profit column
- **Create Signal Button**: Blue button for manual signal creation

### Telegram Page
- **Phone Number Input**: Enter Telegram phone number
- **Session String Input**: Optional session string for authentication
- **Connect Button**: Establish Telegram connection

### MT5 Page
- **Account Settings**: MT5 account number, server, password, and path
- **Connect Button**: Establish MT5 connection
- **Connection Status**: Real-time MT5 connection status

### Risk Management Page
- **Fixed Lot Size**: Set fixed lot size for trades
- **Risk Percent**: Set risk percentage per trade
- **Max Trades**: Maximum number of simultaneous trades
- **Save Button**: Save risk management settings

### Settings Page
- **License Key Input**: Enter license key for activation
- **Activate Button**: Activate the application license
- **License Status**: Current license status display

## Customization

### Colors
The dashboard uses a dark theme with the following color palette:
- Background: `#1a1a2e` (dark blue)
- Sidebar: `#16213e` (medium blue)
- Accent: `#4fc3f7` (light blue)
- Borders: `#0f3460` (dark blue)
- Text: `#ffffff` (white)
- Sell signals: `#ff6b6b` (light red)

### Styling
All styling is done through CSS-like stylesheets in the `setup_styles()` method. You can modify colors, fonts, and layout by editing this method.

## Integration

The modern dashboard is a complete, standalone application that includes all the functionality from the original Falcon Trade Signal Copier:

1. **Settings Management**: Complete settings system with JSON persistence
2. **Telegram Integration**: Full Telegram client with signal monitoring
3. **MT5 Integration**: Direct MetaTrader 5 connection for trade execution
4. **Risk Management**: Comprehensive risk management with configurable parameters
5. **License Management**: Built-in license validation and activation system
6. **Real-time Updates**: Live status updates and signal processing
7. **Signal Processing**: Automatic signal parsing and trade execution
8. **Trade Tracking**: Active trade monitoring and management

## Application Logic

The modern dashboard includes the complete application logic:

### Core Managers
- **SettingsManager**: Handles application settings and persistence
- **TelegramManager**: Manages Telegram connections and signal monitoring
- **MT5Manager**: Handles MetaTrader 5 connections and trade execution
- **SupabaseManager**: Manages license validation and cloud services

### Key Features
- **Hardware ID Generation**: Device-specific licensing
- **Session Management**: Persistent Telegram sessions
- **Risk Calculation**: Dynamic lot sizing based on risk parameters
- **Trade Execution**: Automated trade placement and management
- **Error Handling**: Comprehensive error handling and logging
- **Status Monitoring**: Real-time connection and trade status

## Dependencies

- **PySide6**: Qt framework for Python (GUI components)
- **Python 3.7+**: Required for modern Python features
- **Telethon**: Telegram client library (optional)
- **MetaTrader5**: MT5 Python library (optional)
- **Supabase**: Cloud database client (optional)

### Installation
```bash
pip install PySide6
pip install telethon  # For Telegram integration
pip install MetaTrader5  # For MT5 integration
pip install supabase  # For cloud services
```

## File Structure

```
FTSC/
├── gui/
│   ├── modern_dashboard.py    # Main dashboard implementation
│   ├── logo_header.py         # Logo component (existing)
│   └── ...                    # Other GUI components
└── ...

run_modern_dashboard.py        # Launcher script
test_modern_dashboard.py       # Test script
MODERN_DASHBOARD_README.md     # This file
```

## Troubleshooting

### Common Issues

1. **Import Error**: Make sure PySide6 is installed
   ```bash
   pip install PySide6
   ```

2. **Module Not Found**: Ensure you're running from the correct directory or use the launcher script

3. **Display Issues**: The dashboard requires a graphical environment. For headless servers, consider using X11 forwarding or a virtual display.

### Performance

The dashboard is optimized for performance with:
- Efficient widget layouts
- Minimal redraws
- Optimized styling
- Responsive design

## Future Enhancements

Potential improvements for the modern dashboard:
- Real-time data updates
- Interactive charts and graphs
- Advanced filtering and sorting
- Export functionality
- User preferences and themes
- Mobile-responsive design
- Accessibility features

## License

This modern dashboard is part of the Falcon Trade Signal Copier project and follows the same licensing terms.
