#!/bin/bash
# SOC Bot Preloader Service Installation Script

set -e  # Exit on any error

echo "🚀 Installing SOC Bot Preloader Service..."

# Check if running as root for system service installation
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux with systemd
    if [[ $EUID -eq 0 ]]; then
        echo "✅ Installing as system service (Linux)..."
        
        # Copy service file to systemd directory
        cp soc-bot-preloader.service /etc/systemd/system/
        
        # Set proper permissions
        chmod 644 /etc/systemd/system/soc-bot-preloader.service
        
        # Reload systemd and enable service
        systemctl daemon-reload
        systemctl enable soc-bot-preloader.service
        
        echo "✅ Service installed and enabled!"
        echo "📋 Available commands:"
        echo "   • Start:   sudo systemctl start soc-bot-preloader"
        echo "   • Stop:    sudo systemctl stop soc-bot-preloader"
        echo "   • Status:  sudo systemctl status soc-bot-preloader"
        echo "   • Logs:    sudo journalctl -u soc-bot-preloader -f"
        
    else
        echo "❌ Please run as root to install system service: sudo ./install_preloader_service.sh"
        exit 1
    fi

elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS with launchd
    echo "✅ Installing as user service (macOS)..."
    
    # Find the correct Python executable (with packages)
    PYTHON_PATH=$(which python3)
    echo "Using Python: $PYTHON_PATH"
    
    # Create LaunchAgent plist
    cat > ~/Library/LaunchAgents/com.acme.soc-bot-preloader.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.acme.soc-bot-preloader</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$(pwd)/preload_soc_bot.py</string>
    </array>
    
    <key>WorkingDirectory</key>
    <string>$(pwd)</string>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>/tmp/soc-bot-preloader.out</string>
    
    <key>StandardErrorPath</key>
    <string>/tmp/soc-bot-preloader.err</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>$(pwd)</string>
    </dict>
</dict>
</plist>
EOF
    
    # Load the service
    launchctl load ~/Library/LaunchAgents/com.acme.soc-bot-preloader.plist
    
    echo "✅ Service installed and loaded!"
    echo "📋 Available commands:"
    echo "   • Start:   launchctl start com.acme.soc-bot-preloader"
    echo "   • Stop:    launchctl stop com.acme.soc-bot-preloader"
    echo "   • Status:  launchctl list | grep soc-bot-preloader"
    echo "   • Logs:    tail -f /tmp/soc-bot-preloader.log"
    
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo ""
echo "🎯 Installation completed!"
echo "📝 The service will now:"
echo "   • Start automatically on boot"
echo "   • Load all SOC bot components into memory"
echo "   • Keep them warm for instant responses"
echo "   • Restart automatically if it crashes"
echo ""
echo "🔥 Your SOC bot will now be HOT and ready immediately after boot!"
echo "⚡ Message responses should be instant once the service is running."