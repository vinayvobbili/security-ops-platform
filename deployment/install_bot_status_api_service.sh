#!/bin/bash
# Installation script for Bot Status API systemd service

set -e

echo "Installing Bot Status API systemd service..."

# Stop any manually running instance
echo "Stopping any manually running bot status API..."
pkill -f "deployment/bot_status_api.py" 2>/dev/null || true
sleep 2

# Copy service file to systemd directory
echo "Installing service file..."
sudo cp /home/user/pub/IR/deployment/ir-bot-status-api.service /etc/systemd/system/

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable service to start on boot
echo "Enabling service to start on boot..."
sudo systemctl enable ir-bot-status-api.service

# Start the service now
echo "Starting service..."
sudo systemctl start ir-bot-status-api.service

# Check status
echo ""
echo "Service status:"
sudo systemctl status ir-bot-status-api.service --no-pager

echo ""
echo "✅ Bot Status API service installed and started successfully!"
echo "   The service will now automatically start on boot."
echo ""
echo "Useful commands:"
echo "  - Check status:  sudo systemctl status ir-bot-status-api"
echo "  - View logs:     sudo journalctl -u ir-bot-status-api -f"
echo "  - Restart:       sudo systemctl restart ir-bot-status-api"
echo "  - Stop:          sudo systemctl stop ir-bot-status-api"
echo "  - Disable:       sudo systemctl disable ir-bot-status-api"
