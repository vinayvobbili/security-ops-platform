#!/bin/bash
# Setup Logdy log viewer for IR services
# Run this script with: bash setup_logdy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IR_DIR="/home/vinay/pub/IR"

echo "================================================"
echo "Setting up Logdy Log Viewer"
echo "================================================"
echo ""

# Check if logdy is installed
if [ ! -f "$HOME/bin/logdy" ]; then
    echo "Installing Logdy..."
    cd /tmp
    wget -q https://github.com/logdyhq/logdy-core/releases/download/v0.17.0/logdy_linux_amd64
    chmod +x logdy_linux_amd64
    mv logdy_linux_amd64 ~/bin/logdy
    echo "  ✓ Logdy installed to ~/bin/logdy"
else
    echo "  ✓ Logdy already installed"
fi
echo ""

# Generate password if it doesn't exist
if [ ! -f "$IR_DIR/.logdy_password" ]; then
    echo "Generating secure password for Logdy UI..."
    # Generate a random password
    PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
    echo "$PASSWORD" > "$IR_DIR/.logdy_password"
    chmod 600 "$IR_DIR/.logdy_password"
    echo "  ✓ Password saved to $IR_DIR/.logdy_password"
    echo ""
    echo "  Your Logdy password: $PASSWORD"
    echo "  (Save this - you'll need it to access the web UI)"
else
    echo "  ✓ Using existing password from $IR_DIR/.logdy_password"
fi
echo ""

# Install systemd service
echo "Installing Logdy systemd service..."
sudo cp "$SCRIPT_DIR/systemd/ir-logdy.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ir-logdy.service
echo "  ✓ Systemd service installed and enabled"
echo ""

# Start the service
echo "Starting Logdy service..."
sudo systemctl start ir-logdy.service
sleep 2
echo "  ✓ Logdy service started"
echo ""

# Get VM IP address
VM_IP=$(hostname -I | awk '{print $1}')

echo "================================================"
echo "✅ Logdy Setup Complete!"
echo "================================================"
echo ""
echo "Access the log viewer at:"
echo "  http://$VM_IP:8030"
echo "  or"
echo "  http://$(hostname):8030"
echo ""
echo "Login credentials:"
echo "  Username: (leave blank or type anything)"
echo "  Password: $(cat $IR_DIR/.logdy_password)"
echo ""
echo "The log viewer will show real-time logs from all IR services:"
echo "  - ir-all-jobs"
echo "  - ir-msoar"
echo "  - ir-money-ball"
echo "  - ir-toodles"
echo "  - ir-barnacles"
echo "  - ir-jarvais"
echo ""
echo "Management:"
echo "  Check status: sudo systemctl status ir-logdy"
echo "  Restart:      sudo systemctl restart ir-logdy"
echo "  Stop:         sudo systemctl stop ir-logdy"
echo "  View logs:    journalctl -u ir-logdy -f"
echo ""
