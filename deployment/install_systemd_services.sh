#!/bin/bash
# Install systemd service files for IR bots
# Run this script with: sudo bash install_systemd_services.sh

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR="$SCRIPT_DIR/systemd"

echo "================================================"
echo "Installing IR Systemd Services"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Copy service files
echo "Installing service files to /etc/systemd/system/..."
cp "$SYSTEMD_DIR"/*.service /etc/systemd/system/
echo "  ✓ Copied service files"
echo ""

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "  ✓ Daemon reloaded"
echo ""

# Enable services
echo "Enabling services to start on boot..."
systemctl enable ir-all-jobs.service
systemctl enable ir-msoar.service
systemctl enable ir-money-ball.service
systemctl enable ir-toodles.service
systemctl enable ir-barnacles.service
systemctl enable ir-jarvis.service
echo "  ✓ All services enabled"
echo ""

echo "================================================"
echo "✅ Systemd services installed successfully!"
echo "================================================"
echo ""
echo "Available services:"
echo "  - ir-all-jobs      (Job scheduler)"
echo "  - ir-msoar         (MSOAR bot)"
echo "  - ir-money-ball    (MoneyBall bot)"
echo "  - ir-toodles       (Toodles bot)"
echo "  - ir-barnacles     (Barnacles bot)"
echo "  - ir-jarvis        (Jarvis bot)"
echo ""
echo "Management commands:"
echo "  Start all:    sudo systemctl start ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvis"
echo "  Stop all:     sudo systemctl stop ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvis"
echo "  Restart all:  sudo systemctl restart ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvis"
echo "  Status:       sudo systemctl status ir-*"
echo ""
echo "View logs:"
echo "  journalctl -u ir-all-jobs -f"
echo "  journalctl -u ir-msoar -f"
echo "  journalctl -u ir-money-ball -f"
echo "  etc..."
echo ""
