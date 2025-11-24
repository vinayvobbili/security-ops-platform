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

# Enable bot services
echo "Enabling bot services to start on boot..."
systemctl enable ir-all-jobs.service
systemctl enable ir-msoar.service
systemctl enable ir-money-ball.service
systemctl enable ir-toodles.service
systemctl enable ir-barnacles.service
systemctl enable ir-jarvis.service
echo "  ✓ Bot services enabled"
echo ""

# Enable log viewer services
echo "Enabling log viewer services..."
systemctl enable ir-log-viewer-all.service
systemctl enable ir-log-viewer-jobs.service
systemctl enable ir-log-viewer-barnacles.service
systemctl enable ir-log-viewer-msoar.service
systemctl enable ir-log-viewer-money-ball.service
systemctl enable ir-log-viewer-toodles.service
systemctl enable ir-log-viewer-jarvis.service
echo "  ✓ Log viewer services enabled"
echo ""

echo "================================================"
echo "✅ Systemd services installed successfully!"
echo "================================================"
echo ""
echo "Available bot services:"
echo "  - ir-all-jobs      (Job scheduler)"
echo "  - ir-msoar         (MSOAR bot)"
echo "  - ir-money-ball    (MoneyBall bot)"
echo "  - ir-toodles       (Toodles bot)"
echo "  - ir-barnacles     (Barnacles bot)"
echo "  - ir-jarvis        (Jarvis bot)"
echo ""
echo "Available log viewer services:"
echo "  - ir-log-viewer-all          (All services - port 8030)"
echo "  - ir-log-viewer-jobs         (All Jobs - port 8037)"
echo "  - ir-log-viewer-barnacles    (Barnacles - port 8031)"
echo "  - ir-log-viewer-msoar        (MSOAR - port 8032)"
echo "  - ir-log-viewer-money-ball   (MoneyBall - port 8033)"
echo "  - ir-log-viewer-toodles      (Toodles - port 8034)"
echo "  - ir-log-viewer-jarvis       (Jarvis - port 8036)"
echo ""
echo "Management commands:"
echo "  Start all bots:     sudo systemctl start ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvis"
echo "  Start all viewers:  sudo systemctl start ir-log-viewer-*"
echo "  Stop all:           sudo systemctl stop ir-*"
echo "  Restart all:        sudo systemctl restart ir-*"
echo "  Status:             sudo systemctl status ir-*"
echo ""
echo "View logs:"
echo "  journalctl -u ir-all-jobs -f"
echo "  journalctl -u ir-msoar -f"
echo "  journalctl -u ir-money-ball -f"
echo "  etc..."
echo ""
echo "Access log viewers:"
echo "  All services:  http://localhost:8030 (user: metcirt, pass: metcirt)"
echo "  All Jobs:      http://localhost:8037 (user: metcirt, pass: metcirt)"
echo "  Barnacles:     http://localhost:8031 (user: metcirt, pass: metcirt)"
echo "  MSOAR:         http://localhost:8032 (user: metcirt, pass: metcirt)"
echo "  MoneyBall:     http://localhost:8033 (user: metcirt, pass: metcirt)"
echo "  Toodles:       http://localhost:8034 (user: metcirt, pass: metcirt)"
echo "  Jarvis:        http://localhost:8036 (user: metcirt, pass: metcirt)"
echo ""
