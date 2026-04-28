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
systemctl enable ir-scheduler.service
systemctl enable ir-msoar.service
systemctl enable ir-money-ball.service
systemctl enable ir-toodles.service
systemctl enable ir-barnacles.service
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
echo "  ✓ Log viewer services enabled"
echo ""

echo "================================================"
echo "✅ Systemd services installed successfully!"
echo "================================================"
echo ""
echo "Available bot services:"
echo "  - ir-scheduler     (Job scheduler)"
echo "  - ir-msoar         (the case orchestrator bot)"
echo "  - ir-money-ball    (MoneyBall bot)"
echo "  - ir-toodles       (the notification service bot)"
echo "  - ir-barnacles     (the alert triage service bot)"
echo ""
echo "Available log viewer services:"
echo "  - ir-log-viewer-all          (All services - port 8030)"
echo "  - ir-log-viewer-jobs         (Scheduler - port 8037)"
echo "  - ir-log-viewer-barnacles    (the alert triage service - port 8031)"
echo "  - ir-log-viewer-msoar        (the case orchestrator - port 8032)"
echo "  - ir-log-viewer-money-ball   (MoneyBall - port 8033)"
echo "  - ir-log-viewer-toodles      (the notification service - port 8034)"
echo ""
echo "Management commands:"
echo "  Start all bots:     sudo systemctl start ir-scheduler ir-msoar ir-money-ball ir-toodles ir-barnacles"
echo "  Start all viewers:  sudo systemctl start ir-log-viewer-*"
echo "  Stop all:           sudo systemctl stop ir-*"
echo "  Restart all:        sudo systemctl restart ir-*"
echo "  Status:             sudo systemctl status ir-*"
echo ""
echo "View logs:"
echo "  journalctl -u ir-scheduler -f"
echo "  journalctl -u ir-msoar -f"
echo "  journalctl -u ir-money-ball -f"
echo "  etc..."
echo ""
echo "Access log viewers:"
echo "  All services:  http://localhost:8030 (user: sirt, pass: sirt)"
echo "  Scheduler:     http://localhost:8037 (user: sirt, pass: sirt)"
echo "  the alert triage service:     http://localhost:8031 (user: sirt, pass: sirt)"
echo "  the case orchestrator:         http://localhost:8032 (user: sirt, pass: sirt)"
echo "  MoneyBall:     http://localhost:8033 (user: sirt, pass: sirt)"
echo "  the notification service:       http://localhost:8034 (user: sirt, pass: sirt)"
echo ""
