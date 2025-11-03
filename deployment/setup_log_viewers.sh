#!/bin/bash
# Setup Python-based log viewers with nginx landing page
# Run this script with: bash setup_log_viewers.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================"
echo "Setting up Log Viewers with nginx Landing Page"
echo "================================================"
echo ""

# Install nginx if not present
if ! command -v nginx &> /dev/null; then
    echo "Installing nginx..."
    sudo apt-get update -qq
    sudo apt-get install -y nginx apache2-utils
    echo "  ✓ nginx installed"
else
    echo "  ✓ nginx already installed"
fi
echo ""

# Create htpasswd file for basic auth
echo "Setting up password protection..."
echo -n "metcirt" | sudo htpasswd -i -c /home/vinay/pub/IR/.htpasswd metcirt
sudo chown vinay:vinay /home/vinay/pub/IR/.htpasswd
sudo chmod 644 /home/vinay/pub/IR/.htpasswd
echo "  ✓ Password configured (username: metcirt, password: metcirt)"
echo ""

# Ensure home directory is accessible for nginx
echo "Configuring directory permissions..."
chmod 751 /home/vinay
echo "  ✓ Directory permissions set"
echo ""

# Install nginx configuration
echo "Installing nginx configuration..."
sudo cp "$SCRIPT_DIR/nginx-log-viewer.conf" /etc/nginx/sites-available/ir-log-viewer.conf
sudo ln -sf /etc/nginx/sites-available/ir-log-viewer.conf /etc/nginx/sites-enabled/ir-log-viewer.conf
sudo nginx -t
echo "  ✓ nginx configuration installed"
echo ""

# Install Python log viewer systemd services
echo "Installing new log viewer systemd services..."
sudo cp "$SCRIPT_DIR/systemd"/ir-log-viewer-*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable all services
for service in all toodles msoar money-ball jarvais barnacles jobs; do
    sudo systemctl enable ir-log-viewer-${service}.service
done
echo "  ✓ Systemd services installed and enabled"
echo ""

# Make log viewer script executable
echo "Making log viewer script executable..."
chmod +x "$SCRIPT_DIR/log_viewer.py"
echo "  ✓ Script permissions set"
echo ""

# Start all log viewer services
echo "Starting log viewer services..."
for service in all toodles msoar money-ball jarvais barnacles jobs; do
    sudo systemctl start ir-log-viewer-${service}.service
done
sleep 2
echo "  ✓ All log viewer services started"
echo ""

# Restart nginx
echo "Restarting nginx..."
sudo systemctl restart nginx
echo "  ✓ nginx restarted"
echo ""

echo "================================================"
echo "✅ Log Viewers Setup Complete!"
echo "================================================"
echo ""
echo "IMPORTANT: Ask network engineer to open ports 8030-8037"
echo ""
echo "Landing page:"
echo "  http://metcirt-lab-12.internal.company.com:8030"
echo "  (Username: metcirt, Password: metcirt)"
echo ""
echo "Direct access URLs:"
echo "  http://metcirt-lab-12.internal.company.com:8031 - All Services (journalctl)"
echo "  http://metcirt-lab-12.internal.company.com:8032 - Toodles"
echo "  http://metcirt-lab-12.internal.company.com:8033 - MSOAR"
echo "  http://metcirt-lab-12.internal.company.com:8034 - MoneyBall"
echo "  http://metcirt-lab-12.internal.company.com:8035 - Jarvais"
echo "  http://metcirt-lab-12.internal.company.com:8036 - Barnacles"
echo "  http://metcirt-lab-12.internal.company.com:8037 - All Jobs"
echo "  (Each protected with username: metcirt, password: metcirt)"
echo ""
echo "Features:"
echo "  ✓ Full log streaming (like tail -f)"
echo "  ✓ Auto-scrolling with pause on manual scroll"
echo "  ✓ Color-coded log levels (ERROR, WARNING, INFO, DEBUG)"
echo "  ✓ Browser native search (Ctrl+F)"
echo "  ✓ Dark theme optimized for readability"
echo "  ✓ Real-time connection status"
echo "  ✓ Password protected"
echo "  ✓ No SSH access required"
echo ""
echo "Management:"
echo "  Check status: sudo systemctl status ir-log-viewer-*"
echo "  Restart all:  for s in all toodles msoar money-ball jarvais barnacles jobs; do sudo systemctl restart ir-log-viewer-\$s; done"
echo "  nginx status: sudo systemctl status nginx"
echo "  View logs:    sudo journalctl -u ir-log-viewer-* -f"
echo ""
echo "Testing locally (before firewall opens ports):"
echo "  ssh -L 8030:localhost:8030 -L 8031:localhost:8031 -L 8032:localhost:8032 -L 8033:localhost:8033 -L 8034:localhost:8034 -L 8035:localhost:8035 -L 8036:localhost:8036 -L 8037:localhost:8037 metcirt-lab"
echo "  Then access: http://localhost:8030"
echo ""
