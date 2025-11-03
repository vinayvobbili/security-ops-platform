#!/bin/bash
# Setup Logdy with nginx reverse proxy for organized log viewing
# Run this script with: bash setup_logdy_nginx.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IR_DIR="/home/vinay/pub/IR"

echo "================================================"
echo "Setting up Logdy with nginx Reverse Proxy"
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
echo -n "metcirt" | sudo htpasswd -i -c /home/vinay/pub/IR/.htpasswd admin
sudo chown vinay:vinay /home/vinay/pub/IR/.htpasswd
sudo chmod 600 /home/vinay/pub/IR/.htpasswd
echo "  ✓ Password configured (username: admin, password: metcirt)"
echo ""

# Install nginx configuration
echo "Installing nginx configuration..."
sudo cp "$SCRIPT_DIR/nginx-logdy.conf" /etc/nginx/sites-available/ir-logdy.conf
sudo ln -sf /etc/nginx/sites-available/ir-logdy.conf /etc/nginx/sites-enabled/ir-logdy.conf
sudo nginx -t
echo "  ✓ nginx configuration installed"
echo ""

# Stop and disable old ir-logdy service if it exists
if systemctl list-unit-files | grep -q "^ir-logdy.service"; then
    echo "Disabling old ir-logdy service..."
    sudo systemctl stop ir-logdy 2>/dev/null || true
    sudo systemctl disable ir-logdy 2>/dev/null || true
    echo "  ✓ Old service disabled"
fi
echo ""

# Install all logdy systemd services
echo "Installing Logdy systemd services..."
sudo cp "$SCRIPT_DIR/systemd"/ir-logdy-*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable all services
for service in all toodles msoar money-ball jarvais barnacles jobs; do
    sudo systemctl enable ir-logdy-${service}.service
done
echo "  ✓ Systemd services installed and enabled"
echo ""

# Start all logdy services
echo "Starting Logdy services..."
for service in all toodles msoar money-ball jarvais barnacles jobs; do
    sudo systemctl start ir-logdy-${service}.service
done
sleep 2
echo "  ✓ All Logdy services started"
echo ""

# Restart nginx
echo "Restarting nginx..."
sudo systemctl restart nginx
echo "  ✓ nginx restarted"
echo ""

# Get VM details
VM_IP=$(hostname -I | awk '{print $1}')
VM_HOSTNAME=$(hostname)

echo "================================================"
echo "✅ Logdy Setup Complete!"
echo "================================================"
echo ""
echo "IMPORTANT: Ask network engineer to open ports 8030-8037"
echo ""
echo "Landing page:"
echo "  http://metcirt-lab-12.internal.company.com:8030"
echo "  (Password: metcirt)"
echo ""
echo "Direct access URLs:"
echo "  http://metcirt-lab-12.internal.company.com:8031 - All services (journalctl)"
echo "  http://metcirt-lab-12.internal.company.com:8032 - Toodles"
echo "  http://metcirt-lab-12.internal.company.com:8033 - MSOAR"
echo "  http://metcirt-lab-12.internal.company.com:8034 - MoneyBall"
echo "  http://metcirt-lab-12.internal.company.com:8035 - Jarvais"
echo "  http://metcirt-lab-12.internal.company.com:8036 - Barnacles"
echo "  http://metcirt-lab-12.internal.company.com:8037 - All Jobs"
echo "  (Each protected with password: metcirt)"
echo ""
echo "Features:"
echo "  ✓ Beautiful landing page with direct links"
echo "  ✓ Real-time log streaming"
echo "  ✓ Color-coded log levels"
echo "  ✓ Search and filter functionality"
echo "  ✓ Password protected"
echo "  ✓ No SSH access required"
echo ""
echo "Management:"
echo "  Check status: sudo systemctl status ir-logdy-*"
echo "  Restart all:  for s in all toodles msoar money-ball jarvais barnacles jobs; do sudo systemctl restart ir-logdy-\$s; done"
echo "  nginx status: sudo systemctl status nginx"
echo ""
