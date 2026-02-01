#!/bin/bash
# Infrastructure fixes for lab-vm VM
# Run this script with: sudo bash vm_infrastructure_fixes.sh

set -e  # Exit on error

echo "================================================"
echo "IR Infrastructure Fixes for lab-vm VM"
echo "================================================"
echo ""

# Fix 1: Increase File Descriptor Limits
echo "✓ Fix 1: Setting file descriptor limits to 65536..."
cat > /etc/security/limits.d/99-ir-bots.conf << 'EOF'
# IR Bot File Descriptor Limits
# Increased from default 1024 to handle websocket connections
* soft nofile 65536
* hard nofile 65536
user soft nofile 65536
user hard nofile 65536
EOF
echo "  Created /etc/security/limits.d/99-ir-bots.conf"
echo ""

# Fix 2: TCP Keepalive Settings
echo "✓ Fix 2: Configuring TCP keepalive for websocket stability..."
cat > /etc/sysctl.d/99-ir-keepalive.conf << 'EOF'
# TCP Keepalive Settings for Websocket Connections
# Reduced from 2 hours to 60 seconds to detect stale connections faster
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
EOF
echo "  Created /etc/sysctl.d/99-ir-keepalive.conf"
sysctl -p /etc/sysctl.d/99-ir-keepalive.conf
echo ""

# Fix 3: Netplan Permissions
echo "✓ Fix 3: Securing netplan configuration files..."
chmod 600 /etc/netplan/*.yaml
echo "  Set permissions to 600 on /etc/netplan/*.yaml"
echo ""

# Fix 4: Disable IPv6 (optional - reduces DNS lookup overhead)
echo "✓ Fix 4: Disabling IPv6 to reduce DNS overhead..."
cat > /etc/sysctl.d/99-disable-ipv6.conf << 'EOF'
# Disable IPv6 to reduce DNS lookup overhead
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/99-disable-ipv6.conf
echo ""

echo "================================================"
echo "✅ All infrastructure fixes applied!"
echo "================================================"
echo ""
echo "Changes that require reboot:"
echo "  - File descriptor limits (requires new login session)"
echo ""
echo "Changes active immediately:"
echo "  - TCP keepalive settings"
echo "  - IPv6 disabled"
echo "  - Netplan permissions secured"
echo ""
echo "Recommended: Reboot the VM or restart all bot processes"
echo ""
