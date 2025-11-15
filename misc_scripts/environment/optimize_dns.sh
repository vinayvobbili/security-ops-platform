#!/bin/bash

echo "=== Applying DNS Optimization (Option 1) ==="
echo ""

# Create optimized DNS configuration
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/99-api-optimized.conf << 'DNSCONF'
[Resolve]
# Use multiple fast DNS servers for redundancy
DNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4
FallbackDNS=9.9.9.9 149.112.112.112
# Aggressive caching to reduce lookups
Cache=yes
CacheFromLocalhost=no
# Keep stale cache for 7 days to handle temporary DNS issues
StaleRetentionSec=604800
# Reduce negative cache impact
DNSSEC=no
DNSStubListener=yes
DNSCONF

echo ""
echo "✓ DNS resolver configuration created"
echo ""

# Backup and optimize nsswitch to remove mDNS delays
sudo cp /etc/nsswitch.conf "/etc/nsswitch.conf.bak.$(date +%Y%m%d)"
sudo sed -i 's/hosts:.*/hosts:          files dns/' /etc/nsswitch.conf

echo "✓ NSSwitch configuration optimized (backup created)"
echo ""

# Restart DNS resolver
sudo systemctl restart systemd-resolved

echo "✓ systemd-resolved restarted"
echo ""
echo "=== Configuration Applied Successfully ==="
echo ""

# Verify configuration
echo "=== Current DNS Status ==="
resolvectl status

echo ""
echo "=== Testing DNS Resolution ==="
echo "Testing Webex API..."
time nslookup webexapis.com | grep -E 'Server:|Address: [0-9]'

echo ""
echo "Testing with multiple queries for reliability..."
FAIL_COUNT=0
for _ in {1..10}; do
    timeout 2 dig +time=1 +tries=1 webexapis.com +short >/dev/null 2>&1 || ((FAIL_COUNT++))
done
echo "DNS reliability test: $((10-FAIL_COUNT))/10 successful queries"

echo ""
echo "=== NSSwitch Configuration ==="
grep hosts /etc/nsswitch.conf
