#!/bin/bash
# Network Evidence Collection Script
# For escalating VM network issues to infrastructure team
# Usage: ./collect_network_evidence.sh

EVIDENCE_DIR="/tmp/network_evidence_$(date +%Y%m%d_%H%M)"
mkdir -p $EVIDENCE_DIR

echo "🔍 Collecting network evidence for escalation..."
echo "📂 Evidence will be saved to: $EVIDENCE_DIR"
echo ""

# 1. TCP statistics snapshot
echo "📊 Collecting TCP statistics..."
netstat -s > $EVIDENCE_DIR/tcp_stats_$(date +%H%M).txt

# 2. Active connection states
echo "🔌 Collecting connection states..."
ss -tan > $EVIDENCE_DIR/connections_$(date +%H%M).txt
ss -s > $EVIDENCE_DIR/socket_summary.txt

# 3. Route and ARP table
echo "🛣️  Collecting routing info..."
ip route show > $EVIDENCE_DIR/routing.txt
arp -n > $EVIDENCE_DIR/arp_table.txt
ip addr show > $EVIDENCE_DIR/interfaces.txt

# 4. Continuous ping to Webex (10 minutes)
echo "🏓 Starting 10-minute ping test to webexapis.com..."
ping -D -i 1 webexapis.com -c 600 > $EVIDENCE_DIR/ping_webex.txt 2>&1 &
PING_PID=$!

# 5. TCP connection test with detailed timing
echo "⏱️  Testing HTTPS connection timing..."
for i in {1..10}; do
  echo "--- Attempt $i at $(date) ---" >> $EVIDENCE_DIR/curl_timing.txt
  curl -w "@-" -o /dev/null -s https://webexapis.com/v1/people/me << 'CURL_FORMAT' >> $EVIDENCE_DIR/curl_timing.txt
time_namelookup:    %{time_namelookup}s
time_connect:       %{time_connect}s
time_appconnect:    %{time_appconnect}s
time_pretransfer:   %{time_pretransfer}s
time_starttransfer: %{time_starttransfer}s
time_total:         %{time_total}s
http_code:          %{http_code}
CURL_FORMAT
  sleep 5
done

# 6. Traceroute to Webex endpoints
echo "🗺️  Tracing route to Webex..."
# Install traceroute if needed: sudo apt-get install -y traceroute
which traceroute && traceroute -m 20 webexapis.com > $EVIDENCE_DIR/traceroute_webex.txt 2>&1 || echo "traceroute not installed, skipping"

# 7. DNS resolution test
echo "🌐 Testing DNS resolution..."
for endpoint in webexapis.com mercury-connection-a.wbx2.com; do
  echo "--- $endpoint ---" >> $EVIDENCE_DIR/dns_tests.txt
  nslookup $endpoint >> $EVIDENCE_DIR/dns_tests.txt
  host $endpoint >> $EVIDENCE_DIR/dns_tests.txt
  echo "" >> $EVIDENCE_DIR/dns_tests.txt
done

# 8. System info
echo "💻 Collecting system info..."
uname -a > $EVIDENCE_DIR/system_info.txt
uptime >> $EVIDENCE_DIR/system_info.txt
cat /etc/os-release >> $EVIDENCE_DIR/system_info.txt

# 9. Network interface details
echo "🔧 Collecting NIC details..."
ip -s link show ens192 > $EVIDENCE_DIR/nic_stats.txt
ethtool ens192 > $EVIDENCE_DIR/nic_settings.txt 2>&1 || echo "ethtool not available or requires sudo"

# Wait for ping to complete
echo "⏳ Waiting for ping test to complete (10 minutes)..."
wait $PING_PID

# 10. Extract bot logs showing connection issues
echo "📝 Extracting relevant bot logs..."
if [ -d ~/pub/IR/logs ]; then
  cd ~/pub/IR/logs
  tail -5000 *.log 2>/dev/null | grep -E "(timeout|Timeout|TIMEOUT|Connection|reconnect|Keepalive|failed)" > $EVIDENCE_DIR/bot_connection_logs.txt || echo "No bot logs found"
else
  echo "Bot logs directory not found" > $EVIDENCE_DIR/bot_connection_logs.txt
fi

# Create summary
cat > $EVIDENCE_DIR/README.txt << EOF
Network Evidence Collection Summary
====================================
Date: $(date)
VM: $(hostname) ($(hostname -I))
Uptime: $(uptime)

Files Collected:
- tcp_stats_*.txt: TCP protocol statistics
- connections_*.txt: Active connection states
- socket_summary.txt: Socket summary statistics
- routing.txt: Routing table
- arp_table.txt: ARP cache
- interfaces.txt: Network interface configuration
- ping_webex.txt: 10-minute ping test to Webex (600 packets)
- curl_timing.txt: HTTPS connection timing (10 samples)
- traceroute_webex.txt: Network path to Webex
- dns_tests.txt: DNS resolution tests
- system_info.txt: System information
- nic_stats.txt: Network interface statistics
- nic_settings.txt: NIC hardware settings
- bot_connection_logs.txt: Bot connection/timeout logs

Next Steps:
1. Review ping_webex.txt for packet loss
2. Check curl_timing.txt for connection delays
3. Analyze tcp_stats_*.txt for timeout trends
4. Include in escalation email to infrastructure team

Escalation Email Template:
See docs/VM_NETWORK_TROUBLESHOOTING.md for complete email template
EOF

echo ""
echo "✅ Evidence collection complete!"
echo "📂 Location: $EVIDENCE_DIR"
echo ""
ls -lh $EVIDENCE_DIR
echo ""
echo "📧 To create archive for email:"
echo "   cd /tmp && tar czf network_evidence_$(date +%Y%m%d_%H%M).tar.gz $(basename $EVIDENCE_DIR)"
echo ""
echo "📧 Attach the .tar.gz file to your escalation email"
echo "📄 See docs/VM_NETWORK_TROUBLESHOOTING.md for email template"
