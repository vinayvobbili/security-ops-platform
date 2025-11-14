# VM Network Troubleshooting Guide

**Date Created**: 2025-11-14
**VM**: inr106 (10.10.40.110/24)
**Issue**: WebSocket connection timeouts and missed messages on VM (not present on MacBook)

---

## Problem Summary

### Symptoms

1. **Missed First Messages**: After 10-20 minutes of inactivity, bots miss the first incoming message
2. **Upload Timeouts**: Large file uploads (charts, 500KB+ PNG files) fail with:
   ```
   TimeoutError: The write operation timed out
   requests.exceptions.ConnectionError: ('Connection aborted.', TimeoutError('The write operation timed out'))
   ```
3. **VM-Specific**: Same code runs perfectly on MacBook, only fails on VM

### Example Timeline

```
7:38 AM  - User sends "Hi" → Bot responds ✅
8:52 AM  - User sends "Hi" (after 1h15m gap) → Bot MISSES message ❌
8:52 AM  - User sends "Hi" again → Bot responds ✅
```

---

## Root Cause Analysis

### Network Infrastructure Issues

The VM network path has TCP timeout problems **NOT present on MacBook**:

```bash
# TCP Statistics (from netstat -s on VM after 9 days uptime)
TCPTimeouts:                20,022  ⚠️
Connections aborted:         1,734  ⚠️
TCP retransmissions:        38,260  ⚠️
Established resets:            664  ⚠️
```

**Context**:
- VM uptime: 9 days
- Total TCP segments: 54.5M in, 18.8M out
- Timeout rate: 0.037% (low but impactful)
- Gateway: 10.10.40.1 (VMware virtual network)

### Why Messages Are Missed

1. **Firewall Connection Tracking Expiration**:
   - After ~10-20 minutes of idle time, the firewall at `10.10.40.1` expires the connection from its state table
   - WebSocket appears "alive" locally (TCP keepalives work)
   - But firewall has dropped the connection → incoming messages can't reach the bot
   - Bot doesn't detect this until keepalive health check fails

2. **Why Large Uploads Timeout**:
   - Python sockets have NO default write timeout
   - On unreliable networks, write operations can hang indefinitely waiting for ACKs
   - VM network has packet loss/congestion (38K retransmissions)
   - Socket write buffer fills → operation times out

---

## Fixes Implemented

### 1. Socket Write Timeout Patch
**File**: `src/utils/bot_resilience.py:119-147`

**Problem**: Python sockets have no write timeout → uploads hang forever on unreliable networks

**Fix**: Patched `urllib3.util.connection.create_connection` to set 180s timeout on ALL sockets

```python
def create_connection_with_timeout(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, *args, **kwargs):
    sock = _orig_create_connection(address, timeout, *args, **kwargs)
    if timeout is not None and timeout != socket._GLOBAL_DEFAULT_TIMEOUT:
        sock.settimeout(timeout)
    else:
        sock.settimeout(180.0)  # Default to 180s
    return sock
```

**Impact**: Prevents indefinite hangs, fails fast after 180s

---

### 2. Reduced Idle Timeout
**File**: `src/utils/bot_resilience.py:77`

**Problem**: 20-minute idle timeout was too long → firewall expires connection first

**Fix**: Reduced to 10 minutes for VM networks

```python
max_idle_minutes: int = 10  # Changed from 20
```

**Impact**: Bot proactively reconnects BEFORE firewall times out → no missed messages

---

### 3. Chart Upload Retry Logic
**File**: `src/secops.py:932-953`

**Problem**: Large chart uploads failing with write timeout errors

**Fix**: Added exponential backoff retry wrapper

```python
def send_chart_with_retry(room_id, text, markdown, files=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            webex_api.messages.create(...)
            return
        except (ConnectionError, Timeout, TimeoutError) as e:
            wait_time = 2 ** attempt  # 1s, 2s, 4s
            logger.warning(f"Retrying in {wait_time}s...")
            time.sleep(wait_time)
```

**Impact**: Automatic recovery from transient network failures

---

## Multi-Layered Defense Strategy

The bot now has 6 layers of protection:

1. **TCP Keepalive (60s)**: Keeps firewall connection tracking alive at kernel level
2. **WebSocket Ping (10s)**: Application-level keepalive for quick failure detection
3. **API Health Checks (120s)**: Detects stale application state via periodic API calls
4. **Idle Timeout (10min)**: Proactive reconnection if no messages received
5. **Max Age (12h)**: Prevents long-lived connection degradation
6. **Socket Write Timeout (180s)**: Prevents hangs during file uploads

---

## Testing Plan

### Phase 1: Deploy and Monitor (1 Week)

**Deployment**:
```bash
ssh metcirt-lab
cd ~/pub/IR
git pull
# Restart all bots to pick up changes
```

**Monitoring Checklist**:

- [ ] Day 1-2: Watch for socket timeout patch logs
  ```
  ⏱️  Patched socket write timeouts to prevent hangs on VM network (180s)
  ```

- [ ] Day 3-4: Test missed message scenario
  - Wait 15+ minutes without bot activity
  - Send "Hi" to bot
  - **Expected**: Bot responds immediately (no missed message)

- [ ] Day 5-7: Monitor chart upload success rate
  - Check daily operational report chart uploads
  - **Expected**: No `TimeoutError` or automatic retry/success
  - Look for retry logs:
    ```
    ⚠️  Chart upload timeout (attempt 1/3): ... Retrying in 1s...
    ```

**Success Criteria**:
- ✅ No missed first messages after idle periods
- ✅ All chart uploads succeed (possibly with retries)
- ✅ No manual bot restarts needed

---

## Evidence Collection (If Issues Persist)

If problems continue after 1 week, run this script to collect evidence for escalation:

```bash
#!/bin/bash
# Save as: /tmp/collect_network_evidence.sh

EVIDENCE_DIR="/tmp/network_evidence_$(date +%Y%m%d_%H%M)"
mkdir -p $EVIDENCE_DIR

echo "Collecting network evidence for escalation..."

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
which traceroute && traceroute -m 20 webexapis.com > $EVIDENCE_DIR/traceroute_webex.txt 2>&1

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
ethtool ens192 > $EVIDENCE_DIR/nic_settings.txt 2>&1 || echo "ethtool not available"

# Wait for ping to complete
echo "⏳ Waiting for ping test to complete..."
wait $PING_PID

# 10. Extract bot logs showing connection issues
echo "📝 Extracting relevant bot logs..."
cd ~/pub/IR/logs
tail -5000 *.log | grep -E "(timeout|Timeout|TIMEOUT|Connection|reconnect|Keepalive|failed)" > $EVIDENCE_DIR/bot_connection_logs.txt

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
EOF

echo ""
echo "✅ Evidence collection complete!"
echo "📂 Location: $EVIDENCE_DIR"
echo ""
ls -lh $EVIDENCE_DIR
echo ""
echo "📧 Attach these files to your escalation email"
```

**Usage**:
```bash
chmod +x /tmp/collect_network_evidence.sh
/tmp/collect_network_evidence.sh
```

---

## Escalation Email Template

**Use this if issues persist after testing code fixes.**

```
Subject: VM Network Connectivity Issues - WebSocket Connection Timeouts (INR106)

Hi [Infrastructure Team],

We're experiencing network connectivity issues on VM inr106 (10.10.40.110)
that are impacting our Webex bot applications. These issues do NOT occur
when running the same code on our MacBook, indicating a network infrastructure
difference.

SYMPTOMS:
1. WebSocket connections missing first incoming messages after 10+ minutes of inactivity
2. Large file uploads (500KB+ PNG charts) timing out with "write operation timed out"
3. Connections appear alive locally but messages aren't received until reconnection

BUSINESS IMPACT:
- Critical alert notifications delayed or missed (Example: [timestamp of missed alert])
- Automated reports failing to deliver (Example: [timestamp of failed chart upload])
- Manual intervention required to restart bots

SPECIFIC INCIDENTS (Last 7 Days):
[Add specific examples here after monitoring period]
- [Date/Time]: Missed alert for [incident]
- [Date/Time]: Chart upload timeout for [report]
- [Date/Time]: Forced reconnection after [duration]

NETWORK DATA:
- VM: inr106 (10.10.40.110/24)
- Gateway: 10.10.40.1
- OS: Ubuntu 24.04.3 LTS (Noble Numbat)
- Destination: webexapis.com (170.72.245.x)
- Protocol: HTTPS WebSocket (443) + HTTPS API calls (443)
- TCP Statistics over [X] days:
  * TCPTimeouts: [from evidence]
  * Connections aborted due to timeout: [from evidence]
  * TCP retransmissions: [from evidence]
  * Packet loss: [from ping evidence]

EVIDENCE ATTACHED:
- Network diagnostics package (see README.txt for details)
- TCP statistics showing timeout patterns
- Ping results showing packet loss/latency
- Connection timing showing delays
- Bot logs showing connection failures

QUESTIONS FOR INFRASTRUCTURE:
1. Are there aggressive connection tracking timeouts on the gateway/firewall at 10.10.40.1?
2. What is the idle timeout for established TCP connections on the firewall?
3. Are there any DPI (Deep Packet Inspection) or application-level proxies
   interfering with WebSocket traffic to *.webex.com / *.wbx2.com?
4. Can we see firewall logs showing connection state table evictions for 10.10.40.110?
5. Are there any QoS policies or rate limiting affecting this VM?
6. Can we increase the connection tracking timeout for this VM or whitelist Webex endpoints?

WORKAROUNDS IMPLEMENTED (CODE CHANGES):
- TCP keepalive (60s) - Attempts to keep firewall state alive
- WebSocket ping (10s) - Application-level keepalive
- Application-level reconnection (10min idle) - Proactive reconnection
- Socket write timeout (180s) - Prevents indefinite hangs
- Request retry logic - Automatic recovery from failures

These workarounds help but don't fully resolve the underlying network issue.
We still experience intermittent failures and missed messages.

REQUESTED ACTION:
1. Review firewall/gateway configuration at 10.10.40.1
2. Increase connection tracking timeout for established connections (recommend 30+ minutes)
3. Whitelist WebSocket traffic to *.webex.com and *.wbx2.com from firewall inspection
4. Provide feedback on any network policies affecting this VM

Please advise on firewall/network configuration that may be causing these timeouts.

Best regards,
[Your Name]
[Contact Info]
```

---

## Quick Reference

### Check if Code Fixes Are Active

```bash
# SSH to VM
ssh metcirt-lab

# Check bot logs for patch confirmation
cd ~/pub/IR/logs
tail -100 *.log | grep -E "Patched socket|TCP keepalive|Increased SDK"

# Expected output:
# ⏱️  Increased SDK HTTP timeout from 60s to 180s for device registration
# ⏱️  Patched socket write timeouts to prevent hangs on VM network (180s)
# 🔧 Patched WebSocket with TCP keepalive to prevent firewall connection timeout
```

### Monitor for Issues

```bash
# Watch for timeout errors in real-time
tail -f ~/pub/IR/logs/*.log | grep -i timeout

# Check for reconnection events
tail -f ~/pub/IR/logs/*.log | grep -E "reconnect|Idle timeout|Connection appears stale"

# Monitor upload retries
tail -f ~/pub/IR/logs/*.log | grep "Chart upload timeout"
```

### Verify Bot Health

```bash
# Check if bots are running
ps aux | grep python | grep -E "jarvis|barnacles|toodles|pokedex|hal9000"

# Check recent bot activity
cd ~/pub/IR/logs
ls -lt *.log | head -5

# Look for successful keepalive pings
grep "Keepalive ping successful" *.log | tail -10
```

---

## Timeline

- **2025-11-14**: Issue identified, code fixes implemented
- **2025-11-15 to 2025-11-21**: Monitoring period (7 days)
- **2025-11-22**: Decision point
  - ✅ If resolved: Document success, close issue
  - ❌ If persists: Collect evidence, escalate to infrastructure

---

## Additional Notes

### TCP Timeout Context

The observed timeout rates (0.037%) are **higher than ideal** but not catastrophic:
- MacBook likely has: 0.001-0.01% timeout rate
- VM has: 0.037% timeout rate
- Enterprise networks typically: < 0.02%

**Conclusion**: VM network is degraded but workable with proper code resilience.

### Why MacBook Doesn't Have This Issue

1. **Direct Internet Access**: No corporate firewall/NAT in the path
2. **Better Network Quality**: Consumer ISPs often have lower latency/loss
3. **No Connection Tracking**: Home routers less aggressive with timeouts
4. **No Virtualization Layer**: No VMware network overhead

### Long-Term Solution

Ideally, the infrastructure team should:
1. Increase firewall connection tracking timeout from ~15min to 30+ minutes
2. Whitelist WebSocket traffic to Webex endpoints from DPI
3. Tune QoS policies to prioritize low-latency traffic
4. Consider dedicated network path for production bots

But the code fixes should make the bots resilient enough to work despite network issues.

---

## References

- Bot Resilience Framework: `src/utils/bot_resilience.py`
- Chart Upload Function: `src/secops.py:929` (send_daily_operational_report_charts)
- Network Diagnostics: This document, Evidence Collection section
- Escalation Template: This document, Escalation Email section

**Document Version**: 1.0
**Last Updated**: 2025-11-14
**Next Review**: 2025-11-22
