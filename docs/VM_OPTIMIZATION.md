# VM Network Optimization Guide

This document explains the optimizations made for running XSOAR API scripts on slow network environments (VMs).

## Problem

Scripts that worked fine on local Mac development machines were timing out on VMs due to:
- Slower network throughput (100+ seconds per API page vs 5-15 seconds)
- Geographic distance to XSOAR API servers
- Network routing differences

## Solution

Made XSOAR API operations configurable via environment variables to optimize for different network speeds.

---

## Configuration Variables

### 1. XSOAR API Pagination (`services/xsoar.py`)

#### `XSOAR_PAGE_SIZE`
- **Default**: 2000 tickets per page
- **Fast networks (Mac)**: Use 5000
- **Slow networks (VM)**: Use 1000-2000
- **Why**: Smaller pages return faster, reducing timeout risk

#### `XSOAR_READ_TIMEOUT`
- **Default**: 180 seconds
- **Fast networks (Mac)**: Use 60-120 seconds
- **Slow networks (VM)**: Use 180-300 seconds
- **Why**: Allows time for slow network responses

### 2. Ticket Note Enrichment (`src/components/ticket_cache.py`)

#### `TICKET_ENRICHMENT_WORKERS`
- **Default**: 10 parallel workers
- **Fast networks (Mac)**: Use 25 workers
- **Slow networks (VM)**: Use 5-10 workers
- **Why**: Fewer parallel requests prevents overwhelming slow networks

#### `TICKET_ENRICHMENT_TIMEOUT`
- **Default**: 180 seconds per ticket
- **Fast networks (Mac)**: Use 90 seconds
- **Slow networks (VM)**: Use 180-300 seconds
- **Why**: Individual ticket note fetches need more time on slow networks

---

## Usage Examples

### VM (Slow Network) - Use Defaults
```bash
# No env vars needed - defaults are optimized for slow networks
python -m src.charts.inflow
python -m src.components.ticket_cache
```

### Mac (Fast Network) - Optimize for Speed
```bash
# Set environment variables for faster processing
export XSOAR_PAGE_SIZE=5000
export XSOAR_READ_TIMEOUT=90
export TICKET_ENRICHMENT_WORKERS=25
export TICKET_ENRICHMENT_TIMEOUT=90

python -m src.charts.inflow
python -m src.components.ticket_cache
```

### Very Slow Network - Extra Conservative
```bash
# If default VM settings still timeout
export XSOAR_PAGE_SIZE=1000
export XSOAR_READ_TIMEOUT=300
export TICKET_ENRICHMENT_WORKERS=5
export TICKET_ENRICHMENT_TIMEOUT=300

python -m src.charts.inflow
python -m src.components.ticket_cache
```

---

## Debug Logging

Enable detailed diagnostics to troubleshoot network issues:

```bash
export DEBUG_LOGS=true
python -m src.charts.inflow

# Output will include:
# - DNS resolution timing
# - Per-request timing
# - API call durations
# - Worker activity
```

---

## Performance Comparison

### Before Optimization (VM)
- ❌ Timed out fetching 5000 tickets per page
- ❌ 25 parallel workers overwhelming network
- ❌ 60s timeout too short for slow responses
- ❌ Script failed to complete

### After Optimization (VM)
- ✅ 2000 tickets per page completes in ~40s
- ✅ 10 parallel workers manageable
- ✅ 180s timeout accommodates slow network
- ✅ Successfully fetched 15,825 tickets in ~17 minutes

### Mac (Fast Network)
- ✅ Works with both default and optimized settings
- ✅ Faster with increased page size and workers
- ✅ No timeout issues

---

## Diagnostic Tools

### Network Diagnostics Script
```bash
python diagnose_network.py
```

Tests:
- DNS resolution
- TCP connection
- HTTP request
- System DNS configuration

### Quick API Test
```bash
python -c "
from services.xsoar import TicketHandler, XsoarEnvironment
import time

print(f'Page size: {TicketHandler.DEFAULT_PAGE_SIZE}')
print(f'Read timeout: {TicketHandler.READ_TIMEOUT}s')

handler = TicketHandler(XsoarEnvironment.PROD)
start = time.time()
tickets = handler.get_tickets('type:METCIRT created:>2025-11-17', paginate=True)
elapsed = time.time() - start

print(f'✓ Fetched {len(tickets)} tickets in {elapsed:.1f}s')
"
```

---

## Troubleshooting

### Still Timing Out?
1. Increase `XSOAR_READ_TIMEOUT` to 300 or 600
2. Decrease `XSOAR_PAGE_SIZE` to 1000 or 500
3. Reduce `TICKET_ENRICHMENT_WORKERS` to 5
4. Check network connectivity with `diagnose_network.py`

### High Failure Rate in Note Enrichment?
1. Reduce worker count (fewer parallel requests)
2. Increase individual timeout
3. Check API rate limiting
4. Review logs for 429 (Too Many Requests) errors

### DNS Issues?
```bash
# Check DNS resolution
cat /etc/resolv.conf
nslookup api-msoar.crtx.us.paloaltonetworks.com

# Test with Google DNS
export XSOAR_DNS_SERVER=8.8.8.8
```

---

## Best Practices

1. **Start Conservative**: Use defaults on new VMs, then optimize if needed
2. **Monitor Logs**: Enable DEBUG_LOGS to identify bottlenecks
3. **Test Incrementally**: Change one variable at a time
4. **Document Settings**: Add environment variables to deployment scripts
5. **Regular Testing**: Network conditions can change over time

---

## Related Files

- `services/xsoar.py` - XSOAR API client with timeout/pagination config
- `src/components/ticket_cache.py` - Parallel note enrichment with worker config
- `src/charts/inflow.py` - Chart generation using XSOAR API
- `diagnose_network.py` - Network diagnostic tool

---

## Version History

- **2025-11-18**: Initial optimization for VM slow networks
  - Reduced default page size: 5000 → 2000
  - Increased read timeout: 60s → 180s
  - Reduced workers: 25 → 10
  - Made all settings configurable via env vars
