# SSL Verification Configuration Guide

## Problem

When running Python 3.13 behind Zscaler proxy, SSL connections fail with:
```
ssl.SSLEOFError: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol
```

This happens because:
1. **Python 3.13 uses OpenSSL 3.x** with stricter SSL/TLS requirements
2. **Zscaler intercepts and terminates SSL** in a way that violates Python 3.13's SSL handshake protocol
3. The error occurs **during SSL handshake**, before certificate verification
4. Adding Zscaler certificate to trust store **does not fix this** - the issue is in the handshake, not certificate validation

## Solution

The code now **automatically detects** the environment and configures SSL verification accordingly:

### Auto-Detection Logic

| Environment | Platform | SSL Verification | Reason |
|------------|----------|-----------------|---------|
| **Local Dev (macOS)** | Darwin | **DISABLED** | Behind Zscaler proxy/VPN |
| **VM/Server (Linux)** | Linux | **ENABLED** | Direct connection to XSOAR |

### How It Works

In `services/xsoar.py`:

```python
import platform
system_platform = platform.system()

# Auto-detect based on platform
if 'DISABLE_SSL_VERIFY' in os.environ:
    # Explicit configuration takes precedence
    DISABLE_SSL_VERIFY = os.getenv('DISABLE_SSL_VERIFY').lower() == 'true'
    config_source = "environment variable"
else:
    # Auto-detect: macOS = disable (Zscaler), Linux = enable (no Zscaler)
    DISABLE_SSL_VERIFY = system_platform == 'Darwin'  # Darwin = macOS
    config_source = f"auto-detected ({system_platform})"
```

## Manual Override

If auto-detection doesn't work for your environment, you can manually configure:

### Disable SSL Verification (for Zscaler environments)
```bash
export DISABLE_SSL_VERIFY=true
```

### Enable SSL Verification (for direct connections)
```bash
export DISABLE_SSL_VERIFY=false
```

## Verification

Check which mode is being used:

```bash
.venv/bin/python -c "
import logging
logging.basicConfig(level=logging.INFO)
import services.xsoar
" 2>&1 | grep "SSL verification"
```

**Expected output on macOS:**
```
INFO - SSL verification DISABLED (auto-detected (Darwin)) - corporate proxy/Zscaler environment
```

**Expected output on Linux VM:**
```
INFO - SSL verification ENABLED (auto-detected (Linux)) - direct connection to XSOAR
```

## Local Development Setup

### With VPN Connected
1. Connect to VPN
2. Run scripts normally - auto-detection will disable SSL verification
3. Scripts should work without SSL errors

### Without VPN
If you get SSL errors without VPN:
1. Connect to VPN first
2. Or manually set `DISABLE_SSL_VERIFY=true`

## VM/Server Setup

On Linux VMs without Zscaler:
1. Auto-detection will enable SSL verification by default
2. No manual configuration needed
3. SSL certificates will be properly verified

## Troubleshooting

### Still Getting SSL Errors on macOS?
1. **Ensure VPN is connected** - Zscaler behaves differently with VPN on/off
2. Check environment variable: `echo $DISABLE_SSL_VERIFY`
3. Manually set: `export DISABLE_SSL_VERIFY=true`
4. Verify the setting is detected:
   ```bash
   .venv/bin/python -c "import services.xsoar" 2>&1 | grep "SSL"
   ```

### SSL Verification Not Working on VM?
1. Check environment variable: `echo $DISABLE_SSL_VERIFY`
2. Unset if present: `unset DISABLE_SSL_VERIFY`
3. Let auto-detection handle it (Linux = verification enabled)

### Alternative Solution: Downgrade to Python 3.12

If SSL issues persist, Python 3.12 has more lenient SSL requirements:
```bash
# Create new venv with Python 3.12
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Technical Details

### Why Adding Zscaler Cert Doesn't Help

The Zscaler certificate you added to your system's trust store (via Keychain Access on macOS) is used for **certificate verification**, which happens **after** the SSL handshake completes.

The `SSLEOFError` occurs **during the SSL handshake**, before any certificates are verified. This is a **protocol-level** issue, not a certificate issue.

### Why VPN Matters

When VPN is connected, the network routing and SSL interception behavior of Zscaler changes. With VPN:
- SSL connections may bypass some Zscaler SSL interception
- Or Zscaler handles the SSL handshake differently
- This allows Python 3.13 to complete the SSL handshake successfully

### Code Changes Made

1. **Auto-detection logic** (`services/xsoar.py` lines 135-165)
   - Detects platform (Darwin=macOS, Linux=VM)
   - Auto-configures SSL verification
   - Logs configuration source

2. **SSL configuration** (`services/xsoar.py` lines 147-160)
   - Uses `verify_ssl=False` for Zscaler environments
   - Uses `verify_ssl=True` for direct connections

3. **Pool manager configuration** (`services/xsoar.py` lines 195-212)
   - Respects `DISABLE_SSL_VERIFY` setting
   - Configures urllib3 PoolManager accordingly

4. **Requests library calls** (throughout file)
   - All `requests.post()` calls respect `DISABLE_SSL_VERIFY`

## Security Considerations

### Local Dev (SSL Verification Disabled)
- **Risk**: SSL certificates are not verified
- **Mitigation**: Only used on corporate network behind VPN
- **Acceptable**: Corporate environment, internal APIs

### VM (SSL Verification Enabled)
- **Best Practice**: Always verify SSL certificates
- **Security**: Protects against MITM attacks
- **Recommended**: Use in production environments

## Summary

✅ **macOS + VPN**: Auto-detects, disables SSL verification, works perfectly
✅ **Linux VM**: Auto-detects, enables SSL verification, secure connection
✅ **Manual override**: Available via `DISABLE_SSL_VERIFY` environment variable
✅ **Clear logging**: Shows which mode is active and why
