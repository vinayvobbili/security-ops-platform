# ZScaler SSL Certificate Configuration

## Current Status - ✅ COMPLETED (2025-09-30)
- **Issue**: ~~SSL certificate verification failures for WebX bots and Python applications~~ **RESOLVED**
- **Root Cause**: ZScaler proxy performs SSL/TLS inspection, presents certificates signed by ZScaler Root CA
- **Solution**: ZScaler Root CA certificate received from Noah and properly installed
- **SSL Bypass Code**: Disabled in all applications (commented out for future reference)
- **Applications Working**: All WebX bots, secops.py, all_jobs.py now using proper SSL verification

## Installation Instructions for Other Computers

To configure ZScaler SSL on additional machines, follow these steps:

### 1. Get the ZScaler Root CA Certificate
The certificate file `Zscaler Root CA.pem` is available in the Downloads folder of the primary machine, or obtain it from Noah.

### 2. Install ZScaler Root CA System-Wide
```bash
# Add to macOS system trust store (requires admin password)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "Zscaler Root CA.pem"

# Verify installation
security verify-cert -c "Zscaler Root CA.pem"
```

### 3. Update Python Certificate Bundle
```bash
# Add ZScaler Root CA to Python's certifi bundle in your virtual environment
cat "Zscaler Root CA.pem" >> /path/to/your/project/.venv/lib/python3.13/site-packages/certifi/cacert.pem

# Example for this project:
# cat "Zscaler Root CA.pem" >> /Users/USERNAME/PycharmProjects/IR/.venv/lib/python3.13/site-packages/certifi/cacert.pem
```

### 4. Test SSL Connection
```bash
# Test direct connection
timeout 10 openssl s_client -connect webexapis.com:443 -servername webexapis.com -verify_return_error < /dev/null

# Test Python requests (should return status 401, which confirms SSL works)
python3 -c "import requests; print('Status:', requests.get('https://webexapis.com').status_code)"
```

### 5. Code Changes (Already Completed)
✅ SSL bypass code has been disabled in all applications. No additional code changes needed on other computers.

The following files have SSL bypass commented out:
- `webex_bots/money_ball.py`
- `webex_bots/jarvais.py`
- `webex_bots/barnacles.py`
- `webex_bots/hal9000.py`
- `webex_bots/toodles.py`
- `webex_bots/pokedex.py`
- `src/all_jobs.py`

### 6. Verification Checklist
- [x] ZScaler Root CA installed in macOS system keychain
- [x] ZScaler Root CA added to Python certificate bundles
- [x] Direct OpenSSL connection to webexapis.com succeeds
- [x] Python requests to webexapis.com succeed without SSL bypass
- [x] Pokedex bot starts and connects successfully (WebSocket connected)
- [x] SSL bypass code disabled in all applications
- [x] Applications tested and working with proper SSL

## Summary for Other Computers

**What you need to do on each new machine:**
1. Copy `Zscaler Root CA.pem` from Downloads folder
2. Run: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "Zscaler Root CA.pem"`
3. Run: `cat "Zscaler Root CA.pem" >> /path/to/project/.venv/lib/python3.13/site-packages/certifi/cacert.pem`
4. Test SSL connection
5. Pull latest code from git (SSL bypass already disabled)
6. Start applications - they will use proper SSL verification

**No code changes needed** - all code modifications are already committed to the repository.

## Files Modified (SSL Bypass Now Disabled)
- `src/utils/ssl_config.py` - Common SSL configuration module (kept for future reference)
- `webex_bots/money_ball.py` - SSL bypass disabled
- `webex_bots/jarvais.py` - SSL bypass disabled
- `webex_bots/barnacles.py` - SSL bypass disabled
- `webex_bots/hal9000.py` - SSL bypass disabled
- `webex_bots/toodles.py` - SSL bypass disabled
- `webex_bots/pokedex.py` - SSL bypass disabled
- `src/all_jobs.py` - SSL bypass disabled

## Contact
- **ZScaler Engineer**: Noah
- **Certificate Received**: 2025-09-30
- **Status**: ✅ COMPLETED

## Notes
- ✅ SSL bypass disabled after proper certificates installed and verified
- ✅ All applications tested and working with proper SSL verification
- `ssl_config.py` module kept for future corporate proxy scenarios (currently unused)
- Pokedex bot verified running with WebSocket successfully connected