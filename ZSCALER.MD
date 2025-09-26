# ZScaler SSL Certificate Configuration

## Current Status
- **Issue**: SSL certificate verification failures for WebX bots and Python applications
- **Root Cause**: ZScaler proxy performs SSL/TLS inspection, presents certificates signed by ZScaler Root CA
- **Temporary Fix**: SSL verification bypass implemented via `src/utils/ssl_config.py`
- **Applications Fixed**: All WebX bots, secops.py, all_jobs.py

## Next Steps After Receiving ZScaler Root CA from Noah

### 1. Install ZScaler Root CA System-Wide
```bash
# Download certificate from Noah (likely named something like zscaler-root-ca.crt)

# Add to macOS system trust store
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain zscaler-root-ca.crt

# Verify installation
security find-certificate -a -c "Zscaler" /Library/Keychains/System.keychain
```

### 2. Update Python Certificate Bundle
```bash
# Add ZScaler Root CA to Python's certificate bundle
cat zscaler-root-ca.crt >> /Users/user/PycharmProjects/IR/.venv/lib/python3.13/site-packages/certifi/cacert.pem

# Or system-wide if needed
cat zscaler-root-ca.crt >> /Library/Frameworks/Python.framework/Versions/3.13/etc/openssl/cert.pem
```

### 3. Test SSL Connection
```bash
# Test direct connection
openssl s_client -connect webexapis.com:443 -servername webexapis.com -verify_return_error

# Test Python requests
python3 -c "import requests; print(requests.get('https://webexapis.com').status_code)"
```

### 4. Remove SSL Bypass Code (When Proper Certs Work)
```bash
# Files to modify after proper SSL works:
# 1. Comment out SSL bypass in all applications:
#    - webex_bots/*.py (all bot files)
#    - src/all_jobs.py
#    - src/secops.py

# 2. Test each application to ensure SSL works properly
# 3. Remove src/utils/ssl_config.py imports (but keep the module for future use)
```

### 5. Verification Checklist
- [ ] ZScaler Root CA installed in macOS system keychain
- [ ] ZScaler Root CA added to Python certificate bundles
- [ ] Direct OpenSSL connection to webexapis.com succeeds
- [ ] Python requests to webexapis.com succeed without SSL bypass
- [ ] MoneyBall bot starts and connects successfully
- [ ] Other WebX bots connect successfully
- [ ] all_jobs.py runs without SSL errors
- [ ] secops.py functions work properly

### 6. Code Cleanup
```python
# In each application, change from:
from src.utils.ssl_config import configure_ssl_if_needed
configure_ssl_if_needed()

# To (commented out but kept for future reference):
# Configure SSL for corporate proxy environments (Zscaler, etc.)
# from src.utils.ssl_config import configure_ssl_if_needed
# configure_ssl_if_needed()  # Disabled after proper ZScaler Root CA installation
```

## Files Modified with Temporary SSL Bypass
- `src/utils/ssl_config.py` - Common SSL configuration module
- `webex_bots/money_ball.py`
- `webex_bots/jarvais.py`
- `webex_bots/barnacles.py`
- `webex_bots/hal9000.py`
- `webex_bots/toodles.py`
- `webex_bots/pokedex.py`
- `src/all_jobs.py`
- `src/secops.py` (also has SSL exception handling fix)

## Contact
- **ZScaler Engineer**: Noah
- **Request Status**: Email sent requesting ZScaler Root CA certificate
- **Expected Timeline**: 1-2 weeks

## Notes
- Keep SSL bypass active until proper certificates are installed and verified
- Test thoroughly before removing bypass code
- Consider keeping ssl_config.py module for future corporate proxy scenarios
- The SSL exception handling fix in secops.py should remain regardless of certificate setup