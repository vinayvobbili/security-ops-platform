#!/usr/bin/env python3
"""
Network diagnostics for XSOAR API connectivity issues.

Run this on the VM to diagnose network/DNS problems.
"""
import socket
import time
from urllib.parse import urlparse

import requests
from my_config import get_config

CONFIG = get_config()


def test_dns_resolution(url):
    """Test DNS resolution for a given URL."""
    print(f"\n{'='*60}")
    print(f"Testing DNS Resolution")
    print(f"{'='*60}")

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    print(f"Hostname: {hostname}")

    try:
        start = time.time()
        ip_address = socket.gethostbyname(hostname)
        elapsed = time.time() - start
        print(f"✓ DNS Resolution: SUCCESS")
        print(f"  IP Address: {ip_address}")
        print(f"  Time: {elapsed:.3f}s")
        return True, ip_address
    except socket.gaierror as e:
        print(f"✗ DNS Resolution: FAILED")
        print(f"  Error: {e}")
        return False, None


def test_tcp_connection(hostname, port=443):
    """Test TCP connection to hostname:port."""
    print(f"\n{'='*60}")
    print(f"Testing TCP Connection")
    print(f"{'='*60}")

    print(f"Connecting to: {hostname}:{port}")

    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, port))
        elapsed = time.time() - start
        sock.close()
        print(f"✓ TCP Connection: SUCCESS")
        print(f"  Time: {elapsed:.3f}s")
        return True
    except Exception as e:
        print(f"✗ TCP Connection: FAILED")
        print(f"  Error: {e}")
        return False


def test_http_request(url):
    """Test HTTP request to URL."""
    print(f"\n{'='*60}")
    print(f"Testing HTTP Request")
    print(f"{'='*60}")

    print(f"URL: {url}")

    try:
        start = time.time()
        # Make a simple GET request with timeout
        response = requests.get(url, timeout=(10, 30), verify=False)
        elapsed = time.time() - start
        print(f"✓ HTTP Request: SUCCESS")
        print(f"  Status Code: {response.status_code}")
        print(f"  Time: {elapsed:.3f}s")
        return True
    except requests.exceptions.Timeout:
        print(f"✗ HTTP Request: TIMEOUT")
        print(f"  The request took too long to complete")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"✗ HTTP Request: CONNECTION ERROR")
        print(f"  Error: {e}")
        return False
    except Exception as e:
        print(f"✗ HTTP Request: FAILED")
        print(f"  Error: {e}")
        return False


def check_system_dns():
    """Check system DNS configuration."""
    print(f"\n{'='*60}")
    print(f"System DNS Configuration")
    print(f"{'='*60}")

    try:
        # Try to read /etc/resolv.conf
        with open('/etc/resolv.conf', 'r') as f:
            content = f.read()
            print("Contents of /etc/resolv.conf:")
            print(content)
    except FileNotFoundError:
        print("⚠ /etc/resolv.conf not found (this is normal on some systems)")
    except PermissionError:
        print("⚠ Permission denied reading /etc/resolv.conf")
    except Exception as e:
        print(f"⚠ Error reading /etc/resolv.conf: {e}")


def main():
    """Run all diagnostics."""
    print("="*60)
    print("XSOAR API Network Diagnostics")
    print("="*60)

    # Test PROD environment
    print(f"\n\n{'#'*60}")
    print(f"# TESTING PROD ENVIRONMENT")
    print(f"{'#'*60}")

    prod_url = CONFIG.xsoar_prod_api_base_url
    print(f"Base URL: {prod_url}")

    # 1. DNS Resolution
    dns_ok, ip_address = test_dns_resolution(prod_url)

    if not dns_ok:
        print("\n❌ DNS resolution failed. This is likely the root cause.")
        print("   Possible fixes:")
        print("   - Check /etc/resolv.conf for valid DNS servers")
        print("   - Try: ping <hostname>")
        print("   - Check if corporate VPN or proxy is required")
        return

    # 2. TCP Connection
    parsed = urlparse(prod_url)
    hostname = parsed.netloc.split(':')[0]
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    tcp_ok = test_tcp_connection(hostname, port)

    if not tcp_ok:
        print("\n❌ TCP connection failed. Network or firewall issue.")
        print("   Possible fixes:")
        print("   - Check if firewall is blocking the connection")
        print("   - Verify the port is correct")
        print("   - Check if corporate proxy is required")
        return

    # 3. HTTP Request
    http_ok = test_http_request(prod_url)

    if not http_ok:
        print("\n❌ HTTP request failed.")
        print("   Possible fixes:")
        print("   - Check if authentication is required")
        print("   - Verify SSL/TLS settings")
        print("   - Check if proxy settings are needed")
        return

    # 4. Check system DNS config
    check_system_dns()

    print(f"\n\n{'='*60}")
    print("✓ All network diagnostics passed!")
    print("If API calls are still slow, this may be a:")
    print("  - Server-side performance issue")
    print("  - Rate limiting issue")
    print("  - Query complexity issue")
    print(f"{'='*60}")


if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
