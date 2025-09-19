#!/usr/bin/env python3
"""
URL Traffic Testing Script
Tests if URLs are allowed/blocked by ZScaler and Bloxone filtering systems.
"""

import json
import logging
import os
import sys
import time
from typing import Dict, Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from texttable import Texttable

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from my_config import get_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class URLChecker:
    """Test URL filtering across different network security solutions."""

    def __init__(self, jump_server_host: str = None, jump_server_port: int = 8080):
        # Use config jump server if not explicitly provided
        if jump_server_host is None:
            try:
                config = get_config()
                self.jump_server_host = config.jump_server_host
            except Exception:
                self.jump_server_host = None
        else:
            self.jump_server_host = jump_server_host

        self.jump_server_port = jump_server_port
        self.session = self._create_session()

    @staticmethod
    def _create_session() -> requests.Session:
        """Create HTTP session with security-focused retry strategy."""
        session = requests.Session()

        # Security-focused retry strategy: fewer retries, shorter backoff
        retry_strategy = Retry(
            total=2,  # Reduced retries to minimize exposure
            backoff_factor=0.5,  # Shorter backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]  # Only allow safe methods
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _make_request(self, url: str, proxies: Dict[str, str] = None, checker_func=None) -> Dict[str, Any]:
        """Make HTTP request and return standardized result."""
        system = "Bloxone" if proxies else "ZScaler"
        logger.debug(f"[{system}] Testing URL: {url}")

        try:
            # Disable SSL verification for proxy tests (HTTPS interception)
            verify_ssl = proxies is None

            # Use GET request for accurate block detection
            response = self.session.get(
                url,
                timeout=10,
                allow_redirects=True,  # Allow redirects to see final destination
                proxies=proxies,
                verify=verify_ssl,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
            )

            # Log raw response details
            logger.debug(f"[{system}] Response status: {response.status_code}")
            logger.debug(f"[{system}] Response headers: {dict(response.headers)}")
            if hasattr(response, '_content') and response._content:
                logger.debug(f"[{system}] Response content (first 500 chars): {response.text[:500]}")
            logger.debug(f"[{system}] Response time: {response.elapsed.total_seconds() * 1000:.2f}ms")

            # Check for block indicators first
            blocked_indicators = checker_func(response) if checker_func else {}
            is_blocked = blocked_indicators.get('blocked', False)

            # Determine if URL is allowed: good status code AND not blocked by content filtering
            is_allowed = response.status_code < 400 and not is_blocked

            return {
                'allowed': is_allowed,
                'status_code': response.status_code,
                'response_time_ms': response.elapsed.total_seconds() * 1000,
                'headers': dict(response.headers),
                'content_length': len(response.content) if hasattr(response, '_content') else 0,
                'blocked_indicators': blocked_indicators,
                'error': None,
                'user_friendly_error': None
            }
        except requests.exceptions.RequestException as e:
            logger.debug(f"[{system}] Request failed: {str(e)}")
            user_friendly_error = self._get_user_friendly_error(e, system)
            return {
                'allowed': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'user_friendly_error': user_friendly_error
            }

    @staticmethod
    def _get_user_friendly_error(exception: requests.exceptions.RequestException, system: str) -> str:
        """Convert technical error to user-friendly message focused on filtering outcome."""
        error_type = type(exception).__name__
        error_str = str(exception).lower()

        # For timeouts and connection issues, the URL is likely blocked/filtered
        if ('timeout' in error_str or 'timed out' in error_str or
                error_type in ['ConnectTimeout', 'ReadTimeout'] or
                ('connection' in error_str and ('failed' in error_str or 'refused' in error_str))):
            return f"{system} blocked/filtered"

        # DNS issues could indicate blocking at DNS level
        elif 'name resolution failed' in error_str or 'nodename nor servname provided' in error_str:
            return f"{system} DNS blocked"

        # SSL/certificate errors are usually legitimate technical issues
        elif 'ssl' in error_str or 'certificate' in error_str:
            return f"{system} SSL error"

        # Proxy-specific issues
        elif 'proxy' in error_str:
            return f"{system} proxy issue"

        # Generic network errors - could be blocking
        elif error_type == 'ConnectionError':
            return f"{system} blocked/filtered"

        # Fallback for other errors
        else:
            return f"{system} error"

    def _test_zscaler(self, url: str) -> Dict[str, Any]:
        """Test direct connection through ZScaler proxy."""
        return self._make_request(url, checker_func=self._check_zscaler_blocks)

    def _test_bloxone(self, url: str) -> Dict[str, Any]:
        """Test via jump server proxy (Bloxone filtering)."""
        if not self.jump_server_host:
            return {'error': 'No jump server configured'}

        proxies = {
            'http': f'http://{self.jump_server_host}:{self.jump_server_port}',
            'https': f'http://{self.jump_server_host}:{self.jump_server_port}'
        }
        return self._make_request(url, proxies=proxies, checker_func=self._check_bloxone_blocks)

    @staticmethod
    def _check_zscaler_blocks(response: requests.Response) -> Dict[str, Any]:
        """Check for ZScaler blocking indicators."""
        indicators = {
            'blocked': False,
            'block_page_detected': False,
            'suspicious_headers': [],
            'block_reason': None
        }

        # Check for ZScaler block page content
        content_lower = response.text.lower()
        zscaler_patterns = [
            'zscaler', 'blocked by policy', 'access denied', 'category blocked', 'security policy',
            'website blocked', 'not allowed', 'permission to visit', 'social network site',
            'your organization has selected zscaler', '1-800-ask-met2'
        ]

        for pattern in zscaler_patterns:
            if pattern in content_lower:
                indicators.update({'blocked': True, 'block_page_detected': True, 'block_reason': f'ZScaler block: {pattern}'})
                break

        # Check suspicious headers
        indicators['suspicious_headers'] = [h for h in response.headers if any(x in h.lower() for x in ['x-zscaler', 'x-content-filter', 'x-blocked'])]

        # Check for redirect to block page
        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            if any(x in location.lower() for x in ['blocked', 'denied']):
                indicators.update({'blocked': True, 'block_reason': f'Redirect: {location}'})

        return indicators

    @staticmethod
    def _check_bloxone_blocks(response: requests.Response) -> Dict[str, Any]:
        """Check for Bloxone/Infoblox blocking indicators."""
        indicators = {
            'blocked': False,
            'dns_blocked': False,
            'suspicious_headers': [],
            'block_reason': None
        }

        # Check for Infoblox/Bloxone block page content
        content_lower = response.text.lower()

        # Try to decode UTF-16 if it starts with BOM
        if response.content.startswith(b'\xff\xfe'):
            try:
                decoded_content = response.content.decode('utf-16-le').lower()
                content_lower = decoded_content
            except Exception as e:
                pass  # Fall back to original text

        bloxone_patterns = [
            'infoblox', 'bloxone', 'dns protection', 'threat protection', 'blocked domain', 'security response',
            'web filter message', 'web filtering', 'content blocked', 'access denied', 'category blocked',
            'site blocked', 'blocked by policy', 'webfilter', 'filter message'
        ]

        # Also check for spaced-out text patterns (like "w e b   f i l t e r")
        spaced_patterns = ['w e b   f i l t e r', 'b l o c k e d', 'a c c e s s   d e n i e d']

        for pattern in bloxone_patterns + spaced_patterns:
            if pattern in content_lower:
                indicators.update({'blocked': True, 'dns_blocked': True, 'block_reason': f'Bloxone: {pattern}'})
                break

        # Check for DNS-level blocking
        if response.status_code in [204, 404]:
            indicators.update({'blocked': True, 'dns_blocked': True, 'block_reason': f'DNS block: {response.status_code}'})

        return indicators

    @staticmethod
    def parse_url_input(url_input: str) -> list:
        """Parse URL input string (supports CSV, space-separated, or single URLs)."""
        if not url_input or not url_input.strip():
            return []

        # First try CSV parsing (comma-separated)
        if ',' in url_input:
            urls = [url.strip() for url in url_input.split(',') if url.strip()]
        else:
            # Fall back to space-separated
            urls = [url.strip() for url in url_input.split() if url.strip()]

        return urls

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract core domain from URL."""
        parsed = urlparse(url if '://' in url else f'https://{url}')
        domain = parsed.netloc.lower()
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    @staticmethod
    def normalize_urls(urls: list) -> list:
        """Extract core domains and convert to https URLs."""
        fixed_urls = []
        for url in urls:
            domain = URLChecker.extract_domain(url)
            fixed_urls.append(f"https://{domain}")
        return fixed_urls

    @classmethod
    def parse_and_normalize_urls(cls, url_input: str) -> list:
        """Parse URL input and normalize schemes in one step."""
        urls = cls.parse_url_input(url_input)
        return cls.normalize_urls(urls)

    def get_block_verdict(self, urls: list, normalize: bool = True) -> Dict[str, Any]:
        """Test URLs and return aggregated results."""
        if normalize:
            urls = self.normalize_urls(urls)

        results = {
            'total_tested': len(urls),
            'zscaler_blocked': 0,
            'bloxone_blocked': 0,
            'both_blocked': 0,
            'both_allowed': 0,
            'details': []
        }

        for i, url in enumerate(urls):
            if normalize:
                url = self.normalize_urls([url])[0]

            # Security: Add rate limiting between requests
            if i > 0:
                time.sleep(0.5)  # 500ms delay between requests

            # Security logging: Log all URL tests for monitoring
            logger.info(f"Security Analysis: Testing URL {i+1}/{len(urls)}: {url}")

            result = {
                'url': url,
                'timestamp': time.time(),
                'zscaler': self._test_zscaler(url),
                'bloxone': self._test_bloxone(url) if self.jump_server_host else {'skipped': 'No jump server configured'}
            }
            results['details'].append(result)

            # Security logging: Log results
            zs_result = "BLOCKED" if not result['zscaler'].get('allowed', True) else "ALLOWED"
            bo_result = "SKIPPED" if 'skipped' in result['bloxone'] else ("BLOCKED" if not result['bloxone'].get('allowed', True) else "ALLOWED")
            logger.info(f"Security Analysis Result: {url} - ZScaler: {zs_result}, Bloxone: {bo_result}")

            zscaler_blocked = not result['zscaler'].get('allowed', True)
            bloxone_blocked = not result['bloxone'].get('allowed', True) if 'skipped' not in result['bloxone'] else False

            if zscaler_blocked:
                results['zscaler_blocked'] += 1
            if bloxone_blocked:
                results['bloxone_blocked'] += 1
            if zscaler_blocked and bloxone_blocked:
                results['both_blocked'] += 1
            if not zscaler_blocked and not bloxone_blocked:
                results['both_allowed'] += 1

        return results


def print_results_table(results: list):
    """Print results in a clean table format."""
    table = Texttable()
    table.set_cols_align(['l', 'c', 'c'])
    table.set_cols_width([40, 12, 12])

    # Header
    table.add_row(['URL', 'ZScaler', 'Bloxone'])

    for result in results:
        url = result['url']
        zs = result['zscaler']
        bo = result['bloxone']

        # Status indicators
        zs_status = '✓ ALLOWED' if zs.get('allowed') else '✗ BLOCKED'

        if 'skipped' in bo:
            bo_status = 'SKIPPED'
        else:
            bo_status = '✓ ALLOWED' if bo.get('allowed') else '✗ BLOCKED'

        table.add_row([url, zs_status, bo_status])

    print(table.draw())


def print_result_summary(result: Dict[str, Any]):
    """Print a formatted summary of test results."""
    print(f"\n{'=' * 60}")
    print(f"URL: {result['url']}")
    print(f"{'=' * 60}")

    # ZScaler results
    zs = result['zscaler']
    print(f"ZScaler:  {' ALLOWED' if zs.get('allowed') else ' BLOCKED'}")
    if not zs.get('allowed'):
        print(f"  Status: {zs.get('status_code', 'N/A')}")
        if zs.get('error'):
            print(f"  Error: {zs['error']}")
        elif zs.get('blocked_indicators', {}).get('block_reason'):
            print(f"  Reason: {zs['blocked_indicators']['block_reason']}")

    # Bloxone results
    bo = result['bloxone']
    if 'skipped' in bo:
        print(f"Bloxone:  SKIPPED ({bo['skipped']})")
    else:
        print(f"Bloxone:  {' ALLOWED' if bo.get('allowed') else ' BLOCKED'}")
        if not bo.get('allowed'):
            print(f"  Status: {bo.get('status_code', 'N/A')}")
            if bo.get('error'):
                print(f"  Error: {bo['error']}")
            elif bo.get('blocked_indicators', {}).get('block_reason'):
                print(f"  Reason: {bo['blocked_indicators']['block_reason']}")


def main():
    """Main function - simple test interface."""
    # Test configuration - modify these as needed
    url_input = 'chatgpt.com, facebook.com, company.com, google.com'  # CSV format supported
    json_output = False
    verbose = False

    # Parse and normalize URLs using backend logic
    urls = URLChecker.parse_and_normalize_urls(url_input)

    # Create tester and run tests
    tester = URLChecker()

    if tester.jump_server_host and not json_output:
        print(f"Using jump server: {tester.jump_server_host}:{tester.jump_server_port} (from config)")

    # Test URLs and collect results
    result = tester.get_block_verdict(urls)
    results = result['details']

    # Display results
    if json_output:
        if len(urls) == 1:
            # For single URL, show just the result object
            print(json.dumps(results[0], indent=2))
        else:
            # For multiple URLs, show full batch result with summary
            print(json.dumps(result, indent=2))
    else:
        print_results_table(results)

        if verbose and len(urls) == 1:
            print("\nDetailed Results:")
            print(json.dumps(results[0], indent=2))


if __name__ == '__main__':
    main()
