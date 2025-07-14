import base64
import time
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

from config import get_config

CONFIG = get_config()


@dataclass
class SecurityVerdict:
    """Data class to store security verdict information"""
    platform: str
    category: str
    verdict: str  # 'allow', 'block', 'unknown'
    confidence: Optional[str] = None
    subcategory: Optional[str] = None
    risk_score: Optional[int] = None
    additional_info: Optional[Dict] = None


class ZscalerClient:
    """Client for Zscaler URL categorization API"""

    def __init__(self, base_url: str, username: str, password: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.api_key = api_key
        self.session = requests.Session()
        self.auth_token = None

    def authenticate(self):
        """Authenticate with Zscaler API"""
        auth_url = f"{self.base_url}/api/v1/authenticatedSession"

        # Create timestamp and obfuscated API key
        timestamp = int(time.time() * 1000)
        key = f"{self.api_key}{timestamp}"
        obfuscated_key = base64.b64encode(key.encode()).decode()

        auth_data = {
            "username": self.username,
            "password": self.password,
            "apiKey": obfuscated_key,
            "timestamp": timestamp
        }

        response = self.session.post(auth_url, json=auth_data)
        if response.status_code == 200:
            self.auth_token = response.cookies.get('JSESSIONID')
            return True
        return False

    def get_url_category(self, url: str) -> SecurityVerdict:
        """Get URL category from Zscaler"""
        if not self.auth_token:
            if not self.authenticate():
                return SecurityVerdict("Zscaler", "unknown", "unknown", additional_info={"error": "Authentication failed"})

        lookup_url = f"{self.base_url}/api/v1/urlLookup"
        data = {"urls": [url]}

        response = self.session.post(lookup_url, json=data)

        if response.status_code == 200:
            result = response.json()
            if result and len(result) > 0:
                url_info = result[0]
                category = url_info.get('urlClassifications', ['unknown'])[0]

                # Determine verdict based on category
                blocked_categories = ['malware', 'phishing', 'spam', 'botnet', 'adult', 'gambling']
                verdict = 'block' if any(cat in category.lower() for cat in blocked_categories) else 'allow'

                return SecurityVerdict(
                    platform="Zscaler",
                    category=category,
                    verdict=verdict,
                    confidence=url_info.get('urlClassificationScore'),
                    additional_info=url_info
                )

        return SecurityVerdict("Zscaler", "unknown", "unknown", additional_info={"error": "API call failed"})


class InfobloxClient:
    """Client for Infoblox Threat Intelligence API"""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False  # Often needed for on-premise Infoblox

    def get_url_category(self, url: str) -> SecurityVerdict:
        """Get URL category from Infoblox"""
        # Extract domain from URL
        domain = urlparse(url).netloc

        # Infoblox Threat Intelligence lookup
        lookup_url = f"{self.base_url}/wapi/v2.12/record:rpz:cname"
        params = {
            "name": domain,
            "_return_fields": "name,canonical,zone,comment"
        }

        try:
            response = self.session.get(lookup_url, params=params)

            if response.status_code == 200:
                results = response.json()

                if results:
                    # URL is in RPZ (blocked)
                    rpz_info = results[0]
                    category = rpz_info.get('comment', 'malicious')

                    return SecurityVerdict(
                        platform="Infoblox",
                        category=category,
                        verdict="block",
                        additional_info=rpz_info
                    )
                else:
                    # Not in RPZ, check threat intelligence
                    return self._check_threat_intelligence(domain)

        except Exception as e:
            return SecurityVerdict("Infoblox", "unknown", "unknown", additional_info={"error": str(e)})

    def _check_threat_intelligence(self, domain: str) -> SecurityVerdict:
        """Check domain against Infoblox threat intelligence"""
        ti_url = f"{self.base_url}/wapi/v2.12/threatinsight:lookalike"
        params = {
            "target": domain,
            "_return_fields": "target,threat_type,confidence,detected_at"
        }

        try:
            response = self.session.get(ti_url, params=params)

            if response.status_code == 200:
                results = response.json()

                if results:
                    threat_info = results[0]
                    threat_type = threat_info.get('threat_type', 'suspicious')
                    confidence = threat_info.get('confidence', 'medium')

                    return SecurityVerdict(
                        platform="Infoblox",
                        category=threat_type,
                        verdict="block" if confidence in ['high', 'medium'] else "allow",
                        confidence=confidence,
                        additional_info=threat_info
                    )
                else:
                    # Clean domain
                    return SecurityVerdict("Infoblox", "clean", "allow")

        except Exception as e:
            return SecurityVerdict("Infoblox", "unknown", "unknown", additional_info={"error": str(e)})


class PaloAltoClient:
    """Client for Palo Alto URL Filtering API"""

    def __init__(self, host: str, api_key: str):
        self.host = host
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False  # Often needed for on-premise PA

    def get_url_category(self, url: str) -> SecurityVerdict:
        """Get URL category from Palo Alto"""
        # URL category lookup
        lookup_url = f"https://{self.host}/api/"
        params = {
            "type": "op",
            "cmd": f"<test><url-info-cloud><url>{url}</url></url-info-cloud></test>",
            "key": self.api_key
        }

        try:
            response = self.session.get(lookup_url, params=params)

            if response.status_code == 200:
                # Parse XML response
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)

                # Navigate XML structure
                result = root.find('.//result')
                if result is not None:
                    category = result.find('category')
                    if category is not None:
                        cat_text = category.text

                        # Determine verdict based on category
                        blocked_categories = [
                            'malware', 'phishing', 'command-and-control', 'abused-drugs',
                            'adult', 'gambling', 'hacking', 'proxy-avoidance-and-anonymizers'
                        ]

                        verdict = 'block' if cat_text in blocked_categories else 'allow'

                        return SecurityVerdict(
                            platform="Palo Alto",
                            category=cat_text,
                            verdict=verdict,
                            additional_info={"xml_response": response.text}
                        )

        except Exception as e:
            return SecurityVerdict("Palo Alto", "unknown", "unknown", additional_info={"error": str(e)})

        return SecurityVerdict("Palo Alto", "unknown", "unknown", additional_info={"error": "API call failed"})


class URLSecurityChecker:
    """Main class to orchestrate URL security checks across all platforms"""

    def __init__(self):
        self.zscaler = None
        self.infoblox = None
        self.palo_alto = None

    def configure_zscaler(self, base_url: str, username: str, password: str, api_key: str):
        """Configure Zscaler client"""
        self.zscaler = ZscalerClient(base_url, username, password, api_key)

    def configure_infoblox(self, base_url: str, username: str, password: str):
        """Configure Infoblox client"""
        self.infoblox = InfobloxClient(base_url, username, password)

    def configure_palo_alto(self, host: str, api_key: str):
        """Configure Palo Alto client"""
        self.palo_alto = PaloAltoClient(host, api_key)

    def check_url(self, url: str) -> Dict[str, SecurityVerdict]:
        """Check URL across all configured platforms"""
        results = {}

        if self.zscaler:
            print(f"Checking {url} with Zscaler...")
            results['zscaler'] = self.zscaler.get_url_category(url)

        if self.infoblox:
            print(f"Checking {url} with Infoblox...")
            results['infoblox'] = self.infoblox.get_url_category(url)

        if self.palo_alto:
            print(f"Checking {url} with Palo Alto...")
            results['palo_alto'] = self.palo_alto.get_url_category(url)

        return results

    def check_single_url(self, url: str) -> Dict[str, SecurityVerdict]:
        """Check a single URL and return results"""
        return self.check_url(url)

    def get_summary(self, results: Dict[str, SecurityVerdict]) -> Dict[str, str]:
        """Get a summary of verdicts across all platforms"""
        summary = {}
        block_count = 0
        allow_count = 0

        for platform, verdict in results.items():
            summary[platform] = {
                'category': verdict.category,
                'verdict': verdict.verdict,
                'confidence': verdict.confidence
            }

            if verdict.verdict == 'block':
                block_count += 1
            elif verdict.verdict == 'allow':
                allow_count += 1

        # Overall recommendation
        if block_count > 0:
            summary['overall_recommendation'] = 'BLOCK'
        elif allow_count > 0:
            summary['overall_recommendation'] = 'ALLOW'
        else:
            summary['overall_recommendation'] = 'UNKNOWN'

        return summary
        """Print formatted results"""
        print(f"\n{'=' * 60}")
        print(f"Security Check Results for: {url}")
        print(f"{'=' * 60}")

        for platform, verdict in results.items():
            print(f"\n{verdict.platform}:")
            print(f"  Category: {verdict.category}")
            print(f"  Verdict: {verdict.verdict.upper()}")
            if verdict.confidence:
                print(f"  Confidence: {verdict.confidence}")
            if verdict.subcategory:
                print(f"  Subcategory: {verdict.subcategory}")
            if verdict.risk_score:
                print(f"  Risk Score: {verdict.risk_score}")
            if verdict.additional_info and 'error' in verdict.additional_info:
                print(f"  Error: {verdict.additional_info['error']}")


def main():
    """Example usage"""
    import sys

    # Initialize the checker
    checker = URLSecurityChecker()

    # Configure platforms using environment variables
    # Zscaler
    zscaler_url = CONFIG.zscaler_url
    zscaler_username = CONFIG.zscaler_username
    zscaler_password = CONFIG.zscaler_password
    zscaler_api_key = CONFIG.zscaler_api_key

    if all([zscaler_url, zscaler_username, zscaler_password, zscaler_api_key]):
        checker.configure_zscaler(zscaler_url, zscaler_username, zscaler_password, zscaler_api_key)
        print("✓ Zscaler configured")
    else:
        print("⚠ Zscaler credentials not found in environment")

    # Infoblox
    infoblox_url = os.getenv('INFOBLOX_BASE_URL')
    infoblox_username = os.getenv('INFOBLOX_USERNAME')
    infoblox_password = os.getenv('INFOBLOX_PASSWORD')

    if all([infoblox_url, infoblox_username, infoblox_password]):
        checker.configure_infoblox(infoblox_url, infoblox_username, infoblox_password)
        print("✓ Infoblox configured")
    else:
        print("⚠ Infoblox credentials not found in environment")

    # Palo Alto
    palo_alto_host = os.getenv('PALO_ALTO_HOST')
    palo_alto_api_key = os.getenv('PALO_ALTO_API_KEY')

    if all([palo_alto_host, palo_alto_api_key]):
        checker.configure_palo_alto(palo_alto_host, palo_alto_api_key)
        print("✓ Palo Alto configured")
    else:
        print("⚠ Palo Alto credentials not found in environment")

    # Check if URL provided as command line argument
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(f"\nChecking URL from command line: {url}")
        results = checker.check_url(url)
        checker.print_results(url, results)

        # Print summary
        summary = checker.get_summary(results)
        print(f"\nOverall Recommendation: {summary['overall_recommendation']}")

    else:
        # Test URLs from environment or default
        test_urls = os.getenv('TEST_URLS', 'https://google.com,https://facebook.com').split(',')

        print(f"\nTesting {len(test_urls)} URLs...")

        # Check each URL
        for url in test_urls:
            url = url.strip()
            if url:
                results = checker.check_url(url)
                checker.print_results(url, results)
                time.sleep(1)  # Rate limiting


if __name__ == "__main__":
    main()
