"""Domain Lookalike Detection Service using dnstwist and Censys CT logs."""

import logging
import subprocess
import json
import re
import sys
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import requests
import whois
from datetime import datetime

logger = logging.getLogger(__name__)

# Lazy import for Censys to avoid circular imports
_censys_module = None


def _get_censys_module():
    """Lazy load Censys CT module."""
    global _censys_module
    if _censys_module is None:
        try:
            from services import censys_ct
            _censys_module = censys_ct
        except ImportError:
            logger.debug("Censys CT module not available")
            _censys_module = False
    return _censys_module if _censys_module else None

# Get dnstwist path - check venv first, then system PATH
_VENV_BIN = Path(sys.executable).parent
_VENV_DNSTWIST = _VENV_BIN / 'dnstwist'
_HOMEBREW_DNSTWIST = Path('/opt/homebrew/bin/dnstwist')

# Use venv dnstwist if available, otherwise fall back to homebrew/system
if _VENV_DNSTWIST.exists():
    DNSTWIST_PATH = _VENV_DNSTWIST
elif _HOMEBREW_DNSTWIST.exists():
    DNSTWIST_PATH = _HOMEBREW_DNSTWIST
else:
    DNSTWIST_PATH = Path('dnstwist')  # Hope it's in PATH

# Top malicious TLDs commonly used in phishing attacks
# Source: Cybercrime Information Center - Top 20 TLDs by Malicious Phishing Domains
# Note: .com excluded as it's typically the original domain
MALICIOUS_TLDS = [
    'tk', 'buzz', 'xyz', 'top', 'ga', 'ml', 'info', 'cf', 'gq', 'icu',
    'wang', 'live', 'net', 'cn', 'online', 'host', 'org', 'us', 'ru'
]

# Known parking page indicators
PARKING_INDICATORS = [
    # Common parking page text
    r'this domain is for sale',
    r'buy this domain',
    r'domain for sale',
    r'domain is parked',
    r'parked by',
    r'parked domain',
    r'parked free',
    r'this domain may be for sale',
    r'make an offer',
    r'domain parking',
    r'acquire this domain',
    r'purchase this domain',
    r'domain available',
    r'is available for purchase',
    # Parking service signatures
    r'sedoparking\.com',
    r'sedo domain parking',
    r'sedo\.com',
    r'bodis\.com',
    r'parkingcrew\.net',
    r'above\.com',
    r'hugedomains\.com',
    r'afternic\.com',
    r'dan\.com',
    r'sav\.com',
    r'atom\.com',
    r'domains\.atom\.com',
    r'godaddy.*parked',
    r'namecheap.*parked',
    r'registered with namecheap',
    r'recently been registered',
    r'domainnamesales\.com',
    r'undeveloped\.com',
    r'domainmarket\.com',
    r'brandpa\.com',
    r'squadhelp\.com',
    # Ad-heavy parking indicators
    r'sponsored listings',
    r'related links',
    r'related searches',
    r'relevant searches',
    r'click here to inquire',
    # JavaScript-based parking (GoDaddy, etc.)
    r'LANDER_SYSTEM',
    r'parking-lander',
    r'wsimg\.com.*parking',
    r'google\.com/adsense/domains',
    r'adsense/domains/caf\.js',
]

# Compile patterns for efficiency
PARKING_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PARKING_INDICATORS]

# Known domain marketplace hostnames - redirects to these indicate parked domains
DOMAIN_MARKETPLACE_HOSTS = [
    'domains.atom.com',
    'atom.com',
    'sedo.com',
    'sedoparking.com',
    'dan.com',
    'afternic.com',
    'hugedomains.com',
    'bodis.com',
    'parkingcrew.net',
    'above.com',
    'sav.com',
    'domainnamesales.com',
    'undeveloped.com',
    'domainmarket.com',
    'brandpa.com',
    'squadhelp.com',
    # GoDaddy parking network
    'searchhounds.com',
    'godaddy.com',
    'porkbun.com',
    'namecheap.com',
    'dynadot.com',
    'epik.com',
    'uniregistry.com',
    'brandbucket.com',
    'buydomains.com',
    'domainagents.com',
    'parklogic.com',
]

# URL parameters commonly used by parking services to track the original domain
PARKING_URL_PARAMS = {'domain', 'd', 'siteid', 'site_id', 'ref', 'source'}

# Brand protection registrars - domains registered through these are typically defensive
# These companies specialize in protecting brands from cybersquatting
BRAND_PROTECTION_REGISTRARS = {
    'markmonitor',
    'csc corporate domains',
    'csc global',
    'safenames',
    'comlaude',
    'nom-iq',
    'clarivate',
    'brandshelter',
    'corsearch',
    'valideus',
    'gandi corporate',
    'corporation service company',
    'ncc group',
    'brand protection',
}

# Known parking service nameservers - authoritative source: MISP warninglists
# https://github.com/MISP/misp-warninglists/blob/main/lists/parking-domain-ns/list.json
# Additional entries added based on observed false negatives
PARKING_NAMESERVERS = {
    'above.com', 'afternic.com', 'alter.com', 'atom.com', 'bodis.com', 'bookmyname.com',
    'brainydns.com', 'brandbucket.com', 'chookdns.com', 'cnomy.com', 'commonmx.com',
    'dan.com', 'day.biz', 'dingodns.com', 'directnic.com', 'dne.com', 'dnslink.com',
    'dnsnuts.com', 'dnsowl.com', 'dnsspark.com', 'domain-for-sale.at', 'domain-for-sale.se',
    'domaincntrol.com', 'domainhasexpired.com', 'domainist.com', 'domainmarket.com',
    'domainmx.com', 'domainorderdns.nl', 'domainparking.ru', 'domainprofi.de',
    'domainrecover.com', 'dsredirection.com', 'dsredirects.com', 'eftydns.com',
    'emailverification.info', 'emu-dns.com', 'expiereddnsmanager.com', 'expirationwarning.net',
    'fabulous.com', 'fastpark.net', 'freenom.com', 'gname.net', 'hastydns.com',
    'hostresolver.com', 'ibspark.com', 'kirklanddc.com', 'koaladns.com', 'magpiedns.com',
    'malkm.com', 'markmonitor.com', 'mijndomein.nl', 'milesmx.com', 'mytrafficmanagement.com',
    'namedynamics.net', 'nameprovider.net', 'ndsplitter.com', 'nsresolution.com',
    'onlydomains.com', 'panamans.com', 'parking-page.net', 'parkingcrew.net',
    'parkingspa.com', 'parklogic.com', 'parktons.com', 'perfectdomain.com', 'quokkadns.com',
    'redirectdom.com', 'redmonddc.com', 'renewyourname.net', 'rentondc.com', 'rookdns.com',
    'rzone.de', 'sav.com', 'searchfusion.com', 'searchreinvented.com',
    'securetrafficrouting.com', 'sedo.com', 'sedoparking.com', 'smtmdns.com', 'snparking.ru',
    'squadhelp.com', 'sslparking.com', 'tacomadc.com', 'taipandns.com', 'thednscloud.com',
    'torresdns.com', 'trafficcontrolrouter.com', 'voodoo.com', 'weaponizedcow.com',
    'wombatdns.com', 'ztomy.com',
    # Specific NS hostnames
    'ns01.cashparking.com', 'ns02.cashparking.com', 'ns1.namefind.com', 'ns2.namefind.com',
    'ns1.park.do', 'ns2.park.do', 'ns1.pql.net', 'ns2.pql.net', 'ns1.smartname.com',
    'ns2.smartname.com', 'ns1.sonexo.eu', 'ns2.sonexo.com', 'ns1.undeveloped.com',
    'ns2.undeveloped.com', 'ns3.tppns.com', 'ns4.tppns.com', 'park1.encirca.net',
    'park2.encirca.net', 'parkdns1.internetvikings.com', 'parkdns2.internetvikings.com',
    'parking.namecheap.com', 'parking1.ovh.net', 'parking2.ovh.net',
    'parkingpage.namecheap.com', 'expired.uniregistry-dns.com', 'uniregistrymarket.link',
}


def check_if_parked_by_ns(ns_records: List[str]) -> Optional[bool]:
    """Check if a domain is parked based on its nameserver records.

    This is the most authoritative method - parking services use consistent nameservers.

    Args:
        ns_records: List of nameserver hostnames (e.g., ['ns1.sedoparking.com', 'ns2.sedoparking.com'])

    Returns:
        True if NS indicates parked, False if NS indicates not parked, None if inconclusive
    """
    if not ns_records:
        return None

    for ns in ns_records:
        ns_lower = ns.lower().rstrip('.')

        # Check exact match
        if ns_lower in PARKING_NAMESERVERS:
            logger.debug(f"NS {ns} matches known parking NS")
            return True

        # Check if NS is a subdomain of a known parking service
        for parking_ns in PARKING_NAMESERVERS:
            if ns_lower.endswith('.' + parking_ns) or ns_lower == parking_ns:
                logger.debug(f"NS {ns} matches parking domain {parking_ns}")
                return True

    # NS records present but don't match parking - likely not parked
    return None  # Inconclusive, fall back to other methods


def detect_defensive_registration(
    domain: str,
    monitored_domain: str,
    ns_records: Optional[List[str]] = None,
    registrar: Optional[str] = None,
    allowlist: Optional[List[str]] = None
) -> bool:
    """Detect if a lookalike domain is a defensive registration owned by the company.

    Uses multiple signals to determine ownership:
    1. Nameserver matching - NS contains monitored domain (e.g., ns.example.com for example.com)
    2. Brand protection registrar - MarkMonitor, CSC, Safenames, etc.
    3. Manual allowlist - Explicitly confirmed defensive domains

    Args:
        domain: The lookalike domain being checked
        monitored_domain: The company's primary domain being monitored
        ns_records: List of nameserver hostnames for the lookalike
        registrar: WHOIS registrar name
        allowlist: List of known defensive domains for this company

    Returns:
        True if domain appears to be a defensive registration
    """
    # Check manual allowlist first (most authoritative)
    if allowlist and domain.lower() in [d.lower() for d in allowlist]:
        logger.debug(f"{domain}: Defensive (in allowlist)")
        return True

    # Extract base name from monitored domain for NS matching
    # e.g., "example.com" -> "example", "mycompany.co.uk" -> "mycompany"
    monitored_base = monitored_domain.split('.')[0].lower()

    # Check nameservers contain monitored domain
    if ns_records:
        for ns in ns_records:
            ns_lower = ns.lower().rstrip('.')
            # Check if NS is under the monitored domain (e.g., ns.example.com)
            if monitored_base in ns_lower:
                logger.debug(f"{domain}: Defensive (NS {ns} contains {monitored_base})")
                return True
            # Check if NS contains exact monitored domain
            if monitored_domain.lower().rstrip('.') in ns_lower:
                logger.debug(f"{domain}: Defensive (NS {ns} contains {monitored_domain})")
                return True

    # Check brand protection registrar
    if registrar:
        registrar_lower = registrar.lower()
        for bp_registrar in BRAND_PROTECTION_REGISTRARS:
            if bp_registrar in registrar_lower:
                logger.debug(f"{domain}: Defensive (registrar {registrar} is brand protection)")
                return True

    return False


def classify_domain_risk(
    domain_data: Dict[str, Any],
    monitored_domain: str,
    defensive_allowlist: Optional[List[str]] = None
) -> str:
    """Classify a lookalike domain into a risk level.

    Risk levels:
    - 'defensive': Owned by the company (no alert needed)
    - 'parked': For sale, no active content (monitor)
    - 'suspicious': Active but unknown owner (investigate)
    - 'high_risk': Active + MX records or malicious indicators (urgent action)
    - 'unknown': Unable to determine

    Args:
        domain_data: Domain dictionary with DNS, parking, and threat intel data
        monitored_domain: The company's primary domain
        defensive_allowlist: List of known defensive domains

    Returns:
        Risk classification string
    """
    domain = domain_data.get('domain', '')

    # Check if defensive registration
    is_defensive = detect_defensive_registration(
        domain=domain,
        monitored_domain=monitored_domain,
        ns_records=domain_data.get('dns_ns') or domain_data.get('whois_name_servers'),
        registrar=domain_data.get('registrar'),
        allowlist=defensive_allowlist
    )

    if is_defensive:
        return 'defensive'

    # Check if parked
    if domain_data.get('parked') is True:
        return 'parked'

    # Check for high-risk indicators
    has_mx = bool(domain_data.get('dns_mx'))
    vt_malicious = domain_data.get('vt_reputation', {}).get('malicious', 0)
    rf_high_risk = (domain_data.get('rf_risk_score') or 0) >= 65

    if has_mx or vt_malicious >= 1 or rf_high_risk:
        return 'high_risk'

    # Active domain with A records but no high-risk signals
    if domain_data.get('dns_a') or domain_data.get('parked') is False:
        return 'suspicious'

    return 'unknown'


def check_if_parked_content(domain: str, timeout: int = 5) -> Optional[bool]:
    """Check if a domain appears to be parked using content analysis (fallback method).

    Args:
        domain: Domain to check
        timeout: HTTP request timeout in seconds

    Returns:
        True if parked, False if not parked, None if unable to determine
    """
    for protocol in ['https', 'http']:
        url = f"{protocol}://{domain}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )

            # Check if redirected to a known domain marketplace
            final_host = urlparse(response.url).netloc.lower()
            for marketplace in DOMAIN_MARKETPLACE_HOSTS:
                if marketplace in final_host:
                    logger.debug(f"{domain} detected as parked (redirected to {final_host})")
                    return True

            content = response.text.lower()

            # Check for parking indicators in content
            for pattern in PARKING_PATTERNS:
                if pattern.search(content):
                    logger.debug(f"{domain} detected as parked (matched: {pattern.pattern})")
                    return True

            # If we got a real page with content, it's not parked
            if len(content) > 500:
                return False

            # Very short pages are suspicious but not definitive
            return False

        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            if protocol == 'https':
                continue
            return None
        except requests.exceptions.Timeout:
            logger.debug(f"{domain} timed out during parking check")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"{domain} request failed: {e}")
            return None

    return None


def check_if_parked_detailed(
    domain: str,
    timeout: int = 10,
    ns_records: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Check if a domain is parked with detailed information about the detection.

    Returns a dict with:
        - is_parked: bool indicating if domain appears to be parked
        - parking_provider: the detected parking service (if any)
        - redirect_chain: list of URLs in the redirect chain
        - final_url: the final destination URL
        - confidence: 'high', 'medium', or 'low'
        - indicators: list of reasons why it was flagged as parked
    """
    result = {
        'is_parked': False,
        'parking_provider': None,
        'redirect_chain': [],
        'final_url': None,
        'confidence': 'low',
        'indicators': []
    }

    clean_domain = domain.replace('https://', '').replace('http://', '').rstrip('/')

    # Check NS records first (most authoritative)
    if ns_records:
        ns_result = check_if_parked_by_ns(ns_records)
        if ns_result is True:
            result['is_parked'] = True
            result['confidence'] = 'high'
            result['indicators'].append('Nameserver matches known parking provider')
            # Try to identify the provider from NS
            for ns in ns_records:
                ns_lower = ns.lower()
                for marketplace in DOMAIN_MARKETPLACE_HOSTS:
                    if marketplace in ns_lower:
                        result['parking_provider'] = marketplace
                        break
                if result['parking_provider']:
                    break
            return result

    # Try HTTPS then HTTP
    for protocol in ['https', 'http']:
        url = f"{protocol}://{clean_domain}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )

            # Build redirect chain
            if response.history:
                result['redirect_chain'] = [r.url for r in response.history]
            result['redirect_chain'].append(response.url)
            result['final_url'] = response.url

            # Parse final URL
            parsed_final = urlparse(response.url)
            final_domain = parsed_final.netloc.lower()

            # Remove www. prefix for comparison
            if final_domain.startswith('www.'):
                final_domain = final_domain[4:]

            # Check 1: Did it redirect to a different domain?
            redirected_to_different = final_domain != clean_domain and final_domain != f'www.{clean_domain}'

            # Check 2: Is the final domain a known parking service?
            for marketplace in DOMAIN_MARKETPLACE_HOSTS:
                if final_domain == marketplace or final_domain.endswith(f'.{marketplace}'):
                    result['is_parked'] = True
                    result['parking_provider'] = marketplace
                    result['indicators'].append(f'Redirected to parking domain: {marketplace}')
                    break

            # Check 3: Look for parking-related URL parameters
            query_params = parse_qs(parsed_final.query.lower())
            for param in PARKING_URL_PARAMS:
                if param in query_params:
                    param_value = query_params[param][0] if query_params[param] else ''
                    if clean_domain.lower() in param_value.lower():
                        result['indicators'].append(f'URL parameter "{param}" references original domain')
                        if not result['is_parked'] and redirected_to_different:
                            result['is_parked'] = True

            # Check 4: Content-based detection
            content = response.text
            content_lower = content.lower()

            # Check for JavaScript redirects to parking lander pages
            # GoDaddy uses: window.location.href="/lander"
            js_redirect_match = re.search(r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', content)
            if js_redirect_match and not result['is_parked']:
                js_path = js_redirect_match.group(1)
                if 'lander' in js_path.lower():
                    # Follow the JS redirect
                    try:
                        lander_url = f"{protocol}://{clean_domain}{js_path}" if js_path.startswith('/') else js_path
                        lander_response = requests.get(
                            lander_url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                        )
                        result['redirect_chain'].append(lander_url)
                        result['final_url'] = lander_response.url
                        content = lander_response.text
                        content_lower = content.lower()
                        result['indicators'].append(f'JavaScript redirect to: {js_path}')
                    except Exception:
                        pass

            # Now check content for parking patterns
            if not result['is_parked']:
                for pattern in PARKING_PATTERNS:
                    match = pattern.search(content_lower)
                    if match:
                        result['is_parked'] = True
                        result['indicators'].append(f'Content matched: "{match.group()}"')
                        # Try to extract provider from content
                        if 'wsimg.com' in content_lower or 'lander_system' in content_lower:
                            result['parking_provider'] = 'godaddy.com'
                        else:
                            for marketplace in DOMAIN_MARKETPLACE_HOSTS:
                                if marketplace in content_lower:
                                    result['parking_provider'] = marketplace
                                    break
                        break

            # Determine confidence level
            if result['is_parked']:
                if result['parking_provider'] and len(result['indicators']) > 1:
                    result['confidence'] = 'high'
                elif result['parking_provider'] or len(result['indicators']) >= 1:
                    result['confidence'] = 'medium'

            # If we got this far with a response, we have our answer
            return result

        except requests.exceptions.SSLError:
            if protocol == 'https':
                continue
            result['indicators'].append('SSL error')
        except requests.exceptions.Timeout:
            result['indicators'].append('Connection timeout')
        except requests.exceptions.ConnectionError as e:
            result['indicators'].append(f'Connection error')
        except Exception as e:
            result['indicators'].append(f'Error: {str(e)[:50]}')

    return result


def check_if_parked(
    domain: str,
    timeout: int = 5,
    use_urlscan: bool = True,
    ns_records: Optional[List[str]] = None
) -> Optional[bool]:
    """Check if a domain appears to be parked.

    Uses a three-tier approach:
    1. Primary: NS record check (most authoritative - parking services use consistent nameservers)
    2. Secondary: URLScan.io categorization (uses existing scan data)
    3. Fallback: Content-based pattern matching (if other methods inconclusive)

    Args:
        domain: Domain to check
        timeout: HTTP request timeout in seconds (for content fallback)
        use_urlscan: Whether to try URLScan.io (default True)
        ns_records: Optional list of nameserver records (e.g., from dnstwist)

    Returns:
        True if parked, False if not parked, None if unable to determine
    """
    # 1. Check NS records first (most authoritative)
    if ns_records:
        ns_result = check_if_parked_by_ns(ns_records)
        if ns_result is True:
            logger.debug(f"{domain}: Detected as parked via NS records")
            return True

    # 2. Try URLScan.io
    if use_urlscan:
        try:
            from services.urlscan import URLScanClient
            client = URLScanClient()
            result = client.check_parking_status(domain)
            if result is not None:
                return result
            logger.debug(f"{domain}: URLScan returned no result, falling back to content analysis")
        except ImportError:
            logger.debug("URLScan client not available, using content analysis")
        except Exception as e:
            logger.warning(f"URLScan check failed for {domain}: {e}, falling back to content analysis")

    # 3. Fallback to content-based detection
    return check_if_parked_content(domain, timeout=timeout)


def check_parking_batch(domains: List[Dict[str, Any]], max_workers: int = 10) -> List[Dict[str, Any]]:
    """Check parking status for multiple domains in parallel with detailed information.

    Args:
        domains: List of domain dictionaries (must have 'domain' and 'registered' keys)
        max_workers: Maximum concurrent checks

    Returns:
        Same list with parking details added to each domain:
        - parked: bool (True/False/None)
        - parking_provider: str or None (e.g., 'searchhounds.com')
        - parking_confidence: str ('high', 'medium', 'low')
        - parking_indicators: list of str (reasons for detection)
        - parking_final_url: str or None (where it redirected to)
    """
    registered_domains = [d for d in domains if d.get('registered')]
    logger.info(f"Checking parking status for {len(registered_domains)} registered domains")

    # Check parking in parallel with detailed detection
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_if_parked_detailed, d['domain'], ns_records=d.get('dns_ns')): d
            for d in registered_domains
        }

        for future in concurrent.futures.as_completed(future_to_domain):
            domain_data = future_to_domain[future]
            try:
                result = future.result()
                domain_data['parked'] = result['is_parked']
                domain_data['parking_provider'] = result['parking_provider']
                domain_data['parking_confidence'] = result['confidence']
                domain_data['parking_indicators'] = result['indicators']
                domain_data['parking_final_url'] = result['final_url']
            except Exception as e:
                logger.error(f"Error checking parking for {domain_data['domain']}: {e}")
                domain_data['parked'] = None
                domain_data['parking_provider'] = None
                domain_data['parking_confidence'] = None
                domain_data['parking_indicators'] = []
                domain_data['parking_final_url'] = None

    # Set parking fields to None for unregistered domains
    for d in domains:
        if not d.get('registered'):
            d['parked'] = None
            d['parking_provider'] = None
            d['parking_confidence'] = None
            d['parking_indicators'] = []
            d['parking_final_url'] = None

    parked_count = sum(1 for d in domains if d.get('parked') is True)
    logger.info(f"Found {parked_count} parked domains")

    return domains


def generate_tld_variations(domain: str) -> List[Dict[str, Any]]:
    """Generate domain variations using malicious TLDs.

    Takes the base domain name (without TLD) and appends each malicious TLD.

    Args:
        domain: The original domain (e.g., 'example.com')

    Returns:
        List of domain dictionaries with TLD variations
    """
    # Extract base domain name (everything before the last dot)
    parts = domain.rsplit('.', 1)
    if len(parts) < 2:
        return []

    base_name = parts[0]
    original_tld = parts[1].lower()

    variations = []
    for tld in MALICIOUS_TLDS:
        # Skip if same as original TLD
        if tld.lower() == original_tld:
            continue

        variation_domain = f"{base_name}.{tld}"
        variations.append({
            'domain': variation_domain,
            'fuzzer': 'tld-swap',
            'dns_a': [],
            'dns_aaaa': [],
            'dns_mx': [],
            'dns_ns': [],
            'geoip': '',
            'registered': False  # Will be checked later if registered_only is True
        })

    return variations


def get_domain_lookalikes(
    domain: str,
    registered_only: bool = False,
    include_malicious_tlds: bool = False,
    include_censys_impersonation: bool = True,
    legitimate_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Get lookalike domains using dnstwist and Censys CT log search.

    Args:
        domain: The domain to check for lookalikes
        registered_only: If True, only return registered domains (with DNS records)
        include_malicious_tlds: If True, also generate variations using known malicious TLDs
        include_censys_impersonation: If True, search Censys CT logs for brand impersonation
            domains (e.g., acme-loan.com). Requires CENSYS_API_ID/SECRET. Default True.
        legitimate_domains: List of legitimate domains to exclude from Censys results.
            If None, only the monitored domain is excluded.

    Returns:
        Dictionary containing lookalike domains and metadata
    """
    logger.info(f"Generating lookalike domains for: {domain}")

    try:
        # Run dnstwist with JSON output
        # Note: dnstwist performs DNS resolution by default (as of v20250130+)
        # -r: Filter output to show only registered domains
        # -f json: Output in JSON format
        # Use full path to dnstwist to ensure it's found even when PATH doesn't include venv
        cmd = [str(DNSTWIST_PATH), '-f', 'json']

        if registered_only:
            cmd.append('-r')  # Filter to registered domains only

        cmd.append(domain)

        # Use longer timeout for DNS resolution mode (30 min) vs basic mode (10 min)
        timeout_seconds = 1800 if registered_only else 600
        logger.info(f"Running command: {' '.join(cmd)} (timeout: {timeout_seconds}s)")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )

        if result.returncode != 0:
            logger.error(f"dnstwist failed: {result.stderr}")
            return {
                'success': False,
                'error': f'dnstwist execution failed: {result.stderr}',
                'domains': []
            }

        # Parse JSON output
        try:
            lookalikes = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse dnstwist output: {e}")
            return {
                'success': False,
                'error': 'Failed to parse dnstwist output',
                'domains': []
            }

        # Process and enrich the results
        processed_domains = []
        for entry in lookalikes:
            domain_data = {
                'domain': entry.get('domain', ''),
                'fuzzer': entry.get('fuzzer', ''),
                'dns_a': entry.get('dns_a', []),
                'dns_aaaa': entry.get('dns_aaaa', []),
                'dns_mx': entry.get('dns_mx', []),
                'dns_ns': entry.get('dns_ns', []),
                'geoip': entry.get('geoip', ''),
                'registered': bool(entry.get('dns_a') or entry.get('dns_aaaa') or entry.get('dns_mx'))
            }

            # Skip original domain
            if entry.get('fuzzer') == 'original':
                continue

            # Filter by registration status if requested
            if registered_only and not domain_data['registered']:
                continue

            processed_domains.append(domain_data)

        # Add malicious TLD variations if requested
        if include_malicious_tlds:
            tld_variations = generate_tld_variations(domain)
            existing_domains = {d['domain'] for d in processed_domains}
            added_count = 0

            for tld_var in tld_variations:
                # Skip if already in results from dnstwist
                if tld_var['domain'] in existing_domains:
                    continue

                # If registered_only, check DNS for this domain
                if registered_only:
                    try:
                        import socket
                        socket.gethostbyname(tld_var['domain'])
                        tld_var['registered'] = True
                        tld_var['dns_a'] = [socket.gethostbyname(tld_var['domain'])]
                    except socket.gaierror:
                        # Not registered, skip in registered_only mode
                        continue

                processed_domains.append(tld_var)
                added_count += 1

            logger.info(f"Added {added_count} TLD variations from {len(MALICIOUS_TLDS)} malicious TLDs")

        # Add brand impersonation domains (semantic attacks like "acme-loan.com")
        # These cannot be detected by dnstwist's fuzzing algorithms
        # Priority: 1) RecordedFuture (best) 2) Shodan CT (paid) 3) crt.sh watchlist (free)
        censys_count = 0
        censys_error = None
        if include_censys_impersonation:
            # Extract brand name from domain
            brand_name = domain.split('.')[0]

            # Build list of legitimate domains to exclude
            legit_domains = legitimate_domains or []
            if domain not in legit_domains:
                legit_domains = [domain] + list(legit_domains)

            # Load watchlist from config (used by crt.sh fallback)
            watchlist_domains = []
            try:
                config_path = Path(__file__).parent.parent / "data" / "transient" / "domain_monitoring" / "config.json"
                if config_path.exists():
                    with open(config_path) as f:
                        config = json.load(f)
                        watchlist = config.get("watchlist", {})
                        watchlist_domains = watchlist.get(domain, [])
                        if watchlist_domains:
                            logger.info(f"Loaded {len(watchlist_domains)} watchlist domains from config")
            except Exception as e:
                logger.warning(f"Failed to load watchlist config: {e}")

            existing_domains = {d['domain'].lower() for d in processed_domains}
            source_used = None

            # Option 1: RecordedFuture (best for enterprise users)
            try:
                from services.recorded_future import RecordedFutureClient
                rf_client = RecordedFutureClient()
                if rf_client.is_configured():
                    logger.info(f"Searching RecordedFuture for '{brand_name}' brand impersonation")
                    rf_result = rf_client.search_brand_domains(
                        brand=brand_name,
                        legitimate_domains=legit_domains,
                        min_risk_score=0,  # Get all, will sort by risk
                        limit=200,
                    )

                    if rf_result.get("success"):
                        source_used = "recordedfuture"
                        for imp in rf_result.get("impersonation_domains", []):
                            imp_domain = imp.get("domain", "").lower()
                            if imp_domain and imp_domain not in existing_domains:
                                processed_domains.append({
                                    'domain': imp_domain,
                                    'fuzzer': 'rf-brand-impersonation',
                                    'dns_a': [],
                                    'dns_aaaa': [],
                                    'dns_mx': [],
                                    'dns_ns': [],
                                    'geoip': '',
                                    'registered': True,
                                    'rf_risk_score': imp.get('rf_risk_score'),
                                    'rf_risk_level': imp.get('rf_risk_level'),
                                    'rf_rules': imp.get('rf_rules', []),
                                })
                                existing_domains.add(imp_domain)
                                censys_count += 1

                        logger.info(f"Added {censys_count} brand impersonation domains from RecordedFuture")
                    else:
                        censys_error = rf_result.get("error", "Unknown error")
                        logger.warning(f"RF brand search failed: {censys_error}")

            except ImportError:
                logger.debug("RecordedFuture client not available")
            except Exception as e:
                censys_error = str(e)
                logger.warning(f"RF brand search error: {e}")

            # Option 2: Shodan CT (paid, if RF not available/failed)
            if not source_used:
                censys_module = _get_censys_module()
                if censys_module and censys_module.is_configured():
                    logger.info(f"Searching Shodan CT logs for '{brand_name}' brand impersonation")
                    try:
                        censys_result = censys_module.search_brand_impersonation(
                            brand=brand_name,
                            legitimate_domains=legit_domains,
                            max_results=100,
                        )

                        if censys_result.get("success"):
                            source_used = "shodan"
                            for imp in censys_result.get("impersonation_domains", []):
                                imp_domain = imp.get("domain", "").lower()
                                if imp_domain and imp_domain not in existing_domains:
                                    processed_domains.append({
                                        'domain': imp_domain,
                                        'fuzzer': 'ct-brand-impersonation',
                                        'dns_a': [],
                                        'dns_aaaa': [],
                                        'dns_mx': [],
                                        'dns_ns': [],
                                        'geoip': '',
                                        'registered': True,
                                        'censys_issuer': imp.get('issuer_org', ''),
                                        'censys_link': imp.get('censys_link', ''),
                                    })
                                    existing_domains.add(imp_domain)
                                    censys_count += 1

                            logger.info(f"Added {censys_count} brand impersonation domains from Shodan CT logs")
                        else:
                            if not censys_error:
                                censys_error = censys_result.get("error", "Unknown error")
                            logger.warning(f"Shodan search failed: {censys_error}")

                    except Exception as e:
                        if not censys_error:
                            censys_error = str(e)
                        logger.error(f"Shodan brand search error: {e}")

            # Option 3: crt.sh watchlist (free, always check known suspicious domains)
            if watchlist_domains:
                logger.info(f"Checking {len(watchlist_domains)} watchlist domains via crt.sh")
                try:
                    from services.cert_transparency import search_brand_certificates

                    crtsh_result = search_brand_certificates(
                        brand=brand_name,
                        legitimate_domains=legit_domains,
                        watchlist_domains=watchlist_domains,
                        days_back=90,
                    )

                    if crtsh_result.get("success"):
                        watchlist_count = 0
                        for imp in crtsh_result.get("domains", []):
                            imp_domain = imp.get("domain", "").lower()
                            if imp_domain and imp_domain not in existing_domains:
                                processed_domains.append({
                                    'domain': imp_domain,
                                    'fuzzer': 'ct-brand-impersonation',
                                    'dns_a': [],
                                    'dns_aaaa': [],
                                    'dns_mx': [],
                                    'dns_ns': [],
                                    'geoip': '',
                                    'registered': True,
                                    'censys_issuer': imp.get('issuer', ''),
                                    'crt_sh_link': imp.get('crt_sh_link', ''),
                                })
                                existing_domains.add(imp_domain)
                                watchlist_count += 1
                                censys_count += 1

                        if watchlist_count > 0:
                            logger.info(f"Added {watchlist_count} watchlist domains with SSL certs")

                except Exception as e:
                    logger.warning(f"Watchlist check error: {e}")

        logger.info(f"Found {len(processed_domains)} total lookalike domains")

        result = {
            'success': True,
            'original_domain': domain,
            'total_count': len(processed_domains),
            'registered_count': sum(1 for d in processed_domains if d['registered']),
            'censys_impersonation_count': censys_count,
            'domains': processed_domains
        }

        if censys_error:
            result['censys_error'] = censys_error

        return result

    except subprocess.TimeoutExpired:
        logger.error(f"dnstwist timed out after {timeout_seconds}s")
        timeout_msg = f'Operation timed out (exceeded {timeout_seconds//60} minutes). Try scanning without DNS resolution for faster results.'
        return {
            'success': False,
            'error': timeout_msg,
            'domains': []
        }
    except FileNotFoundError:
        logger.error(f"dnstwist not found at {DNSTWIST_PATH}")
        return {
            'success': False,
            'error': f'dnstwist not found at {DNSTWIST_PATH}. Install with: pip install dnstwist',
            'domains': []
        }
    except Exception as e:
        logger.error(f"Error generating lookalike domains: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'domains': []
        }


def get_domain_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for a domain.

    Args:
        domain: The domain to look up

    Returns:
        Dictionary containing WHOIS information
    """
    try:
        logger.info(f"Getting WHOIS info for: {domain}")
        w = whois.whois(domain)

        # Handle different date formats
        def format_date(date_val):
            if isinstance(date_val, list):
                date_val = date_val[0] if date_val else None
            if isinstance(date_val, datetime):
                return date_val.strftime('%Y-%m-%d')
            return str(date_val) if date_val else 'N/A'

        return {
            'success': True,
            'domain': domain,
            'registrar': w.registrar or 'N/A',
            'creation_date': format_date(w.creation_date),
            'expiration_date': format_date(w.expiration_date),
            'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
        }

    except Exception as e:
        logger.error(f"Error getting WHOIS info for {domain}: {e}")
        return {
            'success': False,
            'domain': domain,
            'error': str(e)
        }


def check_dnstwist_available() -> Dict[str, Any]:
    """Check if dnstwist is available and get version info.

    Returns:
        Dictionary with availability status and version
    """
    try:
        result = subprocess.run(
            [str(DNSTWIST_PATH), '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        version = result.stdout.strip() if result.returncode == 0 else 'unknown'

        return {
            'available': result.returncode == 0,
            'version': version,
            'path': str(DNSTWIST_PATH)
        }
    except FileNotFoundError:
        return {
            'available': False,
            'error': f'dnstwist not found at {DNSTWIST_PATH}'
        }
    except Exception as e:
        return {
            'available': False,
            'error': str(e)
        }


def enrich_with_recorded_future(domains: List[Dict[str, Any]], batch_size: int = 100) -> List[Dict[str, Any]]:
    """Enrich lookalike domains with RecordedFuture threat intelligence.

    Adds RF risk scores and evidence rules to each domain.

    Args:
        domains: List of domain dictionaries (must have 'domain' key)
        batch_size: Number of domains per API call (max 1000)

    Returns:
        Same list with 'rf_risk_score', 'rf_risk_level', and 'rf_rules' added
    """
    try:
        from services.recorded_future import RecordedFutureClient
    except ImportError:
        logger.warning("RecordedFuture client not available")
        return domains

    client = RecordedFutureClient()
    if not client.is_configured():
        logger.warning("RecordedFuture API key not configured, skipping enrichment")
        return domains

    # Filter to registered domains only (no point enriching unregistered)
    registered = [d for d in domains if d.get('registered')]
    if not registered:
        logger.info("No registered domains to enrich")
        return domains

    domain_names = [d['domain'] for d in registered]
    logger.info(f"Enriching {len(domain_names)} domains with RecordedFuture")

    # Process in batches
    enrichment_map = {}
    for i in range(0, len(domain_names), batch_size):
        batch = domain_names[i:i + batch_size]
        logger.debug(f"Processing RF batch {i // batch_size + 1}: {len(batch)} domains")

        result = client.enrich_domains(batch)

        if "error" in result:
            logger.warning(f"RF enrichment error: {result['error']}")
            continue

        # Extract results into lookup map
        enriched = client.extract_enrichment_results(result)
        for item in enriched:
            enrichment_map[item['value']] = {
                'rf_risk_score': item.get('risk_score', 0),
                'rf_risk_level': item.get('risk_level', 'Unknown'),
                'rf_rules': item.get('rules', []),
                'rf_evidence_count': item.get('evidence_count', 0),
            }

    # Apply enrichment to domains
    for domain_data in domains:
        domain_name = domain_data.get('domain', '').lower()
        if domain_name in enrichment_map:
            domain_data.update(enrichment_map[domain_name])
        else:
            # Not enriched (unregistered or not in results)
            domain_data['rf_risk_score'] = None
            domain_data['rf_risk_level'] = None
            domain_data['rf_rules'] = []

    # Log summary
    enriched_count = len(enrichment_map)
    high_risk = sum(1 for d in domains if d.get('rf_risk_score', 0) and d['rf_risk_score'] >= 65)
    logger.info(f"RF enrichment complete: {enriched_count} domains enriched, {high_risk} high-risk")

    return domains


def enrich_ips_with_recorded_future(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Enrich IP addresses with RecordedFuture threat intelligence.

    Args:
        ips: List of IP addresses to enrich

    Returns:
        Dictionary mapping IP -> enrichment data
    """
    try:
        from services.recorded_future import RecordedFutureClient
    except ImportError:
        logger.warning("RecordedFuture client not available")
        return {}

    client = RecordedFutureClient()
    if not client.is_configured():
        logger.warning("RecordedFuture API key not configured")
        return {}

    if not ips:
        return {}

    # Dedupe IPs
    unique_ips = list(set(ip.strip() for ip in ips if ip))
    logger.info(f"Enriching {len(unique_ips)} IPs with RecordedFuture")

    result = client.enrich_ips(unique_ips)

    if "error" in result:
        logger.warning(f"RF IP enrichment error: {result['error']}")
        return {}

    enrichment_map = {}
    enriched = client.extract_enrichment_results(result)
    for item in enriched:
        enrichment_map[item['value']] = {
            'rf_risk_score': item.get('risk_score', 0),
            'rf_risk_level': item.get('risk_level', 'Unknown'),
            'rf_rules': item.get('rules', []),
        }

    return enrichment_map
