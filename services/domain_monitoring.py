import json
import os
import time
import logging
import traceback
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, parse_qs
import socket

import requests
import schedule
import whois
from dotenv import load_dotenv

# Known domain parking service domains
PARKING_DOMAINS = {
    # GoDaddy network
    'searchhounds.com',
    'godaddy.com',
    'afternic.com',
    'parkingcrew.net',
    # Sedo
    'sedo.com',
    'sedoparking.com',
    # Other major parking services
    'dan.com',
    'bodis.com',
    'above.com',
    'hugedomains.com',
    'domainmarket.com',
    'uniregistry.com',
    'porkbun.com',
    'namecheap.com',
    'dynadot.com',
    'epik.com',
    'squadhelp.com',
    'brandbucket.com',
    'undeveloped.com',
    'buydomains.com',
    'domainagents.com',
    'parklogic.com',
    'domainnamesales.com',
}

# URL parameters commonly used by parking services to track the original domain
PARKING_URL_PARAMS = {'domain', 'd', 'siteid', 'site_id', 'ref', 'source'}

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('domain_status.log'),
        logging.StreamHandler()
    ]
)

def check_domain_connectivity(domain):
    """Check if the domain can be resolved"""
    try:
        # Remove protocol if present
        clean_domain = domain.replace('https://', '').replace('http://', '')

        # Try to resolve domain
        socket.gethostbyname(clean_domain)
        logging.info(f"Domain {clean_domain} is resolvable")
        return True
    except socket.gaierror:
        logging.error(f"Cannot resolve domain: {clean_domain}")
        return False

def check_parking_status(domain: str, timeout: int = 10) -> Dict:
    """
    Check if a domain is parked by following redirects and analyzing the final destination.

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
    url = f'https://{clean_domain}'

    try:
        # Follow redirects and capture the chain
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
        redirected_to_different_domain = final_domain != clean_domain and final_domain != f'www.{clean_domain}'

        # Check 2: Is the final domain a known parking service?
        for parking_domain in PARKING_DOMAINS:
            if final_domain == parking_domain or final_domain.endswith(f'.{parking_domain}'):
                result['is_parked'] = True
                result['parking_provider'] = parking_domain
                result['indicators'].append(f'Redirected to known parking domain: {parking_domain}')
                break

        # Check 3: Look for parking-related URL parameters
        query_params = parse_qs(parsed_final.query.lower())
        for param in PARKING_URL_PARAMS:
            if param in query_params:
                param_value = query_params[param][0] if query_params[param] else ''
                # Check if the parameter references our original domain
                if clean_domain.lower() in param_value.lower():
                    result['indicators'].append(f'URL parameter "{param}" references original domain')
                    if not result['is_parked'] and redirected_to_different_domain:
                        result['is_parked'] = True

        # Determine confidence level
        if result['is_parked']:
            if result['parking_provider'] and len(result['indicators']) > 1:
                result['confidence'] = 'high'
            elif result['parking_provider'] or len(result['indicators']) > 0:
                result['confidence'] = 'medium'

        logging.info(f"Parking check for {domain}: is_parked={result['is_parked']}, "
                    f"provider={result['parking_provider']}, confidence={result['confidence']}")

    except requests.exceptions.SSLError:
        # Try HTTP fallback
        try:
            response = requests.get(
                f'http://{clean_domain}',
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            # Recursively check with the HTTP response
            result['final_url'] = response.url
            result['redirect_chain'] = [r.url for r in response.history] + [response.url]
            # Re-run parking checks on HTTP response
            parsed_final = urlparse(response.url)
            final_domain = parsed_final.netloc.lower()
            if final_domain.startswith('www.'):
                final_domain = final_domain[4:]
            for parking_domain in PARKING_DOMAINS:
                if final_domain == parking_domain or final_domain.endswith(f'.{parking_domain}'):
                    result['is_parked'] = True
                    result['parking_provider'] = parking_domain
                    result['indicators'].append(f'Redirected to known parking domain: {parking_domain}')
                    result['confidence'] = 'medium'
                    break
        except Exception as e:
            logging.warning(f"HTTP fallback also failed for {domain}: {e}")
            result['indicators'].append(f'Connection failed: {e}')

    except requests.exceptions.Timeout:
        logging.warning(f"Timeout checking parking status for {domain}")
        result['indicators'].append('Connection timeout')
    except requests.exceptions.ConnectionError as e:
        logging.warning(f"Connection error checking parking status for {domain}: {e}")
        result['indicators'].append(f'Connection error: {e}')
    except Exception as e:
        logging.error(f"Error checking parking status for {domain}: {e}")
        result['indicators'].append(f'Error: {e}')

    return result


def advanced_whois_query(domain):
    """More robust WHOIS query with multiple fallback mechanisms"""
    try:
        # Try standard whois query
        result = whois.query(domain)
        if result:
            logging.info(f"WHOIS query successful for {domain}")
            return result
    except Exception as e:
        logging.error(f"Standard WHOIS query failed: {e}")

    # Additional fallback mechanisms could be added here
    # For example, using alternative WHOIS libraries or services
    logging.warning(f"All WHOIS query methods failed for {domain}")
    return None

def main():
    domain = os.getenv('MONITOR_DOMAIN', '')
    if not domain:
        logging.error("No domain specified in environment variables")
        return

    # First, check domain connectivity
    if not check_domain_connectivity(domain):
        logging.critical(f"Domain {domain} is not resolvable")
        return

    # Check if domain is parked
    parking_result = check_parking_status(domain)
    if parking_result['is_parked']:
        logging.info(f"Domain {domain} appears to be PARKED")
        logging.info(f"  Parking provider: {parking_result['parking_provider']}")
        logging.info(f"  Confidence: {parking_result['confidence']}")
        logging.info(f"  Indicators: {parking_result['indicators']}")
        logging.info(f"  Final URL: {parking_result['final_url']}")
        if parking_result['redirect_chain']:
            logging.info(f"  Redirect chain: {' -> '.join(parking_result['redirect_chain'])}")
    else:
        logging.info(f"Domain {domain} does not appear to be parked")
        if parking_result['final_url']:
            logging.info(f"  Final URL: {parking_result['final_url']}")

    # Then attempt advanced WHOIS query
    whois_result = advanced_whois_query(domain)

    if whois_result:
        # Process and log WHOIS information
        logging.info(f"WHOIS Details for {domain}:")
        logging.info(f"Status: {getattr(whois_result, 'status', 'Unknown')}")
        logging.info(f"Expiration Date: {getattr(whois_result, 'expiration_date', 'Unknown')}")
    else:
        logging.error(f"Could not retrieve WHOIS information for {domain}")

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    main()