import json
import os
import time
import logging
import traceback
from typing import Optional, Dict
import socket

import requests
import schedule
import whois
from dotenv import load_dotenv

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