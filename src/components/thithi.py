import logging

import requests
from bs4 import BeautifulSoup
from webexpythonsdk import WebexAPI

from my_config import get_config

logger = logging.getLogger(__name__)

# Load configuration
CONFIG = get_config()
DRIKPANCHANG_URL = 'https://www.drikpanchang.com/'
BACKUP_URL = 'https://www.prokerala.com/astrology/panchangam/'
REQUEST_TIMEOUT = 15  # Increased timeout for reliability


def setup_webex_api():
    """Initialize and return Webex API client."""
    try:
        return WebexAPI(CONFIG.webex_bot_access_token_hal9000)
    except Exception as e:
        logger.error(f"Failed to initialize Webex API: {e}")
        return None


def fetch_webpage(url):
    """Fetch webpage content with error handling."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
        }
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        response.raise_for_status()  # Raise exception for HTTP errors
        return response.content
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None


def get_panchang_info():
    """
    Extract thithi and paksha information from Drik Panchang website.
    Returns tuple of (thithi, paksha) or (None, None) if extraction fails.
    """
    # Try primary URL first
    html_content = fetch_webpage(DRIKPANCHANG_URL)
    if html_content:
        thithi, paksha = extract_from_drikpanchang(html_content)
        if thithi and paksha:
            return thithi, paksha

    # If primary URL fails, try backup URL
    logger.info("Primary site extraction failed, trying backup site")
    html_content = fetch_webpage(BACKUP_URL)
    if html_content:
        thithi, paksha = extract_from_prokerala(html_content)
        if thithi and paksha:
            return thithi, paksha

    logger.warning("Could not extract panchang information from any source")
    return None, None


def extract_from_drikpanchang(html_content):
    """Extract information from Drik Panchang."""
    try:
        soup = BeautifulSoup(html_content, "html.parser")

        # Method 1: Using class-based extraction
        panchang_values = soup.find_all("span", class_="dpDainikPanchangValue")
        if len(panchang_values) >= 8:
            thithi = panchang_values[2].get_text().strip()
            paksha = panchang_values[7].get_text().strip()
            logger.info(f"Successfully extracted - Thithi: {thithi}, Paksha: {paksha}")
            return thithi, paksha

        # Method 2: Backup extraction method
        logger.info("Primary extraction method failed, trying alternative method")
        paksha_info = get_alternative_panchang_info(soup)
        if paksha_info:
            parts = paksha_info.split(',')
            if len(parts) >= 2:
                paksha = parts[0].strip()
                thithi = parts[1].strip()
                return thithi, paksha

        return None, None
    except Exception as e:
        logger.error(f"Error parsing DrikPanchang HTML: {e}")
        return None, None


def extract_from_prokerala(html_content):
    """Extract panchang information from Prokerala website."""
    try:
        soup = BeautifulSoup(html_content, "html.parser")

        # Find the thithi and paksha information
        thithi_element = soup.find('dt', string=lambda s: s and 'Tithi' in s)
        paksha_element = soup.find('dt', string=lambda s: s and 'Paksha' in s)

        thithi = None
        paksha = None

        if thithi_element and thithi_element.find_next('dd'):
            thithi = thithi_element.find_next('dd').get_text().strip()
            logger.info(f"Found thithi from Prokerala: {thithi}")

        if paksha_element and paksha_element.find_next('dd'):
            paksha = paksha_element.find_next('dd').get_text().strip()
            logger.info(f"Found paksha from Prokerala: {paksha}")

        if thithi and paksha:
            return thithi, paksha

        return None, None
    except Exception as e:
        logger.error(f"Error extracting from Prokerala: {e}")
        return None, None


def get_alternative_panchang_info(soup):
    """Alternative method to extract panchang information."""
    try:
        # Try using CSS selector
        paksha_element = soup.select_one('div.dpPHeaderLeftWrapper > div > div:nth-child(2)')
        if paksha_element:
            return paksha_element.get_text().strip()

        # Try using header wrapper
        header_left_wrapper = soup.find("div", class_="dpPHeaderLeftWrapper")
        if header_left_wrapper:
            divs = header_left_wrapper.find_all("div", recursive=False)
            if len(divs) > 0:
                inner_divs = divs[0].find_all("div")
                if len(inner_divs) >= 2:
                    return inner_divs[1].get_text().strip()

        return None
    except Exception as e:
        logger.error(f"Error in alternative extraction method: {e}")
        return None


def broadcast_to_webex(message, webex_api=None):
    """Send message through Webex."""
    if not webex_api:
        webex_api = setup_webex_api()

    if not webex_api:
        logger.error("Could not initialize Webex API. Message not sent.")
        return False

    try:
        logger.info(f"Broadcasting message: {message}")
        webex_api.messages.create(
            toPersonEmail=CONFIG.my_email_address,
            text=message
        )
        logger.info("Message sent successfully via Webex")
        return True
    except Exception as e:
        logger.error(f"Failed to send Webex message: {e}")
        return False


def main():
    """Main function to fetch and broadcast thithi information."""
    try:
        logger.info("Starting panchang information service")

        # Initialize Webex API
        webex_api = setup_webex_api()
        if not webex_api:
            logger.error("Exiting: Failed to initialize Webex API")
            return

        # Get thithi and paksha
        thithi, paksha = get_panchang_info()

        if thithi and paksha:
            message = f'Thithi: {thithi}, {paksha}'
            broadcast_to_webex(message, webex_api)
        else:
            message = "Could not retrieve thithi and paksha information"
            logger.warning(message)

    except Exception as e:
        logger.error(f"Error in main function: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Configure logging when run as main module
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    main()
