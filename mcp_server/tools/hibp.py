"""Have I Been Pwned (HIBP) breach checking tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.hibp import HIBPClient
        _client = HIBPClient()
    return _client


@mcp.tool()
def hibp_check_email(email: str) -> dict:
    """Check if an email address appears in known data breaches.

    Queries the HaveIBeenPwned database for the email address and returns
    all breaches it appears in, including breach names, dates, and the
    types of data exposed (passwords, credit cards, etc.).

    Args:
        email: Email address to check (e.g. '<redacted-email>')
    """
    client = _get_client()
    return client.check_email(email)


@mcp.tool()
def hibp_check_domain(domain: str) -> dict:
    """Check if a domain's email addresses appear in known data breaches.

    Checks common email patterns for the domain (admin@, info@, security@,
    etc.) against HIBP. Useful for assessing organizational credential
    exposure without checking every individual user.

    Args:
        domain: Domain to check (e.g. 'company.com')
    """
    client = _get_client()
    return client.check_domain_emails(domain)
