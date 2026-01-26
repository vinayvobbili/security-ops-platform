"""
HaveIBeenPwned (HIBP) Tools Module

Provides HIBP API integration for checking breached credentials.
Returns breach information for email addresses and domains.

Useful for:
- Checking if user credentials may have been exposed
- Identifying which breaches affected an email address
- Scanning a domain's common email addresses for breaches
- Getting details about specific data breaches

API Documentation: https://haveibeenpwned.com/API/v3
Note: Requires paid API key. Rate limited to 10 requests/minute.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.hibp import HIBPClient
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Initialize HIBP client once
_hibp_client: Optional[HIBPClient] = None

try:
    logger.info("Initializing HIBP client...")
    _hibp_client = HIBPClient()

    if _hibp_client.is_configured():
        logger.info("HIBP client initialized successfully.")
    else:
        logger.warning("HIBP client not configured (missing API key). Tools will be disabled.")
        _hibp_client = None

except Exception as e:
    logger.error(f"Failed to initialize HIBP client: {e}")
    _hibp_client = None


def _get_severity_emoji(breach_count: int) -> str:
    """Get severity emoji based on number of breaches."""
    if breach_count >= 10:
        return "🔴"
    elif breach_count >= 5:
        return "🟠"
    elif breach_count >= 1:
        return "🟡"
    return "✅"


def _format_email_result(data: dict) -> str:
    """Format email breach check result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    email = data.get("email", "Unknown")
    breached = data.get("breached", False)
    breach_count = data.get("breach_count", 0)
    breaches = data.get("breaches", [])

    if not breached:
        return (
            f"## HIBP Email Check\n"
            f"**Email:** {email}\n"
            f"**Status:** ✅ No breaches found\n\n"
            f"This email address was not found in any known data breaches."
        )

    severity_emoji = _get_severity_emoji(breach_count)

    result = [
        f"## HIBP Email Check",
        f"**Email:** {email}",
        f"**Status:** {severity_emoji} Found in {breach_count} breach(es)",
        "",
        "### Breaches",
    ]

    # Format breach list
    for breach in breaches[:15]:  # Limit to 15 breaches
        if isinstance(breach, dict):
            name = breach.get("Name", "Unknown")
            domain = breach.get("Domain", "")
            date = breach.get("BreachDate", "Unknown")
            pwn_count = breach.get("PwnCount", 0)
            data_classes = breach.get("DataClasses", [])

            result.append(f"**{name}**" + (f" ({domain})" if domain else ""))
            result.append(f"- Date: {date}")
            if pwn_count:
                result.append(f"- Affected accounts: {pwn_count:,}")
            if data_classes:
                result.append(f"- Exposed data: {', '.join(data_classes[:5])}")
            result.append("")
        else:
            # Truncated response - just breach name
            result.append(f"- {breach}")

    if len(breaches) > 15:
        result.append(f"_...and {len(breaches) - 15} more breaches_")

    result.append("")
    result.append("### Recommendations")
    result.append("1. Change passwords for accounts using this email")
    result.append("2. Enable multi-factor authentication where possible")
    result.append("3. Check if the same password was reused elsewhere")
    result.append("")
    result.append(f"🔗 [View on HIBP](https://haveibeenpwned.com/account/{email})")

    return "\n".join(result)


def _format_domain_result(data: dict) -> str:
    """Format domain breach check result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    domain = data.get("domain", "Unknown")
    emails_checked = data.get("emails_checked", 0)
    emails_breached = data.get("emails_breached", 0)
    total_breaches = data.get("total_breaches", 0)
    breached_emails = data.get("breached_emails", [])
    errors = data.get("errors", [])

    if emails_breached == 0:
        return (
            f"## HIBP Domain Check\n"
            f"**Domain:** {domain}\n"
            f"**Emails Checked:** {emails_checked}\n"
            f"**Status:** ✅ No breached emails found\n\n"
            f"None of the common email patterns checked were found in known breaches."
        )

    severity_emoji = _get_severity_emoji(emails_breached)

    result = [
        f"## HIBP Domain Check",
        f"**Domain:** {domain}",
        f"**Emails Checked:** {emails_checked}",
        f"**Status:** {severity_emoji} {emails_breached} email(s) found in breaches",
        f"**Total Breach Occurrences:** {total_breaches}",
        "",
        "### Breached Emails",
    ]

    for entry in breached_emails[:10]:  # Limit to 10 emails
        email = entry.get("email", "Unknown")
        count = entry.get("breach_count", 0)
        breaches = entry.get("breaches", [])

        result.append(f"**{email}** - {count} breach(es)")

        # List breach names
        breach_names = []
        for b in breaches[:5]:
            if isinstance(b, dict):
                breach_names.append(b.get("Name", "Unknown"))
            else:
                breach_names.append(str(b))

        if breach_names:
            result.append(f"  Breaches: {', '.join(breach_names)}")
        result.append("")

    if len(breached_emails) > 10:
        result.append(f"_...and {len(breached_emails) - 10} more breached emails_")

    # Note any errors
    if errors:
        result.append("")
        result.append(f"⚠️ {len(errors)} email(s) could not be checked (rate limit or errors)")

    result.append("")
    result.append("### Recommendations")
    result.append("1. Reset passwords for all breached email accounts")
    result.append("2. Audit these accounts for unauthorized access")
    result.append("3. Consider credential monitoring for the domain")

    return "\n".join(result)


def _format_breach_info(data: dict) -> str:
    """Format breach details for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    breach = data.get("breach", {})
    if not breach:
        return "No breach information found."

    name = breach.get("Name", "Unknown")
    title = breach.get("Title", name)
    domain = breach.get("Domain", "Unknown")
    breach_date = breach.get("BreachDate", "Unknown")
    added_date = breach.get("AddedDate", "Unknown")[:10] if breach.get("AddedDate") else "Unknown"
    pwn_count = breach.get("PwnCount", 0)
    description = breach.get("Description", "No description available.")
    data_classes = breach.get("DataClasses", [])
    is_verified = breach.get("IsVerified", False)
    is_sensitive = breach.get("IsSensitive", False)

    result = [
        f"## Breach Details: {title}",
        f"**Name:** {name}",
        f"**Domain:** {domain}",
        f"**Breach Date:** {breach_date}",
        f"**Added to HIBP:** {added_date}",
        f"**Affected Accounts:** {pwn_count:,}",
        f"**Verified:** {'Yes ✓' if is_verified else 'No'}",
    ]

    if is_sensitive:
        result.append("**⚠️ Sensitive Breach:** Yes (may contain adult content)")

    result.append("")
    result.append("### Exposed Data Types")
    if data_classes:
        for dc in data_classes:
            result.append(f"- {dc}")
    else:
        result.append("- Unknown")

    result.append("")
    result.append("### Description")
    # Clean up HTML in description
    clean_desc = description.replace("<p>", "").replace("</p>", "\n").replace("<a href=", "[").replace("</a>", "]")
    result.append(clean_desc[:500] + ("..." if len(description) > 500 else ""))

    result.append("")
    result.append(f"🔗 [View on HIBP](https://haveibeenpwned.com/PwnedWebsites#{name})")

    return "\n".join(result)


@tool
@log_tool_call
def check_email_hibp(email: str) -> str:
    """Check if an email address has been pwned or involved in known data breaches.

    Use this tool when a user asks "have I been pwned" (or misspells it as "pawned"),
    wants to know if an email address has been pwned, compromised, or appears in any
    data breaches. Returns a list of breaches the email was found in.

    This is useful for:
    - "Have I been pwned?" checks (including "pawned" misspelling)
    - Checking if user credentials may have been exposed or pwned
    - Identifying which specific breaches affected an account
    - Assessing credential exposure risk for a user
    - Incident response when investigating compromised accounts

    Note: Rate limited to 10 requests/minute. Use conservatively.

    Args:
        email: The email address to check (e.g., "user@example.com")
    """
    if not _hibp_client:
        return "Error: HIBP service is not configured. Missing API key."

    try:
        # Get full breach details (not truncated)
        data = _hibp_client.check_email(email.strip(), truncate_response=False)
        return _format_email_result(data)
    except Exception as e:
        logger.error(f"HIBP email check failed: {e}")
        return f"Error checking email in HIBP: {str(e)}"


@tool
@log_tool_call
def check_domain_hibp(domain: str) -> str:
    """Check common email addresses for a domain against known data breaches.

    Use this tool when investigating credential exposure for an organization.
    Checks common email patterns (admin@, info@, support@, etc.) against HIBP.

    This is useful for:
    - Assessing overall credential exposure for a domain
    - Finding which organizational emails have been breached
    - Security assessments and audits
    - Identifying high-risk accounts that need password resets

    Note: Checks up to 20 common email patterns. Rate limited, takes ~2 minutes.

    Args:
        domain: The domain to check (e.g., "example.com")
    """
    if not _hibp_client:
        return "Error: HIBP service is not configured. Missing API key."

    try:
        # Clean up domain input
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]
        if "@" in domain:
            domain = domain.split("@", 1)[1]

        data = _hibp_client.check_domain_emails(domain, max_checks=20)
        return _format_domain_result(data)
    except Exception as e:
        logger.error(f"HIBP domain check failed: {e}")
        return f"Error checking domain in HIBP: {str(e)}"


@tool
@log_tool_call
def get_breach_info_hibp(breach_name: str) -> str:
    """Get detailed information about a specific data breach.

    Use this tool when a user wants to know more about a particular breach,
    such as what data was exposed, how many accounts were affected, etc.

    Common breach names: Adobe, LinkedIn, Dropbox, MySpace, Canva, Apollo, etc.

    Args:
        breach_name: The name of the breach (e.g., "Adobe", "LinkedIn")
    """
    if not _hibp_client:
        return "Error: HIBP service is not configured. Missing API key."

    try:
        data = _hibp_client.get_breach_details(breach_name.strip())
        return _format_breach_info(data)
    except Exception as e:
        logger.error(f"HIBP breach info failed: {e}")
        return f"Error getting breach info from HIBP: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover HIBP capabilities:
#
# - "Have I been pwned? user@example.com"
# - "Have I been pawned? user@example.com" (common misspelling)
# - "Has user@example.com been pwned?"
# - "Check if my email was pwned: admin@company.com"
# - "Has user@example.com been breached?"
# - "Check example.com for breached emails"
# - "Is this email in any data breaches: admin@company.com"
# - "Tell me about the Adobe breach"
# - "What data was exposed in the LinkedIn breach?"
# - "Check HIBP for user@company.com"
# =============================================================================
