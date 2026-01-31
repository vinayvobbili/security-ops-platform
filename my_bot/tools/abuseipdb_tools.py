"""
AbuseIPDB Tools Module

Provides AbuseIPDB API integration for IP reputation lookups.
Complements VirusTotal with community-reported abuse data (spam, hacking, DDoS, brute force).

Free tier: 1,000 checks per day.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.abuseipdb import AbuseIPDBClient, ABUSE_CATEGORIES
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized AbuseIPDB client
_abuseipdb_client: Optional[AbuseIPDBClient] = None


def _get_abuseipdb_client() -> Optional[AbuseIPDBClient]:
    """Get AbuseIPDB client (lazy initialization)."""
    global _abuseipdb_client
    if _abuseipdb_client is None:
        try:
            client = AbuseIPDBClient()
            if client.is_configured():
                _abuseipdb_client = client
            else:
                logger.warning("AbuseIPDB client not configured (missing API key)")
        except Exception as e:
            logger.error(f"Failed to initialize AbuseIPDB client: {e}")
    return _abuseipdb_client


def _get_category_names(category_ids: list) -> list[str]:
    """Convert category IDs to human-readable names."""
    return [ABUSE_CATEGORIES.get(c, f"Unknown ({c})") for c in category_ids]


def _get_threat_level(abuse_score: int) -> str:
    """Determine threat level based on abuse confidence score."""
    if abuse_score >= 75:
        return "🔴 HIGH RISK"
    elif abuse_score >= 50:
        return "🟠 MEDIUM RISK"
    elif abuse_score >= 25:
        return "🟡 LOW RISK"
    elif abuse_score > 0:
        return "🟢 MINIMAL RISK"
    else:
        return "✅ CLEAN"


def _format_ip_result(data: dict) -> str:
    """Format IP lookup result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    ip = data.get("ip", "Unknown")
    abuse_score = data.get("abuse_confidence_score", 0)
    threat_level = _get_threat_level(abuse_score)

    result = [
        f"## AbuseIPDB IP Analysis",
        f"**IP Address:** {ip}",
        f"**Threat Level:** {threat_level}",
        f"**Abuse Confidence Score:** {abuse_score}%",
        "",
        f"**Country:** {data.get('country_code', 'Unknown')}",
        f"**ISP:** {data.get('isp', 'Unknown')}",
        f"**Domain:** {data.get('domain', 'N/A')}",
        f"**Usage Type:** {data.get('usage_type', 'Unknown')}",
        "",
        f"**Total Reports:** {data.get('total_reports', 0)}",
        f"**Distinct Reporters:** {data.get('num_distinct_users', 0)}",
    ]

    if data.get("last_reported_at"):
        result.append(f"**Last Reported:** {data['last_reported_at']}")

    if data.get("is_whitelisted"):
        result.append(f"**Whitelisted:** Yes ✅")

    # Add recent reports summary
    reports = data.get("reports", [])
    if reports:
        result.append("")
        result.append("### Recent Reports")
        for i, report in enumerate(reports[:5], 1):
            categories = _get_category_names(report.get("categories", []))
            cat_str = ", ".join(categories) if categories else "Unknown"
            reported_at = report.get("reported_at", "Unknown")[:10] if report.get("reported_at") else "Unknown"
            comment = report.get("comment", "")

            result.append(f"{i}. **{cat_str}** ({reported_at})")
            if comment:
                # Truncate long comments
                comment_preview = comment[:100] + "..." if len(comment) > 100 else comment
                result.append(f"   _{comment_preview}_")

    result.append("")
    result.append(f"🔗 [View on AbuseIPDB]({data.get('abuseipdb_link', f'https://www.abuseipdb.com/check/{ip}')})")

    return "\n".join(result)


def _format_domain_result(data: dict) -> str:
    """Format domain lookup result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    domain = data.get("domain", "Unknown")
    max_score = data.get("max_abuse_score", 0)
    threat_level = _get_threat_level(max_score)
    ips_checked = data.get("ips_checked", 0)
    malicious_ips = data.get("malicious_ips", [])
    clean_ips = data.get("clean_ips", [])

    result = [
        f"## AbuseIPDB Domain Analysis",
        f"**Domain:** {domain}",
        f"**Threat Level:** {threat_level}",
        f"**Max Abuse Score:** {max_score}%",
        "",
        f"**IPs Checked:** {ips_checked}",
        f"**Malicious IPs:** {len(malicious_ips)}",
        f"**Clean IPs:** {len(clean_ips)}",
    ]

    # List malicious IPs
    if malicious_ips:
        result.append("")
        result.append("### Malicious IPs Detected")
        for ip_info in malicious_ips:
            ip = ip_info.get("ip", "Unknown")
            score = ip_info.get("abuse_score", 0)
            reports = ip_info.get("total_reports", 0)
            isp = ip_info.get("isp", "Unknown")
            country = ip_info.get("country", "Unknown")
            result.append(f"- **{ip}** - Score: {score}%, Reports: {reports}, ISP: {isp}, Country: {country}")

    # List clean IPs
    if clean_ips:
        result.append("")
        result.append(f"**Clean IPs:** {', '.join(clean_ips)}")

    return "\n".join(result)


@tool
@log_tool_call
def lookup_ip_abuseipdb(ip_address: str) -> str:
    """Look up an IP address in AbuseIPDB for abuse reports and reputation.

    Use this tool when a user asks about IP reputation, abuse reports, or whether an IP
    has been reported for malicious activity. AbuseIPDB provides community-reported data
    on spam, hacking attempts, DDoS attacks, brute force attacks, and other abuse.

    This complements VirusTotal by providing different threat intelligence sources.
    AbuseIPDB is especially useful for:
    - Checking if an IP has been reported for attacks
    - Seeing what types of abuse have been reported (SSH brute force, port scans, etc.)
    - Getting ISP and usage type information
    - Viewing recent abuse report comments

    Args:
        ip_address: The IP address to look up (e.g., "192.168.1.1" or "8.8.8.8")
    """
    client = _get_abuseipdb_client()
    if not client:
        return "Error: AbuseIPDB service is not available."

    try:
        data = client.check_ip(ip_address.strip())
        return _format_ip_result(data)
    except Exception as e:
        logger.error(f"AbuseIPDB IP lookup failed: {e}")
        return f"Error looking up IP in AbuseIPDB: {str(e)}"


@tool
@log_tool_call
def lookup_domain_abuseipdb(domain: str) -> str:
    """Look up a domain in AbuseIPDB by checking its resolved IP addresses.

    Use this tool when a user wants to check if a domain's infrastructure has been
    reported for abuse. This resolves the domain to IP addresses and checks each one
    against AbuseIPDB's database.

    Useful for:
    - Checking if a domain is hosted on known malicious infrastructure
    - Identifying if any of the domain's IPs have abuse reports
    - Getting aggregate abuse scores for a domain's hosting

    Note: This uses multiple API calls (one per IP), so use sparingly to conserve quota.

    Args:
        domain: The domain to look up (e.g., "example.com")
    """
    client = _get_abuseipdb_client()
    if not client:
        return "Error: AbuseIPDB service is not available."

    try:
        # Remove protocol if present
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        data = client.check_domain(domain)
        return _format_domain_result(data)
    except Exception as e:
        logger.error(f"AbuseIPDB domain lookup failed: {e}")
        return f"Error looking up domain in AbuseIPDB: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover AbuseIPDB capabilities:
#
# - "Check IP 192.168.1.1 on AbuseIPDB"
# - "Has 10.0.0.1 been reported for abuse?"
# - "Look up IP abuse reports for 8.8.8.8"
# - "Check if this IP has been reported: 1.2.3.4"
# - "What abuse reports exist for 203.0.113.1?"
# - "Check AbuseIPDB for this domain: example.com"
# =============================================================================
