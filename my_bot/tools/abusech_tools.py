"""
abuse.ch Tools Module

Provides abuse.ch API integration for malware and botnet threat intelligence.
Completely FREE - no API key required.

Sources:
- URLhaus: Malicious URLs used for malware distribution
- ThreatFox: IOCs (domains, IPs, hashes) associated with malware
- Feodo Tracker: Botnet C2 servers (Emotet, Dridex, TrickBot, QakBot)

Useful for:
- Checking if a domain/IP is associated with malware distribution
- Identifying botnet command & control (C2) servers
- Looking up malware IOCs
- Complementing VirusTotal with specialized malware intelligence
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.abusech import AbuseCHClient
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized abuse.ch client (no API key needed - free!)
_abusech_client: Optional[AbuseCHClient] = None


def _get_abusech_client() -> Optional[AbuseCHClient]:
    """Get abuse.ch client (lazy initialization)."""
    global _abusech_client
    if _abusech_client is None:
        try:
            _abusech_client = AbuseCHClient()
        except Exception as e:
            logger.error(f"Failed to initialize abuse.ch client: {e}")
    return _abusech_client


def _format_domain_result(data: dict) -> str:
    """Format domain check result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    domain = data.get("domain", "Unknown")
    is_malicious = data.get("is_malicious", False)
    threat_types = data.get("threat_types", [])
    sources = data.get("sources", {})

    if not is_malicious:
        return (
            f"## abuse.ch Domain Check\n"
            f"**Domain:** {domain}\n"
            f"**Status:** ✅ Clean\n\n"
            f"Not found in URLhaus or ThreatFox malware databases."
        )

    result = [
        f"## abuse.ch Domain Check",
        f"**Domain:** {domain}",
        f"**Status:** 🔴 MALICIOUS",
        f"**Threat Types:** {', '.join(threat_types) if threat_types else 'Unknown'}",
    ]

    # URLhaus results
    urlhaus = sources.get("urlhaus", {})
    if urlhaus.get("found"):
        result.append("")
        result.append("### 🦠 URLhaus (Malware Distribution)")
        result.append(f"**Malicious URLs:** {urlhaus.get('url_count', 0)}")

        blacklists = urlhaus.get("blacklists", {})
        if blacklists:
            bl_list = [f"{k}: {v}" for k, v in blacklists.items() if v]
            if bl_list:
                result.append(f"**Blacklists:** {', '.join(bl_list)}")

        urls = urlhaus.get("urls", [])
        if urls:
            result.append("")
            result.append("**Recent Malicious URLs:**")
            for url_info in urls[:5]:
                url = url_info.get("url", "")[:60]
                threat = url_info.get("threat", "Unknown")
                status = url_info.get("url_status", "Unknown")
                tags = ", ".join(url_info.get("tags", [])[:3])
                result.append(f"- `{url}...`")
                result.append(f"  Threat: {threat} | Status: {status}")
                if tags:
                    result.append(f"  Tags: {tags}")

        result.append(f"\n🔗 [View on URLhaus]({urlhaus.get('urlhaus_link', '')})")

    # ThreatFox results
    threatfox = sources.get("threatfox", {})
    if threatfox.get("found"):
        result.append("")
        result.append("### 🦊 ThreatFox (Malware IOCs)")
        result.append(f"**IOC Count:** {threatfox.get('ioc_count', 0)}")

        iocs = threatfox.get("iocs", [])
        if iocs:
            result.append("")
            result.append("**Associated Malware:**")
            for ioc in iocs[:5]:
                malware = ioc.get("malware_printable") or ioc.get("malware", "Unknown")
                threat_type = ioc.get("threat_type", "Unknown")
                confidence = ioc.get("confidence_level", "Unknown")
                first_seen = ioc.get("first_seen", "")[:10] if ioc.get("first_seen") else "Unknown"
                result.append(f"- **{malware}** ({threat_type})")
                result.append(f"  Confidence: {confidence}% | First Seen: {first_seen}")

        result.append(f"\n🔗 [View on ThreatFox]({threatfox.get('threatfox_link', '')})")

    # Recommendations
    result.append("")
    result.append("### ⚠️ Recommendations")
    result.append("1. **Block immediately** - Add to blocklist/firewall")
    result.append("2. **Check logs** - Search for historical connections to this domain")
    result.append("3. **Investigate hosts** - Identify any systems that communicated with it")

    return "\n".join(result)


def _format_ip_result(data: dict) -> str:
    """Format IP check result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    ip = data.get("ip", "Unknown")
    is_malicious = data.get("is_malicious", False)
    is_c2 = data.get("is_c2", False)
    threat_types = data.get("threat_types", [])
    sources = data.get("sources", {})

    if not is_malicious:
        return (
            f"## abuse.ch IP Check\n"
            f"**IP Address:** {ip}\n"
            f"**Status:** ✅ Clean\n\n"
            f"Not found in ThreatFox or Feodo Tracker databases."
        )

    # Determine severity
    if is_c2:
        status_emoji = "🔴"
        status_text = "BOTNET C2 SERVER"
    else:
        status_emoji = "🟠"
        status_text = "MALICIOUS"

    result = [
        f"## abuse.ch IP Check",
        f"**IP Address:** {ip}",
        f"**Status:** {status_emoji} {status_text}",
    ]

    if threat_types:
        result.append(f"**Threats:** {', '.join(threat_types)}")

    # Feodo Tracker results (C2 servers)
    feodo = sources.get("feodo", {})
    if feodo.get("is_c2"):
        result.append("")
        result.append("### 🤖 Feodo Tracker (Botnet C2)")
        result.append(f"**Malware Family:** {feodo.get('malware', 'Unknown')}")
        result.append(f"**Port:** {feodo.get('port', 'Unknown')}")
        result.append(f"**Status:** {feodo.get('status', 'Unknown')}")
        result.append(f"**First Seen:** {feodo.get('first_seen', 'Unknown')}")
        result.append(f"**Last Online:** {feodo.get('last_online', 'Unknown')}")
        result.append(f"\n🔗 [View on Feodo Tracker]({feodo.get('feodo_link', '')})")

    # ThreatFox results
    threatfox = sources.get("threatfox", {})
    if threatfox.get("found"):
        result.append("")
        result.append("### 🦊 ThreatFox (Malware IOCs)")
        result.append(f"**IOC Count:** {threatfox.get('ioc_count', 0)}")

        iocs = threatfox.get("iocs", [])
        if iocs:
            for ioc in iocs[:3]:
                malware = ioc.get("malware", "Unknown")
                threat_type = ioc.get("threat_type", "Unknown")
                confidence = ioc.get("confidence_level", "Unknown")
                result.append(f"- **{malware}** ({threat_type}) - {confidence}% confidence")

    # Recommendations
    result.append("")
    result.append("### ⚠️ Recommendations")
    if is_c2:
        result.append("1. **CRITICAL** - This is an active botnet C2 server")
        result.append("2. **Block immediately** at firewall/perimeter")
        result.append("3. **Hunt for infections** - Search for any internal connections to this IP")
        result.append("4. **Isolate compromised hosts** that communicated with this C2")
    else:
        result.append("1. **Block** - Add to blocklist")
        result.append("2. **Investigate** - Check for connections from internal hosts")

    return "\n".join(result)


@tool
@log_tool_call
def check_domain_abusech(domain: str) -> str:
    """Check if a domain is associated with malware distribution or malicious activity.

    Searches abuse.ch databases (URLhaus and ThreatFox) for malware-related IOCs.
    This is a FREE service with no API key required.

    Use this tool when:
    - Investigating a suspicious domain
    - Checking if a domain is used for malware distribution
    - Looking for malware family associations
    - Complementing VirusTotal results with malware-specific intelligence

    Args:
        domain: The domain to check (e.g., "malicious-site.com")
    """
    client = _get_abusech_client()
    if not client:
        return "Error: abuse.ch service is not available."

    try:
        # Clean up domain input
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        data = client.check_domain_all(domain)
        return _format_domain_result(data)
    except Exception as e:
        logger.error(f"abuse.ch domain check failed: {e}")
        return f"Error checking domain on abuse.ch: {str(e)}"


@tool
@log_tool_call
def check_ip_abusech(ip_address: str) -> str:
    """Check if an IP address is a known malware C2 server or malicious host.

    Searches abuse.ch databases (ThreatFox and Feodo Tracker) for:
    - Botnet command & control (C2) servers (Emotet, Dridex, TrickBot, QakBot, etc.)
    - Malware-associated IP addresses
    - Known malicious infrastructure

    This is a FREE service with no API key required.

    Use this tool when:
    - Investigating a suspicious IP address
    - Checking if an IP is a botnet C2 server
    - Looking for malware associations
    - Triaging potential infections

    Args:
        ip_address: The IP address to check (e.g., "192.168.1.1")
    """
    client = _get_abusech_client()
    if not client:
        return "Error: abuse.ch service is not available."

    try:
        data = client.check_ip_all(ip_address.strip())
        return _format_ip_result(data)
    except Exception as e:
        logger.error(f"abuse.ch IP check failed: {e}")
        return f"Error checking IP on abuse.ch: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover abuse.ch capabilities:
#
# - "Check if malicious-domain.com is in abuse.ch"
# - "Is 192.168.1.1 a botnet C2 server?"
# - "Check abuse.ch for this domain: example.com"
# - "Look up IP 10.0.0.1 on Feodo Tracker"
# - "Is this domain distributing malware: evil-site.net"
# - "Check URLhaus for suspicious-domain.com"
# - "Is this IP associated with Emotet or TrickBot?"
# =============================================================================
