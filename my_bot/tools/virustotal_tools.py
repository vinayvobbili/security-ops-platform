"""
VirusTotal Tools Module

Provides VirusTotal API integration for threat intelligence lookups.
Supports IP addresses, domains, URLs, and file hashes.
"""

import logging
import re
from datetime import datetime
from typing import Optional

from langchain_core.tools import tool

from services.virustotal import VirusTotalClient
from src.utils.tool_decorator import log_tool_call

# Lazy-initialized VirusTotal client
_vt_client: Optional[VirusTotalClient] = None


def _get_vt_client() -> Optional[VirusTotalClient]:
    """Get VirusTotal client (lazy initialization)."""
    global _vt_client
    if _vt_client is None:
        try:
            client = VirusTotalClient()
            if client.is_configured():
                _vt_client = client
            else:
                logging.warning("VirusTotal client not configured (missing API key)")
        except Exception as e:
            logging.error(f"Failed to initialize VirusTotal client: {e}")
    return _vt_client


def _format_analysis_date(timestamp: int) -> str:
    """Format Unix timestamp to readable date in Eastern time."""
    if not timestamp:
        return "Unknown"
    try:
        from pytz import timezone
        eastern = timezone('US/Eastern')
        dt = datetime.fromtimestamp(timestamp, tz=eastern)
        return dt.strftime("%m/%d/%Y %I:%M %p ET")
    except (ValueError, OSError):
        return "Unknown"


def _format_ip_result(data: dict) -> str:
    """Format IP lookup result."""
    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        return "No data available for this IP"

    stats = attrs.get("last_analysis_stats", {})
    threat_level = VirusTotalClient.get_threat_level(stats)
    last_analysis = _format_analysis_date(attrs.get("last_analysis_date"))

    result = [
        f"## VirusTotal IP Analysis",
        f"**Threat Level:** {threat_level}",
        f"**Last Analyzed:** {last_analysis}",
        f"**Detection Stats:** {VirusTotalClient.format_analysis_stats(stats)}",
        "",
        f"**Country:** {attrs.get('country', 'Unknown')}",
        f"**AS Owner:** {attrs.get('as_owner', 'Unknown')}",
        f"**Network:** {attrs.get('network', 'Unknown')}",
    ]

    if "reputation" in attrs:
        result.append(f"**Reputation Score:** {attrs['reputation']}")

    return "\n".join(result)


def _format_domain_result(data: dict) -> str:
    """Format domain lookup result."""
    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        return "No data available for this domain"

    stats = attrs.get("last_analysis_stats", {})
    threat_level = VirusTotalClient.get_threat_level(stats)
    last_analysis = _format_analysis_date(attrs.get("last_analysis_date"))

    result = [
        f"## VirusTotal Domain Analysis",
        f"**Threat Level:** {threat_level}",
        f"**Last Analyzed:** {last_analysis}",
        f"**Detection Stats:** {VirusTotalClient.format_analysis_stats(stats)}",
        "",
        f"**Registrar:** {attrs.get('registrar', 'Unknown')}",
        f"**Creation Date:** {attrs.get('creation_date', 'Unknown')}",
    ]

    categories = attrs.get("categories", {})
    if categories:
        cat_list = list(categories.values())[:5]
        result.append(f"**Categories:** {', '.join(cat_list)}")

    if "reputation" in attrs:
        result.append(f"**Reputation Score:** {attrs['reputation']}")

    return "\n".join(result)


def _format_url_result(data: dict) -> str:
    """Format URL lookup result."""
    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        return "No data available for this URL"

    stats = attrs.get("last_analysis_stats", {})
    threat_level = VirusTotalClient.get_threat_level(stats)
    last_analysis = _format_analysis_date(attrs.get("last_analysis_date"))

    result = [
        f"## VirusTotal URL Analysis",
        f"**Threat Level:** {threat_level}",
        f"**Last Analyzed:** {last_analysis}",
        f"**Detection Stats:** {VirusTotalClient.format_analysis_stats(stats)}",
        "",
        f"**Final URL:** {attrs.get('last_final_url', attrs.get('url', 'Unknown'))}",
        f"**Title:** {attrs.get('title', 'N/A')}",
    ]

    categories = attrs.get("categories", {})
    if categories:
        cat_list = list(categories.values())[:5]
        result.append(f"**Categories:** {', '.join(cat_list)}")

    return "\n".join(result)


def _format_hash_result(data: dict) -> str:
    """Format file hash lookup result."""
    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        return "No data available for this file hash"

    stats = attrs.get("last_analysis_stats", {})
    threat_level = VirusTotalClient.get_threat_level(stats, is_file=True)
    last_analysis = _format_analysis_date(attrs.get("last_analysis_date"))

    # Get file name
    file_name = attrs.get("meaningful_name")
    if not file_name:
        names = attrs.get("names", [])
        file_name = names[0] if names else "Unknown"

    result = [
        f"## VirusTotal File Analysis",
        f"**Threat Level:** {threat_level}",
        f"**Last Analyzed:** {last_analysis}",
        f"**Detection Stats:** {VirusTotalClient.format_analysis_stats(stats)}",
        "",
        f"**File Name:** {file_name}",
        f"**File Type:** {attrs.get('type_description', 'Unknown')}",
        f"**File Size:** {attrs.get('size', 'Unknown')} bytes",
    ]

    if "sha256" in attrs:
        result.append(f"**SHA256:** {attrs['sha256']}")
    if "md5" in attrs:
        result.append(f"**MD5:** {attrs['md5']}")

    signature = attrs.get("signature_info", {})
    if signature:
        result.append(f"**Signed:** {signature.get('verified', 'Unknown')}")
        if signature.get("signers"):
            result.append(f"**Signer:** {signature['signers']}")

    popular_threat = attrs.get("popular_threat_classification", {})
    if popular_threat:
        label = popular_threat.get("suggested_threat_label", "")
        if label:
            result.append(f"**Threat Label:** {label}")

    return "\n".join(result)


@tool
@log_tool_call
def lookup_ip_virustotal(ip_address: str) -> str:
    """Look up an IP address in VirusTotal for threat intelligence.

    Use this tool when a user asks about the reputation or threat status of an IP address.
    Returns detection stats, country, network owner, and threat level assessment.

    Args:
        ip_address: The IP address to look up (e.g., "8.8.8.8")
    """
    client = _get_vt_client()
    if not client:
        return "Error: VirusTotal service is not available."

    data = client.lookup_ip(ip_address)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_ip_result(data)


@tool
@log_tool_call
def lookup_domain_virustotal(domain: str) -> str:
    """Look up a domain in VirusTotal for threat intelligence.

    Use this tool when a user asks about the reputation or threat status of a domain.
    Returns detection stats, registrar info, categories, and threat level assessment.

    Args:
        domain: The domain to look up (e.g., "example.com")
    """
    client = _get_vt_client()
    if not client:
        return "Error: VirusTotal service is not available."

    data = client.lookup_domain(domain)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_domain_result(data)


@tool
@log_tool_call
def lookup_url_virustotal(url: str) -> str:
    """Look up a URL in VirusTotal for threat intelligence.

    Use this tool when a user asks about the reputation or threat status of a full URL.
    Returns detection stats, final URL, categories, and threat level assessment.

    Args:
        url: The full URL to look up (e.g., "https://example.com/page")
    """
    client = _get_vt_client()
    if not client:
        return "Error: VirusTotal service is not available."

    data = client.lookup_url(url)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_url_result(data)


@tool
@log_tool_call
def lookup_hash_virustotal(file_hash: str) -> str:
    """Look up a file hash in VirusTotal for malware analysis.

    Use this tool when a user asks about a file hash (MD5, SHA1, or SHA256).
    Returns detection stats, file info, threat labels, and malware classification.

    Args:
        file_hash: The file hash to look up (MD5, SHA1, or SHA256)
    """
    client = _get_vt_client()
    if not client:
        return "Error: VirusTotal service is not available."

    data = client.lookup_hash(file_hash)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_hash_result(data)


def _detect_indicator_type(indicator: str) -> str:
    """Detect the type of indicator (ip, domain, url, or hash)."""
    indicator = indicator.strip()

    # Check for URL (has protocol or path)
    url_prefixes = ("http://", "https://")  # noqa: S310 - URL detection, not actual request
    if indicator.startswith(url_prefixes) or ("/" in indicator and "." in indicator):
        return "url"

    # Check for IP address (IPv4)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, indicator):
        return "ip"

    # Check for hash (MD5=32, SHA1=40, SHA256=64 hex chars)
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    if re.match(hash_pattern, indicator):
        return "hash"

    # Default to domain
    return "domain"


def _format_analysis_result(
    analysis_data: dict,
    indicator_type: str,
    indicator: str,
    original_date: Optional[int] = None
) -> str:
    """Format the results from a completed analysis job.

    The /analyses/{id} endpoint returns fresh stats directly from the reanalysis.
    """
    attrs = analysis_data.get("data", {}).get("attributes", {})
    if not attrs:
        return "No analysis data available"

    stats = attrs.get("stats", {})
    analysis_date = attrs.get("date")
    threat_level = VirusTotalClient.get_threat_level(stats, is_file=(indicator_type == "hash"))

    # Check if this is actually a fresh scan or cached results
    is_fresh = original_date is None or (analysis_date and analysis_date > original_date)

    result = [
        f"## VirusTotal {'Fresh' if is_fresh else 'Cached'} Analysis",
        f"**Indicator:** {indicator}",
        f"**Type:** {indicator_type.upper()}",
        f"**Threat Level:** {threat_level}",
        f"**Analyzed:** {_format_analysis_date(analysis_date)}",
        f"**Detection Stats:** {VirusTotalClient.format_analysis_stats(stats)}",
    ]

    if not is_fresh:
        result.append("")
        result.append("*Note: VirusTotal returned cached results. The indicator was recently scanned and VT did not perform a new analysis.*")

    return "\n".join(result)


def _get_original_analysis_date(indicator: str, indicator_type: str) -> Optional[int]:
    """Get the current last_analysis_date for an indicator."""
    lookup_map = {
        "ip": client.lookup_ip,
        "domain": client.lookup_domain,
        "url": client.lookup_url,
        "hash": client.lookup_hash,
    }

    lookup_fn = lookup_map.get(indicator_type)
    if not lookup_fn:
        return None

    data = lookup_fn(indicator)
    if "error" in data:
        return None

    return data.get("data", {}).get("attributes", {}).get("last_analysis_date")


@tool
@log_tool_call
def reanalyze_virustotal(indicator: str) -> str:
    """Request fresh re-analysis of an indicator in VirusTotal and return updated results.

    Use this tool when a user asks for a "fresh scan", "rescan", "re-analyze", or
    "updated verdict" of an IP, domain, URL, or file hash. This submits the indicator
    for fresh analysis by all VirusTotal engines and returns the new results.

    Note: Re-analysis may return cached results if the indicator was recently scanned.
    VirusTotal limits how often you can request fresh scans for the same resource.

    Args:
        indicator: The indicator to reanalyze (IP address, domain, URL, or file hash)
    """
    client = _get_vt_client()
    if not client:
        return "Error: VirusTotal service is not available."

    indicator = indicator.strip()
    indicator_type = _detect_indicator_type(indicator)

    logging.info(f"Reanalyzing {indicator_type}: {indicator}")

    # Map indicator types to reanalyze functions
    reanalyze_map = {
        "ip": client.reanalyze_ip,
        "domain": client.reanalyze_domain,
        "url": client.reanalyze_url,
        "hash": client.reanalyze_hash,
    }

    if indicator_type not in reanalyze_map:
        return f"Error: Could not determine indicator type for '{indicator}'"

    # Get the original analysis date to compare later
    original_date = _get_original_analysis_date(indicator, indicator_type)
    logging.info(f"Original last_analysis_date: {original_date} ({_format_analysis_date(original_date)})")

    # Submit for reanalysis
    reanalyze_fn = reanalyze_map[indicator_type]
    reanalyze_result = reanalyze_fn(indicator)

    if "error" in reanalyze_result:
        return f"Error submitting for reanalysis: {reanalyze_result['error']}"

    # Extract analysis ID - this is required to get fresh results
    analysis_id = reanalyze_result.get("data", {}).get("id")
    if not analysis_id:
        return "Error: No analysis ID returned from VirusTotal"

    logging.info(f"Waiting for analysis job {analysis_id} to complete...")

    # Wait for analysis to complete and get the results directly from the analysis endpoint
    analysis_result = client.wait_for_analysis(analysis_id, timeout=180, poll_interval=10)

    if not analysis_result:
        return "Error: Analysis timed out after 3 minutes. Try again later or check VirusTotal directly."

    if "error" in analysis_result:
        return f"Error fetching analysis results: {analysis_result['error']}"

    # Get the analysis date from the result to compare
    result_date = analysis_result.get("data", {}).get("attributes", {}).get("date")
    logging.info(f"Analysis result date: {result_date} ({_format_analysis_date(result_date)})")

    # Format and return the analysis results with freshness indicator
    return _format_analysis_result(analysis_result, indicator_type, indicator, original_date)


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover VirusTotal capabilities:
#
# - "Check 8.8.8.8 on VirusTotal"
# - "Is example.com malicious on VT?"
# - "Look up this hash on VirusTotal: abc123..."
# - "What does VirusTotal say about evil.com?"
# - "Check this URL on VT: https://suspicious-site.com/page"
# - "Rescan 1.2.3.4 on VirusTotal"
# - "Get fresh VT scan for malware.exe hash"
# - "Reanalyze suspicious-domain.com on VirusTotal"
# - "Is this file malicious? SHA256: def456..."
# - "VT reputation for 192.168.1.1"
# =============================================================================
