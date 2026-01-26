"""
IntelligenceX (IntelX) Tools Module

Provides IntelligenceX API integration for searching dark web, data leaks, and paste sites.
Returns mentions of domains, emails, or other identifiers across Tor, I2P, and breach databases.

Useful for:
- Finding dark web mentions of your organization
- Discovering leaked credentials or data
- Identifying paste site exposures
- Threat intelligence gathering

API Documentation: https://github.com/IntelligenceX/SDK
Note: Free tier has limited results. Paid API key provides full access.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.intelx import IntelligenceXClient, get_client
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Initialize IntelX client once
_intelx_client: Optional[IntelligenceXClient] = None

try:
    logger.info("Initializing IntelligenceX client...")
    _intelx_client = get_client()
    if _intelx_client.is_public_key:
        logger.warning("IntelligenceX using public API key - results will be limited.")
    else:
        logger.info("IntelligenceX client initialized with custom API key.")
except Exception as e:
    logger.error(f"Failed to initialize IntelligenceX client: {e}")
    _intelx_client = None


def _get_severity_emoji(darkweb_count: int, leak_count: int) -> str:
    """Get severity emoji based on findings."""
    total = darkweb_count + leak_count
    if total >= 10 or darkweb_count >= 5:
        return "🔴"
    elif total >= 5 or darkweb_count >= 2:
        return "🟠"
    elif total >= 1:
        return "🟡"
    return "✅"


def _format_search_result(data: dict) -> str:
    """Format IntelX search result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    term = data.get("term", "Unknown")
    total = data.get("total_findings", 0)
    darkweb = data.get("darkweb_findings", [])
    leaks = data.get("leak_findings", [])
    pastes = data.get("paste_findings", [])
    other = data.get("other_findings", [])
    is_limited = data.get("is_limited", False)

    if total == 0:
        result = [
            f"## IntelligenceX Search",
            f"**Search Term:** {term}",
            f"**Status:** ✅ No findings",
            "",
            "No mentions found in dark web, leaks, or paste sites.",
        ]
        if is_limited:
            result.append("")
            result.append("_Note: Using free API tier - results may be limited._")
        return "\n".join(result)

    severity_emoji = _get_severity_emoji(len(darkweb), len(leaks))

    result = [
        f"## IntelligenceX Search",
        f"**Search Term:** {term}",
        f"**Status:** {severity_emoji} Found {total} mention(s)",
        "",
        f"| Category | Count |",
        f"|----------|-------|",
        f"| 🌑 Dark Web | {len(darkweb)} |",
        f"| 💧 Data Leaks | {len(leaks)} |",
        f"| 📋 Paste Sites | {len(pastes)} |",
        f"| 🔍 Other Sources | {len(other)} |",
    ]

    # Dark web findings
    if darkweb:
        result.append("")
        result.append("### 🌑 Dark Web Mentions")
        for finding in darkweb[:5]:
            name = finding.get("name", "Unknown")[:50]
            date = finding.get("date", "")[:10] if finding.get("date") else "Unknown"
            url = finding.get("intelx_url", "")
            result.append(f"- **{name}** ({date})")
            if url:
                result.append(f"  [View on IntelX]({url})")
        if len(darkweb) > 5:
            result.append(f"  _...and {len(darkweb) - 5} more_")

    # Leak findings
    if leaks:
        result.append("")
        result.append("### 💧 Data Leak Mentions")
        for finding in leaks[:5]:
            name = finding.get("name", "Unknown")[:50]
            date = finding.get("date", "")[:10] if finding.get("date") else "Unknown"
            url = finding.get("intelx_url", "")
            result.append(f"- **{name}** ({date})")
            if url:
                result.append(f"  [View on IntelX]({url})")
        if len(leaks) > 5:
            result.append(f"  _...and {len(leaks) - 5} more_")

    # Paste findings
    if pastes:
        result.append("")
        result.append("### 📋 Paste Site Mentions")
        for finding in pastes[:5]:
            name = finding.get("name", "Unknown")[:50]
            date = finding.get("date", "")[:10] if finding.get("date") else "Unknown"
            result.append(f"- **{name}** ({date})")
        if len(pastes) > 5:
            result.append(f"  _...and {len(pastes) - 5} more_")

    # Recommendations
    result.append("")
    result.append("### Recommendations")
    if darkweb:
        result.append("- ⚠️ Dark web presence detected - investigate for active threats")
    if leaks:
        result.append("- 🔐 Data leak exposure - check for credential compromise")
    if pastes:
        result.append("- 📋 Paste exposure - review for sensitive data disclosure")

    if is_limited:
        result.append("")
        result.append("_Note: Using free API tier - results may be limited. Upgrade for full access._")

    result.append("")
    result.append(f"🔗 [Search on IntelX](https://intelx.io/?s={term})")

    return "\n".join(result)


@tool
@log_tool_call
def search_intelx(search_term: str) -> str:
    """Search IntelligenceX for dark web, leak, and paste site mentions.

    Use this tool when investigating potential data exposure for a domain, email,
    or other identifier. Searches across Tor/I2P dark web sites, data breach
    databases, and paste sites (including deleted pastes).

    This is useful for:
    - Finding if a domain/email appears on the dark web
    - Discovering leaked credentials or sensitive data
    - Identifying paste site exposures (Pastebin, etc.)
    - Threat intelligence and brand monitoring
    - Investigating potential data breaches

    Note: Free tier has limited results. Full access requires paid API key.

    Args:
        search_term: Domain, email, IP, or other term to search (e.g., "example.com", "user@example.com")
    """
    if not _intelx_client:
        return "Error: IntelligenceX service is not initialized."

    try:
        data = _intelx_client.search_domain(search_term.strip())
        return _format_search_result(data)
    except Exception as e:
        logger.error(f"IntelX search failed: {e}")
        return f"Error searching IntelligenceX: {str(e)}"


@tool
@log_tool_call
def search_darkweb_intelx(search_term: str) -> str:
    """Search IntelligenceX specifically for dark web (Tor/I2P) mentions only.

    Use this tool when you specifically want to check if something appears on
    the dark web, excluding leaks and paste sites.

    Args:
        search_term: Domain, email, or term to search for dark web mentions
    """
    if not _intelx_client:
        return "Error: IntelligenceX service is not initialized."

    try:
        data = _intelx_client.search_darkweb_only(search_term.strip(), max_results=50)

        if not data.get("success"):
            return f"Error: {data.get('error', 'Unknown error')}"

        results = data.get("results", [])
        term = data.get("term", search_term)

        if not results:
            return f"## Dark Web Search\n**Term:** {term}\n**Status:** ✅ No dark web mentions found"

        output = [
            f"## Dark Web Search (Tor/I2P)",
            f"**Term:** {term}",
            f"**Status:** 🌑 Found {len(results)} dark web mention(s)",
            "",
            "### Findings",
        ]

        for finding in results[:10]:
            name = finding.get("name", "Unknown")[:60]
            date = finding.get("date", "")[:10] if finding.get("date") else "Unknown"
            url = finding.get("intelx_url", "")
            media_type = finding.get("media_type", "unknown")

            output.append(f"- **{name}**")
            output.append(f"  Date: {date} | Type: {media_type}")
            if url:
                output.append(f"  [View on IntelX]({url})")

        if len(results) > 10:
            output.append(f"\n_...and {len(results) - 10} more results_")

        return "\n".join(output)

    except Exception as e:
        logger.error(f"IntelX dark web search failed: {e}")
        return f"Error searching dark web: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover IntelX capabilities:
#
# - "Search IntelX for example.com"
# - "Check if example.com appears on the dark web"
# - "Search for user@example.com on IntelligenceX"
# - "Look for dark web mentions of my-company.com"
# - "Check IntelX for leaked data about example.org"
# - "Search paste sites for example.com"
# =============================================================================
