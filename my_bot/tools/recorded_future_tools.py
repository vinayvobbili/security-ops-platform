"""
Recorded Future Tools Module

Provides Recorded Future API integration for threat intelligence lookups.
Supports IP addresses, domains, URLs, file hashes, CVEs, and threat actors.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.recorded_future import RecordedFutureClient
from src.utils.tool_decorator import log_tool_call

# Lazy-initialized Recorded Future client
_rf_client: Optional[RecordedFutureClient] = None


def _get_rf_client() -> Optional[RecordedFutureClient]:
    """Get Recorded Future client (lazy initialization)."""
    global _rf_client
    if _rf_client is None:
        try:
            client = RecordedFutureClient()
            if client.is_configured():
                _rf_client = client
            else:
                logging.warning("Recorded Future client not configured (missing API key)")
        except Exception as e:
            logging.error(f"Failed to initialize Recorded Future client: {e}")
    return _rf_client


def _format_enrichment_result(data: dict, indicator_type: str, indicator: str) -> str:
    """Format enrichment result for display."""
    if "error" in data:
        return f"Error: {data['error']}"

    # Extract results from response
    results = client.extract_enrichment_results(data) if _rf_client else []

    if not results:
        return f"No enrichment data found for {indicator_type}: {indicator}"

    # Find the matching result
    result = None
    for r in results:
        if r.get("value", "").lower() == indicator.lower():
            result = r
            break

    if not result:
        result = results[0] if results else None

    if not result:
        return f"No enrichment data found for {indicator_type}: {indicator}"

    risk_score = result.get("risk_score", 0)
    risk_level = result.get("risk_level", "Unknown")
    evidence_count = result.get("evidence_count", 0)
    rules = result.get("rules", [])
    criticality = result.get("criticality_label", "")

    output = [
        f"## Recorded Future {indicator_type.upper()} Analysis",
        f"**Indicator:** {indicator}",
        f"**Risk Score:** {risk_score}/99",
        f"**Risk Level:** {risk_level}",
    ]

    if criticality:
        output.append(f"**Criticality:** {criticality}")

    output.append(f"**Evidence Count:** {evidence_count}")

    if rules:
        output.append("")
        output.append("**Risk Rules Triggered:**")
        for rule in rules[:5]:
            output.append(f"- {rule}")
        if len(rules) > 5:
            output.append(f"- ... and {len(rules) - 5} more")

    return "\n".join(output)


def _format_actor_result(data: dict) -> str:
    """Format threat actor search/lookup result."""
    if "error" in data:
        return f"Error: {data['error']}"

    match_type = data.get("match")

    if match_type == "single":
        actor = data.get("actor", {})
        summary = RecordedFutureClient.extract_actor_summary(actor)
        return _format_actor_summary(summary)

    elif match_type == "multiple":
        actors = data.get("actors", [])
        total = data.get("total", len(actors))

        output = [
            f"## Recorded Future Threat Actor Search",
            f"**Found {total} matching threat actors:**",
            ""
        ]

        for actor in actors[:5]:
            summary = RecordedFutureClient.extract_actor_summary(actor)
            name = summary.get("name", "Unknown")
            risk = summary.get("risk_score", "N/A")
            aliases = summary.get("common_names", [])

            actor_line = f"- **{name}** (Risk: {risk})"
            if aliases:
                actor_line += f" - AKA: {', '.join(aliases[:3])}"
            output.append(actor_line)

        if total > 5:
            output.append(f"\n*... and {total - 5} more results*")

        return "\n".join(output)

    # Direct API response (e.g., from search_actor)
    actors = data.get("data", [])
    if not actors:
        return "No threat actors found matching that query."

    total = data.get("counts", {}).get("total", len(actors))

    output = [
        f"## Recorded Future Threat Actor Search",
        f"**Found {total} matching threat actors:**",
        ""
    ]

    for actor in actors[:5]:
        summary = RecordedFutureClient.extract_actor_summary(actor)
        name = summary.get("name", "Unknown")
        risk = summary.get("risk_score", "N/A")
        aliases = summary.get("common_names", [])

        actor_line = f"- **{name}** (Risk: {risk})"
        if aliases:
            actor_line += f" - AKA: {', '.join(aliases[:3])}"
        output.append(actor_line)

    if total > 5:
        output.append(f"\n*... and {total - 5} more results*")

    return "\n".join(output)


def _format_actor_summary(summary: dict) -> str:
    """Format a single actor summary for display."""
    output = [
        f"## Recorded Future Threat Actor Profile",
        f"**Name:** {summary.get('name', 'Unknown')}",
        f"**ID:** {summary.get('id', 'Unknown')}",
    ]

    if summary.get("risk_score"):
        output.append(f"**Risk Score:** {summary['risk_score']}")

    if summary.get("common_names"):
        output.append(f"**Also Known As:** {', '.join(summary['common_names'][:5])}")

    if summary.get("aliases"):
        output.append(f"**Aliases:** {', '.join(summary['aliases'][:5])}")

    if summary.get("categories"):
        output.append(f"**Categories:** {', '.join(summary['categories'])}")

    if summary.get("target_industries"):
        output.append(f"**Target Industries:** {', '.join(summary['target_industries'][:5])}")

    if summary.get("target_countries"):
        output.append(f"**Target Countries:** {', '.join(summary['target_countries'][:5])}")

    if summary.get("last_seen"):
        output.append(f"**Last Seen:** {summary['last_seen']}")

    if summary.get("description"):
        desc = summary["description"]
        if len(desc) > 500:
            desc = desc[:500] + "..."
        output.append("")
        output.append(f"**Description:** {desc}")

    return "\n".join(output)


@tool
@log_tool_call
def lookup_ip_recorded_future(ip_address: str) -> str:
    """Look up an IP address in Recorded Future for threat intelligence.

    Use this tool when a user asks about the reputation, risk score, or threat status
    of an IP address using Recorded Future intelligence. Returns risk score (0-99),
    risk level, and triggered risk rules.

    Args:
        ip_address: The IP address to look up (e.g., "8.8.8.8")
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    ip_address = ip_address.strip()
    data = client.enrich_ips([ip_address])

    return _format_enrichment_result(data, "IP", ip_address)


@tool
@log_tool_call
def lookup_domain_recorded_future(domain: str) -> str:
    """Look up a domain in Recorded Future for threat intelligence.

    Use this tool when a user asks about the reputation, risk score, or threat status
    of a domain using Recorded Future intelligence. Returns risk score (0-99),
    risk level, and triggered risk rules.

    Args:
        domain: The domain to look up (e.g., "example.com")
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    # Clean domain
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]

    data = client.enrich_domains([domain])

    return _format_enrichment_result(data, "Domain", domain)


@tool
@log_tool_call
def lookup_hash_recorded_future(file_hash: str) -> str:
    """Look up a file hash in Recorded Future for malware intelligence.

    Use this tool when a user asks about a file hash (MD5, SHA1, or SHA256)
    using Recorded Future intelligence. Returns risk score, malware associations,
    and triggered risk rules.

    Args:
        file_hash: The file hash to look up (MD5, SHA1, or SHA256)
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    file_hash = file_hash.strip().lower()
    data = client.enrich_hashes([file_hash])

    return _format_enrichment_result(data, "Hash", file_hash)


@tool
@log_tool_call
def lookup_url_recorded_future(url: str) -> str:
    """Look up a URL in Recorded Future for threat intelligence.

    Use this tool when a user asks about a URL's reputation or threat status
    using Recorded Future intelligence. Returns risk score (0-99),
    risk level, and triggered risk rules.

    Args:
        url: The full URL to look up (e.g., "https://example.com/page")
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    url = url.strip()
    data = client.enrich_urls([url])

    return _format_enrichment_result(data, "URL", url)


@tool
@log_tool_call
def lookup_cve_recorded_future(cve_id: str) -> str:
    """Look up a CVE/vulnerability in Recorded Future for intelligence.

    Use this tool when a user asks about a CVE vulnerability using Recorded Future.
    Returns risk score, exploitability info, and threat context.

    Args:
        cve_id: The CVE ID to look up (e.g., "CVE-2021-44228")
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    cve_id = cve_id.strip().upper()
    data = client.enrich(vulnerabilities=[cve_id])

    return _format_enrichment_result(data, "CVE", cve_id)


@tool
@log_tool_call
def search_threat_actor_recorded_future(actor_name: str) -> str:
    """Search for a threat actor in Recorded Future.

    Use this tool when a user asks about a threat actor, APT group, or
    hacker group. Returns matching actors with risk scores and aliases.

    Args:
        actor_name: The threat actor name to search (e.g., "APT28", "Fancy Bear", "Lazarus Group")
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    actor_name = actor_name.strip()
    data = client.lookup_actor_by_name(actor_name)

    return _format_actor_result(data)


@tool
@log_tool_call
def triage_for_phishing_recorded_future(indicator: str) -> str:
    """Triage an indicator (domain, URL, or IP) for phishing risk using Recorded Future.

    Use this tool when a user wants to specifically check if an indicator is
    associated with phishing attacks. Returns phishing-context risk assessment.

    Args:
        indicator: Domain, URL, or IP to check for phishing risk
    """
    client = _get_rf_client()
    if not client:
        return "Error: Recorded Future service is not available."

    indicator = indicator.strip()

    # Determine indicator type
    if indicator.startswith("http://") or indicator.startswith("https://"):
        data = client.triage_for_phishing(urls=[indicator])
    elif _is_ip_address(indicator):
        data = client.triage_for_phishing(ips=[indicator])
    else:
        # Assume domain
        domain = indicator.lower().replace("https://", "").replace("http://", "").split("/")[0]
        data = client.triage_for_phishing(domains=[domain])

    if "error" in data:
        return f"Error: {data['error']}"

    # Format triage results
    results = client.extract_enrichment_results(data)

    if not results:
        return f"No phishing intelligence found for: {indicator}"

    result = results[0]
    risk_score = result.get("risk_score", 0)
    risk_level = result.get("risk_level", "Unknown")
    rules = result.get("rules", [])

    output = [
        f"## Recorded Future Phishing Triage",
        f"**Indicator:** {indicator}",
        f"**Phishing Risk Score:** {risk_score}/99",
        f"**Risk Level:** {risk_level}",
    ]

    if risk_score >= 65:
        output.append("")
        output.append("**Verdict: HIGH PHISHING RISK**")
    elif risk_score >= 25:
        output.append("")
        output.append("**Verdict: MODERATE PHISHING RISK**")
    else:
        output.append("")
        output.append("**Verdict: LOW PHISHING RISK**")

    if rules:
        output.append("")
        output.append("**Triggered Rules:**")
        for rule in rules[:5]:
            output.append(f"- {rule}")

    return "\n".join(output)


def _is_ip_address(value: str) -> bool:
    """Check if a string is an IP address."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, value))


# =============================================================================
# Sample Test Prompts for Pokedex Bot
# =============================================================================
#
# IP Lookup:
#   "Look up IP 8.8.8.8 on Recorded Future"
#   "Check 1.2.3.4 reputation in Recorded Future"
#
# Domain Lookup:
#   "Look up domain example.com on Recorded Future"
#   "Check evil.com in Recorded Future"
#
# Hash Lookup:
#   "Look up hash abc123def456 on Recorded Future"
#   "Check this SHA256 on Recorded Future: <hash>"
#
# CVE Lookup:
#   "Look up CVE-2021-44228 on Recorded Future"
#   "Get Recorded Future intel on CVE-2024-12345"
#
# Threat Actor Search:
#   "Search for APT28 on Recorded Future"
#   "Get info on Fancy Bear threat actor"
#   "Look up Lazarus Group in Recorded Future"
#
# Phishing Triage:
#   "Check if evil.com is a phishing domain on Recorded Future"
#   "Triage https://suspicious.com/login for phishing"
