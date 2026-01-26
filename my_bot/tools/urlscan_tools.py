"""
URLScan.io Tools Module

Provides URLScan.io API integration for URL/domain scanning and analysis.
Returns screenshots, page info, detected technologies, and security verdicts.

API Documentation: https://urlscan.io/docs/api/
"""

import logging
import time
from datetime import datetime
from typing import Optional

from langchain_core.tools import tool

from services.urlscan import URLScanClient
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Initialize URLScan client once
_urlscan_client: Optional[URLScanClient] = None

try:
    logger.info("Initializing URLScan client...")
    _urlscan_client = URLScanClient()
    # Search works without API key, so client is always usable
    logger.info(f"URLScan client initialized (API key configured: {_urlscan_client.is_configured()}).")
except Exception as e:
    logger.error(f"Failed to initialize URLScan client: {e}")
    _urlscan_client = None


def _format_timestamp(ts: str) -> str:
    """Format ISO timestamp to readable format."""
    if not ts:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%m/%d/%Y %I:%M %p UTC")
    except (ValueError, AttributeError):
        return ts[:19] if ts else "Unknown"


def _get_verdict_emoji(verdict: dict) -> str:
    """Get emoji based on verdict score/malicious status."""
    if verdict.get("malicious"):
        return "🔴"
    score = verdict.get("score", 0)
    if score >= 50:
        return "🟠"
    elif score > 0:
        return "🟡"
    return "✅"


def _format_search_result(data: dict, domain: str) -> str:
    """Format search results for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    total = data.get("total", 0)
    results = data.get("results", [])

    if total == 0 or not results:
        return f"No existing scans found for **{domain}** on URLScan.io.\n\nUse the `scan_url_urlscan` tool to submit a new scan."

    output = [
        f"## URLScan.io Search Results",
        f"**Domain:** {domain}",
        f"**Total Scans Found:** {total}",
        "",
        "### Recent Scans",
    ]

    for i, result in enumerate(results[:5], 1):
        task = result.get("task", {})
        page = result.get("page", {})
        stats = result.get("stats", {})

        scan_time = _format_timestamp(task.get("time"))
        scan_url = task.get("url", "Unknown")
        scan_id = result.get("_id", "")

        # Page info
        title = page.get("title", "No title")[:60]
        if len(page.get("title", "")) > 60:
            title += "..."
        server = page.get("server", "Unknown")
        ip = page.get("ip", "Unknown")
        country = page.get("country", "Unknown")
        status = page.get("status", "Unknown")

        # Stats
        requests_count = stats.get("requests", 0)
        ips_count = stats.get("ips", 0)
        domains_count = stats.get("domains", 0)

        output.append(f"**{i}. Scan from {scan_time}**")
        output.append(f"   - **URL:** {scan_url}")
        output.append(f"   - **Title:** {title}")
        output.append(f"   - **Server:** {server} | **IP:** {ip} ({country})")
        output.append(f"   - **HTTP Status:** {status}")
        output.append(f"   - **Stats:** {requests_count} requests, {ips_count} IPs, {domains_count} domains")
        output.append(f"   - 🔗 [View Full Report](https://urlscan.io/result/{scan_id}/)")
        output.append("")

    return "\n".join(output)


def _format_scan_result(data: dict, url: str) -> str:
    """Format full scan result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    scan_data = data.get("data", {})

    task = scan_data.get("task", {})
    page = scan_data.get("page", {})
    stats = scan_data.get("stats", {})
    verdicts = scan_data.get("verdicts", {})
    lists = scan_data.get("lists", {})

    # Basic info
    scan_time = _format_timestamp(task.get("time"))
    scan_uuid = task.get("uuid", "")
    final_url = page.get("url", url)
    title = page.get("title", "No title")
    server = page.get("server", "Unknown")
    ip = page.get("ip", "Unknown")
    country = page.get("country", "Unknown")
    status = page.get("status", "Unknown")
    mime_type = page.get("mimeType", "Unknown")

    # Stats
    requests_count = stats.get("requests", 0)
    ips_count = stats.get("ips", 0)
    domains_count = stats.get("domains", 0)
    data_length = stats.get("dataLength", 0)
    encoded_length = stats.get("encodedDataLength", 0)

    # Verdicts
    urlscan_verdict = verdicts.get("urlscan", {})
    community_verdict = verdicts.get("community", {})
    overall_verdict = verdicts.get("overall", {})

    urlscan_emoji = _get_verdict_emoji(urlscan_verdict)
    overall_emoji = _get_verdict_emoji(overall_verdict)

    output = [
        f"## URLScan.io Analysis",
        f"**Scanned URL:** {url}",
        f"**Final URL:** {final_url}",
        f"**Scan Time:** {scan_time}",
        "",
        "### Page Information",
        f"- **Title:** {title}",
        f"- **Server:** {server}",
        f"- **IP Address:** {ip} ({country})",
        f"- **HTTP Status:** {status}",
        f"- **MIME Type:** {mime_type}",
        "",
        "### Statistics",
        f"- **HTTP Requests:** {requests_count}",
        f"- **Unique IPs:** {ips_count}",
        f"- **Unique Domains:** {domains_count}",
        f"- **Data Transferred:** {encoded_length:,} bytes",
        "",
        "### Security Verdicts",
    ]

    # URLScan verdict
    urlscan_score = urlscan_verdict.get("score", 0)
    urlscan_categories = urlscan_verdict.get("categories", [])
    urlscan_malicious = urlscan_verdict.get("malicious", False)

    output.append(f"{urlscan_emoji} **URLScan Verdict:** Score {urlscan_score}/100" +
                  (" - MALICIOUS" if urlscan_malicious else ""))
    if urlscan_categories:
        output.append(f"   Categories: {', '.join(urlscan_categories)}")

    # Community verdict
    community_score = community_verdict.get("score", 0)
    community_categories = community_verdict.get("categories", [])
    community_votes = community_verdict.get("votesMalicious", 0)

    if community_score > 0 or community_votes > 0:
        output.append(f"👥 **Community Verdict:** Score {community_score}, {community_votes} malicious votes")
        if community_categories:
            output.append(f"   Categories: {', '.join(community_categories)}")

    # Overall verdict
    overall_malicious = overall_verdict.get("malicious", False)
    overall_score = overall_verdict.get("score", 0)
    if overall_malicious:
        output.append(f"{overall_emoji} **Overall:** ⚠️ MALICIOUS (Score: {overall_score})")

    # Detected technologies/brands
    brands = verdicts.get("urlscan", {}).get("brands", [])
    if brands:
        brand_names = [b.get("name", "") for b in brands[:5] if b.get("name")]
        if brand_names:
            output.append("")
            output.append(f"**Detected Brands:** {', '.join(brand_names)}")

    # List of contacted domains (top 10)
    contacted_domains = lists.get("domains", [])
    if contacted_domains:
        output.append("")
        output.append("### Contacted Domains (Top 10)")
        for domain in contacted_domains[:10]:
            output.append(f"- {domain}")

    # IPs contacted
    contacted_ips = lists.get("ips", [])
    if contacted_ips:
        output.append("")
        output.append(f"### IPs Contacted")
        output.append(f"{', '.join(contacted_ips[:10])}" + ("..." if len(contacted_ips) > 10 else ""))

    # Links
    output.append("")
    output.append(f"🔗 [View Full Report](https://urlscan.io/result/{scan_uuid}/)")
    output.append(f"📸 [Screenshot](https://urlscan.io/screenshots/{scan_uuid}.png)")

    return "\n".join(output)


@tool
@log_tool_call
def search_urlscan(domain: str) -> str:
    """Search URLScan.io for existing scans of a domain.

    Use this tool when a user wants to see what URLScan.io knows about a domain
    without submitting a new scan. This searches for previous scans and returns
    page information, server details, and scan statistics.

    This is useful for:
    - Checking historical scan data for a domain
    - Seeing what IPs/servers a domain has resolved to
    - Getting page titles and technologies without triggering a new scan
    - Quick reconnaissance before deciding to do a full scan

    Note: This searches existing public scans only - does not submit new scans.

    Args:
        domain: The domain to search for (e.g., "example.com")
    """
    if not _urlscan_client:
        return "Error: URLScan service is not initialized."

    try:
        # Clean up domain input
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        data = _urlscan_client.search_domain(domain, size=5)
        return _format_search_result(data, domain)
    except Exception as e:
        logger.error(f"URLScan search failed: {e}")
        return f"Error searching URLScan: {str(e)}"


@tool
@log_tool_call
def scan_url_urlscan(url: str) -> str:
    """Submit a URL to URLScan.io for fresh scanning and analysis.

    Use this tool when a user wants to scan a URL/domain and get detailed analysis
    including screenshots, security verdicts, contacted domains/IPs, and more.

    This is useful for:
    - Analyzing suspicious URLs or phishing pages
    - Getting a screenshot of what a page looks like
    - Identifying what external resources a page loads
    - Checking for malicious indicators
    - Seeing what domains/IPs a page contacts

    Note: This submits a new scan which takes ~30 seconds to complete.
    The scan will be publicly visible on URLScan.io.

    Args:
        url: The full URL to scan (e.g., "https://example.com/page")
    """
    if not _urlscan_client:
        return "Error: URLScan service is not initialized."

    if not _urlscan_client.is_configured():
        return "Error: URLScan API key not configured. Cannot submit new scans.\n\nUse `search_urlscan` to search existing scans instead."

    try:
        url = url.strip()

        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        logger.info(f"Submitting URL to URLScan: {url}")

        # Submit scan
        submit_result = _urlscan_client.submit_scan(url, visibility="public")

        if not submit_result.get("success"):
            return f"Error submitting scan: {submit_result.get('error', 'Unknown error')}"

        uuid = submit_result.get("uuid")
        if not uuid:
            return "Error: No scan ID returned from URLScan"

        # Wait for scan to complete (typically 15-30 seconds)
        logger.info(f"Waiting for scan {uuid} to complete...")
        time.sleep(20)  # Initial wait

        # Poll for results
        max_attempts = 4
        for attempt in range(max_attempts):
            result = _urlscan_client.get_scan_result(uuid)

            if result.get("success"):
                return _format_scan_result(result, url)

            if attempt < max_attempts - 1:
                logger.info(f"Scan not ready, waiting... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(10)

        # If we get here, scan didn't complete in time
        return (
            f"Scan submitted but not yet complete.\n\n"
            f"**Scan ID:** {uuid}\n"
            f"🔗 [View Results When Ready](https://urlscan.io/result/{uuid}/)\n\n"
            f"The scan is still processing. Check the link above in a minute."
        )

    except Exception as e:
        logger.error(f"URLScan scan failed: {e}")
        return f"Error scanning URL: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover URLScan capabilities:
#
# - "Search URLScan for example.com"
# - "Scan this URL on URLScan: https://suspicious.com"
# - "What does URLScan know about evil-domain.net?"
# - "Check URLScan for previous scans of phishing-site.com"
# - "Scan https://login.fake-bank.com on URLScan"
# - "Get URLScan screenshot for suspicious-page.com"
# =============================================================================
