"""
Zscaler Tools Module

Provides Zscaler ZIA integration for URL lookups, sandbox analysis,
and security policy operations.
"""

import logging
from typing import Any, Dict, List, Optional

from langchain_core.tools import tool

from my_config import get_config
from services.zscaler import ZscalerClient, ZscalerError
from src.utils.tool_decorator import log_tool_call

# Initialize Zscaler client once
_zscaler_client: Optional[ZscalerClient] = None

try:
    logging.info("Initializing Zscaler client...")
    config = get_config()

    if config.zscaler_username and config.zscaler_password and config.zscaler_api_key:
        _zscaler_client = ZscalerClient(
            username=config.zscaler_username,
            password=config.zscaler_password,
            api_key=config.zscaler_api_key,
            base_url=config.zscaler_base_url
        )
        logging.info("Zscaler client initialized successfully.")
    else:
        logging.warning("Zscaler client not configured (missing credentials). Tools will be disabled.")

except Exception as e:
    logging.error(f"Failed to initialize Zscaler client: {e}")
    _zscaler_client = None


def _format_url_lookup_results(results: List[Dict[str, Any]]) -> str:
    """Format URL lookup results for display."""
    if not results:
        return "No URL lookup results found."

    lines = [f"## Zscaler URL Lookup Results ({len(results)} URLs)", ""]

    for result in results:
        url = result.get("url", "Unknown")
        classifications = result.get("urlClassifications", [])
        classifications_with_security = result.get("urlClassificationsWithSecurityAlert", [])

        lines.append(f"### {url}")

        if classifications:
            lines.append(f"**Categories:** {', '.join(classifications)}")
        else:
            lines.append("**Categories:** None")

        if classifications_with_security:
            lines.append(f"**Security Alerts:** {', '.join(classifications_with_security)}")

        lines.append("")

    return "\n".join(lines)


def _format_sandbox_report(report: Dict[str, Any]) -> str:
    """Format sandbox report for display."""
    if not report:
        return "No sandbox report found for this hash."

    full_report = report.get("Full Details", {}) or report.get("Summary", {}) or report

    lines = ["## Zscaler Sandbox Report", ""]

    # Basic info
    md5 = full_report.get("Classification", {}).get("DetectedMalware", "Unknown")
    classification = full_report.get("Classification", {})
    score = classification.get("Score", "N/A")
    category = classification.get("Category", "Unknown")
    malware_type = classification.get("Type", "Unknown")

    lines.append(f"**Score:** {score}/100")
    lines.append(f"**Category:** {category}")
    lines.append(f"**Type:** {malware_type}")

    if md5 and md5 != "Unknown":
        lines.append(f"**Detected Malware:** {md5}")

    # File info
    file_properties = full_report.get("FileProperties", {})
    if file_properties:
        lines.append("")
        lines.append("### File Properties")
        lines.append(f"**File Type:** {file_properties.get('FileType', 'Unknown')}")
        lines.append(f"**File Size:** {file_properties.get('FileSize', 'Unknown')} bytes")
        lines.append(f"**MD5:** `{file_properties.get('MD5', 'Unknown')}`")
        lines.append(f"**SHA256:** `{file_properties.get('SHA256', 'Unknown')}`")

    # Summary info
    summary = full_report.get("Summary", {})
    if summary:
        lines.append("")
        lines.append("### Analysis Summary")
        duration = summary.get("Duration", "Unknown")
        start_time = summary.get("StartTime", "Unknown")
        lines.append(f"**Analysis Duration:** {duration}s")
        lines.append(f"**Start Time:** {start_time}")

        # Status
        status = summary.get("Status", "Unknown")
        lines.append(f"**Status:** {status}")

    # Networking
    networking = full_report.get("Networking", [])
    if networking:
        lines.append("")
        lines.append("### Network Activity")
        for net in networking[:5]:
            action = net.get("Action", "Unknown")
            host = net.get("Host", "Unknown")
            lines.append(f"- {action}: {host}")
        if len(networking) > 5:
            lines.append(f"- ... and {len(networking) - 5} more")

    return "\n".join(lines)


def _format_url_categories(categories: List[Dict[str, Any]]) -> str:
    """Format URL categories for display."""
    if not categories:
        return "No custom URL categories found."

    lines = [f"## Zscaler Custom URL Categories ({len(categories)} found)", ""]

    for cat in categories:
        cat_id = cat.get("id", "Unknown")
        name = cat.get("configuredName", cat.get("val", "Unknown"))
        urls_count = len(cat.get("urls", []))
        keywords_count = len(cat.get("dbCategorizedUrls", []))

        lines.append(f"### {name}")
        lines.append(f"**ID:** `{cat_id}`")
        lines.append(f"**URLs:** {urls_count}")
        lines.append(f"**DB Categorized URLs:** {keywords_count}")

        # Show first few URLs
        urls = cat.get("urls", [])[:3]
        if urls:
            lines.append(f"**Sample URLs:** {', '.join(urls)}")

        lines.append("")

    return "\n".join(lines)


def _format_blocklist(blocklist: Dict[str, Any]) -> str:
    """Format blocklist for display."""
    urls = blocklist.get("blacklistUrls", [])

    if not urls:
        return "The URL blocklist is empty."

    lines = [f"## Zscaler URL Blocklist ({len(urls)} URLs)", ""]

    for url in urls[:20]:
        lines.append(f"- {url}")

    if len(urls) > 20:
        lines.append(f"- ... and {len(urls) - 20} more URLs")

    return "\n".join(lines)


@tool
@log_tool_call
def lookup_zscaler_url(url: str) -> str:
    """Look up the categorization of a URL in Zscaler.

    Use this tool to check how Zscaler categorizes a URL and whether
    it triggers any security alerts.

    Args:
        url: The URL to look up (e.g., "example.com" or "https://example.com/path")
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        url = url.strip()
        results = _zscaler_client.url_lookup([url])
        return _format_url_lookup_results(results)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error looking up URL in Zscaler: {e}")
        return f"Error looking up URL: {str(e)}"


@tool
@log_tool_call
def lookup_zscaler_urls(urls: str) -> str:
    """Look up the categorization of multiple URLs in Zscaler.

    Use this tool to check how Zscaler categorizes multiple URLs at once.
    Provide URLs separated by commas or newlines.

    Args:
        urls: URLs to look up, separated by commas or newlines (max 100)
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        # Parse URLs from input
        url_list = [u.strip() for u in urls.replace('\n', ',').split(',') if u.strip()]

        if not url_list:
            return "Error: No valid URLs provided."

        if len(url_list) > 100:
            url_list = url_list[:100]
            note = "\n\n*Note: Only the first 100 URLs were processed.*"
        else:
            note = ""

        results = _zscaler_client.url_lookup(url_list)
        return _format_url_lookup_results(results) + note

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error looking up URLs in Zscaler: {e}")
        return f"Error looking up URLs: {str(e)}"


@tool
@log_tool_call
def get_zscaler_sandbox_report(md5_hash: str) -> str:
    """Get sandbox analysis report for a file by MD5 hash.

    Use this tool to retrieve Zscaler sandbox analysis results for a
    previously analyzed file. The report includes malware classification,
    file properties, and behavioral analysis.

    Args:
        md5_hash: MD5 hash of the file to look up
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        md5_hash = md5_hash.strip().lower()

        # Validate MD5 hash format
        if len(md5_hash) != 32 or not all(c in '0123456789abcdef' for c in md5_hash):
            return "Error: Invalid MD5 hash format. Must be 32 hexadecimal characters."

        report = _zscaler_client.get_sandbox_report(md5_hash)
        return _format_sandbox_report(report)

    except ZscalerError as e:
        if e.status_code == 404:
            return f"No sandbox report found for MD5 hash: {md5_hash}"
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching sandbox report: {e}")
        return f"Error fetching sandbox report: {str(e)}"


@tool
@log_tool_call
def get_zscaler_url_categories() -> str:
    """Get custom URL categories from Zscaler.

    Use this tool to list all custom URL categories configured in Zscaler ZIA.
    Shows category names, IDs, and sample URLs in each category.
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        categories = _zscaler_client.get_url_categories(custom_only=True)
        return _format_url_categories(categories)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching URL categories: {e}")
        return f"Error fetching URL categories: {str(e)}"


@tool
@log_tool_call
def get_zscaler_blocklist() -> str:
    """Get the current URL blocklist from Zscaler.

    Use this tool to see which URLs are currently blocked by Zscaler's
    advanced security settings blocklist.
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        blocklist = _zscaler_client.get_url_blocklist()
        return _format_blocklist(blocklist)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching blocklist: {e}")
        return f"Error fetching blocklist: {str(e)}"


@tool
@log_tool_call
def add_url_to_zscaler_blocklist(url: str) -> str:
    """Add a URL to the Zscaler blocklist.

    Use this tool to block a malicious URL in Zscaler. The URL will be
    added to the advanced security settings blocklist.

    Args:
        url: The URL to block (e.g., "malicious-site.com")
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        url = url.strip()
        if not url:
            return "Error: No URL provided."

        _zscaler_client.add_urls_to_blocklist([url])
        return f"Successfully added `{url}` to the Zscaler blocklist.\n\n**Note:** Changes may need activation to take effect."

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error adding URL to blocklist: {e}")
        return f"Error adding URL to blocklist: {str(e)}"


@tool
@log_tool_call
def remove_url_from_zscaler_blocklist(url: str) -> str:
    """Remove a URL from the Zscaler blocklist.

    Use this tool to unblock a URL that was previously added to the
    Zscaler blocklist.

    Args:
        url: The URL to unblock
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        url = url.strip()
        if not url:
            return "Error: No URL provided."

        _zscaler_client.remove_urls_from_blocklist([url])
        return f"Successfully removed `{url}` from the Zscaler blocklist.\n\n**Note:** Changes may need activation to take effect."

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error removing URL from blocklist: {e}")
        return f"Error removing URL from blocklist: {str(e)}"


@tool
@log_tool_call
def search_zscaler_users(search_term: str, limit: int = 20) -> str:
    """Search for users in Zscaler.

    Use this tool to find users by name or email address in Zscaler ZIA.

    Args:
        search_term: Name or email to search for
        limit: Maximum number of users to return (default 20, max 100)
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    limit = min(max(1, limit), 100)

    try:
        users = _zscaler_client.get_users(search=search_term, page_size=limit)

        if not users:
            return f"No users found matching '{search_term}'."

        lines = [f"## Zscaler Users ({len(users)} found)", ""]

        for user in users:
            user_id = user.get("id", "Unknown")
            name = user.get("name", "Unknown")
            email = user.get("email", "N/A")
            dept = user.get("department", {}).get("name", "N/A")
            groups = [g.get("name", "") for g in user.get("groups", [])]

            lines.append(f"### {name}")
            lines.append(f"**ID:** `{user_id}`")
            lines.append(f"**Email:** {email}")
            lines.append(f"**Department:** {dept}")
            if groups:
                lines.append(f"**Groups:** {', '.join(groups[:3])}")
            lines.append("")

        return "\n".join(lines)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error searching users: {e}")
        return f"Error searching users: {str(e)}"


@tool
@log_tool_call
def get_zscaler_departments() -> str:
    """Get all departments from Zscaler.

    Use this tool to list all departments configured in Zscaler ZIA.
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        departments = _zscaler_client.get_departments()

        if not departments:
            return "No departments found."

        lines = [f"## Zscaler Departments ({len(departments)} found)", ""]

        for dept in departments:
            dept_id = dept.get("id", "Unknown")
            name = dept.get("name", "Unknown")
            comments = dept.get("comments", "")

            lines.append(f"- **{name}** (ID: `{dept_id}`)")
            if comments:
                lines.append(f"  - {comments[:100]}")

        return "\n".join(lines)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching departments: {e}")
        return f"Error fetching departments: {str(e)}"


@tool
@log_tool_call
def get_zscaler_status() -> str:
    """Get the current activation status from Zscaler.

    Use this tool to check if there are pending changes that need
    to be activated in Zscaler ZIA.
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        status = _zscaler_client.get_status()

        lines = ["## Zscaler Status", ""]

        if isinstance(status, dict):
            for key, value in status.items():
                lines.append(f"**{key}:** {value}")
        else:
            lines.append(f"Status: {status}")

        return "\n".join(lines)

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching status: {e}")
        return f"Error fetching status: {str(e)}"


@tool
@log_tool_call
def activate_zscaler_changes() -> str:
    """Activate pending configuration changes in Zscaler.

    Use this tool to push pending configuration changes to the
    Zscaler cloud. This is required after making policy changes.
    """
    if not _zscaler_client:
        return "Error: Zscaler service is not initialized."

    try:
        result = _zscaler_client.activate_changes()

        status = result.get("status", "Unknown")
        return f"Activation request submitted.\n\n**Status:** {status}"

    except ZscalerError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error activating changes: {e}")
        return f"Error activating changes: {str(e)}"


# =============================================================================
# SAMPLE TEST PROMPTS
# =============================================================================
# Use these prompts to test Zscaler tools via the Pokedex bot:
#
# --- URL Lookup Tools ---
#
# lookup_zscaler_url:
#   "Check the Zscaler category for google.com"
#   "What category is example.com in Zscaler?"
#   "Look up facebook.com in Zscaler"
#   "Is malware.testing.google.test blocked in Zscaler?"
#
# lookup_zscaler_urls:
#   "Look up these URLs in Zscaler: google.com, facebook.com, twitter.com"
#   "Check Zscaler categories for: bing.com, yahoo.com"
#
# --- Sandbox Tools ---
#
# get_zscaler_sandbox_report:
#   "Get Zscaler sandbox report for hash abc123..."
#   "What did Zscaler sandbox find for MD5 d41d8cd98f00b204e9800998ecf8427e?"
#
# --- Category Tools ---
#
# get_zscaler_url_categories:
#   "Show me custom URL categories in Zscaler"
#   "What custom categories are configured in Zscaler?"
#   "List Zscaler URL categories"
#
# --- Blocklist Tools ---
#
# get_zscaler_blocklist:
#   "What URLs are blocked in Zscaler?"
#   "Show me the Zscaler blocklist"
#
# add_url_to_zscaler_blocklist:
#   "Block malicious-site.com in Zscaler"
#   "Add evil.com to the Zscaler blocklist"
#
# remove_url_from_zscaler_blocklist:
#   "Unblock example.com in Zscaler"
#   "Remove test.com from Zscaler blocklist"
#
# --- User Tools ---
#
# search_zscaler_users:
#   "Find user john.doe in Zscaler"
#   "Search for users named Smith in Zscaler"
#
# get_zscaler_departments:
#   "List Zscaler departments"
#   "What departments are in Zscaler?"
#
# --- Status Tools ---
#
# get_zscaler_status:
#   "What's the Zscaler activation status?"
#   "Are there pending changes in Zscaler?"
#
# activate_zscaler_changes:
#   "Activate Zscaler changes"
#   "Push Zscaler configuration"
#
# --- Combined/Natural Queries ---
#
#   "Check if evil-phishing-site.com is blocked in Zscaler"
#   "What does Zscaler say about this suspicious URL?"
#   "Add this malicious domain to Zscaler blocklist and activate"
#
# =============================================================================
