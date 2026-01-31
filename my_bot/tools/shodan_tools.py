"""
Shodan Tools Module

Provides Shodan API integration for infrastructure reconnaissance.
Returns open ports, running services, SSL certificates, and known vulnerabilities.

Useful for:
- Identifying exposed services on IPs/domains
- Finding open ports and what's running on them
- Checking for known CVEs on infrastructure
- IoT device discovery and fingerprinting

Note: Free tier is limited to ~100 queries/month. Use conservatively.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.shodan_monitor import ShodanClient
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized Shodan client
_shodan_client: Optional[ShodanClient] = None


def _get_shodan_client() -> Optional[ShodanClient]:
    """Get Shodan client (lazy initialization)."""
    global _shodan_client
    if _shodan_client is None:
        try:
            client = ShodanClient()
            if client.is_configured():
                _shodan_client = client
            else:
                logger.warning("Shodan client not configured (missing API key)")
        except Exception as e:
            logger.error(f"Failed to initialize Shodan client: {e}")
    return _shodan_client


def _get_risk_emoji(port: int, product: str = "") -> str:
    """Get risk indicator emoji based on port/service."""
    # High risk - remote access and databases
    if port in [21, 23, 3389, 5900]:  # FTP, Telnet, RDP, VNC
        return "🔴"
    if port in [1433, 3306, 5432, 27017, 6379]:  # SQL Server, MySQL, PostgreSQL, MongoDB, Redis
        return "🔴"
    # Medium risk - common attack targets
    if port in [22, 25, 445, 139]:  # SSH, SMTP, SMB
        return "🟠"
    # Admin interfaces
    if "admin" in product.lower() or "management" in product.lower():
        return "🟠"
    # Standard web services
    if port in [80, 443, 8080, 8443]:
        return "🟢"
    return "⚪"


def _format_ip_result(data: dict) -> str:
    """Format IP lookup result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    ip = data.get("ip", "Unknown")
    ports = data.get("ports", [])
    vulns = data.get("vulns", [])
    services = data.get("services", [])
    hostnames = data.get("hostnames", [])

    result = [
        f"## Shodan IP Analysis",
        f"**IP Address:** {ip}",
        f"**Organization:** {data.get('org', 'Unknown')}",
        f"**ISP:** {data.get('isp', 'Unknown')}",
        f"**ASN:** {data.get('asn', 'Unknown')}",
        f"**Location:** {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
    ]

    if hostnames:
        result.append(f"**Hostnames:** {', '.join(hostnames[:5])}")

    if data.get("last_update"):
        result.append(f"**Last Seen:** {data['last_update'][:10]}")

    # Open ports summary
    result.append("")
    result.append(f"### Open Ports ({len(ports)})")
    if ports:
        result.append(f"`{', '.join(map(str, sorted(ports)))}`")
    else:
        result.append("No open ports detected")

    # Services detail
    if services:
        result.append("")
        result.append("### Running Services")
        for svc in services[:15]:  # Limit to 15 services
            port = svc.get("port", "?")
            protocol = svc.get("protocol", "tcp")
            product = svc.get("product") or "Unknown"
            version = svc.get("version") or ""
            module = svc.get("module") or ""

            risk_emoji = _get_risk_emoji(port, product)
            service_line = f"{risk_emoji} **{port}/{protocol}**"

            if product != "Unknown":
                service_line += f" - {product}"
                if version:
                    service_line += f" {version}"
            elif module:
                service_line += f" - {module}"

            # SSL indicator
            if svc.get("ssl"):
                service_line += " 🔒"
                ssl_cert = svc.get("ssl_cert", {})
                if ssl_cert:
                    cn = ssl_cert.get("CN", "")
                    if cn:
                        service_line += f" (CN: {cn})"

            result.append(service_line)

    # Vulnerabilities
    if vulns:
        result.append("")
        result.append(f"### ⚠️ Known Vulnerabilities ({len(vulns)})")
        for vuln in vulns[:10]:  # Limit to 10 CVEs
            result.append(f"- **{vuln}**")
        if len(vulns) > 10:
            result.append(f"- _...and {len(vulns) - 10} more_")

    # Risk assessment
    result.append("")
    result.append("### Risk Assessment")
    high_risk_ports = [p for p in ports if p in [21, 23, 3389, 5900, 1433, 3306, 5432, 27017, 6379]]
    if vulns:
        result.append(f"🔴 **HIGH** - {len(vulns)} known CVE(s) detected")
    elif high_risk_ports:
        result.append(f"🟠 **MEDIUM** - Sensitive ports exposed: {high_risk_ports}")
    elif len(ports) > 10:
        result.append(f"🟡 **LOW** - Many ports open ({len(ports)}), review services")
    else:
        result.append("🟢 **LOW** - No critical exposures detected")

    result.append("")
    result.append(f"🔗 [View on Shodan](https://www.shodan.io/host/{ip})")

    return "\n".join(result)


def _format_domain_result(data: dict) -> str:
    """Format domain lookup result for display."""
    if not data.get("success"):
        return f"Error: {data.get('error', 'Unknown error')}"

    domain = data.get("domain", "Unknown")
    hosts = data.get("hosts", [])
    total_ports = data.get("total_ports", 0)
    total_vulns = data.get("total_vulns", 0)
    exposed_services = data.get("exposed_services", [])
    vulnerabilities = data.get("vulnerabilities", [])

    result = [
        f"## Shodan Domain Infrastructure Analysis",
        f"**Domain:** {domain}",
        f"**IPs Checked:** {data.get('ips_checked', 0)}",
        f"**Total Open Ports:** {total_ports}",
        f"**Total Vulnerabilities:** {total_vulns}",
    ]

    # Risk summary
    result.append("")
    if total_vulns > 0:
        result.append(f"### ⚠️ Risk Level: 🔴 HIGH")
        result.append(f"Found {total_vulns} known vulnerabilities across infrastructure")
    elif exposed_services:
        result.append(f"### ⚠️ Risk Level: 🟠 MEDIUM")
        result.append(f"Found {len(exposed_services)} potentially risky exposed services")
    else:
        result.append(f"### Risk Level: 🟢 LOW")
        result.append("No critical exposures detected")

    # Exposed risky services
    if exposed_services:
        result.append("")
        result.append("### Risky Exposed Services")
        for svc in exposed_services[:10]:
            ip = svc.get("ip", "?")
            port = svc.get("port", "?")
            product = svc.get("product", "Unknown")
            reason = svc.get("risk_reason", "")
            result.append(f"- 🔴 **{ip}:{port}** - {product}")
            if reason:
                result.append(f"  _{reason}_")

    # Vulnerabilities found
    if vulnerabilities:
        result.append("")
        result.append("### Detected CVEs")
        for vuln in vulnerabilities[:10]:
            ip = vuln.get("ip", "?")
            cve = vuln.get("cve", "Unknown")
            result.append(f"- **{cve}** on {ip}")
        if len(vulnerabilities) > 10:
            result.append(f"- _...and {len(vulnerabilities) - 10} more_")

    # Per-host summary
    result.append("")
    result.append("### Host Details")
    for host in hosts:
        if host.get("error"):
            result.append(f"- **{host.get('ip')}**: {host.get('error')}")
        else:
            ip = host.get("ip", "?")
            ports = host.get("ports", [])
            org = host.get("org", "Unknown")
            vulns = host.get("vulns", [])
            vuln_indicator = f" ⚠️ {len(vulns)} CVEs" if vulns else ""
            result.append(f"- **{ip}** ({org}) - {len(ports)} ports{vuln_indicator}")

    return "\n".join(result)


@tool
@log_tool_call
def lookup_ip_shodan(ip_address: str) -> str:
    """Look up an IP address in Shodan for exposed services and vulnerabilities.

    Use this tool when a user wants to know what services are running on an IP,
    what ports are open, or if there are any known vulnerabilities.

    Shodan is useful for:
    - Identifying exposed services (web servers, databases, IoT devices)
    - Finding open ports and what software is running
    - Checking for known CVEs on the target
    - Getting SSL certificate information
    - Understanding the attack surface of an IP

    Note: Uses 1 query credit per lookup. Free tier has ~100 queries/month.

    Args:
        ip_address: The IP address to look up (e.g., "8.8.8.8")
    """
    client = _get_shodan_client()
    if not client:
        return "Error: Shodan service is not available."

    try:
        data = client.lookup_ip(ip_address.strip())
        return _format_ip_result(data)
    except Exception as e:
        logger.error(f"Shodan IP lookup failed: {e}")
        return f"Error looking up IP in Shodan: {str(e)}"


@tool
@log_tool_call
def lookup_domain_shodan(domain: str) -> str:
    """Look up a domain's infrastructure in Shodan for exposed services.

    Use this tool when a user wants to understand the attack surface of a domain,
    find what servers/services are exposed, or check for vulnerabilities.

    This resolves the domain to IPs and checks each one in Shodan, providing:
    - All open ports across the domain's infrastructure
    - Running services and their versions
    - Known CVEs affecting the infrastructure
    - Potentially risky exposed services (databases, admin panels, etc.)

    Note: Uses 1 query credit per IP (up to 3 IPs checked to conserve credits).

    Args:
        domain: The domain to look up (e.g., "example.com")
    """
    client = _get_shodan_client()
    if not client:
        return "Error: Shodan service is not available."

    try:
        # Clean up domain input
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        data = client.lookup_domain(domain)
        return _format_domain_result(data)
    except Exception as e:
        logger.error(f"Shodan domain lookup failed: {e}")
        return f"Error looking up domain in Shodan: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover Shodan capabilities:
#
# - "Check 8.8.8.8 on Shodan"
# - "What ports are open on 192.168.1.1?"
# - "Look up example.com infrastructure on Shodan"
# - "Does this IP have any known vulnerabilities: 10.0.0.1"
# - "What services are running on 203.0.113.1?"
# - "Check Shodan for exposed services on my-domain.com"
# =============================================================================
