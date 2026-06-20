"""CVE triage & exposure tools.

Conversational vulnerability-remediation lookups: our triage verdict for a CVE
(priority/SLA/action, or live risk facts when not yet triaged), and which
applications in the portfolio are affected (Veracode SCA).
"""

import logging
from typing import Union

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool(tags={"readonly"})
def cve_triage_lookup(cve_id: str) -> dict:
    """Get our remediation verdict and risk facts for a CVE.

    Returns our stored triage verdict (priority P1-P4, SLA, remediation_required,
    recommended_action, affected component, attack layer, and risk signals: CVSS,
    CISA KEV, EPSS) when the CVE has been triaged. Otherwise returns the live,
    no-LLM facts (NVD CVSS, KEV, EPSS, affected products, Veracode affected-app
    count). The slow LLM triage debate is not run here.

    Args:
        cve_id: A CVE identifier, e.g. "CVE-2025-24813".
    """
    from services import cve_lookup

    return cve_lookup.triage_lookup(cve_id)


@mcp.tool(tags={"readonly"})
def cve_app_exposure(query: Union[str, int]) -> dict:
    """Find which applications are affected by a CVE or carry a named package.

    Maps a CVE id or open-source package name to applications in the Veracode
    portfolio that carry the vulnerable component, per open SCA findings. A miss
    is not proof the package is absent from every app's full SBOM.

    Args:
        query: A CVE id (e.g. "CVE-2021-44228") or a package name (e.g. "log4j-core").
    """
    from services import cve_lookup

    return cve_lookup.app_exposure(query)
