# /my_bot/tools/cve_tools.py
"""
CVE Triage & Exposure Tools

Conversational vulnerability-remediation lookups for SOC analysts:
  - lookup_cve_triage: our triage verdict (priority/SLA/action) or live risk facts
  - check_cve_app_exposure: which of our apps are affected (Veracode SCA)

Backed by services.cve_lookup (which composes services.cve_triage + veracode).
"""

from typing import Union

from my_bot.tools._tagging import readonly_tool
from src.utils.tool_decorator import log_tool_call

from services import cve_lookup


@readonly_tool
@log_tool_call
def lookup_cve_triage(cve_id: str) -> str:
    """Get our remediation verdict and risk facts for a CVE.

    USE THIS TOOL when the user asks how bad a CVE is for us, whether we need to
    remediate it, its priority/SLA, or "what's our triage verdict for CVE-X".

    If the CVE has already been triaged, returns our stored verdict: priority
    (P1-P4), SLA, whether remediation is required, the recommended action,
    affected component, attack layer, and risk signals (CVSS, CISA KEV, EPSS).
    If it has NOT been triaged yet, returns the live facts an analyst would look
    up (NVD CVSS, KEV, EPSS, affected products, and the Veracode SCA affected-app
    count) — without running the slow LLM triage (that's on the web page).

    Args:
        cve_id: A CVE identifier, e.g. "CVE-2025-24813".
    """
    return cve_lookup.triage_text(cve_id)


@readonly_tool
@log_tool_call
def check_cve_app_exposure(query: Union[str, int]) -> str:
    """Find which of our applications are affected by a CVE or carry a package.

    USE THIS TOOL when the user asks which apps / how many apps are affected by a
    CVE, or which apps carry a given open-source package — "are we exposed to
    CVE-X", "which applications run log4j", etc.

    Maps the CVE (or package name) to applications in our Veracode portfolio that
    carry the vulnerable component, per open SCA findings. A miss is NOT proof the
    package is absent from every app's full SBOM.

    Args:
        query: A CVE id (e.g. "CVE-2021-44228") or a package name (e.g. "log4j-core").
    """
    return cve_lookup.app_exposure_text(query)
