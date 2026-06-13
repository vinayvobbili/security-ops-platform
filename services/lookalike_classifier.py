"""Risk classification for lookalike domains.

Turns the raw facts gathered for a candidate (DNS, WHOIS registrar/nameservers,
parking status, age) into a coarse disposition the dashboard and alerts use:

- ``defensive``  — the brand owner (or an allowlisted entity) registered it to
  keep it out of an attacker's hands; not a threat.
- ``parked``     — registered but a for-sale/placeholder page; low priority.
- ``high_risk``  — mail-capable or freshly-stood-up impersonation infra.
- ``suspicious`` — registered and resolving, no benign explanation yet.
- ``unknown``    — too little signal to classify.

The brand-protection registrar list is the strongest defensive signal: these
registrars are used almost exclusively by corporate brand-protection programs,
so a lookalike sitting at one is overwhelmingly the brand defending itself.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Registrars used predominantly by corporate brand-protection / IP-management
# programs. A lookalike registered through one of these is almost always a
# defensive registration by the brand owner.
_BRAND_PROTECTION_REGISTRARS = (
    "markmonitor", "csc corporate domains", "cscglobal", "com laude", "comlaude",
    "safenames", "nom-iq", "ebrandservices", "brandsight", "gandi corporate",
    "fairwinds", "ldhouse", "in2net", "网络营销", "corporation service company",
)


def _norm(val: Any) -> str:
    return str(val or "").strip().lower()


def _nameservers(domain_data: Dict[str, Any]) -> List[str]:
    ns = (domain_data.get("whois_name_servers")
          or domain_data.get("name_servers")
          or domain_data.get("dns_ns") or [])
    if isinstance(ns, str):
        ns = [ns]
    return [_norm(n) for n in ns if n]


def detect_defensive_registration(
    domain_data: Dict[str, Any],
    monitored_domain: Optional[str] = None,
    defensive_allowlist: Optional[List[str]] = None,
) -> bool:
    """Return True when the candidate looks like a defensive registration.

    Defensive signals: it's on the per-brand allowlist, it's registered through
    a brand-protection registrar, or its registrant org matches the brand name.
    """
    domain = _norm(domain_data.get("domain"))
    allowlist = {_norm(d) for d in (defensive_allowlist or [])}
    if domain and domain in allowlist:
        return True

    registrar = _norm(domain_data.get("registrar"))
    if registrar and any(bp in registrar for bp in _BRAND_PROTECTION_REGISTRARS):
        return True

    # Registrant org matching the protected brand's label (e.g. "acme" in
    # "Acme Inc") is a strong ownership signal.
    if monitored_domain:
        brand_label = _norm(monitored_domain).split(".")[0]
        registrant = _norm(domain_data.get("registrant_org") or domain_data.get("registrant"))
        if brand_label and len(brand_label) >= 3 and brand_label in registrant:
            return True

    return False


def classify_domain_risk(
    domain_data: Dict[str, Any],
    monitored_domain: Optional[str] = None,
    defensive_allowlist: Optional[List[str]] = None,
) -> str:
    """Classify a single lookalike into a risk disposition.

    Returns one of ``defensive``, ``parked``, ``high_risk``, ``suspicious``,
    ``unknown``.
    """
    if detect_defensive_registration(domain_data, monitored_domain, defensive_allowlist):
        return "defensive"

    if domain_data.get("parked") is True:
        return "parked"

    has_ips = bool(domain_data.get("dns_a") or domain_data.get("dns_aaaa"))
    has_mx = bool(domain_data.get("dns_mx"))
    registered = bool(domain_data.get("registered") or has_ips or has_mx
                      or domain_data.get("registrar"))

    if not registered:
        return "unknown"

    # Mail-capable infra (MX) or a freshly-registered, live domain is the
    # highest-priority impersonation signal.
    newly_registered = bool(domain_data.get("newly_registered"))
    if has_mx or (newly_registered and has_ips):
        return "high_risk"

    if has_ips:
        return "suspicious"

    # Registered (WHOIS present) but not resolving — registered placeholder.
    return "suspicious" if registered else "unknown"
