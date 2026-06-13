"""Lookalike-domain engine — candidate generation, DNS resolution, WHOIS, and
parking detection, powered by the open-source `domainflow` toolkit.

`domainflow` (https://pypi.org/project/domainflow/) owns the hard parts: it
generates the typo-squat / brand-impersonation space for a domain and carries
the WHOIS snapshot + page-scoring layers. This module is the thin adapter that
the rest of the app talks to — it turns domainflow's output into the
result shapes the monitoring pipeline, web routes, and bots already expect
(``get_domain_lookalikes`` → ``{success, domains:[...]}``, etc.).

Design notes:
- ``domainflow`` is imported lazily inside the functions that need it, so this
  module always imports even before ``pip install -r requirements.txt`` has
  pulled it in. The network-backed calls degrade to a clean error/empty result
  when the dependency (or its optional extras) isn't present.
- DNS resolution uses the stdlib ``socket`` for A records, and ``dnspython``
  for AAAA/MX/NS when it's available — a domain that resolves to nothing is
  treated as unregistered.
"""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Brand+keyword dictionary used by the dictionary-combo generator and reused by
# the S3 brand-squatting scanner. Kept local so this module imports without the
# domainflow dependency present.
DICTIONARY_WORDS: List[str] = [
    "login", "signin", "secure", "verify", "auth", "account", "portal",
    "access", "support", "help", "service", "update", "pay", "payment",
    "billing", "home", "online", "web", "app", "my", "go", "get", "mail",
    "email", "vpn", "cloud", "api", "mobile", "admin", "corp", "global",
]

# Page/title markers that indicate a parked / for-sale placeholder rather than a
# stood-up impersonation site.
_PARKING_MARKERS = (
    "domain is for sale", "buy this domain", "this domain may be for sale",
    "domain for sale", "is for sale", "parked", "parking", "under construction",
    "buy now for", "domain parking", "godaddy", "sedo", "dan.com", "afternic",
    "hugedomains", "namecheap parking",
)

_RESOLVE_WORKERS = 50
_PARKING_WORKERS = 12


def _domainflow():
    """Return the domainflow package, or raise a clear ImportError if missing."""
    try:
        import domainflow  # noqa: F401
        return domainflow
    except ImportError as e:  # pragma: no cover - dependency guard
        raise ImportError(
            "the domain lookalike engine needs the 'domainflow' package: "
            "pip install 'domainflow[ct,whois,score]'"
        ) from e


def _resolve(domain: str) -> Dict[str, Any]:
    """Resolve the DNS facts the pipeline cares about for one candidate.

    A records come from the stdlib; AAAA/MX/NS are filled in when ``dnspython``
    is available. ``registered`` is True when anything resolves at all.
    """
    a: List[str] = []
    aaaa: List[str] = []
    mx: List[str] = []
    ns: List[str] = []
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        a = list(dict.fromkeys(ips))
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        pass

    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = 4.0
        for rtype, bucket in (("AAAA", aaaa), ("MX", mx), ("NS", ns)):
            try:
                for ans in resolver.resolve(domain, rtype):
                    if rtype == "MX":
                        bucket.append(str(ans.exchange).rstrip("."))
                    else:
                        bucket.append(str(ans).rstrip("."))
            except Exception:
                pass
    except ImportError:
        pass

    return {
        "dns_a": a,
        "dns_aaaa": list(dict.fromkeys(aaaa)),
        "dns_mx": list(dict.fromkeys(mx)),
        "dns_ns": list(dict.fromkeys(ns)),
        "registered": bool(a or aaaa or mx or ns),
    }


def get_domain_lookalikes(
    domain: str,
    registered_only: bool = True,
    include_dictionary_combos: bool = True,
) -> Dict[str, Any]:
    """Generate the lookalike space for ``domain`` and resolve each candidate.

    Args:
        domain: the legitimate domain to protect (e.g. ``acme.com``).
        registered_only: only return candidates that currently resolve (the
            actionable set). When False, every generated candidate is returned
            with whatever DNS resolved — a much larger, slower result.
        include_dictionary_combos: include the brand+keyword combinations
            (``acme-login.com``) in addition to the classic typo-squats.

    Returns:
        ``{success, domain, domains: [{domain, fuzzer, registered, dns_a,
        dns_aaaa, dns_mx, dns_ns, geoip, parked}], count}``.
    """
    try:
        from domainflow import generate_lookalikes
        from domainflow.discover import DEFAULT_FUZZERS
    except ImportError as e:
        logger.warning("Lookalike engine unavailable: %s", e)
        return {"success": False, "error": str(e), "domain": domain, "domains": []}

    try:
        fuzzers = list(DEFAULT_FUZZERS)
        if not include_dictionary_combos:
            fuzzers = [f for f in fuzzers if f != "dictionary-combo"]

        candidates = generate_lookalikes(domain, fuzzers=fuzzers, keywords=DICTIONARY_WORDS)
        results: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=_RESOLVE_WORKERS) as ex:
            futures = {ex.submit(_resolve, la.domain): la for la in candidates}
            for fut in concurrent.futures.as_completed(futures):
                la = futures[fut]
                try:
                    rec = fut.result()
                except Exception:
                    rec = {"dns_a": [], "dns_aaaa": [], "dns_mx": [],
                           "dns_ns": [], "registered": False}
                if registered_only and not rec["registered"]:
                    continue
                results.append({
                    "domain": la.domain,
                    "fuzzer": la.fuzzer,
                    "geoip": "",
                    "parked": None,
                    **rec,
                })

        results.sort(key=lambda d: d["domain"])
        return {"success": True, "domain": domain, "domains": results, "count": len(results)}
    except Exception as e:
        logger.error("Lookalike generation failed for %s: %s", domain, e, exc_info=True)
        return {"success": False, "error": str(e), "domain": domain, "domains": []}


def check_if_parked_content(domain: str) -> bool:
    """Fetch the domain's page and decide whether it's a parked/for-sale
    placeholder. Returns False on any error or unreachable page."""
    try:
        from domainflow import score
    except ImportError:
        return False
    try:
        signals = score.gather_signals(domain, verify_tls=False)
    except Exception as e:
        logger.debug("Parking check failed for %s: %s", domain, e)
        return False

    page = signals.get("page") or {}
    if not page.get("reachable"):
        return False
    blob = " ".join([
        (signals.get("page_text_excerpt") or ""),
        (page.get("title") or ""),
        (page.get("final_url") or ""),
    ]).lower()
    return any(marker in blob for marker in _PARKING_MARKERS)


def check_if_parked(domain: str) -> bool:
    """Single-domain parking check (legacy alias for content-based detection)."""
    return check_if_parked_content(domain)


def check_parking_batch(domains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Set ``parked`` on each domain dict in ``domains`` (in place) by fetching
    each page. Best-effort and threaded; a failure leaves ``parked`` as None."""
    if not domains:
        return domains

    def _check(entry: Dict[str, Any]) -> None:
        try:
            entry["parked"] = check_if_parked_content(entry.get("domain", ""))
        except Exception:
            entry.setdefault("parked", None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=_PARKING_WORKERS) as ex:
        list(ex.map(_check, domains))
    return domains


def get_domain_whois_info(domain: str) -> Dict[str, Any]:
    """Return normalized WHOIS info for ``domain``.

    Returns ``{success, domain, creation_date (YYYY-MM-DD|None), registrar,
    name_servers}``. ``success`` is False when the WHOIS extra isn't installed
    or the lookup yields nothing usable.
    """
    try:
        from domainflow.monitor import whois as df_whois
    except ImportError as e:
        return {"success": False, "error": str(e), "domain": domain}

    try:
        snap = df_whois.snapshot(domain)
    except Exception as e:
        return {"success": False, "error": str(e), "domain": domain}

    if not (snap.get("registrar") or snap.get("created") or snap.get("name_servers")):
        return {"success": False, "error": snap.get("error") or "no whois data",
                "domain": domain}

    created = snap.get("created")
    creation_date = created.split("T")[0] if isinstance(created, str) else None
    return {
        "success": True,
        "domain": domain,
        "creation_date": creation_date,
        "registrar": snap.get("registrar"),
        "name_servers": snap.get("name_servers") or [],
    }


def check_dnstwist_available() -> Dict[str, Any]:
    """Health probe for the lookalike engine. Reports whether ``domainflow`` is
    importable so the connectors page can show the engine's status."""
    try:
        df = _domainflow()
        return {"available": True, "engine": "domainflow",
                "version": getattr(df, "__version__", "unknown")}
    except ImportError as e:
        return {"available": False, "error": str(e)}


def enrich_with_recorded_future(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Optional commercial risk-scoring enrichment.

    No-op pass-through in the open-source build — wire a provider in
    ``services.risk_enrichment`` to populate ``rf_risk_score``/evidence. Returns
    the records unchanged so callers degrade gracefully when none is configured.
    """
    try:
        from services.risk_enrichment import enrich_domains
    except ImportError:
        logger.info("Risk-scoring provider not configured; skipping (%d records)",
                    len(records or []))
        return records
    return enrich_domains(records)
