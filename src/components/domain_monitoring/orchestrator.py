"""Domain monitoring orchestrator.

Main entry point for daily domain monitoring. Coordinates all monitoring
checks and sends appropriate alerts.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict

from services.abusech import bulk_check_domains as abusech_bulk_check
from services.abuseipdb import bulk_check_domains as abuseipdb_bulk_check, AbuseIPDBClient
from services.cert_transparency import (
    check_lookalike_certs, check_suspicious_domains, discover_brand_impersonation
)
from services.dark_web_monitor import search_dark_web
from services.intelx import search_intelx, get_client as get_intelx_client
from services.domain_monitor import scan_domain
from services.hibp import check_domain_breaches, HIBPClient
from services.shodan_monitor import lookup_domain_infrastructure, ShodanClient
from services.whois_monitor import scan_domains_whois

from .config import (
    EASTERN_TZ, RESULTS_DIR, WEB_BASE_URL, CONFIG_FILE,
    ALERT_ROOM_ID_TEST, ALERT_ROOM_ID_PROD,
    ENABLE_DARK_WEB, ENABLE_INTELX,
    load_monitored_domains, load_watchlist, load_defensive_domains,
    get_webex_api, get_vt_client, set_active_room_id,
)
from .rf_watchlist import monitor_rf_watchlist, load_brand_keywords, brand_search_terms, brand_for_domain
from .enrichment import enrich_with_virustotal
from .alerts import send_daily_summary
# Individual alert functions disabled - only daily summary is sent
# All findings available on web dashboard at /domain-monitoring

logger = logging.getLogger(__name__)


def _merge_results(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Merge one staggered slot's results into the day's accumulated results.

    Per-domain findings are unioned; ``total_*`` counters are summed; the
    once-per-day global sweep sections (rf_watchlist, brand-keyword
    impersonation) are taken from whichever slot produced them. Slots scan
    disjoint domain sets and the global sweeps run in exactly one slot, so the
    additive merge never double-counts within a day.
    """
    existing.setdefault("domains", {}).update(new.get("domains", {}))
    for key, val in new.items():
        if key.startswith("total_") and isinstance(val, (int, float)):
            existing[key] = existing.get(key, 0) + val
    for key in ("rf_watchlist", "brand_keyword_impersonation"):
        if key in new:
            existing[key] = new[key]
    existing["scan_time"] = new.get("scan_time", existing.get("scan_time"))
    return existing


def _save_results(results: Dict[str, Any], merge: bool = False) -> str:
    """Save results to web-accessible JSON in a date-based directory.

    When ``merge`` is True and today's results file already exists (i.e. an
    earlier staggered slot ran), this slot's results are merged into it rather
    than overwriting — so the dashboard shows every brand's findings for the day,
    not just the last slot's. The first slot of the day (no file yet) always
    writes fresh, which also discards yesterday's ``latest.json``.
    """
    date_str = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d')
    date_dir = RESULTS_DIR / date_str
    date_dir.mkdir(parents=True, exist_ok=True)

    filename = "results.json"
    filepath = date_dir / filename

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    latest_filepath = RESULTS_DIR / "latest.json"

    if merge and filepath.exists():
        try:
            with open(filepath) as f:
                existing = json.load(f)
            results = _merge_results(existing, results)
            logger.info("Merged slot results into existing daily report")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not merge into existing results, overwriting: {e}")

    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        with open(latest_filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Saved monitoring results to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

    return filename


def run_daily_monitoring(
    room_id: str | None = None,
    domains_subset: list[str] | None = None,
    *,
    merge_results: bool = False,
    run_global_sweeps: bool = True,
    send_summary: bool = True,
) -> None:
    """Run daily monitoring for the configured (or a given subset of) domains.

    Called by the scheduler. With no extra args it preserves the original
    behaviour — scan every monitored domain, run the global sweeps, save fresh,
    and post the daily summary. The staggered scheduler drives it per-brand via
    ``run_brand_slot`` using the keyword-only flags.

    Args:
        room_id: Optional Webex room ID for alerts. Defaults to prod room.
        domains_subset: If given, scan only these domains (a staggered slot's
            partition) instead of the full monitored list.
        merge_results: Merge this run into today's accumulated report instead of
            overwriting it (used by staggered slots).
        run_global_sweeps: Run the once-per-day RF watchlist enrichment and
            brand-keyword CT sweep (the staggered scheduler enables this on the
            first slot only).
        send_summary: Post the Webex daily summary at the end (the staggered
            scheduler disables this and posts one consolidated summary later).

    Monitors for:
        - New lookalike domain registrations
        - Parked domains becoming active (HIGH PRIORITY)
        - New MX records (email infrastructure)
        - IP/GeoIP changes
        - Dark web findings (IntelX Tor/I2P)
        - Public leaks (GitHub, Pastebin)
        - New SSL certificates for lookalikes (CT logs)
        - WHOIS changes for lookalikes
        - VirusTotal malicious domain detection
        - HIBP credential breaches
        - Shodan infrastructure exposure
        - abuse.ch malware/C2 detection
        - AbuseIPDB malicious IP detection
    """
    if room_id:
        set_active_room_id(room_id)
    else:
        set_active_room_id(ALERT_ROOM_ID_PROD)

    monitored_domains = domains_subset if domains_subset is not None else load_monitored_domains()
    if not monitored_domains and not run_global_sweeps:
        logger.info("Slot has no domains and no global sweeps — nothing to do")
        return
    if not monitored_domains and run_global_sweeps:
        logger.warning("No domains configured for monitoring; running global sweeps only")

    logger.info(f"Starting domain monitoring for {len(monitored_domains)} domains")

    webex_api = get_webex_api()
    vt_client = get_vt_client()

    results = {
        "scan_time": datetime.now(EASTERN_TZ).isoformat(),
        "domains": {},
        "total_new_lookalikes": 0,
        "total_became_active": 0,
        "total_reregistered": 0,
        "total_mx_changes": 0,
        "total_dark_web_findings": 0,
        "total_ct_findings": 0,
        "total_watchlist_with_certs": 0,  # Semantic impersonation domains with SSL certs
        "total_censys_brand_impersonation": 0,  # Brand impersonation found via Censys CT search
        "total_whois_changes": 0,
        "total_vt_high_risk": 0,
        "total_hibp_breaches": 0,
        "total_shodan_exposures": 0,
        "total_abusech_malicious": 0,
        "total_abuseipdb_malicious": 0,
        "total_intelx_findings": 0,
        "total_rf_watchlist": 0,
        "total_rf_watchlist_high_risk": 0,
        "total_brand_keyword_impersonation": 0,
        "alerts_sent": 0,
    }

    for domain in monitored_domains:
        logger.info(f"Monitoring domain: {domain}")

        # Lookalike monitoring with full change detection
        lookalike_result = scan_domain(domain, check_parking=True)
        results["domains"][domain] = {"lookalikes": lookalike_result}

        all_lookalikes = []
        active_lookalikes = []

        if lookalike_result.get("success"):
            is_first_scan = lookalike_result.get("is_first_scan", False)

            new_count = lookalike_result.get("new_count", 0)
            became_active_count = lookalike_result.get("became_active_count", 0)
            mx_changes_count = lookalike_result.get("mx_changes_count", 0)

            reregistered_count = lookalike_result.get("reregistered_count", 0)

            results["total_new_lookalikes"] += new_count
            results["total_became_active"] += became_active_count
            results["total_reregistered"] += reregistered_count
            results["total_mx_changes"] += mx_changes_count

            for d in lookalike_result.get("new_domains", []):
                all_lookalikes.append(d.get("domain"))
            for d in lookalike_result.get("became_active", []):
                active_lookalikes.append(d.get("domain"))
                if d.get("domain") not in all_lookalikes:
                    all_lookalikes.append(d.get("domain"))
            for d in lookalike_result.get("reregistered", []):
                dn = d.get("domain")
                if dn not in active_lookalikes:
                    active_lookalikes.append(dn)
                if dn not in all_lookalikes:
                    all_lookalikes.append(dn)

            # Enrich domains with threat intel
            new_domains = lookalike_result.get("new_domains", [])
            became_active = lookalike_result.get("became_active", [])
            domains_for_vt = new_domains + became_active
            # RF enrichment: enrich all domains (enterprise API key has no limits)
            domains_for_rf = new_domains + became_active

            if domains_for_vt:
                try:
                    enrich_with_virustotal(domains_for_vt, max_checks=50)
                    logger.info(f"VT enrichment complete for {len(domains_for_vt)} domains")
                except Exception as e:
                    logger.warning(f"VT enrichment failed: {e}")

            if domains_for_rf:
                # Optional risk-scoring enrichment via an external threat-intel
                # provider. Wired in environments that have one configured; the
                # pipeline runs fine without it.
                try:
                    from services.risk_enrichment import enrich_domains as enrich_with_recorded_future
                    enrich_with_recorded_future(domains_for_rf)
                    logger.info(f"Risk enrichment complete for {len(domains_for_rf)} domains")
                except ImportError:
                    logger.info("Risk enrichment provider not configured; skipping")
                except Exception as e:
                    logger.warning(f"Risk enrichment failed: {e}")

            # Individual alerts disabled - only daily summary is sent
            # All findings are available on the web dashboard
            pass

        # Dark web monitoring (public leaks)
        if ENABLE_DARK_WEB:
            dark_web_result = search_dark_web(domain)
            results["domains"][domain]["dark_web"] = dark_web_result

            if dark_web_result.get("success"):
                findings = dark_web_result.get("total_findings", 0)
                high_risk = len(dark_web_result.get("high_risk_findings", []))
                results["total_dark_web_findings"] += findings

        # IntelligenceX dark web search (actual Tor/I2P)
        if ENABLE_INTELX:
            intelx_client = get_intelx_client()
            if intelx_client and intelx_client.api_key:
                logger.info(f"Searching IntelligenceX for {domain}")
                try:
                    intelx_result = search_intelx(domain)
                    results["domains"][domain]["intelx"] = intelx_result

                    if intelx_result.get("success"):
                        intelx_findings = intelx_result.get("total_findings", 0)
                        results["total_intelx_findings"] += intelx_findings
                except Exception as e:
                    logger.error(f"IntelligenceX search failed for {domain}: {e}")
                    results["domains"][domain]["intelx"] = {"success": False, "error": str(e)}
            else:
                logger.info("IntelligenceX not configured, skipping dark web search")
                results["domains"][domain]["intelx"] = {"success": False, "error": "API key not configured"}

        # Certificate Transparency monitoring
        if all_lookalikes:
            logger.info(f"Checking CT logs for {len(all_lookalikes)} lookalike domains")
            ct_result = check_lookalike_certs(all_lookalikes, days_back=7)
            results["domains"][domain]["ct_logs"] = ct_result

            if ct_result.get("success"):
                ct_findings = len(ct_result.get("high_risk_domains", []))
                results["total_ct_findings"] += ct_findings
                # Individual CT alert disabled - included in daily summary

        # Watchlist monitoring for semantic impersonation domains
        # These are domains like "acme-loan.com" that dnstwist can't detect
        watchlist_domains = load_watchlist(domain)
        if watchlist_domains:
            logger.info(f"Checking CT logs for {len(watchlist_domains)} watchlist domains")
            watchlist_result = check_suspicious_domains(watchlist_domains, days_back=90)
            results["domains"][domain]["watchlist"] = watchlist_result

            if watchlist_result.get("success"):
                domains_with_certs = watchlist_result.get("domains_with_certs", [])
                results["total_watchlist_with_certs"] += len(domains_with_certs)

                # Add watchlist domains with certs to active_lookalikes for further enrichment
                for d in domains_with_certs:
                    if d["domain"] not in active_lookalikes:
                        active_lookalikes.append(d["domain"])

        # Brand CT log search for impersonation (via crt.sh - FREE)
        # This catches semantic attacks like acme-loan.com that dnstwist cannot detect
        # by searching for ANY certificate containing the brand name
        brand_name = domain.split('.')[0]  # e.g., "acme" from "acme.com"

        # Load brand-specific legitimate domains from config
        try:
            with open(CONFIG_FILE) as f:
                brand_config = json.load(f).get("brand_monitoring", {}).get(brand_name, {})
            legitimate_domains = brand_config.get("legitimate_domains", [])
        except (FileNotFoundError, json.JSONDecodeError):
            legitimate_domains = []

        # Fall back to defensive domains if no brand config
        if not legitimate_domains:
            legitimate_domains = load_defensive_domains(domain)

        logger.info(f"Searching crt.sh CT logs for '{brand_name}' brand impersonation")

        try:
            brand_result = discover_brand_impersonation(
                brand=brand_name,
                legitimate_domains=legitimate_domains,
                hours_back=168,  # Look back 7 days to catch certs issued between daily runs
            )
            results["domains"][domain]["brand_ct_search"] = brand_result

            if brand_result.get("success"):
                new_domains = brand_result.get("new_domains", [])
                results["total_censys_brand_impersonation"] += len(new_domains)

                # Add newly discovered impersonation domains to active_lookalikes
                for imp in new_domains:
                    imp_domain = imp.get("domain")
                    if imp_domain and imp_domain not in active_lookalikes:
                        active_lookalikes.append(imp_domain)
                        logger.warning(f"CT logs discovered brand impersonation: {imp_domain}")

                if new_domains:
                    logger.warning(
                        f"Found {len(new_domains)} NEW brand impersonation domains "
                        f"with SSL certs for '{brand_name}'"
                    )
                else:
                    logger.info(f"Brand monitoring for '{brand_name}': no new suspicious domains")
        except Exception as e:
            logger.error(f"Brand CT search failed for {domain}: {e}")
            results["domains"][domain]["brand_ct_search"] = {"success": False, "error": str(e)}

        # S3 brand squatting scan is on-demand only — ~700 candidates throttled at
        # 3s/request (single worker) takes ~70 min, which exceeds the 30-min job
        # timeout. Run it from the web UI when needed.

        # WHOIS monitoring for active lookalikes
        if active_lookalikes:
            logger.info(f"Checking WHOIS for {len(active_lookalikes)} active lookalike domains")
            whois_result = scan_domains_whois(active_lookalikes)
            results["domains"][domain]["whois"] = whois_result

            if whois_result.get("success"):
                whois_changes = whois_result.get("domains_with_changes", 0)
                results["total_whois_changes"] += whois_changes
                # Individual WHOIS alert disabled - included in daily summary

        # VirusTotal bulk scan
        if active_lookalikes and vt_client:
            logger.info(f"Running VT scan for {len(active_lookalikes)} active lookalike domains")
            vt_result = vt_client.bulk_domain_lookup(active_lookalikes)
            results["domains"][domain]["virustotal"] = vt_result

            if vt_result.get("success"):
                vt_high = len(vt_result.get("high_risk", []))
                results["total_vt_high_risk"] += vt_high
                # Individual VT alert disabled - included in daily summary

        # HaveIBeenPwned check
        hibp_client = HIBPClient()
        if hibp_client.is_configured():
            logger.info(f"Checking HIBP for {domain} email addresses")
            hibp_result = check_domain_breaches(domain, max_checks=20)
            results["domains"][domain]["hibp"] = hibp_result

            if hibp_result.get("success"):
                breached_count = hibp_result.get("emails_breached", 0)
                results["total_hibp_breaches"] += breached_count
                # Individual HIBP alert disabled - included in daily summary
        else:
            logger.warning("HIBP API key not configured, skipping breach check")
            results["domains"][domain]["hibp"] = {"success": False, "error": "API key not configured"}

        # Shodan infrastructure check
        shodan_client = ShodanClient()
        if shodan_client.is_configured():
            logger.info(f"Checking Shodan for {domain} infrastructure")
            shodan_result = lookup_domain_infrastructure(domain)
            results["domains"][domain]["shodan"] = shodan_result

            if shodan_result.get("success"):
                exposures = len(shodan_result.get("exposed_services", []))
                vulns = shodan_result.get("total_vulns", 0)
                results["total_shodan_exposures"] += exposures
                # Individual Shodan alert disabled - included in daily summary
        else:
            logger.warning("Shodan API key not configured, skipping infrastructure check")
            results["domains"][domain]["shodan"] = {"success": False, "error": "API key not configured"}

        # abuse.ch malware/C2 check
        if active_lookalikes:
            logger.info(f"Checking abuse.ch for {len(active_lookalikes)} active lookalike domains")
            abusech_result = abusech_bulk_check(active_lookalikes)
            results["domains"][domain]["abusech"] = abusech_result

            if abusech_result.get("success"):
                malicious_count = len(abusech_result.get("malicious_domains", []))
                results["total_abusech_malicious"] += malicious_count
                # Individual abuse.ch alert disabled - included in daily summary

        # AbuseIPDB check
        abuseipdb_client = AbuseIPDBClient()
        if active_lookalikes and abuseipdb_client.is_configured():
            logger.info(f"Checking AbuseIPDB for {len(active_lookalikes)} active lookalike domains")
            abuseipdb_result = abuseipdb_bulk_check(active_lookalikes)
            results["domains"][domain]["abuseipdb"] = abuseipdb_result

            if abuseipdb_result.get("success"):
                malicious_count = len(abuseipdb_result.get("domains_with_malicious_ips", []))
                results["total_abuseipdb_malicious"] += malicious_count
                # Individual AbuseIPDB alert disabled - included in daily summary
        elif active_lookalikes:
            logger.warning("AbuseIPDB API key not configured, skipping IP reputation check")
            results["domains"][domain]["abuseipdb"] = {"success": False, "error": "API key not configured"}

    # Global, once-per-day sweeps. Under the staggered scheduler these run on the
    # first slot only; a standalone run does them too.
    if run_global_sweeps:
        # Watchlist sweep — onboarded brand-keyword domains (subsidiary and
        # partner brands). Batched risk enrichment + bulk reputation.
        try:
            rf_watchlist_result = monitor_rf_watchlist()
            results["rf_watchlist"] = rf_watchlist_result
            if rf_watchlist_result.get("success"):
                results["total_rf_watchlist"] = rf_watchlist_result.get("total", 0)
                results["total_rf_watchlist_high_risk"] = rf_watchlist_result.get("high_risk_count", 0)
                logger.info(
                    f"RF watchlist: {results['total_rf_watchlist']} domains, "
                    f"{results['total_rf_watchlist_high_risk']} high risk"
                )
        except Exception as e:
            logger.error(f"RF watchlist monitoring failed: {e}")
            results["rf_watchlist"] = {"success": False, "error": str(e)}

        # Widen the crt.sh impersonation sweep to every brand keyword, not just
        # the primary monitored domains — this is how "all brand keywords" get
        # coverage without running the heavy per-domain pipeline for each. Each
        # brand is swept under all of its spelling variants (concatenated /
        # hyphenated) and de-duplicated by domain.
        keywords = load_brand_keywords()
        brand_keyword_hits = []
        seen_imp = set()
        for keyword in keywords:
            for term in brand_search_terms(keyword):
                try:
                    kw_result = discover_brand_impersonation(
                        brand=term,
                        legitimate_domains=[],
                        hours_back=168,
                    )
                    if kw_result.get("success"):
                        for imp in kw_result.get("new_domains", []):
                            dom = imp.get("domain")
                            if dom and dom in seen_imp:
                                continue
                            if dom:
                                seen_imp.add(dom)
                            imp["brand_keyword"] = keyword
                            imp["matched_term"] = term
                            brand_keyword_hits.append(imp)
                except Exception as e:
                    logger.error(f"Brand keyword CT sweep failed for '{term}': {e}")
        results["brand_keyword_impersonation"] = {
            "success": True,
            "new_domains": brand_keyword_hits,
            "keywords_searched": keywords,
        }
        results["total_brand_keyword_impersonation"] = len(brand_keyword_hits)
        if brand_keyword_hits:
            logger.warning(
                f"Brand keyword sweep found {len(brand_keyword_hits)} new impersonation "
                f"domains across {len(keywords)} brand keywords"
            )

    logger.info(
        f"Monitoring complete: {results['total_new_lookalikes']} new lookalikes, "
        f"{results['total_became_active']} became active, "
        f"{results['total_reregistered']} re-registered, "
        f"{results['total_mx_changes']} MX changes, "
        f"{results['total_dark_web_findings']} data leak findings, "
        f"{results['total_intelx_findings']} IntelX dark web findings, "
        f"{results['total_ct_findings']} CT findings, "
        f"{results['total_watchlist_with_certs']} watchlist domains with SSL certs, "
        f"{results['total_censys_brand_impersonation']} Censys brand impersonation domains, "
        f"{results['total_whois_changes']} WHOIS changes, "
        f"{results['total_vt_high_risk']} VT high risk, "
        f"{results['total_hibp_breaches']} HIBP breaches, "
        f"{results['total_shodan_exposures']} Shodan exposures, "
        f"{results['total_abusech_malicious']} abuse.ch malicious, "
        f"{results['total_abuseipdb_malicious']} AbuseIPDB malicious"
    )

    _record_findings_to_ledger(results)

    _save_results(results, merge=merge_results)
    report_url = f"{WEB_BASE_URL}/domain-monitoring"
    if send_summary:
        send_daily_summary(webex_api, results, report_url)

    # Auto-triage (weaponization scoring + exposure hunts) is kicked off LAST and
    # on a background daemon thread, so its page fetches + LLM calls can never
    # delay or fail the scan. It previously ran inline before _save_results and
    # blew the slot's 1800s budget (≈90s/domain × 20 ≈ the whole budget),
    # tripping false "timed out" alerts on slot_0/slot_1 and risking the scan
    # results never being saved. The scheduler process is long-lived, so the
    # thread survives to completion and writes verdicts to the ledger.
    _auto_triage_new_findings(results)


def _record_findings_to_ledger(results: Dict[str, Any]) -> None:
    """UPSERT every domain this run discovered into the findings ledger.

    Discovery only — analyst triage (status/assignee/disposition) is set later
    from the dashboard and is never overwritten here. Best-effort: a ledger
    hiccup must never fail a scan.
    """
    try:
        from .findings_ledger import upsert_finding, set_infrastructure
    except Exception as e:
        logger.error(f"Findings ledger unavailable, skipping: {e}")
        return

    def _record_infra(dom: str, d: Dict[str, Any]) -> None:
        """Persist whatever infrastructure pivots this finding's enrichment
        carries, so campaign clustering can group by shared footprint. Pulls
        from the assorted keys the different scan sources use; best-effort."""
        ips = d.get("dns_a") if isinstance(d.get("dns_a"), list) else None
        ns = d.get("dns_ns") or d.get("whois_name_servers") or d.get("name_servers")
        if isinstance(ns, str):
            ns = [ns]
        elif not isinstance(ns, list):
            ns = None
        set_infrastructure(
            dom,
            registrar=d.get("registrar"),
            registrant_org=d.get("registrant_org") or d.get("registrant"),
            ips=ips,
            nameservers=ns,
            cert_issuer=d.get("issuer"),
        )

    try:
        # Lookalikes (new + became-active), attributed to the parent brand.
        for parent, data in (results.get("domains") or {}).items():
            brand = parent.split(".")[0].title()
            look = data.get("lookalikes") or {}
            for bucket in ("new_domains", "became_active", "reregistered"):
                for d in look.get(bucket, []):
                    dom = d.get("domain")
                    if dom and not d.get("is_defensive"):
                        upsert_finding(dom, source="lookalike", brand=brand,
                                       risk_score=d.get("rf_risk_score"))
                        _record_infra(dom, d)

        # RF watchlist domains — attributed to their brand by keyword match so
        # they don't all collapse into "Unattributed" in the By-Brand rollup.
        for d in (results.get("rf_watchlist") or {}).get("domains", []):
            dom = d.get("domain")
            if dom:
                upsert_finding(dom, source="rf_watchlist",
                               brand=d.get("brand") or brand_for_domain(dom),
                               risk_score=d.get("rf_risk_score"))
                _record_infra(dom, d)

        # Brand-keyword CT impersonation hits, attributed to the brand keyword
        # (falling back to a keyword match on the domain itself).
        for d in (results.get("brand_keyword_impersonation") or {}).get("new_domains", []):
            dom = d.get("domain")
            if dom:
                brand = (d.get("brand_keyword") or "").title() or brand_for_domain(dom)
                upsert_finding(dom, source="brand_ct", brand=brand)
                _record_infra(dom, d)
    except Exception as e:
        logger.error(f"Failed recording findings to ledger: {e}")


# Bound the per-run automated work — each weaponization score is a page fetch +
# LLM call, each exposure hunt is a SIEM sweep. These are the highest-signal
# candidates; analysts can run the rest on demand from the dashboard. The work
# runs on a background thread (see _auto_triage_new_findings), but is still
# capped + wall-clock-budgeted so overlapping slots can't pile up unbounded.
_MAX_AUTO_SCORE = 20
_MAX_AUTO_HUNT = 8
_AUTO_TRIAGE_BUDGET_S = 1200  # 20 min — a slow LLM/fetch pass self-stops here


def _auto_triage_new_findings(results: Dict[str, Any]) -> None:
    """Kick off auto-triage on a background daemon thread and return immediately.

    Scoring 20 domains is ≈90s each (page fetch + DNS + LLM), which would blow
    the scan's job-timeout budget if run inline — so it is fire-and-forget. The
    scheduler process is long-lived, so the thread runs to completion and writes
    verdicts to the findings ledger, where the dashboard picks them up.
    """
    import threading
    threading.Thread(
        target=_auto_triage_worker, args=(results,),
        name="domain-mon-auto-triage", daemon=True,
    ).start()


def _auto_triage_worker(results: Dict[str, Any]) -> None:
    """Background worker: weaponization-score the most interesting NEW domains and
    (for confirmed-live ones) fire a 'were we touched?' exposure hunt.

    Selective and bounded: only newly-active lookalikes, high-risk RF watchlist
    hits, and brand-keyword CT discoveries — not the whole watchlist. Best-effort:
    a triage hiccup must never escape this thread.
    """
    import time
    try:
        from .weaponization import score_and_record
        from .exposure_hunt import start_exposure_hunt
    except Exception as e:
        logger.error(f"Auto-triage unavailable, skipping: {e}")
        return

    # Build the candidate set (domain -> brand), most-interesting first.
    candidates = []
    seen = set()

    def _add(dom, brand):
        dom = (dom or "").strip().lower()
        if dom and dom not in seen:
            seen.add(dom)
            candidates.append((dom, brand))

    for parent, data in (results.get("domains") or {}).items():
        brand = parent.split(".")[0].title()
        look = data.get("lookalikes") or {}
        for d in look.get("became_active", []):
            if not d.get("is_defensive"):
                _add(d.get("domain"), brand)
    for d in (results.get("brand_keyword_impersonation") or {}).get("new_domains", []):
        _add(d.get("domain"), (d.get("brand_keyword") or "").title() or None)
    for d in (results.get("rf_watchlist") or {}).get("domains", []):
        score = d.get("rf_risk_score")
        if isinstance(score, (int, float)) and score >= 65:
            _add(d.get("domain"), None)

    if not candidates:
        return
    logger.info(f"Auto-triage: scoring up to {_MAX_AUTO_SCORE} of {len(candidates)} new domains")

    deadline = time.monotonic() + _AUTO_TRIAGE_BUDGET_S
    hunts_fired = scored = 0
    for dom, brand in candidates[:_MAX_AUTO_SCORE]:
        if time.monotonic() > deadline:
            logger.warning(f"Auto-triage hit its {_AUTO_TRIAGE_BUDGET_S}s budget after "
                           f"{scored} domains; remaining left for on-demand triage")
            break
        try:
            result = score_and_record(dom, brand=brand)
            scored += 1
        except Exception as e:
            logger.warning(f"Auto-score failed for {dom}: {e}")
            continue
        verdict = result.get("verdict") or {}
        # Auto-fire the exposure hunt only for the genuinely weaponized — confirmed
        # active phishing or a P1/P2 tier — and only up to the per-run cap.
        tier = verdict.get("risk_tier")
        if hunts_fired < _MAX_AUTO_HUNT and (verdict.get("is_active_phishing") or tier in ("P1", "P2")):
            try:
                start_exposure_hunt(dom)
                hunts_fired += 1
            except Exception as e:
                logger.warning(f"Auto exposure-hunt failed for {dom}: {e}")
    logger.info(f"Auto-triage complete: {scored} scored, {hunts_fired} hunts fired")


# ── Staggered per-brand scheduling ─────────────────────────────────────────────
# The full per-domain pipeline (dnstwist + WHOIS/VT/Shodan/HIBP/abuse checks) is
# minutes per brand and the daily job has a hard 30-minute timeout, so scanning
# every brand in one run would overrun. Instead the scheduler fires several slots
# spread across the morning; each scans a disjoint partition of the monitored
# brands, merges into the shared day report, and a final job posts one summary.

def _global_sweeps_done_today() -> bool:
    """Have today's once-per-day global sweeps already been recorded?

    Reads today's merged results file and checks for a *successful* RF watchlist
    section. Used to decide which slot runs the global sweeps: rather than pinning
    them to slot 0 (a silent single point of failure if that slot times out), the
    first slot of the day that finds them not-yet-done runs them. Slots execute
    serially, so there is no race.
    """
    try:
        date_str = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d')
        filepath = RESULTS_DIR / date_str / "results.json"
        if not filepath.exists():
            return False
        with open(filepath) as f:
            existing = json.load(f)
        rf = existing.get("rf_watchlist") or {}
        return bool(rf.get("success"))
    except (json.JSONDecodeError, IOError, OSError):
        return False


def run_brand_slot(slot_index: int, total_slots: int, room_id: str | None = None) -> None:
    """Scan one staggered partition of the monitored brands.

    Partitions ``load_monitored_domains()`` deterministically by ``index % total
    _slots`` at run time (so brands added via the management UI are picked up the
    next day without a scheduler restart). The once-per-day global sweeps run in
    the first slot of the day that hasn't recorded them yet — so a failed/slow
    early slot doesn't silently drop the highest-signal RF + brand-keyword
    coverage for the whole day. No per-slot summary is posted —
    ``send_daily_summary_now`` posts a single consolidated one after the last slot.
    """
    all_domains = sorted(load_monitored_domains())
    slot_domains = [d for i, d in enumerate(all_domains) if i % total_slots == slot_index]
    run_globals = not _global_sweeps_done_today()
    logger.info(
        f"Domain monitoring slot {slot_index + 1}/{total_slots}: "
        f"{len(slot_domains)} brand(s) — {', '.join(slot_domains) or '(none)'}"
        f"{' [+ global sweeps]' if run_globals else ''}"
    )
    run_daily_monitoring(
        room_id=room_id,
        domains_subset=slot_domains,
        merge_results=True,
        run_global_sweeps=run_globals,
        send_summary=False,
    )


def send_daily_summary_now(room_id: str | None = None) -> None:
    """Post one consolidated daily summary from the merged day report.

    Called after the final staggered slot so the room gets a single summary that
    covers every brand, instead of one message per slot.
    """
    set_active_room_id(room_id or ALERT_ROOM_ID_PROD)
    latest = RESULTS_DIR / "latest.json"
    if not latest.exists():
        logger.warning("No latest.json to summarize; skipping consolidated summary")
        return
    try:
        with open(latest) as f:
            results = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Could not load results for consolidated summary: {e}")
        return
    webex_api = get_webex_api()
    send_daily_summary(webex_api, results, f"{WEB_BASE_URL}/domain-monitoring")
    logger.info("Posted consolidated daily monitoring summary")
