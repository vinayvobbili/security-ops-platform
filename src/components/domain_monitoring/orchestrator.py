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
from services.domain_lookalike import enrich_with_recorded_future

from .config import (
    EASTERN_TZ, RESULTS_DIR, WEB_BASE_URL, CONFIG_FILE,
    ALERT_ROOM_ID_TEST, ALERT_ROOM_ID_PROD,
    load_monitored_domains, load_watchlist, load_defensive_domains,
    get_webex_api, get_vt_client, set_active_room_id,
)
from .enrichment import enrich_with_virustotal
from .alerts import send_daily_summary
# Individual alert functions disabled - only daily summary is sent
# All findings available on web dashboard at /domain-monitoring

logger = logging.getLogger(__name__)


def _save_results(results: Dict[str, Any]) -> str:
    """Save results to web-accessible JSON file in date-based directory."""
    date_str = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d')
    date_dir = RESULTS_DIR / date_str
    date_dir.mkdir(parents=True, exist_ok=True)

    filename = "results.json"
    filepath = date_dir / filename

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    latest_filepath = RESULTS_DIR / "latest.json"

    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        with open(latest_filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Saved monitoring results to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

    return filename


def run_daily_monitoring(room_id: str | None = None) -> None:
    """Run daily monitoring for all configured domains.

    Called by all_jobs.py scheduler at 8 AM ET.

    Args:
        room_id: Optional Webex room ID for alerts. Defaults to test space.
                 Pass ALERT_ROOM_ID_PROD for production alerts.

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
        set_active_room_id(ALERT_ROOM_ID_TEST)

    monitored_domains = load_monitored_domains()
    if not monitored_domains:
        logger.warning("No domains configured for monitoring")
        return

    logger.info(f"Starting domain monitoring for {len(monitored_domains)} domains")

    webex_api = get_webex_api()
    vt_client = get_vt_client()

    results = {
        "scan_time": datetime.now(EASTERN_TZ).isoformat(),
        "domains": {},
        "total_new_lookalikes": 0,
        "total_became_active": 0,
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

            results["total_new_lookalikes"] += new_count
            results["total_became_active"] += became_active_count
            results["total_mx_changes"] += mx_changes_count

            for d in lookalike_result.get("new_domains", []):
                all_lookalikes.append(d.get("domain"))
            for d in lookalike_result.get("became_active", []):
                active_lookalikes.append(d.get("domain"))
                if d.get("domain") not in all_lookalikes:
                    all_lookalikes.append(d.get("domain"))

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
                try:
                    enrich_with_recorded_future(domains_for_rf)
                    logger.info(f"RF enrichment complete for {len(domains_for_rf)} domains")
                except Exception as e:
                    logger.warning(f"RF enrichment failed: {e}")

            # Individual alerts disabled - only daily summary is sent
            # All findings are available on the web dashboard
            pass

        # Dark web monitoring (public leaks)
        dark_web_result = search_dark_web(domain)
        results["domains"][domain]["dark_web"] = dark_web_result

        if dark_web_result.get("success"):
            findings = dark_web_result.get("total_findings", 0)
            high_risk = len(dark_web_result.get("high_risk_findings", []))
            results["total_dark_web_findings"] += findings
            # Note: Individual dark web alerts disabled - info available on web dashboard

        # IntelligenceX dark web search (actual Tor/I2P)
        intelx_client = get_intelx_client()
        if intelx_client and intelx_client.api_key:
            logger.info(f"Searching IntelligenceX for {domain}")
            try:
                intelx_result = search_intelx(domain)
                results["domains"][domain]["intelx"] = intelx_result

                if intelx_result.get("success"):
                    intelx_findings = intelx_result.get("total_findings", 0)
                    results["total_intelx_findings"] += intelx_findings
                    # Note: Individual IntelX alerts disabled - info available on web dashboard
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
                hours_back=48,  # Look back 48 hours for new certs
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

    logger.info(
        f"Monitoring complete: {results['total_new_lookalikes']} new lookalikes, "
        f"{results['total_became_active']} became active, "
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

    _save_results(results)
    report_url = f"{WEB_BASE_URL}/domain-monitoring"
    send_daily_summary(webex_api, results, report_url)
