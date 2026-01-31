"""Certstream-based Certificate Transparency Monitor.

Provides real-time monitoring of CT logs for brand impersonation domains.
Unlike crt.sh queries which return limited/old results for popular brands,
Certstream gives real-time access to ALL new certificates.

This catches semantic impersonation attacks that dnstwist misses:
- acme-loan.com (brand-keyword)
- secure-acme.net (keyword-brand)
- myacmebenefits.com (brandkeyword)

Usage:
    # One-time scan of recent certificates (last N hours)
    from services.certstream_monitor import scan_recent_certs
    results = scan_recent_certs("acme", ["acme.com"], hours_back=24)

    # Continuous monitoring (blocking)
    from services.certstream_monitor import start_monitor
    start_monitor("acme", ["acme.com"], callback=my_alert_function)
"""

import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import certstream

logger = logging.getLogger(__name__)

# Cache for seen certificates to avoid duplicate alerts
CACHE_DIR = Path(__file__).parent.parent / "data" / "transient" / "certstream"
CACHE_FILE = CACHE_DIR / "seen_domains.json"


def _load_seen_domains() -> set[str]:
    """Load previously seen domains from cache."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE) as f:
                data = json.load(f)
                # Only keep domains from last 7 days
                cutoff = time.time() - (7 * 24 * 60 * 60)
                return {d for d, ts in data.items() if ts > cutoff}
        except (json.JSONDecodeError, IOError):
            pass
    return set()


def _save_seen_domains(domains: dict[str, float]) -> None:
    """Save seen domains to cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(domains, f)
    except IOError as e:
        logger.warning(f"Failed to save seen domains cache: {e}")


def _is_legitimate_domain(domain: str, legitimate_domains: list[str]) -> bool:
    """Check if domain is legitimate (exact match or subdomain)."""
    domain = domain.lower().lstrip("*.")
    for legit in legitimate_domains:
        legit = legit.lower()
        if domain == legit or domain.endswith(f".{legit}"):
            return True
    return False


def _extract_domains_from_cert(message: dict) -> list[str]:
    """Extract all domain names from a certificate message."""
    domains = []
    try:
        data = message.get("data", {})
        leaf_cert = data.get("leaf_cert", {})

        # Get subject CN
        subject = leaf_cert.get("subject", {})
        cn = subject.get("CN")
        if cn:
            domains.append(cn.lower())

        # Get all SANs (Subject Alternative Names)
        all_domains = leaf_cert.get("all_domains", [])
        for d in all_domains:
            domains.append(d.lower())

    except (KeyError, TypeError):
        pass

    # Dedupe and clean
    clean_domains = []
    seen = set()
    for d in domains:
        d = d.lstrip("*.")
        if d and d not in seen:
            seen.add(d)
            clean_domains.append(d)

    return clean_domains


def scan_recent_certs(
    brand: str,
    legitimate_domains: list[str],
    hours_back: int = 24,
    max_certs: int = 100000
) -> dict[str, Any]:
    """Scan recent certificates for brand impersonation.

    Connects to Certstream and collects certificates for a specified duration,
    filtering for domains containing the brand name.

    Args:
        brand: Brand name to search for (e.g., "acme")
        legitimate_domains: List of legitimate domains to exclude
        hours_back: How many hours of certificates to collect
        max_certs: Maximum certificates to process before stopping

    Returns:
        Dict with impersonation domains found
    """
    brand_lower = brand.lower()
    brand_pattern = re.compile(re.escape(brand_lower), re.IGNORECASE)

    results = {
        "success": True,
        "brand": brand,
        "legitimate_domains": legitimate_domains,
        "scan_duration_hours": hours_back,
        "impersonation_domains": [],
        "total_certs_scanned": 0,
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "scan_end": None,
    }

    impersonation = {}
    seen_domains = _load_seen_domains()
    certs_processed = 0
    stop_event = threading.Event()

    def cert_callback(message, context):
        nonlocal certs_processed

        if message["message_type"] != "certificate_update":
            return

        if stop_event.is_set():
            return

        certs_processed += 1

        if certs_processed >= max_certs:
            stop_event.set()
            return

        domains = _extract_domains_from_cert(message)

        for domain in domains:
            # Skip if already seen
            if domain in seen_domains:
                continue

            # Check if domain contains the brand
            if not brand_pattern.search(domain):
                continue

            # Skip legitimate domains
            if _is_legitimate_domain(domain, legitimate_domains):
                continue

            # Found an impersonation domain
            seen_domains.add(domain)

            cert_data = message.get("data", {})
            leaf_cert = cert_data.get("leaf_cert", {})

            if domain not in impersonation:
                impersonation[domain] = {
                    "domain": domain,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "cert_count": 1,
                    "issuer": leaf_cert.get("issuer", {}).get("O", "Unknown"),
                    "not_before": leaf_cert.get("not_before"),
                    "not_after": leaf_cert.get("not_after"),
                    "all_domains": domains[:10],  # Limit SANs for readability
                    "source": cert_data.get("source", {}).get("name", "Unknown"),
                }
                logger.info(f"Found brand impersonation domain: {domain}")
            else:
                impersonation[domain]["cert_count"] += 1

    def on_error(instance, exception):
        logger.error(f"Certstream error: {exception}")

    logger.info(f"Starting Certstream scan for '{brand}' (max {hours_back} hours)")

    # Start certstream in a thread
    stream_thread = threading.Thread(
        target=certstream.listen_for_events,
        kwargs={
            "message_callback": cert_callback,
            "on_error": on_error,
            "url": "wss://certstream.calidog.io/",
        },
        daemon=True,
    )
    stream_thread.start()

    # Run for specified duration
    scan_seconds = hours_back * 60 * 60
    start_time = time.time()

    try:
        while time.time() - start_time < scan_seconds:
            if stop_event.is_set():
                logger.info("Max certificates reached, stopping scan")
                break
            time.sleep(10)  # Check every 10 seconds
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")

    stop_event.set()

    # Save seen domains for next run
    seen_with_timestamps = {d: time.time() for d in seen_domains}
    _save_seen_domains(seen_with_timestamps)

    results["impersonation_domains"] = list(impersonation.values())
    results["total_certs_scanned"] = certs_processed
    results["scan_end"] = datetime.now(timezone.utc).isoformat()
    results["unique_domains_found"] = len(impersonation)

    logger.info(
        f"Certstream scan complete: {certs_processed} certs scanned, "
        f"{len(impersonation)} impersonation domains found"
    )

    return results


def start_monitor(
    brand: str,
    legitimate_domains: list[str],
    callback: Callable[[dict], None] | None = None,
    alert_threshold_minutes: int = 60,
) -> None:
    """Start continuous Certstream monitoring for brand impersonation.

    This is a blocking function that runs indefinitely, alerting when
    new impersonation domains are discovered.

    Args:
        brand: Brand name to monitor (e.g., "acme")
        legitimate_domains: List of legitimate domains to exclude
        callback: Function to call when impersonation domain found.
                  Receives dict with domain info.
        alert_threshold_minutes: Minimum minutes between alerts for same domain
    """
    brand_lower = brand.lower()
    brand_pattern = re.compile(re.escape(brand_lower), re.IGNORECASE)
    seen_domains = _load_seen_domains()
    alert_times: dict[str, float] = {}

    def cert_callback(message, context):
        if message["message_type"] != "certificate_update":
            return

        domains = _extract_domains_from_cert(message)

        for domain in domains:
            # Check if domain contains the brand
            if not brand_pattern.search(domain):
                continue

            # Skip legitimate domains
            if _is_legitimate_domain(domain, legitimate_domains):
                continue

            # Skip if recently alerted
            last_alert = alert_times.get(domain, 0)
            if time.time() - last_alert < alert_threshold_minutes * 60:
                continue

            # New or re-alerting impersonation domain
            is_new = domain not in seen_domains
            seen_domains.add(domain)
            alert_times[domain] = time.time()

            cert_data = message.get("data", {})
            leaf_cert = cert_data.get("leaf_cert", {})

            alert_info = {
                "domain": domain,
                "is_new": is_new,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "issuer": leaf_cert.get("issuer", {}).get("O", "Unknown"),
                "not_before": leaf_cert.get("not_before"),
                "not_after": leaf_cert.get("not_after"),
                "all_domains": domains[:10],
                "source": cert_data.get("source", {}).get("name", "Unknown"),
            }

            logger.warning(f"Brand impersonation detected: {domain}")

            if callback:
                try:
                    callback(alert_info)
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")

    def on_error(instance, exception):
        logger.error(f"Certstream error: {exception}")

    logger.info(f"Starting continuous Certstream monitor for '{brand}'")
    logger.info(f"Excluding legitimate domains: {legitimate_domains}")

    # This blocks forever
    certstream.listen_for_events(
        message_callback=cert_callback,
        on_error=on_error,
        url="wss://certstream.calidog.io/",
    )


def quick_scan(
    brand: str,
    legitimate_domains: list[str],
    duration_minutes: int = 5
) -> dict[str, Any]:
    """Quick scan of Certstream for immediate results.

    Useful for testing or quick checks. Runs for a short duration
    and returns any matching domains found.

    Args:
        brand: Brand name to search for
        legitimate_domains: Legitimate domains to exclude
        duration_minutes: How long to scan (default 5 minutes)

    Returns:
        Dict with results
    """
    return scan_recent_certs(
        brand=brand,
        legitimate_domains=legitimate_domains,
        hours_back=duration_minutes / 60,  # Convert to hours
        max_certs=50000,
    )
