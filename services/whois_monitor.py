"""WHOIS Monitoring Service.

Monitors WHOIS data for lookalike domains to detect:
- Registrant changes (domain takeover indicator)
- Nameserver changes (infrastructure changes)
- Recently registered domains (attacker preparation)
- Expiration date changes

Uses python-whois (free) for WHOIS lookups.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import whois

logger = logging.getLogger(__name__)

# State storage for tracking changes
STATE_DIR = Path(__file__).parent.parent / "data" / "transient" / "whois_state"


class WhoisMonitor:
    """Monitors WHOIS data for domain changes."""

    def __init__(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    def _get_state_file(self, domain: str) -> Path:
        """Get path to state file for a domain."""
        safe_name = domain.replace(".", "_")
        return STATE_DIR / f"{safe_name}.json"

    def _load_previous_state(self, domain: str) -> dict | None:
        """Load previous WHOIS state for a domain."""
        state_file = self._get_state_file(domain)
        if state_file.exists():
            try:
                with open(state_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error loading WHOIS state for {domain}: {e}")
        return None

    def _save_state(self, domain: str, state: dict) -> None:
        """Save current WHOIS state for a domain."""
        state_file = self._get_state_file(domain)
        try:
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"Error saving WHOIS state for {domain}: {e}")

    def _normalize_whois_data(self, w: whois.WhoisEntry) -> dict[str, Any]:
        """Normalize WHOIS data into a consistent format."""
        def to_str(val):
            if val is None:
                return None
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val)

        def to_date_str(val):
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0]  # Take first date if multiple
            if isinstance(val, datetime):
                return val.isoformat()
            return str(val)

        # Extract nameservers - handle various formats
        nameservers = w.name_servers
        if nameservers:
            if isinstance(nameservers, str):
                nameservers = [nameservers.lower()]
            else:
                nameservers = sorted([ns.lower() for ns in nameservers if ns])

        return {
            "domain_name": to_str(w.domain_name),
            "registrar": to_str(w.registrar),
            "registrant": to_str(getattr(w, "registrant", None)),
            "registrant_org": to_str(getattr(w, "org", None)),
            "registrant_country": to_str(getattr(w, "country", None)),
            "creation_date": to_date_str(w.creation_date),
            "expiration_date": to_date_str(w.expiration_date),
            "updated_date": to_date_str(w.updated_date),
            "name_servers": nameservers,
            "status": to_str(w.status),
            "dnssec": to_str(getattr(w, "dnssec", None)),
        }

    def lookup_whois(self, domain: str) -> dict[str, Any]:
        """Perform WHOIS lookup for a domain.

        Args:
            domain: Domain to look up

        Returns:
            Dict with WHOIS data and metadata
        """
        try:
            logger.info(f"WHOIS lookup for: {domain}")
            w = whois.whois(domain)

            if not w or not w.domain_name:
                return {
                    "success": True,
                    "domain": domain,
                    "registered": False,
                    "data": None,
                    "scan_time": datetime.utcnow().isoformat(),
                }

            data = self._normalize_whois_data(w)

            # Check if recently registered (within 30 days)
            is_new = False
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    # Handle timezone-aware vs naive datetime comparison
                    now = datetime.utcnow()
                    if creation_date.tzinfo is not None:
                        creation_date = creation_date.replace(tzinfo=None)
                    days_old = (now - creation_date).days
                    is_new = days_old <= 30

            return {
                "success": True,
                "domain": domain,
                "registered": True,
                "is_newly_registered": is_new,
                "data": data,
                "scan_time": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            # Domain not found or WHOIS error
            logger.debug(f"WHOIS not found for {domain}: {e}")
            return {
                "success": True,
                "domain": domain,
                "registered": False,
                "data": None,
                "scan_time": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"WHOIS lookup error for {domain}: {e}")
            return {
                "success": False,
                "domain": domain,
                "error": str(e),
            }

    def check_for_changes(self, domain: str) -> dict[str, Any]:
        """Check WHOIS data for changes since last scan.

        Args:
            domain: Domain to check

        Returns:
            Dict with current data, changes detected, and metadata
        """
        # Get current WHOIS data
        current = self.lookup_whois(domain)

        if not current.get("success"):
            return current

        # Load previous state
        previous = self._load_previous_state(domain)
        is_first_scan = previous is None

        changes = []
        change_severity = "none"

        if not is_first_scan and current.get("registered") and previous.get("registered"):
            prev_data = previous.get("data", {})
            curr_data = current.get("data", {})

            # Check for registrar change
            if prev_data.get("registrar") != curr_data.get("registrar"):
                changes.append({
                    "field": "registrar",
                    "previous": prev_data.get("registrar"),
                    "current": curr_data.get("registrar"),
                    "severity": "medium",
                })
                change_severity = "medium"

            # Check for nameserver changes (high severity - infrastructure change)
            prev_ns = set(prev_data.get("name_servers") or [])
            curr_ns = set(curr_data.get("name_servers") or [])
            if prev_ns != curr_ns:
                changes.append({
                    "field": "name_servers",
                    "previous": list(prev_ns),
                    "current": list(curr_ns),
                    "added": list(curr_ns - prev_ns),
                    "removed": list(prev_ns - curr_ns),
                    "severity": "high",
                })
                change_severity = "high"

            # Check for registrant/org change (high severity - ownership change)
            if prev_data.get("registrant_org") != curr_data.get("registrant_org"):
                changes.append({
                    "field": "registrant_org",
                    "previous": prev_data.get("registrant_org"),
                    "current": curr_data.get("registrant_org"),
                    "severity": "high",
                })
                change_severity = "high"

            # Check for status changes
            prev_status = prev_data.get("status")
            curr_status = curr_data.get("status")
            if prev_status != curr_status:
                changes.append({
                    "field": "status",
                    "previous": prev_status,
                    "current": curr_status,
                    "severity": "low",
                })
                if change_severity == "none":
                    change_severity = "low"

        # Detect newly registered domains (was not registered, now is)
        if not is_first_scan and current.get("registered") and not previous.get("registered"):
            changes.append({
                "field": "registration",
                "previous": "not_registered",
                "current": "registered",
                "severity": "high",
            })
            change_severity = "high"

        # Save current state for next comparison
        self._save_state(domain, current)

        result = {
            **current,
            "is_first_scan": is_first_scan,
            "changes": changes,
            "has_changes": len(changes) > 0,
            "change_severity": change_severity,
        }

        if changes:
            logger.info(f"WHOIS changes detected for {domain}: {len(changes)} changes ({change_severity})")

        return result

    def scan_domains(self, domains: list[str]) -> dict[str, Any]:
        """Scan multiple domains for WHOIS changes.

        Args:
            domains: List of domains to scan

        Returns:
            Dict with results for all domains and summary
        """
        results = {
            "success": True,
            "scan_time": datetime.utcnow().isoformat(),
            "domains_scanned": len(domains),
            "domains_with_changes": 0,
            "high_severity_changes": [],
            "newly_registered": [],
            "details": {},
        }

        for domain in domains:
            result = self.check_for_changes(domain)
            results["details"][domain] = result

            if result.get("has_changes"):
                results["domains_with_changes"] += 1

                if result.get("change_severity") == "high":
                    results["high_severity_changes"].append({
                        "domain": domain,
                        "changes": result["changes"],
                    })

            if result.get("is_newly_registered"):
                results["newly_registered"].append({
                    "domain": domain,
                    "creation_date": result.get("data", {}).get("creation_date"),
                    "registrar": result.get("data", {}).get("registrar"),
                })

        logger.info(
            f"WHOIS scan complete: {results['domains_with_changes']}/{len(domains)} "
            f"domains have changes, {len(results['high_severity_changes'])} high severity"
        )

        return results


# Singleton instance
_monitor: WhoisMonitor | None = None


def get_monitor() -> WhoisMonitor:
    """Get the singleton WhoisMonitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = WhoisMonitor()
    return _monitor


def lookup_whois(domain: str) -> dict[str, Any]:
    """Convenience function to look up WHOIS for a domain."""
    return get_monitor().lookup_whois(domain)


def check_whois_changes(domain: str) -> dict[str, Any]:
    """Convenience function to check WHOIS changes for a domain."""
    return get_monitor().check_for_changes(domain)


def scan_domains_whois(domains: list[str]) -> dict[str, Any]:
    """Convenience function to scan multiple domains for WHOIS changes."""
    return get_monitor().scan_domains(domains)
