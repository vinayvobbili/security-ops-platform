"""Domain Monitoring Service - Continuous monitoring for lookalike domains.

Tracks:
- New domain registrations
- Removed domains (expired/taken down)
- Status transitions (parked ↔ active)
- IP address changes
- New MX records (email infrastructure)
- GeoIP changes
- Risk classification (defensive, parked, suspicious, high_risk)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from services import domain_lookalike
from services.domain_lookalike import classify_domain_risk, detect_defensive_registration

logger = logging.getLogger(__name__)

# Default storage path for monitoring data
MONITOR_DATA_DIR = Path("data/transient/domain_monitor")

# Config file for domain monitoring settings (defensive allowlists, etc.)
MONITOR_CONFIG_FILE = Path("data/transient/domain_monitoring/config.json")


def _load_monitoring_config() -> Dict[str, Any]:
    """Load domain monitoring configuration including defensive allowlists.

    Config file format:
    {
        "monitored_domains": ["example.com"],
        "defensive_domains": {
            "example.com": ["myexample.com", "example-secure.com"]
        }
    }
    """
    if MONITOR_CONFIG_FILE.exists():
        try:
            with open(MONITOR_CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading monitoring config: {e}")
    return {"monitored_domains": [], "defensive_domains": {}}


class DomainMonitor:
    """Monitors domains for new lookalike registrations."""

    def __init__(self, data_dir: Path = MONITOR_DATA_DIR):
        """Initialize the domain monitor.

        Args:
            data_dir: Directory to store monitoring data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _get_state_file(self, domain: str) -> Path:
        """Get the state file path for a domain."""
        safe_name = domain.replace(".", "_")
        return self.data_dir / f"{safe_name}_state.json"

    def _load_state(self, domain: str) -> Dict[str, Any]:
        """Load previous scan state for a domain."""
        state_file = self._get_state_file(domain)
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error loading state for {domain}: {e}")
        return {"registered_domains": {}, "last_scan": None}

    def _save_state(self, domain: str, state: Dict[str, Any]) -> None:
        """Save scan state for a domain."""
        state_file = self._get_state_file(domain)
        try:
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"Error saving state for {domain}: {e}")

    def scan_and_diff(
        self, domain: str, check_parking: bool = True
    ) -> Dict[str, Any]:
        """Scan for lookalikes and detect changes since last scan.

        Detects:
        - New domain registrations
        - Removed domains
        - Parked → Active transitions (HIGH PRIORITY)
        - Active → Parked transitions
        - IP address changes
        - New MX records
        - GeoIP changes

        Args:
            domain: Domain to monitor
            check_parking: Whether to check parking status

        Returns:
            Dictionary with scan results and all detected changes
        """
        logger.info(f"Starting monitoring scan for {domain}")
        scan_time = datetime.now()

        # Load previous state
        previous_state = self._load_state(domain)
        previous_domains: Dict[str, Any] = previous_state.get("registered_domains", {})
        previous_registered: Set[str] = set(previous_domains.keys())

        # Run new scan with DNS resolution
        result = domain_lookalike.get_domain_lookalikes(domain, registered_only=True)

        if not result.get("success"):
            logger.error(f"Scan failed for {domain}: {result.get('error')}")
            return {
                "success": False,
                "error": result.get("error"),
                "domain": domain,
                "scan_time": scan_time.isoformat(),
            }

        # Extract currently registered domains
        current_domains = {d["domain"]: d for d in result["domains"] if d["registered"]}
        current_registered: Set[str] = set(current_domains.keys())

        # Calculate basic deltas
        new_domain_names = current_registered - previous_registered
        removed_domain_names = previous_registered - current_registered
        existing_domain_names = current_registered & previous_registered

        # Check parking status for all current domains (needed for comparison)
        if check_parking:
            logger.info(f"Checking parking status for {len(current_domains)} domains")
            current_domains_list = list(current_domains.values())
            current_domains_list = domain_lookalike.check_parking_batch(current_domains_list)
            # Update current_domains dict with parking info
            for d in current_domains_list:
                current_domains[d["domain"]] = d

        # Merge WHOIS data from previous scans into current domains
        # This is needed because dnstwist doesn't return WHOIS info,
        # but we need registrar/nameservers for defensive detection
        whois_fields = ["registrar", "registration_date", "whois_name_servers", "first_seen"]
        for domain_name in existing_domain_names:
            if domain_name in previous_domains and domain_name in current_domains:
                prev = previous_domains[domain_name]
                curr = current_domains[domain_name]
                for field in whois_fields:
                    if field in prev and prev[field] and field not in curr:
                        curr[field] = prev[field]

        # Lazy-fetch WHOIS for existing domains that don't have it yet
        # (for domains detected before WHOIS collection was implemented)
        # Limit to 10 per scan to avoid rate limiting
        domains_missing_whois = [
            dn for dn in existing_domain_names
            if dn in current_domains and not current_domains[dn].get("registrar")
        ]
        if domains_missing_whois:
            logger.info(f"Fetching WHOIS for {min(10, len(domains_missing_whois))} domains missing data")
            for domain_name in domains_missing_whois[:10]:
                whois_info = domain_lookalike.get_domain_whois_info(domain_name)
                if whois_info.get("success"):
                    current_domains[domain_name]["registration_date"] = whois_info.get("creation_date")
                    current_domains[domain_name]["registrar"] = whois_info.get("registrar")
                    current_domains[domain_name]["whois_name_servers"] = whois_info.get("name_servers", [])

        # Load defensive allowlist from config for risk classification
        config = _load_monitoring_config()
        defensive_allowlist = config.get("defensive_domains", {}).get(domain, [])

        # Apply risk classification to all current domains
        for domain_name, domain_data in current_domains.items():
            risk_level = classify_domain_risk(
                domain_data,
                monitored_domain=domain,
                defensive_allowlist=defensive_allowlist
            )
            domain_data["risk_level"] = risk_level
            domain_data["is_defensive"] = (risk_level == "defensive")

        # Track all types of changes
        new_domain_details = []
        became_active = []  # Parked → Active (HIGH PRIORITY)
        became_parked = []  # Active → Parked
        ip_changes = []
        mx_changes = []
        geoip_changes = []

        # Process NEW domains - fetch WHOIS registration dates
        for domain_name in new_domain_names:
            domain_data = current_domains[domain_name].copy()
            domain_data["first_seen"] = scan_time.isoformat()
            domain_data["change_type"] = "new_registration"

            # Get actual registration date from WHOIS
            whois_info = domain_lookalike.get_domain_whois_info(domain_name)
            if whois_info.get("success"):
                domain_data["registration_date"] = whois_info.get("creation_date")
                domain_data["registrar"] = whois_info.get("registrar")
                domain_data["whois_name_servers"] = whois_info.get("name_servers", [])

                # Re-classify with WHOIS data (registrar may indicate defensive)
                risk_level = classify_domain_risk(
                    domain_data,
                    monitored_domain=domain,
                    defensive_allowlist=defensive_allowlist
                )
                domain_data["risk_level"] = risk_level
                domain_data["is_defensive"] = (risk_level == "defensive")
                # Update the current_domains dict as well
                current_domains[domain_name]["risk_level"] = risk_level
                current_domains[domain_name]["is_defensive"] = (risk_level == "defensive")
            else:
                domain_data["registration_date"] = None
                logger.warning(f"Could not get WHOIS for {domain_name}: {whois_info.get('error')}")

            new_domain_details.append(domain_data)

        # Process EXISTING domains - detect status changes
        for domain_name in existing_domain_names:
            current = current_domains[domain_name]
            previous = previous_domains[domain_name]

            # Check parking status transition
            prev_parked = previous.get("parked")
            curr_parked = current.get("parked")

            if prev_parked is True and curr_parked is False:
                # PARKED → ACTIVE: High priority alert!
                change_data = current.copy()
                change_data["previous_status"] = "parked"
                change_data["current_status"] = "active"
                change_data["change_type"] = "became_active"

                # Get WHOIS registration date if not already present
                if not previous.get("registration_date"):
                    whois_info = domain_lookalike.get_domain_whois_info(domain_name)
                    if whois_info.get("success"):
                        change_data["registration_date"] = whois_info.get("creation_date")
                        change_data["registrar"] = whois_info.get("registrar")
                else:
                    change_data["registration_date"] = previous.get("registration_date")
                    change_data["registrar"] = previous.get("registrar")

                became_active.append(change_data)
                logger.warning(f"HIGH PRIORITY: {domain_name} changed from PARKED to ACTIVE")

            elif prev_parked is False and curr_parked is True:
                # ACTIVE → PARKED
                change_data = current.copy()
                change_data["previous_status"] = "active"
                change_data["current_status"] = "parked"
                change_data["change_type"] = "became_parked"
                became_parked.append(change_data)

            # Check IP address changes
            prev_ips = set(previous.get("dns_a", []))
            curr_ips = set(current.get("dns_a", []))
            if prev_ips and curr_ips and prev_ips != curr_ips:
                change_data = current.copy()
                change_data["previous_ips"] = list(prev_ips)
                change_data["current_ips"] = list(curr_ips)
                change_data["new_ips"] = list(curr_ips - prev_ips)
                change_data["removed_ips"] = list(prev_ips - curr_ips)
                change_data["change_type"] = "ip_change"
                ip_changes.append(change_data)

            # Check MX record changes (new email infrastructure is suspicious)
            prev_mx = set(previous.get("dns_mx", []))
            curr_mx = set(current.get("dns_mx", []))
            if curr_mx and not prev_mx:
                # New MX records appeared - potential phishing setup
                change_data = current.copy()
                change_data["new_mx_records"] = list(curr_mx)
                change_data["change_type"] = "new_mx_records"
                mx_changes.append(change_data)
                logger.warning(f"New MX records on {domain_name}: {curr_mx}")
            elif prev_mx and curr_mx and prev_mx != curr_mx:
                change_data = current.copy()
                change_data["previous_mx"] = list(prev_mx)
                change_data["current_mx"] = list(curr_mx)
                change_data["change_type"] = "mx_change"
                mx_changes.append(change_data)

            # Check GeoIP changes
            prev_geo = previous.get("geoip", "")
            curr_geo = current.get("geoip", "")
            if prev_geo and curr_geo and prev_geo != curr_geo:
                change_data = current.copy()
                change_data["previous_geoip"] = prev_geo
                change_data["current_geoip"] = curr_geo
                change_data["change_type"] = "geoip_change"
                geoip_changes.append(change_data)

        # Count risk levels across all domains
        risk_counts = {"defensive": 0, "parked": 0, "suspicious": 0, "high_risk": 0, "unknown": 0}
        for d in current_domains.values():
            risk = d.get("risk_level", "unknown")
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts["unknown"] += 1

        # Count non-defensive new domains (actionable alerts)
        actionable_new = [d for d in new_domain_details if not d.get("is_defensive")]
        actionable_became_active = [d for d in became_active if not d.get("is_defensive")]

        logger.info(
            f"Scan complete: {len(current_registered)} registered "
            f"({risk_counts['defensive']} defensive, {risk_counts['high_risk']} high-risk, "
            f"{risk_counts['suspicious']} suspicious, {risk_counts['parked']} parked), "
            f"{len(new_domain_names)} new ({len(actionable_new)} actionable), "
            f"{len(removed_domain_names)} removed, "
            f"{len(became_active)} became active ({len(actionable_became_active)} actionable), "
            f"{len(became_parked)} became parked, "
            f"{len(ip_changes)} IP changes, {len(mx_changes)} MX changes"
        )

        # Update state with full domain info including parking status and risk level
        new_state = {
            "registered_domains": current_domains,
            "last_scan": scan_time.isoformat(),
            "total_registered": len(current_registered),
            "risk_counts": risk_counts,
        }
        self._save_state(domain, new_state)

        return {
            "success": True,
            "domain": domain,
            "scan_time": scan_time.isoformat(),
            "total_registered": len(current_registered),
            "is_first_scan": previous_state.get("last_scan") is None,
            # Risk classification summary
            "risk_counts": risk_counts,
            "defensive_count": risk_counts["defensive"],
            "actionable_count": sum(risk_counts[k] for k in ["suspicious", "high_risk"]),
            # New registrations
            "new_count": len(new_domain_names),
            "new_domains": new_domain_details,
            "new_actionable_count": len(actionable_new),
            "new_defensive_count": len(new_domain_details) - len(actionable_new),
            # Removed domains
            "removed_count": len(removed_domain_names),
            "removed_domains": list(removed_domain_names),
            # Status transitions (SOC priority alerts)
            "became_active": became_active,  # HIGH PRIORITY
            "became_active_count": len(became_active),
            "became_active_actionable_count": len(actionable_became_active),
            "became_parked": became_parked,
            "became_parked_count": len(became_parked),
            # Infrastructure changes
            "ip_changes": ip_changes,
            "ip_changes_count": len(ip_changes),
            "mx_changes": mx_changes,
            "mx_changes_count": len(mx_changes),
            "geoip_changes": geoip_changes,
            "geoip_changes_count": len(geoip_changes),
        }

    def get_monitored_domains(self) -> List[str]:
        """Get list of domains being monitored."""
        domains = []
        for state_file in self.data_dir.glob("*_state.json"):
            domain = state_file.stem.replace("_state", "").replace("_", ".")
            domains.append(domain)
        return domains

    def get_domain_status(self, domain: str) -> Dict[str, Any]:
        """Get current status for a monitored domain."""
        state = self._load_state(domain)
        if not state.get("last_scan"):
            return {"monitored": False, "domain": domain}

        return {
            "monitored": True,
            "domain": domain,
            "last_scan": state.get("last_scan"),
            "total_registered": state.get("total_registered", 0),
            "registered_domains": list(state.get("registered_domains", {}).keys()),
        }


# Singleton instance
_monitor: Optional[DomainMonitor] = None


def get_monitor() -> DomainMonitor:
    """Get the singleton DomainMonitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = DomainMonitor()
    return _monitor


def scan_domain(domain: str, check_parking: bool = True) -> Dict[str, Any]:
    """Convenience function to scan a domain for new lookalikes.

    Args:
        domain: Domain to monitor
        check_parking: Whether to check parking status

    Returns:
        Scan results with delta information
    """
    return get_monitor().scan_and_diff(domain, check_parking)
