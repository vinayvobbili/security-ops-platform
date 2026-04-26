"""Network & Endpoint detection rules: OE-NET-001, OE-NET-002, OE-NET-003."""
from __future__ import annotations

import logging

from src.components.oe_detection.base_rule import BaseRule
from src.components.oe_detection.models import Signal, SignalDomain

logger = logging.getLogger("oe_detector")


class SharedIPNonCorpVPN(BaseRule):
    """OE-NET-001: Shared IP with Non-Corporate VPN.

    Detects when a user's corporate device shares a public IP with
    outbound connections to enterprise SSO/VPN endpoints that don't
    belong to our organization.

    Sources: CrowdStrike EDR + ZScaler (via cs-mcp-server)
    """

    rule_id = "OE-NET-001"
    description = "Shared IP with non-corporate VPN traffic"
    domain = SignalDomain.NETWORK
    default_weight = 20

    def evaluate(self, employee_id: str) -> list[Signal]:
        cs = self.mcp_clients.get("crowdstrike")
        if not cs:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        min_days = rule_cfg.get("min_recurrence_days", 5)
        window = self.config.get("scoring", {}).get("window_days", 30)

        connections = cs.call_tool("get_network_connections", {
            "employee_id": employee_id,
            "days": window,
        })

        if not connections or "connections" not in connections:
            return []

        our_domains = connections.get("org_domains", [])
        suspicious_days = set()

        for conn in connections.get("connections", []):
            dest = conn.get("destination", "")
            dest_type = conn.get("dest_type", "")

            is_enterprise_sso = dest_type in ("okta_tenant", "azure_ad", "ping_sso")
            is_vpn = dest_type in ("cisco_anyconnect", "globalprotect", "zscaler_other")
            is_ours = any(d in dest for d in our_domains)

            if (is_enterprise_sso or is_vpn) and not is_ours:
                day = conn.get("date", "")[:10]
                suspicious_days.add(day)

        if len(suspicious_days) >= min_days:
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"Corporate device shares public IP with non-org enterprise "
                    f"SSO/VPN traffic on {len(suspicious_days)} days "
                    f"(threshold: {min_days})"
                ),
                evidence={
                    "suspicious_days_count": len(suspicious_days),
                    "sample_days": sorted(suspicious_days)[:5],
                    "threshold": min_days,
                },
                source_tool="crowdstrike",
            )]

        return []


class IdleActiveCycling(BaseRule):
    """OE-NET-002: Idle/Active Cycling Pattern.

    Detects regular cycles of active bursts followed by idle periods
    that deviate significantly from the user's historical baseline.

    Source: CrowdStrike process telemetry
    """

    rule_id = "OE-NET-002"
    description = "Idle/Active cycling pattern on endpoint"
    domain = SignalDomain.ENDPOINT
    default_weight = 15

    def evaluate(self, employee_id: str) -> list[Signal]:
        cs = self.mcp_clients.get("crowdstrike")
        if not cs:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        std_threshold = rule_cfg.get("std_dev_threshold", 2.0)
        cycle_min = rule_cfg.get("cycle_min_minutes", 20)
        cycle_max = rule_cfg.get("cycle_max_minutes", 40)
        window = self.config.get("scoring", {}).get("window_days", 30)
        baseline_days = self.config.get("scoring", {}).get("baseline_days", 90)

        timeline = cs.call_tool("get_process_timeline", {
            "employee_id": employee_id,
            "days": window,
        })

        baseline = cs.call_tool("get_process_timeline", {
            "employee_id": employee_id,
            "days": baseline_days,
            "summary_only": True,
        })

        if not timeline or not baseline:
            return []

        current_cycles = timeline.get("idle_active_cycles", [])
        baseline_mean = baseline.get("avg_cycle_minutes", 0)
        baseline_std = baseline.get("std_cycle_minutes", 1)

        suspicious_cycles = [
            c for c in current_cycles
            if cycle_min <= c.get("active_min", 0) <= cycle_max
            and cycle_min <= c.get("idle_min", 0) <= cycle_max
        ]

        if not suspicious_cycles:
            return []

        avg_current = sum(
            c.get("active_min", 0) + c.get("idle_min", 0)
            for c in suspicious_cycles
        ) / len(suspicious_cycles)

        if baseline_std > 0:
            z_score = abs(avg_current - baseline_mean) / baseline_std
        else:
            z_score = 0

        if z_score >= std_threshold and len(suspicious_cycles) >= 5:
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"Regular idle/active cycling detected: "
                    f"{len(suspicious_cycles)} cycles in {cycle_min}-{cycle_max}min range, "
                    f"z-score={z_score:.1f} (threshold: {std_threshold})"
                ),
                evidence={
                    "suspicious_cycle_count": len(suspicious_cycles),
                    "z_score": round(z_score, 2),
                    "avg_cycle_minutes": round(avg_current, 1),
                    "baseline_mean": round(baseline_mean, 1),
                    "baseline_std": round(baseline_std, 1),
                },
                source_tool="crowdstrike",
            )]

        return []


class UnauthorizedRemoteTools(BaseRule):
    """OE-NET-003: Unauthorized Remote Access Tools.

    Detects installation of KVM-sharing, remote desktop, or
    secondary VPN software on corporate endpoints.

    Source: Tanium installed software inventory
    """

    rule_id = "OE-NET-003"
    description = "Unauthorized remote access tools detected"
    domain = SignalDomain.ENDPOINT
    default_weight = 10

    def evaluate(self, employee_id: str) -> list[Signal]:
        tanium = self.mcp_clients.get("tanium")
        if not tanium:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        flagged = [t.lower() for t in rule_cfg.get("flagged_tools", [])]

        software = tanium.call_tool("get_installed_software", {
            "employee_id": employee_id,
        })

        if not software or "applications" not in software:
            return []

        found = []
        for app in software.get("applications", []):
            app_name = app.get("name", "").lower()
            for flagged_tool in flagged:
                if flagged_tool.lower() in app_name:
                    found.append({
                        "name": app.get("name"),
                        "version": app.get("version", "unknown"),
                        "installed_date": app.get("install_date", "unknown"),
                    })

        if found:
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"Unauthorized remote access tool(s) found: "
                    f"{', '.join(f['name'] for f in found)}"
                ),
                evidence={
                    "flagged_applications": found,
                },
                source_tool="tanium",
            )]

        return []
