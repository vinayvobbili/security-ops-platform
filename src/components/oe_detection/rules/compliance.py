"""Compliance-specific detection rules: OE-CMP-001, OE-CMP-002, OE-CMP-003."""
from __future__ import annotations

import logging

from src.components.oe_detection.base_rule import BaseRule
from src.components.oe_detection.models import Signal, SignalDomain

logger = logging.getLogger("oe_detector")


class FINRAOBAInconsistency(BaseRule):
    """OE-CMP-001: FINRA Outside Business Activity Inconsistency.

    Cross-references employee OBA disclosures with:
    - State LLC/business registration databases
    - LinkedIn profile affiliations
    - Public contractor platform profiles (Upwork, Toptal, etc.)

    Source: FINRA OBA disclosures + external data
    """

    rule_id = "OE-CMP-001"
    description = "FINRA OBA disclosure inconsistency"
    domain = SignalDomain.COMPLIANCE
    default_weight = 25

    def evaluate(self, employee_id: str) -> list[Signal]:
        hris = self.mcp_clients.get("hris")
        if not hris:
            return []

        oba_data = hris.call_tool("get_oba_disclosures", {
            "employee_id": employee_id,
        })

        external = hris.call_tool("get_external_activity_scan", {
            "employee_id": employee_id,
        })

        if not oba_data or not external:
            return []

        disclosed = set(oba_data.get("disclosed_activities", []))
        found_external = external.get("detected_activities", [])

        undisclosed = []
        for activity in found_external:
            activity_name = activity.get("name", "")
            activity_type = activity.get("type", "")

            is_disclosed = any(
                activity_name.lower() in d.lower() or d.lower() in activity_name.lower()
                for d in disclosed
            )

            if not is_disclosed:
                undisclosed.append({
                    "name": activity_name,
                    "type": activity_type,
                    "source": activity.get("source", "unknown"),
                    "detected_date": activity.get("detected_date", "unknown"),
                })

        if undisclosed:
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"Undisclosed outside business activity: "
                    f"{len(undisclosed)} finding(s) not in OBA disclosures"
                ),
                evidence={
                    "undisclosed_activities": undisclosed,
                    "disclosed_count": len(disclosed),
                    "total_detected": len(found_external),
                },
                source_tool="hris",
            )]

        return []


class DataExfiltrationPattern(BaseRule):
    """OE-CMP-002: Data Exfiltration Pattern.

    Detects unusual file access breadth, bulk downloads, or uploads
    to personal cloud storage - potential IP transfer to J2.

    Source: Varonis DLP + CrowdStrike cloud storage monitoring
    """

    rule_id = "OE-CMP-002"
    description = "Data exfiltration pattern detected"
    domain = SignalDomain.COMPLIANCE
    default_weight = 20

    def evaluate(self, employee_id: str) -> list[Signal]:
        varonis = self.mcp_clients.get("varonis")
        if not varonis:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        scope_threshold = rule_cfg.get("scope_deviation_pct", 200)
        window = self.config.get("scoring", {}).get("window_days", 30)

        access = varonis.call_tool("get_data_access_patterns", {
            "employee_id": employee_id,
            "window_days": window,
        })

        sensitive = varonis.call_tool("get_sensitive_data_events", {
            "employee_id": employee_id,
            "window_days": window,
        })

        if not access:
            return []

        triggers = []
        evidence = {}

        current_scope = access.get("unique_folders_accessed", 0)
        baseline_scope = access.get("baseline_unique_folders", 0)
        if baseline_scope > 0:
            scope_deviation = (current_scope - baseline_scope) / baseline_scope * 100
            if scope_deviation >= scope_threshold:
                triggers.append(
                    f"access scope +{scope_deviation:.0f}% "
                    f"({baseline_scope}->{current_scope} folders)"
                )
                evidence["scope_deviation_pct"] = round(scope_deviation, 1)

        bulk_events = access.get("bulk_download_events", [])
        if bulk_events:
            triggers.append(f"{len(bulk_events)} bulk download event(s)")
            evidence["bulk_downloads"] = len(bulk_events)
            evidence["bulk_download_details"] = bulk_events[:3]

        cloud_uploads = access.get("personal_cloud_uploads", [])
        if cloud_uploads:
            triggers.append(
                f"{len(cloud_uploads)} upload(s) to personal cloud storage"
            )
            evidence["personal_cloud_uploads"] = len(cloud_uploads)
            evidence["cloud_destinations"] = list(set(
                u.get("destination", "unknown") for u in cloud_uploads
            ))

        if sensitive:
            out_of_scope = sensitive.get("out_of_scope_access", [])
            if out_of_scope:
                triggers.append(
                    f"{len(out_of_scope)} sensitive file(s) accessed outside scope"
                )
                evidence["sensitive_out_of_scope"] = len(out_of_scope)
                evidence["data_classifications"] = list(set(
                    f.get("classification", "unknown") for f in out_of_scope
                ))

        if triggers:
            return [self._make_signal(
                employee_id=employee_id,
                description=f"Data exfiltration indicators: {'; '.join(triggers)}",
                evidence=evidence,
                source_tool="varonis",
            )]

        return []


class BenefitsEnrollmentAnomaly(BaseRule):
    """OE-CMP-003: Benefits Enrollment Anomaly.

    Detects when employees decline health insurance (especially if
    previously enrolled) or make unusual W-4 changes.

    Source: HRIS / Payroll system
    """

    rule_id = "OE-CMP-003"
    description = "Benefits enrollment anomaly"
    domain = SignalDomain.COMPLIANCE
    default_weight = 5

    def evaluate(self, employee_id: str) -> list[Signal]:
        hris = self.mcp_clients.get("hris")
        if not hris:
            return []

        benefits = hris.call_tool("get_benefits_status", {
            "employee_id": employee_id,
        })

        if not benefits:
            return []

        triggers = []
        evidence = {}

        if benefits.get("health_declined_after_enrollment"):
            triggers.append("declined health insurance (previously enrolled)")
            evidence["prior_plan"] = benefits.get("prior_health_plan", "unknown")
            evidence["decline_date"] = benefits.get("decline_date", "unknown")

        w4_changes = benefits.get("recent_w4_changes", [])
        for change in w4_changes:
            if change.get("high_exempt_allowances"):
                triggers.append("W-4 changed to high exempt allowances")
                evidence["w4_change_date"] = change.get("date", "unknown")

        if triggers:
            return [self._make_signal(
                employee_id=employee_id,
                description=f"Benefits anomaly: {'; '.join(triggers)}",
                evidence=evidence,
                source_tool="hris",
            )]

        return []
