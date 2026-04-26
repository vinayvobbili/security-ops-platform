"""Identity & Access detection rules: OE-IDN-001, OE-IDN-002."""
from __future__ import annotations

import logging

from src.components.oe_detection.base_rule import BaseRule
from src.components.oe_detection.models import Signal, SignalDomain

logger = logging.getLogger("oe_detector")


class AuthCadenceShift(BaseRule):
    """OE-IDN-001: Authentication Cadence Shift.

    Detects when a user's login time distribution shifts significantly
    or develops a bimodal pattern (early + late logins).

    Source: Okta / Azure AD authentication logs
    """

    rule_id = "OE-IDN-001"
    description = "Authentication cadence shift detected"
    domain = SignalDomain.IDENTITY
    default_weight = 15

    def evaluate(self, employee_id: str) -> list[Signal]:
        identity = self.mcp_clients.get("identity")
        if not identity:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        shift_hours = rule_cfg.get("login_shift_hours", 1.0)
        session_drop = rule_cfg.get("session_duration_drop_pct", 30)
        window = self.config.get("scoring", {}).get("window_days", 30)
        baseline_days = self.config.get("scoring", {}).get("baseline_days", 90)

        current = identity.call_tool("get_auth_patterns", {
            "employee_id": employee_id,
            "window_days": window,
        })

        baseline = identity.call_tool("get_auth_patterns", {
            "employee_id": employee_id,
            "window_days": baseline_days,
            "summary_only": True,
        })

        if not current or not baseline:
            return []

        signals = []

        current_avg_hour = current.get("avg_first_login_hour", 9.0)
        baseline_avg_hour = baseline.get("avg_first_login_hour", 9.0)
        hour_shift = abs(current_avg_hour - baseline_avg_hour)

        login_hours = current.get("login_hour_distribution", {})
        early_logins = sum(login_hours.get(str(h), 0) for h in range(5, 8))
        late_logins = sum(login_hours.get(str(h), 0) for h in range(18, 23))
        total_logins = sum(login_hours.values()) or 1
        bimodal = (early_logins / total_logins > 0.15) and (late_logins / total_logins > 0.15)

        current_session = current.get("avg_session_minutes", 480)
        baseline_session = baseline.get("avg_session_minutes", 480)
        session_pct_change = 0
        if baseline_session > 0:
            session_pct_change = (
                (baseline_session - current_session) / baseline_session * 100
            )

        triggered = False
        evidence = {}

        if hour_shift >= shift_hours:
            triggered = True
            evidence["login_shift_hours"] = round(hour_shift, 1)
            evidence["current_avg_login"] = f"{current_avg_hour:.1f}:00"
            evidence["baseline_avg_login"] = f"{baseline_avg_hour:.1f}:00"

        if bimodal:
            triggered = True
            evidence["bimodal_pattern"] = True
            evidence["early_login_pct"] = round(early_logins / total_logins * 100, 1)
            evidence["late_login_pct"] = round(late_logins / total_logins * 100, 1)

        if session_pct_change >= session_drop:
            triggered = True
            evidence["session_duration_drop_pct"] = round(session_pct_change, 1)

        if triggered:
            desc_parts = []
            if "login_shift_hours" in evidence:
                desc_parts.append(f"login shifted {evidence['login_shift_hours']}h")
            if evidence.get("bimodal_pattern"):
                desc_parts.append("bimodal login pattern")
            if "session_duration_drop_pct" in evidence:
                desc_parts.append(f"session duration -{evidence['session_duration_drop_pct']:.0f}%")

            return [self._make_signal(
                employee_id=employee_id,
                description=f"Auth cadence anomaly: {'; '.join(desc_parts)}",
                evidence=evidence,
                source_tool="okta",
            )]

        return []


class SaaSEngagementDrop(BaseRule):
    """OE-IDN-002: SaaS Engagement Drop.

    Detects when the number of distinct corporate SaaS apps accessed
    drops significantly, suggesting disengagement.

    Source: Okta SSO app access logs
    """

    rule_id = "OE-IDN-002"
    description = "SaaS application engagement drop"
    domain = SignalDomain.IDENTITY
    default_weight = 10

    def evaluate(self, employee_id: str) -> list[Signal]:
        identity = self.mcp_clients.get("identity")
        if not identity:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        drop_threshold = rule_cfg.get("app_drop_pct", 40)
        window = self.config.get("scoring", {}).get("window_days", 30)

        usage = identity.call_tool("get_sso_app_usage", {
            "employee_id": employee_id,
            "window_days": window,
        })

        if not usage:
            return []

        current_apps = usage.get("avg_daily_apps_current", 0)
        baseline_apps = usage.get("avg_daily_apps_baseline", 0)
        only_essential = usage.get("essential_apps_only_days", 0)
        total_days = usage.get("work_days_in_window", 1)

        if baseline_apps <= 0:
            return []

        drop_pct = (baseline_apps - current_apps) / baseline_apps * 100
        essential_ratio = only_essential / total_days * 100

        if drop_pct >= drop_threshold:
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"SaaS engagement dropped {drop_pct:.0f}% "
                    f"({baseline_apps:.1f} -> {current_apps:.1f} avg daily apps). "
                    f"Essential-only days: {essential_ratio:.0f}%"
                ),
                evidence={
                    "current_avg_daily_apps": round(current_apps, 1),
                    "baseline_avg_daily_apps": round(baseline_apps, 1),
                    "drop_pct": round(drop_pct, 1),
                    "essential_only_days_pct": round(essential_ratio, 1),
                    "remaining_apps": usage.get("current_apps_list", []),
                },
                source_tool="okta",
            )]

        return []
