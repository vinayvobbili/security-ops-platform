"""Behavioral & Collaboration detection rules: OE-BEH-001, OE-BEH-002, OE-BEH-003."""
from __future__ import annotations

import logging

from src.components.oe_detection.base_rule import BaseRule
from src.components.oe_detection.models import Signal, SignalDomain

logger = logging.getLogger("oe_detector")


class MeetingAvoidance(BaseRule):
    """OE-BEH-001: Meeting Avoidance Pattern.

    Detects high decline rates, camera-off spikes, and frequent
    last-minute cancellations.

    Source: Calendar API + Meeting platform analytics
    """

    rule_id = "OE-BEH-001"
    description = "Meeting avoidance pattern"
    domain = SignalDomain.BEHAVIORAL
    default_weight = 10

    def evaluate(self, employee_id: str) -> list[Signal]:
        collab = self.mcp_clients.get("collaboration")
        if not collab:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        decline_thresh = rule_cfg.get("decline_rate_threshold", 40)
        decline_base = rule_cfg.get("decline_rate_baseline", 15)
        cam_off_thresh = rule_cfg.get("camera_off_threshold", 80)
        cam_on_base = rule_cfg.get("camera_on_baseline", 50)
        cancel_max = rule_cfg.get("cancellation_weekly_max", 3)
        window = self.config.get("scoring", {}).get("window_days", 30)

        metrics = collab.call_tool("get_meeting_metrics", {
            "employee_id": employee_id,
            "window_days": window,
        })

        if not metrics:
            return []

        triggers = []
        evidence = {}

        decline_rate = metrics.get("decline_rate_pct", 0)
        baseline_decline = metrics.get("baseline_decline_rate_pct", 0)
        if decline_rate >= decline_thresh and baseline_decline < decline_base:
            triggers.append(f"decline rate {decline_rate:.0f}%")
            evidence["decline_rate_current"] = decline_rate
            evidence["decline_rate_baseline"] = baseline_decline

        cam_off_rate = metrics.get("camera_off_rate_pct", 0)
        baseline_cam_on = metrics.get("baseline_camera_on_pct", 0)
        if cam_off_rate >= cam_off_thresh and baseline_cam_on >= cam_on_base:
            triggers.append(f"camera off {cam_off_rate:.0f}%")
            evidence["camera_off_rate"] = cam_off_rate
            evidence["baseline_camera_on"] = baseline_cam_on

        avg_weekly_cancels = metrics.get("avg_weekly_last_minute_cancels", 0)
        if avg_weekly_cancels >= cancel_max:
            triggers.append(f"{avg_weekly_cancels:.1f} cancels/week")
            evidence["avg_weekly_cancellations"] = avg_weekly_cancels

        if triggers:
            return [self._make_signal(
                employee_id=employee_id,
                description=f"Meeting avoidance: {'; '.join(triggers)}",
                evidence=evidence,
                source_tool="calendar",
            )]

        return []


class ResponseDegradation(BaseRule):
    """OE-BEH-002: Communication Responsiveness Degradation.

    Detects significant increase in message response times and
    extended away/DND periods during core hours.

    Source: Slack / Teams / Webex analytics API
    """

    rule_id = "OE-BEH-002"
    description = "Communication responsiveness degradation"
    domain = SignalDomain.BEHAVIORAL
    default_weight = 10

    def evaluate(self, employee_id: str) -> list[Signal]:
        collab = self.mcp_clients.get("collaboration")
        if not collab:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        response_increase = rule_cfg.get("response_time_increase_pct", 200)
        away_threshold = rule_cfg.get("away_hours_threshold", 4)
        window = self.config.get("scoring", {}).get("window_days", 30)

        metrics = collab.call_tool("get_message_metrics", {
            "employee_id": employee_id,
            "window_days": window,
        })

        presence = collab.call_tool("get_presence_data", {
            "employee_id": employee_id,
            "window_days": window,
        })

        if not metrics and not presence:
            return []

        triggers = []
        evidence = {}

        if metrics:
            current_median = metrics.get("median_response_minutes", 0)
            baseline_median = metrics.get("baseline_median_response_minutes", 0)
            if baseline_median > 0:
                pct_increase = (
                    (current_median - baseline_median) / baseline_median * 100
                )
                if pct_increase >= response_increase:
                    triggers.append(
                        f"response time +{pct_increase:.0f}% "
                        f"({baseline_median:.0f}->{current_median:.0f}min)"
                    )
                    evidence["response_time_increase_pct"] = round(pct_increase, 1)
                    evidence["current_median_response_min"] = round(current_median, 1)
                    evidence["baseline_median_response_min"] = round(baseline_median, 1)

        if presence:
            avg_away_hours = presence.get("avg_away_dnd_core_hours", 0)
            if avg_away_hours >= away_threshold:
                triggers.append(f"Away/DND {avg_away_hours:.1f}h/day core hours")
                evidence["avg_away_core_hours"] = round(avg_away_hours, 1)

        if triggers:
            return [self._make_signal(
                employee_id=employee_id,
                description=f"Responsiveness degradation: {'; '.join(triggers)}",
                evidence=evidence,
                source_tool="collaboration",
            )]

        return []


class OutputVelocityFloor(BaseRule):
    """OE-BEH-003: Output Velocity Floor.

    Detects when work output converges to a suspiciously steady
    minimum-viable level across multiple sprints.

    Source: Jira / GitHub / DevOps platform APIs
    """

    rule_id = "OE-BEH-003"
    description = "Output velocity converged to minimum floor"
    domain = SignalDomain.BEHAVIORAL
    default_weight = 10

    def evaluate(self, employee_id: str) -> list[Signal]:
        collab = self.mcp_clients.get("collaboration")
        if not collab:
            return []

        rule_cfg = self.config.get("rules", {}).get(self.rule_id, {})
        min_sprints = rule_cfg.get("consecutive_sprints", 4)
        cv_threshold = rule_cfg.get("cv_threshold", 0.10)

        metrics = collab.call_tool("get_work_output_metrics", {
            "employee_id": employee_id,
        })

        if not metrics:
            return []

        recent_sprints = metrics.get("recent_sprint_velocities", [])
        baseline_sprints = metrics.get("baseline_sprint_velocities", [])
        min_expected = metrics.get("min_expected_velocity", 0)

        if len(recent_sprints) < min_sprints:
            return []

        import statistics
        recent_window = recent_sprints[-min_sprints:]
        mean_v = statistics.mean(recent_window)
        std_v = statistics.stdev(recent_window) if len(recent_window) > 1 else 0
        cv = std_v / mean_v if mean_v > 0 else 0

        if baseline_sprints and len(baseline_sprints) > 3:
            baseline_mean = statistics.mean(baseline_sprints)
            baseline_std = statistics.stdev(baseline_sprints)
            baseline_cv = baseline_std / baseline_mean if baseline_mean > 0 else 0
        else:
            baseline_cv = 0.3

        near_floor = mean_v <= min_expected * 1.2 if min_expected > 0 else False
        low_variance = cv <= cv_threshold
        variance_dropped = baseline_cv > cv_threshold * 2

        if low_variance and (near_floor or variance_dropped):
            return [self._make_signal(
                employee_id=employee_id,
                description=(
                    f"Output velocity plateaued at floor: "
                    f"CV={cv:.2f} over {min_sprints} sprints "
                    f"(baseline CV={baseline_cv:.2f}), "
                    f"avg velocity={mean_v:.1f}"
                ),
                evidence={
                    "recent_velocities": recent_window,
                    "coefficient_of_variation": round(cv, 3),
                    "baseline_cv": round(baseline_cv, 3),
                    "mean_velocity": round(mean_v, 1),
                    "min_expected": min_expected,
                    "sprints_analyzed": min_sprints,
                },
                source_tool="jira",
            )]

        return []
