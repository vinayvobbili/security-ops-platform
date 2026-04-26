"""Composite Risk Scoring Engine.

Aggregates signals from all detection rules into a per-employee
risk score with time-decayed weights and cross-domain correlation.
"""
from __future__ import annotations

import logging
from datetime import datetime

from src.components.oe_detection.models import RiskLevel, RiskScore, Signal

logger = logging.getLogger("oe_detector")


class ScoringEngine:
    """Calculates composite OE risk scores from individual signals.

    Features:
    - Time-decayed signal weights (recent signals count more)
    - Cross-domain correlation multiplier (3+ domains = boost)
    - Score normalization to 0-100 range
    """

    def __init__(self, config: dict):
        self.config = config
        scoring_cfg = config.get("scoring", {})
        self.window_days = scoring_cfg.get("window_days", 30)
        self.decay_floor = scoring_cfg.get("decay_floor", 0.3)
        self.max_score = scoring_cfg.get("max_score", 100)

        corr_cfg = scoring_cfg.get("correlation", {})
        self.boost_3_domains = corr_cfg.get("domain_threshold_3", 1.25)
        self.boost_4_domains = corr_cfg.get("domain_threshold_4", 1.15)

        self.thresholds = config.get("thresholds", {
            "low": 0, "medium": 30, "high": 55, "critical": 80,
        })

    def calculate(
        self,
        employee_id: str,
        employee_name: str,
        signals: list[Signal],
    ) -> RiskScore:
        now = datetime.utcnow()
        raw_score = 0.0
        domains_hit = set()

        for signal in signals:
            age_days = (now - signal.timestamp).total_seconds() / 86400
            decay = max(
                self.decay_floor,
                1.0 - (age_days / self.window_days * (1.0 - self.decay_floor))
            )
            raw_score += signal.weight * decay
            domains_hit.add(signal.domain.value)

        # Cross-domain correlation multiplier
        multiplier = 1.0
        domain_count = len(domains_hit)

        if domain_count >= 4:
            multiplier = self.boost_3_domains * self.boost_4_domains
        elif domain_count >= 3:
            multiplier = self.boost_3_domains

        boosted_score = raw_score * multiplier
        normalized = min(boosted_score, self.max_score)

        risk_level = RiskLevel.from_score(normalized, self.thresholds)

        score = RiskScore(
            employee_id=employee_id,
            employee_name=employee_name,
            raw_score=raw_score,
            normalized_score=normalized,
            risk_level=risk_level,
            signals=signals,
            domains_hit=domains_hit,
            correlation_multiplier=multiplier,
        )

        logger.info(
            f"Score for {employee_name} ({employee_id}): "
            f"{normalized:.1f} ({risk_level.value}) | "
            f"{len(signals)} signals across {domain_count} domains | "
            f"multiplier={multiplier:.2f}"
        )

        return score

    def should_alert(self, score: RiskScore, min_level: str) -> bool:
        level_order = ["low", "medium", "high", "critical"]
        try:
            score_idx = level_order.index(score.risk_level.value)
            min_idx = level_order.index(min_level)
            return score_idx >= min_idx
        except ValueError:
            return False
