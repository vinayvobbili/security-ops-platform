"""Core data models for the OE Detection Framework."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float, thresholds: dict) -> RiskLevel:
        if score >= thresholds.get("critical", 80):
            return cls.CRITICAL
        if score >= thresholds.get("high", 55):
            return cls.HIGH
        if score >= thresholds.get("medium", 30):
            return cls.MEDIUM
        return cls.LOW


class SignalDomain(str, Enum):
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    BEHAVIORAL = "behavioral"
    COMPLIANCE = "compliance"


@dataclass
class Signal:
    """A single detection signal from a rule evaluation."""
    signal_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    rule_id: str = ""
    employee_id: str = ""
    domain: SignalDomain = SignalDomain.NETWORK
    weight: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    source_tool: str = ""

    def to_dict(self) -> dict:
        return {
            "signal_id": self.signal_id,
            "rule_id": self.rule_id,
            "employee_id": self.employee_id,
            "domain": self.domain.value,
            "weight": self.weight,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "evidence": self.evidence,
            "source_tool": self.source_tool,
        }


@dataclass
class RiskScore:
    """Composite risk score for an employee."""
    score_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    employee_id: str = ""
    employee_name: str = ""
    raw_score: float = 0.0
    normalized_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    signals: list[Signal] = field(default_factory=list)
    domains_hit: set[str] = field(default_factory=set)
    correlation_multiplier: float = 1.0
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    narrative: str = ""

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def domain_count(self) -> int:
        return len(self.domains_hit)

    def to_dict(self) -> dict:
        return {
            "score_id": self.score_id,
            "employee_id": self.employee_id,
            "employee_name": self.employee_name,
            "raw_score": round(self.raw_score, 2),
            "normalized_score": round(self.normalized_score, 2),
            "risk_level": self.risk_level.value,
            "signal_count": self.signal_count,
            "domain_count": self.domain_count,
            "domains_hit": list(self.domains_hit),
            "correlation_multiplier": self.correlation_multiplier,
            "calculated_at": self.calculated_at.isoformat(),
            "narrative": self.narrative,
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass
class Alert:
    """An alert dispatched to SOC / escalation targets."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    risk_score: RiskScore = field(default_factory=RiskScore)
    dispatched_to: list[str] = field(default_factory=list)
    dispatched_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    acknowledged_by: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "risk_score": self.risk_score.to_dict(),
            "dispatched_to": self.dispatched_to,
            "dispatched_at": self.dispatched_at.isoformat(),
            "acknowledged": self.acknowledged,
        }
