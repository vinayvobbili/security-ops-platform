"""Base class for all OE detection rules."""
from __future__ import annotations

from abc import ABC, abstractmethod

from src.components.oe_detection.mcp_client import MCPClient
from src.components.oe_detection.models import Signal, SignalDomain


class BaseRule(ABC):
    """Base class for all OE detection rules.

    Each rule:
      1. Collects data from one or more MCP servers
      2. Evaluates the data against detection logic
      3. Returns a list of Signal objects (empty if no detection)
    """

    rule_id: str = ""
    description: str = ""
    domain: SignalDomain = SignalDomain.NETWORK
    default_weight: int = 0

    def __init__(self, config: dict, mcp_clients: dict[str, MCPClient]):
        self.config = config
        self.mcp_clients = mcp_clients

        rule_cfg = config.get("rules", {}).get(self.rule_id, {})
        self.enabled = rule_cfg.get("enabled", True)
        self.weight = rule_cfg.get("weight", self.default_weight)

    @abstractmethod
    def evaluate(self, employee_id: str) -> list[Signal]:
        """Run detection logic for a single employee.
        Returns list of Signal objects (empty = no detection).
        """
        ...

    def _make_signal(self, employee_id: str, description: str,
                     evidence: dict | None = None,
                     source_tool: str = "") -> Signal:
        return Signal(
            rule_id=self.rule_id,
            employee_id=employee_id,
            domain=self.domain,
            weight=self.weight,
            description=description,
            evidence=evidence or {},
            source_tool=source_tool,
        )
