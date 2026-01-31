"""Data models for the detection rules catalog."""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class DetectionRule:
    """A normalized detection rule from any platform."""
    rule_id: str                    # Platform-specific ID
    platform: str                   # "qradar", "crowdstrike", "tanium"
    name: str                       # Rule name/title
    description: str = ""
    rule_type: str = ""             # "custom_rule", "saved_search", "ioa_rule", "signal", "ioc"
    enabled: bool = True
    severity: str = ""              # "critical", "high", "medium", "low", "informational"
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    created_date: str = ""
    modified_date: str = ""

    def to_search_text(self) -> str:
        """Combine fields into text for embedding."""
        parts = [self.name]
        if self.description:
            parts.append(self.description)
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        if self.malware_families:
            parts.append(f"Malware: {', '.join(self.malware_families)}")
        if self.threat_actors:
            parts.append(f"Actors: {', '.join(self.threat_actors)}")
        if self.mitre_techniques:
            parts.append(f"MITRE: {', '.join(self.mitre_techniques)}")
        return "\n".join(parts)

    def to_metadata(self) -> Dict[str, Any]:
        """Convert to ChromaDB-compatible metadata dict (flat strings)."""
        # Truncate description to 500 chars for ChromaDB storage efficiency
        desc = self.description[:500] if self.description else ""
        return {
            "rule_id": self.rule_id,
            "platform": self.platform,
            "name": self.name,
            "description": desc,
            "rule_type": self.rule_type,
            "enabled": str(self.enabled),
            "severity": self.severity,
            "tags": ", ".join(self.tags) if self.tags else "",
            "malware_families": ", ".join(self.malware_families) if self.malware_families else "",
            "threat_actors": ", ".join(self.threat_actors) if self.threat_actors else "",
            "mitre_techniques": ", ".join(self.mitre_techniques) if self.mitre_techniques else "",
            "created_date": self.created_date,
            "modified_date": self.modified_date,
        }


@dataclass
class RuleSearchResult:
    """A single rule search result with relevance score."""
    rule: DetectionRule
    score: float  # 0.0 to 1.0 similarity
    match_type: str = "vector"  # "vector", "keyword", or "hybrid"


@dataclass
class RuleCatalogSearchResult:
    """Combined result from a catalog search."""
    query: str
    results: List[RuleSearchResult] = field(default_factory=list)
    total_found: int = 0
    platform_filter: str = ""  # If filtered by platform

    @property
    def has_results(self) -> bool:
        return len(self.results) > 0


@dataclass
class PlatformSyncStatus:
    """Sync status for a single platform."""
    platform: str
    success: bool = True
    rules_fetched: int = 0
    rules_upserted: int = 0
    error: str = ""


@dataclass
class CatalogSyncResult:
    """Result of syncing the rules catalog across platforms."""
    platforms: List[PlatformSyncStatus] = field(default_factory=list)
    total_rules: int = 0
    total_upserted: int = 0

    @property
    def all_success(self) -> bool:
        return all(p.success for p in self.platforms)

    @property
    def summary(self) -> str:
        parts = []
        for p in self.platforms:
            status = "OK" if p.success else f"FAILED: {p.error}"
            parts.append(f"  {p.platform}: {p.rules_fetched} rules ({status})")
        return f"Sync complete: {self.total_rules} total rules\n" + "\n".join(parts)
