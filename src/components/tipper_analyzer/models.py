"""Data models for tipper analysis results."""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any, Literal

from pydantic import BaseModel, Field


class NoveltyLLMResponse(BaseModel):
    """Simplified Pydantic model for LLM output.

    LLM focuses on core analysis only. Python handles:
    - what_is_new/what_is_familiar (computed from entity overlap)
    - related_tickets (from vector search)
    - formatting
    """

    novelty_score: int = Field(
        description="Novelty score from 1-10. 1-3: Seen Before, 4-5: Familiar, 6-7: Mostly New, 8-10: Net New",
        ge=1,
        le=10,
    )
    novelty_label: Literal["Seen Before", "Familiar", "Mostly New", "Net New"] = Field(
        description="Human-readable novelty label based on the score"
    )
    summary: str = Field(
        description="2-3 sentence executive summary comparing this tipper to historical ones. Focus on the narrative: what threat is this, who is the actor, what are they doing, and how does it relate to past tippers."
    )
    recommendation: str = Field(
        description="One of: 'PRIORITIZE - Novel threat requiring deep investigation', 'STANDARD - Review and leverage past analysis', or 'EXPEDITE - Familiar pattern, apply known playbook'"
    )


@dataclass
class NoveltyAnalysis:
    """Structured result of tipper novelty analysis."""
    tipper_id: str
    tipper_title: str
    created_date: str  # When the tipper was created
    novelty_score: int  # 1-10 scale
    novelty_label: str  # "Net New", "Mostly New", "Familiar", "Seen Before"
    summary: str
    what_is_new: List[str]
    what_is_familiar: List[str]
    related_tickets: List[Dict]
    recommendation: str
    raw_llm_response: str = ""
    rf_enrichment: Dict[str, Any] = field(default_factory=dict)  # Recorded Future intel
    ioc_history: Dict[str, List[str]] = field(default_factory=dict)  # IOC -> [tipper_ids] seen before
    malware_history: Dict[str, List[str]] = field(default_factory=dict)  # Malware -> [tipper_ids] seen before
    current_malware: List[str] = field(default_factory=list)  # Malware families in current tipper
    total_iocs_extracted: Dict[str, int] = field(default_factory=dict)  # Count of all IOCs extracted
    existing_rules: Dict[str, Any] = field(default_factory=dict)  # Detection rules coverage by search term
    history_dates: Dict[str, str] = field(default_factory=dict)  # tipper_id -> created_date for recency display
    # MITRE ATT&CK coverage analysis
    mitre_techniques: List[str] = field(default_factory=list)  # Techniques extracted from tipper
    mitre_covered: List[str] = field(default_factory=list)  # Techniques with existing detection rules
    mitre_gaps: List[str] = field(default_factory=list)  # Techniques WITHOUT detection rules
    mitre_rules: Dict[str, List[Dict]] = field(default_factory=dict)  # Technique -> [rule info dicts]
    # Actionable recommendations
    actionable_steps: List[Dict[str, str]] = field(default_factory=list)  # {action, priority, detail}
    # Environment exposure
    exposure_summary: Dict[str, Any] = field(default_factory=dict)  # {hosts_affected, users_affected, etc.}
    # Token metrics from LLM call
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    prompt_time: float = 0.0
    generation_time: float = 0.0
    tokens_per_sec: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ToolHuntResult:
    """Result of IOC hunting from a single tool."""
    tool_name: str  # "QRadar", "CrowdStrike", "Abnormal"
    total_hits: int
    ip_hits: List[Dict[str, Any]] = field(default_factory=list)
    domain_hits: List[Dict[str, Any]] = field(default_factory=list)
    url_hits: List[Dict[str, Any]] = field(default_factory=list)  # URL paths (registry.npmjs.org/package/)
    filename_hits: List[Dict[str, Any]] = field(default_factory=list)  # Malicious filenames (install.ps1)
    hash_hits: List[Dict[str, Any]] = field(default_factory=list)
    email_hits: List[Dict[str, Any]] = field(default_factory=list)  # For Abnormal
    errors: List[str] = field(default_factory=list)
    # Queries executed (for transparency)
    queries: List[Dict[str, str]] = field(default_factory=list)  # [{type, query}]


@dataclass
class IOCHuntResult:
    """Combined result of IOC hunting across all tools."""
    tipper_id: str
    tipper_title: str
    hunt_time: str
    total_iocs_searched: int
    total_hits: int
    search_hours: int = 720
    qradar: Optional[ToolHuntResult] = None
    crowdstrike: Optional[ToolHuntResult] = None
    abnormal: Optional[ToolHuntResult] = None
    errors: List[str] = field(default_factory=list)
    # Environment exposure summary
    unique_hosts: int = 0
    unique_users: int = 0
    unique_sources: List[str] = field(default_factory=list)
    # IOCs that were searched (for display in results)
    searched_domains: List[str] = field(default_factory=list)
    searched_urls: List[str] = field(default_factory=list)  # URL paths with benign domains
    searched_filenames: List[str] = field(default_factory=list)  # Malicious script filenames
    searched_ips: List[str] = field(default_factory=list)
    searched_hashes: List[str] = field(default_factory=list)
    # Queries executed (for transparency/verification)
    queries_executed: List[Dict[str, str]] = field(default_factory=list)  # [{tool, query_type, query}]

    def to_dict(self) -> dict:
        return asdict(self)
