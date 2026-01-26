"""Data models for tipper analysis results."""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any


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
    hash_hits: List[Dict[str, Any]] = field(default_factory=list)
    email_hits: List[Dict[str, Any]] = field(default_factory=list)  # For Abnormal
    errors: List[str] = field(default_factory=list)


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

    def to_dict(self) -> dict:
        return asdict(self)
