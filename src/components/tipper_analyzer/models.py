"""Data models for tipper analysis results."""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any, Literal

from pydantic import BaseModel, Field, field_validator

# Default lookback periods for IOC hunting
DEFAULT_QRADAR_HUNT_HOURS = 168    # 7 days
DEFAULT_CROWDSTRIKE_HUNT_HOURS = 720  # 30 days
DEFAULT_XSIAM_HUNT_HOURS = 720     # 30 days
DEFAULT_THREAT_HUNT_HOURS = 168    # 7 days (behavioral/TTP hunts — recent-window focus)


class VulnerableProductMention(BaseModel):
    """A product/version combination explicitly flagged as vulnerable in the tipper text."""
    product: str = Field(
        description="Software or product name as it appears in the tipper, e.g. 'Apache Struts', 'OpenSSL', 'Microsoft Exchange'. Use the canonical product name, not the vendor."
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Vendor name if mentioned, e.g. 'Apache', 'OpenSSL Project', 'Microsoft'."
    )
    version_constraint: Optional[str] = Field(
        default=None,
        description="Affected version range exactly as stated, e.g. '< 2.5.30', '1.0.0 - 2.0.0', 'all versions before 4.2'. Use null if no version constraint is given."
    )


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
    whats_new_reasons: List[str] = Field(
        default_factory=list,
        description="1-3 specific elements that make this tipper NOVEL (e.g., 'New threat actor: APT47', 'Novel supply chain attack vector', 'First campaign targeting healthcare'). Leave empty if nothing is new."
    )
    whats_familiar_reasons: List[str] = Field(
        default_factory=list,
        description="1-3 specific elements that connect this tipper to the HISTORICAL TIPPERS provided. ONLY base this on the historical tippers shown — do NOT use your own knowledge. Reference ticket IDs (e.g., 'Same Octo Tempest campaign from #1237886'). MUST be empty if no historical tippers were provided."
    )
    vulnerable_products: List[VulnerableProductMention] = Field(
        default_factory=list,
        description=(
            "Products on a defender's environment that the tipper says are vulnerable AND that have "
            "NO CVE ID assigned anywhere in the tipper. Default is empty — only populate when both "
            "conditions are clearly met. Skip: (a) any product covered by a CVE-YYYY-NNNNN reference "
            "in the tipper, (b) tools the attacker uses, (c) products the attacker merely targets "
            "without a vulnerability claim, (d) attacker-owned infrastructure, (e) domains/URLs/IPs, "
            "(f) generic categories like 'Linux servers'. See the prompt for WRONG/RIGHT examples."
        )
    )

    @field_validator("vulnerable_products", mode="before")
    @classmethod
    def _coerce_vulnerable_products(cls, v):
        """Tolerate the way GLM (no constrained decoding) renders this field.

        It frequently returns bare product-name strings instead of
        {product, vendor, version_constraint} objects. Coerce strings to objects
        and drop anything unusable rather than failing the whole response.
        """
        if not isinstance(v, list):
            return []
        out = []
        for item in v:
            if isinstance(item, str) and item.strip():
                out.append({"product": item.strip()})
            elif isinstance(item, dict) and item.get("product"):
                out.append(item)
        return out

    @field_validator("novelty_label", mode="before")
    @classmethod
    def _normalize_novelty_label(cls, v):
        """Snap case/spacing variants to the canonical label (e.g. 'mostly new'
        -> 'Mostly New'); pass anything else through for the Literal to reject."""
        canon = {"seen before": "Seen Before", "familiar": "Familiar",
                 "mostly new": "Mostly New", "net new": "Net New"}
        if isinstance(v, str):
            return canon.get(" ".join(v.split()).lower(), v)
        return v


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
    veracode_exposure: Optional[Dict[str, Any]] = None  # Veracode SCA: which apps carry an affected component
    jfrog_exposure: Optional[Dict[str, Any]] = None  # JFrog Xray: which artifacts carry an affected component
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
    # CVE-less vulnerable products extracted from tipper text by the LLM
    vulnerable_products: List[Dict[str, Optional[str]]] = field(default_factory=list)
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
    # CrowdStrike Foundry access status
    foundry_access_denied: bool = False  # True if foundry:read perms not available
    # Raw telemetry events matched in LogScale (CrowdStrike only). Not scored into total_hits.
    logscale_events_found: int = 0


@dataclass
class IOCHuntResult:
    """Combined result of IOC hunting across all tools."""
    tipper_id: str
    tipper_title: str
    hunt_time: str
    total_iocs_searched: int
    total_hits: int
    search_hours_qradar: int = DEFAULT_QRADAR_HUNT_HOURS
    search_hours_crowdstrike: int = DEFAULT_CROWDSTRIKE_HUNT_HOURS
    search_hours_xsiam: int = DEFAULT_XSIAM_HUNT_HOURS
    qradar: Optional[ToolHuntResult] = None
    crowdstrike: Optional[ToolHuntResult] = None
    abnormal: Optional[ToolHuntResult] = None
    xsiam: Optional[ToolHuntResult] = None
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
    # Access issues for Webex notifications
    access_issues: List[str] = field(default_factory=list)  # List of tools/services with access issues

    def to_dict(self) -> dict:
        return asdict(self)


# ── Behavioral Threat Hunt (LLM-authored TTP queries) ─────────────────────────
# Distinct from IOC hunting above: instead of matching known indicators, an LLM
# authors behavioral/TTP hunt queries from the tipper narrative, which are then
# validated and executed against the SIEM.

@dataclass
class BehavioralHunt:
    """A single LLM-authored behavioral hunt: hypothesis + query + outcome."""
    title: str
    hypothesis: str
    query: str
    attack_technique: str = ""          # e.g. "T1059.001" (optional)
    query_type: str = "logscale"        # platform dialect of `query`
    status: str = "pending"             # executed | no_hits | skipped_validation | error
    hit_count: int = 0
    hostnames: List[str] = field(default_factory=list)
    detail: str = ""                    # validation reason / error / notes
    attempts: int = 0                   # how many CQL generations were tried (incl. LLM repairs)


@dataclass
class BehavioralHuntResult:
    """Result of a behavioral threat hunt across all LLM-authored queries."""
    tipper_id: str
    tipper_title: str
    hunt_time: str
    hunts: List[BehavioralHunt] = field(default_factory=list)
    queries_generated: int = 0
    queries_executed: int = 0
    total_hits: int = 0
    search_hours: int = DEFAULT_THREAT_HUNT_HOURS
    platform: str = "CrowdStrike LogScale"
    llm_model: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
