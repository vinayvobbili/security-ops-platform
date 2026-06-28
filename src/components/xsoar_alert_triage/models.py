"""Data models for XSOAR alert triage."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Literal

from pydantic import BaseModel, Field


@dataclass
class SimilarTicketPrediction:
    """Prediction based on semantically similar past XSOAR tickets."""
    sample_size: int
    avg_resolution_hours: Optional[float]
    severity_distribution: Dict[int, int]  # {severity_int: count}
    closure_rate: float
    top_close_reasons: Dict[str, int]  # {reason: count}
    similar_tickets: List[dict]  # top-k results for card display

    @property
    def is_cold_start(self) -> bool:
        return self.sample_size < 3


@dataclass
class ImpactModelPrediction:
    """Scikit-learn 3-class impact prediction (Benign / Ignore / MTP).

    Independent automated signal alongside `SimilarTicketPrediction`. Trained
    on analyst-worked tickets since the BTP/MTP taxonomy cutover (2025-06-04),
    using only triage-time features. See services/ticket_impact_model.py.

    FP and BTP collapse into 'Benign' at training time — the FP/BTP boundary
    isn't predictable from triage features (driven by post-investigation
    findings and transient external events like threat-intel feed bugs).
    """
    label: str  # top class: 'Benign' | 'Ignore' | 'Malicious True Positive'
    confidence: float  # probability of the top class, 0..1
    probabilities: Dict[str, float]  # full class -> probability
    model_version: str = ""


class XsoarTriageLLMResponse(BaseModel):
    """Structured LLM output for XSOAR ticket triage.

    The LLM emits intent + outcome separately. The final `verdict` field is
    derived deterministically from those two by `derive_verdict()` after the
    LLM call (the LLM should also emit verdict for sanity-checking, but the
    derivation is the source of truth — see _apply_intent_outcome_guardrails).
    """

    what_happened: str = Field(
        description="2-3 sentence plain-English explanation of what actually happened, "
        "written for a SOC analyst. Reference the specific detection rule, host, user, "
        "IPs, process, or event that triggered the alert. "
        "e.g. 'QRadar rule _AE_High Volume DNS TXT Queries fired because host <internal-host> "
        "sent 500+ DNS TXT queries to <internal-host> within 5 minutes. The queries were for "
        "_kerberos.mykulacbaprd4.amthe company.local.'",
    )
    why_is_this_a_concern: str = Field(
        description="1-2 sentence explanation of why this activity is flagged as suspicious "
        "and what the worst-case scenario would be if it were malicious. "
        "e.g. 'DNS TXT queries can be abused for data exfiltration or C2 communication. "
        "A high volume in a short window could indicate an active exfil channel.'",
    )
    intent: Literal["malicious", "benign", "unknown"] = Field(
        description="ACTOR INTENT — was the activity itself adversarial? "
        "'malicious' = an external/internal adversary deliberately caused this "
        "(spoofing, phishing, malware, exploit, brute force, recon, etc.) — "
        "regardless of whether they succeeded. "
        "'benign' = the activity was authorized, expected, or non-adversarial "
        "(legitimate user, sanctioned admin tool, internal pentest, BAU process). "
        "'unknown' = insufficient evidence to decide. "
        "CRITICAL: a blocked/rejected attack still has malicious INTENT — "
        "controls reduce IMPACT, not INTENT. Do not mark a real attack as benign "
        "just because it failed.",
    )
    outcome: Literal["successful", "blocked", "attempted", "false_alarm"] = Field(
        description="ACTIVITY OUTCOME — what actually happened to the activity? "
        "'successful' = the activity executed / was delivered / had impact "
        "(malware ran, email delivered, user clicked, account compromised, data accessed). "
        "'blocked' = security controls stopped it before impact "
        "(DMARC rejected, AV quarantined, EDR killed, WAF blocked, account locked, "
        "MFA prevented login). "
        "'attempted' = tried but did not complete and was not explicitly blocked "
        "(connection failed, timeout, partial activity, recon scan). "
        "'false_alarm' = the detection rule fired but the underlying event did not "
        "actually occur as described (rule logic error, IOC mismatch, parsing bug).",
    )
    verdict: Literal[
        "true_positive_malicious",
        "true_positive_malicious_contained",
        "true_positive_benign",
        "false_positive",
    ] = Field(
        description="Ticket classification verdict — MUST be consistent with intent + outcome: "
        "intent=malicious + outcome=successful → true_positive_malicious; "
        "intent=malicious + outcome=blocked/attempted → true_positive_malicious_contained; "
        "intent=benign → true_positive_benign; "
        "outcome=false_alarm → false_positive. "
        "(Will be re-derived from intent+outcome after the call as a guardrail.)",
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in verdict (0.0-1.0)",
    )
    summary: str = Field(
        description="2-3 sentence summary of the ticket and why this verdict was chosen",
    )
    recommended_action: Literal[
        "close_ticket",
        "escalate",
        "investigate",
    ] = Field(
        description="Recommended response action: "
        "close_ticket = close as FP or benign (use for false_positive or true_positive_benign verdicts); "
        "escalate = requires immediate analyst attention (use for true_positive_malicious or high-risk, "
        "or for true_positive_malicious_contained when it indicates an active campaign / repeat targeting); "
        "investigate = needs further analysis before a verdict can be finalized "
        "(default for true_positive_malicious_contained — verify control efficacy and look for related activity)",
    )
    recommended_action_detail: str = Field(
        description="REQUIRED: one-line explanation of why this action is recommended and what "
        "the analyst should do, referencing specific evidence. "
        "e.g. 'Close as FP — internal Kerberos DNS lookups between domain controllers, BAU' "
        "or 'Escalate — VT hit 45/70 on hash, confirmed malware family Emotet' "
        "or 'Investigate — unusual PowerShell execution on server, verify with host owner'",
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="1-5 specific risk indicators supporting the verdict",
    )
    mitigating_factors: List[str] = Field(
        default_factory=list,
        description="1-5 factors that reduce risk or suggest benign activity",
    )
    investigation_pivots: List[str] = Field(
        default_factory=list,
        description="OUTSTANDING QUESTIONS the tool calls you made could not answer — "
        "things a human analyst still needs to do that are outside the tool surface "
        "(talk to a user, check a non-integrated system, review source code of a "
        "custom script, physical verification, etc.). Do NOT list investigations "
        "you could have run via the available tools — if you needed QRadar events, "
        "SNOW changes, Vectra entity details, AD lookups, or IOC intel, you should "
        "have called the tool directly instead of deferring to the analyst. "
        "GOOD examples (outside tool surface): "
        "'Contact maruyama.fumihide@the company.co.jp and verify they ran "
        "Install-Module NtObjectManager intentionally'; "
        "'Review the custom deploy script on the jumpbox that invoked this command — "
        "not in any integrated system'. "
        "BAD examples (should have been tool calls): "
        "'Pull LSASS events on host X' (use run_qradar_aql_query); "
        "'Check for change tickets' (use get_servicenow_changes); "
        "'Look up hash in VirusTotal' (use lookup_hash_virustotal). "
        "For close_ticket actions, leave this list empty. Emit 0-3 entries — "
        "keep it short, these are truly the residual human-only questions.",
    )


class XsoarTriageCritique(BaseModel):
    """Reflector-style critique of the Phase 1 tool trace, run by the router
    LLM before Phase 2 structured-verdict generation. Fed back into the Phase 2
    prompt so the verdict LLM sees the concerns; does NOT override any
    deterministic guardrail."""

    flagged: bool = Field(
        description="True if ANY concern or unused pivot was identified. "
        "False only if the tool trace is complete and evidence-aligned.",
    )
    evidence_alignment: Literal["aligned", "partial", "contradicted"] = Field(
        description="Does the conversation's stated direction match the tool results? "
        "'aligned' = tool results support the emerging picture; "
        "'partial' = tool results were ignored or only partly used; "
        "'contradicted' = tool results contradict the LLM's working hypothesis.",
    )
    concerns: List[str] = Field(
        default_factory=list,
        description="0-3 specific concerns: unused tool results, hallucinated details "
        "not in tool output, contradictions between pivots, premature conclusions.",
    )
    unused_pivots: List[str] = Field(
        default_factory=list,
        description="0-3 obvious tool calls that were NOT made and should have been, "
        "given the ticket type. Name the tool by its bound name (e.g. "
        "'lookup_hash_virustotal', 'run_qradar_aql_query'). Empty if coverage was "
        "adequate or if the tool budget was the limiter.",
    )
    rationale: str = Field(
        description="1-2 sentences explaining the critique. Shown to the Phase 2 LLM.",
    )


def derive_verdict(intent: str, outcome: str) -> str:
    """Deterministically derive the verdict from (intent, outcome).

    This is the source of truth for verdict classification. The LLM's own
    `verdict` field is treated as advisory and overridden by this function.

    Truth table:
        intent=malicious  + outcome=successful           -> true_positive_malicious
        intent=malicious  + outcome=blocked/attempted    -> true_positive_malicious_contained
        intent=benign     + outcome=*                    -> true_positive_benign
        intent=unknown    + outcome=*                    -> true_positive_malicious_contained
                                                            (assume worst case, force investigate)
        intent=*          + outcome=false_alarm          -> false_positive
    """
    # outcome=false_alarm always wins — the detection rule is wrong
    if outcome == "false_alarm":
        return "false_positive"

    if intent == "malicious":
        if outcome == "successful":
            return "true_positive_malicious"
        # blocked or attempted — adversarial activity, contained
        return "true_positive_malicious_contained"

    if intent == "benign":
        return "true_positive_benign"

    # unknown intent — assume worst case to force analyst review
    return "true_positive_malicious_contained"


@dataclass
class XsoarTriageResult:
    """Complete triage result for a single XSOAR ticket."""
    ticket_id: str
    ticket_name: str
    ticket_type: str = ""
    security_category: str = ""
    hostname: str = ""
    username: str = ""
    severity: str = ""
    detection_source: str = ""
    ticket_timestamp: str = ""
    ticket_status: str = ""
    ticket_owner: str = ""
    # Enrichment data
    enrichment: Dict[str, Any] = field(default_factory=dict)
    # LLM context
    llm_what_happened: str = ""
    llm_why_concern: str = ""
    # LLM verdict (derived from intent + outcome via derive_verdict)
    llm_verdict: str = ""
    # LLM intent + outcome (the inputs to the derived verdict)
    llm_intent: str = ""
    llm_outcome: str = ""
    llm_confidence: float = 0.0
    llm_summary: str = ""
    llm_recommended_action: str = ""
    llm_recommended_action_detail: str = ""
    llm_risk_factors: List[str] = field(default_factory=list)
    llm_mitigating_factors: List[str] = field(default_factory=list)
    # Investigation pivots — residual human-only questions the LLM couldn't
    # resolve via tool calls. Empty list for close_ticket verdicts.
    llm_investigation_pivots: List[str] = field(default_factory=list)
    # Tool trace — the tool calls the LLM made during triage, in order.
    # Each entry: {"tool": str, "args": dict, "result_preview": str}.
    llm_tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    # Reflector-style critic output — present only when XSOAR_TRIAGE_CRITIC=1
    # was set and the router LLM returned a critique. flagged=False means
    # the critic ran and found nothing worth surfacing.
    llm_critique_flagged: bool = False
    llm_critique_alignment: str = ""
    llm_critique_concerns: List[str] = field(default_factory=list)
    llm_critique_unused_pivots: List[str] = field(default_factory=list)
    llm_critique_rationale: str = ""
    # Similar ticket prediction (ChromaDB semantic similarity)
    similar_ticket_prediction: Optional[SimilarTicketPrediction] = None
    # Scikit-learn impact model prediction (Benign / Ignore / MTP, 3-class)
    impact_model_prediction: Optional[ImpactModelPrediction] = None
    # Repeat offender: how many tickets this user/host had in the last N days
    repeat_offender_count: int = 0
    repeat_offender_window_days: int = 7
    # Composite priority score (1-10, higher = more urgent)
    priority_score: int = 0
    # Suggested close reason from similar ticket consensus
    suggested_close_reason: str = ""
    # Evidence basis classification (what the verdict is based on)
    evidence_basis: str = ""
    # Verdict vs similar-ticket history disagreement
    verdict_conflicts_history: bool = False
    verdict_conflict_detail: str = ""
    # IOC cross-correlation: other recent tickets sharing the same IOCs
    ioc_correlated_tickets: List[dict] = field(default_factory=list)
    # Asset context from Tanium (OS, tags, EPP status, last seen)
    asset_context: Dict[str, Any] = field(default_factory=dict)
    # Vectra NDR: threat/certainty scores and active detections for host/user entities
    vectra_context: Dict[str, Any] = field(default_factory=dict)
    # QRadar: recent SIEM events for the affected host/user (last N hours)
    qradar_entity_activity: Dict[str, Any] = field(default_factory=dict)
    # ServiceNow: open incidents and change tickets for the affected CI
    snow_context: Dict[str, Any] = field(default_factory=dict)
    # Varonis DatAlert: user alerts and data activity
    varonis_context: Dict[str, Any] = field(default_factory=dict)
    # Active Directory: user and computer object details
    ad_context: Dict[str, Any] = field(default_factory=dict)
    # Time-of-day context (business hours, weekend, after hours)
    time_context: str = ""
    # Rule tuning recommendation (noise reduction)
    tuning_recommendation: str = ""
    # Card tracking
    card_message_id: str = ""
    # Raw ticket data
    raw_ticket: Dict[str, Any] = field(default_factory=dict)
