"""
LangGraph State Schemas

TypedDict definitions for workflow state management.
Each workflow has its own state schema that tracks:
- Input parameters
- Tool results from each step
- Intermediate calculations (risk scores, extracted data)
- Final outputs
"""

from typing import TypedDict, Optional, Literal, Annotated
from operator import add


class IOCInvestigationState(TypedDict):
    """State for IOC investigation workflow.

    Tracks the IOC being investigated and results from each enrichment source.
    Uses Annotated[list, add] for fields that accumulate across nodes.
    """
    # Input
    ioc_value: str
    ioc_type: Literal["ip", "domain", "hash", "url"]

    # Tool results from parallel enrichment
    virustotal_result: Optional[str]
    abuseipdb_result: Optional[str]
    shodan_result: Optional[str]
    recorded_future_result: Optional[str]

    # QRadar search (conditional - only for high risk)
    qradar_result: Optional[str]

    # Synthesized analysis
    risk_score: int
    risk_factors: Annotated[list[str], add]  # Accumulates across nodes
    recommended_actions: list[str]

    # Error tracking
    errors: Annotated[list[str], add]  # Accumulates across nodes

    # Final output
    final_report: Optional[str]


class IncidentResponseState(TypedDict):
    """State for incident response workflow.

    Tracks XSOAR ticket investigation with CrowdStrike status checks,
    IOC enrichment, and executive summary generation.
    """
    # Input
    ticket_id: str

    # XSOAR ticket data
    ticket_data: Optional[dict]
    hostname: Optional[str]
    username: Optional[str]

    # Extracted IOCs from ticket
    iocs_extracted: list[str]

    # CrowdStrike results (parallel)
    crowdstrike_status: Optional[str]
    crowdstrike_detections: Optional[str]

    # IOC enrichment results (dict of IOC -> enrichment data)
    ioc_enrichment_results: dict

    # QRadar correlation
    qradar_events: Optional[str]

    # Synthesized outputs
    executive_summary: Optional[str]
    severity_assessment: Optional[str]
    recommended_actions: list[str]

    # Error tracking
    errors: Annotated[list[str], add]

    # Whether to post results back to XSOAR
    post_to_xsoar: bool
