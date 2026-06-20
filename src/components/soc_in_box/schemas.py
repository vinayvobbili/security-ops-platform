"""SOC-in-a-Box event contract — re-exported from the standalone ``aisoc`` kernel.

The bus envelope and the event types used to live here. They have been extracted
verbatim into the vendor-neutral ``aisoc`` package (``aisoc.schemas``), which is
now the single source of truth: same ``BusEvent`` envelope, the same twelve event
types, the same ``Verdict`` / ``Severity`` vocabularies, and identical required
fields, so events serialize byte-for-byte the way they always have. The aisoc
copy adds a few defaulted convenience fields (e.g. richer ``ActionDecision``
attribution) and a ``parse_event`` dispatcher; nothing existing changes.

Every event published to Redis Streams is still serialized via
``model_dump_json()`` on a subclass of :class:`BusEvent`, and consumers still
re-hydrate by dispatching on ``event_type`` (a Literal on each subclass).

``Verdict`` matches the existing triage vocabulary (``xsoar_alert_triage``) — the
triage pipeline is the producer of ``AlertTriaged``, so its terms are canonical.

Import from here exactly as before; the names resolve to the aisoc definitions.
"""

from __future__ import annotations

from aisoc.schemas import (  # noqa: F401
    EVENT_TYPES,
    VALID_SEVERITIES,
    VALID_VERDICTS,
    ActionDecision,
    ActionProposed,
    AlertReceived,
    AlertTriaged,
    BusEvent,
    CampaignDetected,
    CaseEscalated,
    DetectionTuningReport,
    HuntingReport,
    IRPlan,
    Severity,
    ShiftSummary,
    ThreatIntelReport,
    Tier2Analysis,
    Verdict,
    parse_event,
)
from aisoc.schemas import _new_id, _now  # noqa: F401  # internal default factories

__all__ = [
    "BusEvent",
    "AlertReceived",
    "AlertTriaged",
    "CaseEscalated",
    "Tier2Analysis",
    "IRPlan",
    "ActionProposed",
    "ActionDecision",
    "ThreatIntelReport",
    "DetectionTuningReport",
    "HuntingReport",
    "CampaignDetected",
    "ShiftSummary",
    "Verdict",
    "VALID_VERDICTS",
    "Severity",
    "VALID_SEVERITIES",
    "EVENT_TYPES",
    "parse_event",
]
