"""
Multi-Dimensional XSOAR Ticket Similarity Scoring

Computes structured similarity breakdowns between XSOAR tickets using five signals:
- Narrative Similarity: Cosine similarity from vector embeddings (30%)
- Detection Rule Match: Binary — same offense title / detection name (30%)
- IOC Overlap: Jaccard similarity of IP, domain, hash sets (20%)
- Category+Type Match: Same security category and/or ticket type (10%)
- Host/User Match: Same hostname or username (10%)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    'narrative': 0.30,
    'detection_rule': 0.30,
    'ioc': 0.20,
    'category_type': 0.10,
    'host_user': 0.10,
}


@dataclass
class XsoarSimilarityBreakdown:
    """Multi-dimensional similarity score for an XSOAR ticket candidate."""
    composite_score: float = 0.0
    narrative_similarity: float = 0.0
    detection_rule_match: float = 0.0    # 0.0 or 1.0
    ioc_overlap: float = 0.0            # Jaccard
    category_type_match: float = 0.0    # 0.0, 0.5, or 1.0
    host_user_match: float = 0.0        # 0.0 or 1.0
    # Human-readable match details
    shared_iocs: List[str] = field(default_factory=list)
    matched_rule: str = ""
    matched_host: str = ""
    matched_user: str = ""

    @property
    def shared_ioc_count(self) -> int:
        return len(self.shared_iocs)

    def to_dict(self) -> dict:
        return {
            'composite_score': self.composite_score,
            'narrative_similarity': self.narrative_similarity,
            'detection_rule_match': self.detection_rule_match,
            'ioc_overlap': self.ioc_overlap,
            'category_type_match': self.category_type_match,
            'host_user_match': self.host_user_match,
            'shared_iocs': self.shared_iocs,
            'shared_ioc_count': self.shared_ioc_count,
            'matched_rule': self.matched_rule,
            'matched_host': self.matched_host,
            'matched_user': self.matched_user,
        }


def _jaccard(set_a: set, set_b: set) -> float:
    """Jaccard similarity: |A ∩ B| / |A ∪ B|. Returns 0.0 if both empty."""
    if not set_a and not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 0.0


def _build_ioc_set(fingerprint: dict) -> set:
    """Merge all IOC types into a single lowercased set."""
    iocs = set()
    for key in ('iocs_ip', 'iocs_domain', 'iocs_hash'):
        for val in fingerprint.get(key, []):
            iocs.add(str(val).lower())
    return iocs


def compute_xsoar_similarity_breakdown(
    query_fingerprint: dict,
    candidate_fingerprint: dict,
    narrative_score: float,
    weights: Dict[str, float] = None,
) -> XsoarSimilarityBreakdown:
    """Compute multi-dimensional similarity between two XSOAR ticket fingerprints.

    Args:
        query_fingerprint: Current ticket's fingerprint dict
        candidate_fingerprint: Historical ticket's fingerprint dict
        narrative_score: Cosine similarity from vector search (0.0-1.0)
        weights: Optional weight overrides for composite score

    Returns:
        XsoarSimilarityBreakdown with per-dimension scores and match details
    """
    w = weights or DEFAULT_WEIGHTS

    # --- Detection Rule Match (binary) ---
    q_rule = (query_fingerprint.get('detection_rule', '') or '').lower().strip()
    c_rule = (candidate_fingerprint.get('detection_rule', '') or '').lower().strip()
    rule_match = 1.0 if (q_rule and c_rule and q_rule == c_rule) else 0.0
    matched_rule = candidate_fingerprint.get('detection_rule', '') if rule_match else ""

    # --- IOC Overlap ---
    query_iocs = _build_ioc_set(query_fingerprint)
    candidate_iocs = _build_ioc_set(candidate_fingerprint)
    shared_iocs_set = query_iocs & candidate_iocs
    ioc_overlap = _jaccard(query_iocs, candidate_iocs)

    # --- Category+Type Match ---
    q_cat = (query_fingerprint.get('security_category', '') or '').lower().strip()
    c_cat = (candidate_fingerprint.get('security_category', '') or '').lower().strip()
    q_type = (query_fingerprint.get('ticket_type', '') or '').lower().strip()
    c_type = (candidate_fingerprint.get('ticket_type', '') or '').lower().strip()

    cat_match = 1.0 if (q_cat and c_cat and q_cat == c_cat) else 0.0
    type_match = 1.0 if (q_type and c_type and q_type == c_type) else 0.0
    category_type_match = (cat_match + type_match) / 2.0

    # --- Host/User Match ---
    q_host = (query_fingerprint.get('hostname', '') or '').lower().strip()
    c_host = (candidate_fingerprint.get('hostname', '') or '').lower().strip()
    q_user = (query_fingerprint.get('username', '') or '').lower().strip()
    c_user = (candidate_fingerprint.get('username', '') or '').lower().strip()

    matched_host = ""
    matched_user = ""
    host_user_match = 0.0
    if q_host and c_host and q_host == c_host:
        host_user_match = 1.0
        matched_host = candidate_fingerprint.get('hostname', '')
    elif q_user and c_user and q_user == c_user:
        host_user_match = 1.0
        matched_user = candidate_fingerprint.get('username', '')

    # --- Composite score ---
    composite = (
        w.get('narrative', 0.30) * narrative_score
        + w.get('detection_rule', 0.30) * rule_match
        + w.get('ioc', 0.20) * ioc_overlap
        + w.get('category_type', 0.10) * category_type_match
        + w.get('host_user', 0.10) * host_user_match
    )

    return XsoarSimilarityBreakdown(
        composite_score=round(composite, 3),
        narrative_similarity=round(narrative_score, 3),
        detection_rule_match=rule_match,
        ioc_overlap=round(ioc_overlap, 3),
        category_type_match=category_type_match,
        host_user_match=host_user_match,
        shared_iocs=sorted(shared_iocs_set)[:20],
        matched_rule=matched_rule,
        matched_host=matched_host,
        matched_user=matched_user,
    )


def fingerprint_from_ticket(ticket: dict, entities=None) -> dict:
    """Build a fingerprint dict from a raw XSOAR ticket (for the query ticket).

    Used for the incoming ticket that's not yet in the fingerprint store.
    """
    from src.components.xsoar_ticket_indexer import strip_ticket_id

    name = ticket.get("name", "") or ""
    detection_rule = strip_ticket_id(name).strip()

    ips, domains, hashes = [], [], []
    if entities:
        ips = [ip.lower() for ip in (entities.ips or [])]
        domains = [d.lower() for d in (entities.domains or [])]
        all_hashes = []
        if hasattr(entities, 'hashes') and entities.hashes:
            for hash_list in entities.hashes.values():
                all_hashes.extend(h.lower() for h in hash_list)
        hashes = list(set(all_hashes))

    return {
        'detection_rule': detection_rule,
        'ticket_type': ticket.get("type", "") or "",
        'security_category': ticket.get("security_category", "") or "",
        'hostname': (ticket.get("hostname", "") or "").lower(),
        'username': (ticket.get("username", "") or "").lower(),
        'iocs_ip': ips,
        'iocs_domain': domains,
        'iocs_hash': hashes,
    }
