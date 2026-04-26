"""
Multi-Dimensional Tipper Similarity Scoring

Computes structured similarity breakdowns between tippers using four signals:
- IOC Overlap: Jaccard similarity of IOC sets (IPs, domains, hashes)
- TTP Overlap: Jaccard similarity of MITRE ATT&CK technique IDs
- Actor/Malware Match: Binary signal — any shared actor or malware family
- Narrative Similarity: Cosine similarity from vector embeddings

Replaces the single cosine similarity percentage with an analyst-friendly
multi-dimensional breakdown that answers "WHY are these similar?"
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default weights for composite score
DEFAULT_WEIGHTS = {
    'narrative': 0.40,
    'ioc': 0.25,
    'ttp': 0.20,
    'actor_malware': 0.15,
}


@dataclass
class SimilarityBreakdown:
    """Multi-dimensional similarity score for a candidate tipper."""
    composite_score: float = 0.0       # Weighted combination, 0.0-1.0
    narrative_similarity: float = 0.0  # Cosine similarity from embeddings
    ioc_overlap: float = 0.0           # Jaccard of IOC sets
    ttp_overlap: float = 0.0           # Jaccard of MITRE technique sets
    actor_malware_match: float = 0.0   # 0.0 or 1.0 (binary)
    # Human-readable match reasons
    shared_iocs: List[str] = field(default_factory=list)
    shared_ttps: List[str] = field(default_factory=list)
    shared_actors: List[str] = field(default_factory=list)
    shared_malware: List[str] = field(default_factory=list)

    @property
    def shared_ioc_count(self) -> int:
        return len(self.shared_iocs)

    @property
    def shared_ttp_count(self) -> int:
        return len(self.shared_ttps)

    def to_dict(self) -> dict:
        return {
            'composite_score': self.composite_score,
            'narrative_similarity': self.narrative_similarity,
            'ioc_overlap': self.ioc_overlap,
            'ttp_overlap': self.ttp_overlap,
            'actor_malware_match': self.actor_malware_match,
            'shared_iocs': self.shared_iocs,
            'shared_ttps': self.shared_ttps,
            'shared_actors': self.shared_actors,
            'shared_malware': self.shared_malware,
            'shared_ioc_count': self.shared_ioc_count,
            'shared_ttp_count': self.shared_ttp_count,
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
    for key in ('iocs_ip', 'iocs_domain', 'iocs_hash', 'iocs_url', 'iocs_cve'):
        for val in fingerprint.get(key, []):
            iocs.add(str(val).lower())
    return iocs


def compute_similarity_breakdown(
    query_fingerprint: dict,
    candidate_fingerprint: dict,
    narrative_score: float,
    weights: Dict[str, float] = None,
) -> SimilarityBreakdown:
    """Compute multi-dimensional similarity between two tipper fingerprints.

    Args:
        query_fingerprint: Current tipper's fingerprint dict
        candidate_fingerprint: Historical tipper's fingerprint dict
        narrative_score: Cosine similarity from vector search (0.0-1.0)
        weights: Optional weight overrides for composite score

    Returns:
        SimilarityBreakdown with per-dimension scores and match details
    """
    w = weights or DEFAULT_WEIGHTS

    # --- IOC Overlap ---
    query_iocs = _build_ioc_set(query_fingerprint)
    candidate_iocs = _build_ioc_set(candidate_fingerprint)
    shared_iocs_set = query_iocs & candidate_iocs
    ioc_overlap = _jaccard(query_iocs, candidate_iocs)

    # --- TTP Overlap ---
    query_ttps = set(t.upper() for t in query_fingerprint.get('mitre_techniques', []))
    candidate_ttps = set(t.upper() for t in candidate_fingerprint.get('mitre_techniques', []))
    shared_ttps_set = query_ttps & candidate_ttps
    ttp_overlap = _jaccard(query_ttps, candidate_ttps)

    # --- Actor/Malware Match (binary) ---
    query_actors = set(a.lower() for a in query_fingerprint.get('threat_actors', []))
    candidate_actors = set(a.lower() for a in candidate_fingerprint.get('threat_actors', []))
    shared_actors_set = query_actors & candidate_actors

    query_malware = set(m.lower() for m in query_fingerprint.get('malware_families', []))
    candidate_malware = set(m.lower() for m in candidate_fingerprint.get('malware_families', []))
    shared_malware_set = query_malware & candidate_malware

    actor_malware_match = 1.0 if (shared_actors_set or shared_malware_set) else 0.0

    # --- Composite score ---
    composite = (
        w.get('narrative', 0.40) * narrative_score +
        w.get('ioc', 0.25) * ioc_overlap +
        w.get('ttp', 0.20) * ttp_overlap +
        w.get('actor_malware', 0.15) * actor_malware_match
    )

    return SimilarityBreakdown(
        composite_score=round(composite, 3),
        narrative_similarity=round(narrative_score, 3),
        ioc_overlap=round(ioc_overlap, 3),
        ttp_overlap=round(ttp_overlap, 3),
        actor_malware_match=actor_malware_match,
        shared_iocs=sorted(shared_iocs_set)[:20],
        shared_ttps=sorted(shared_ttps_set),
        # Preserve original casing from candidate fingerprint for display
        shared_actors=sorted(
            a for a in candidate_fingerprint.get('threat_actors', [])
            if a.lower() in shared_actors_set
        ),
        shared_malware=sorted(
            m for m in candidate_fingerprint.get('malware_families', [])
            if m.lower() in shared_malware_set
        ),
    )


def fingerprint_from_entities(entities) -> dict:
    """Build a fingerprint dict from an ExtractedEntities object.

    This is used for the query tipper (not yet in the fingerprint store).
    """
    all_hashes = []
    if hasattr(entities, 'hashes') and entities.hashes:
        for hash_list in entities.hashes.values():
            all_hashes.extend(h.lower() for h in hash_list)

    actors = []
    if hasattr(entities, 'threat_actors_enriched') and entities.threat_actors_enriched:
        seen = set()
        for ta in entities.threat_actors_enriched:
            name = (ta.common_name or ta.name).lower()
            if name not in seen:
                actors.append(ta.common_name or ta.name)
                seen.add(name)
    elif hasattr(entities, 'threat_actors'):
        actors = list(entities.threat_actors)

    return {
        'iocs_ip': [ip.lower() for ip in (entities.ips or [])],
        'iocs_domain': [d.lower() for d in (entities.domains or [])],
        'iocs_hash': list(set(all_hashes)),
        'iocs_url': [u.lower() for u in (entities.urls or [])],
        'iocs_cve': [c.upper() for c in (entities.cves or [])],
        'mitre_techniques': [t.upper() for t in (entities.mitre_techniques or [])],
        'threat_actors': actors,
        'malware_families': list(entities.malware_families or []),
    }
