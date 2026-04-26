"""
MITRE ATT&CK Reference Data Service

Fetches the ATT&CK Enterprise STIX bundle from GitHub, extracts technique
metadata, and caches a slim JSON locally.  Provides helpers to merge
occurrence counts from the threat-intel DB into a matrix-ready structure
and to build ATT&CK Navigator v4.5 layer files for export.
"""

import json
import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Canonical left-to-right ordering of the 14 Enterprise tactics
TACTIC_ORDER = [
    'reconnaissance',
    'resource-development',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact',
]

# Display names for tactics
TACTIC_DISPLAY = {
    'reconnaissance': 'Reconnaissance',
    'resource-development': 'Resource Development',
    'initial-access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege-escalation': 'Privilege Escalation',
    'defense-evasion': 'Defense Evasion',
    'credential-access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement',
    'collection': 'Collection',
    'command-and-control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact',
}

STIX_BUNDLE_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/'
    'enterprise-attack/enterprise-attack.json'
)

CACHE_DIR = Path(__file__).resolve().parent.parent / 'data' / 'threat_intel'
CACHE_FILE = CACHE_DIR / 'attack_enterprise_techniques.json'
MALWARE_CACHE_FILE = CACHE_DIR / 'attack_malware_tools.json'
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def get_attack_techniques() -> list[dict]:
    """Return cached technique data, fetching the STIX bundle if stale."""
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            cached_at = data.get('fetched_at', 0)
            if time.time() - cached_at < CACHE_TTL_SECONDS:
                return data['techniques']
        except (json.JSONDecodeError, KeyError):
            logger.warning('Corrupt ATT&CK techniques cache, will re-fetch')

    bundle = _fetch_stix_bundle()
    if not bundle:
        return []
    techniques = _extract_and_cache_techniques(bundle)
    _extract_and_cache_malware(bundle)
    return techniques


def get_attack_malware_names() -> list[dict]:
    """Return cached malware/tool data, fetching the STIX bundle if stale."""
    if MALWARE_CACHE_FILE.exists():
        try:
            data = json.loads(MALWARE_CACHE_FILE.read_text())
            cached_at = data.get('fetched_at', 0)
            if time.time() - cached_at < CACHE_TTL_SECONDS:
                return data['malware_tools']
        except (json.JSONDecodeError, KeyError):
            logger.warning('Corrupt ATT&CK malware cache, will re-fetch')

    bundle = _fetch_stix_bundle()
    if not bundle:
        return []
    _extract_and_cache_techniques(bundle)
    return _extract_and_cache_malware(bundle)


def _fetch_stix_bundle() -> dict | None:
    """Download the MITRE ATT&CK Enterprise STIX bundle."""
    logger.info('Fetching MITRE ATT&CK Enterprise STIX bundle...')
    try:
        resp = requests.get(STIX_BUNDLE_URL, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error('Failed to fetch STIX bundle: %s', e)
        return None


def _extract_and_cache_techniques(bundle: dict) -> list[dict]:
    """Extract slim technique records from STIX bundle and cache to disk."""
    techniques = []
    for obj in bundle.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue

        # Extract technique ID from external references
        tech_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                break
        if not tech_id or not tech_id.startswith('T'):
            continue

        # Extract tactic short names from kill_chain_phases
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase['phase_name'])

        is_sub = obj.get('x_mitre_is_subtechnique', False)
        parent_id = tech_id.split('.')[0] if is_sub else None

        techniques.append({
            'id': tech_id,
            'name': obj.get('name', ''),
            'tactics': tactics,
            'is_subtechnique': is_sub,
            'parent_id': parent_id,
        })

    # Cache to disk
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_data = {
        'fetched_at': time.time(),
        'count': len(techniques),
        'techniques': techniques,
    }
    CACHE_FILE.write_text(json.dumps(cache_data, separators=(',', ':')))
    logger.info('Cached %d ATT&CK techniques to %s', len(techniques), CACHE_FILE)
    return techniques


def _extract_and_cache_malware(bundle: dict) -> list[dict]:
    """Extract malware and tool objects from STIX bundle and cache to disk."""
    malware_tools = []
    for obj in bundle.get('objects', []):
        if obj.get('type') not in ('malware', 'tool'):
            continue
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue

        # Extract MITRE ID (S-prefixed) from external references
        mitre_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                break
        if not mitre_id or not mitre_id.startswith('S'):
            continue

        name = obj.get('name', '')
        aliases = obj.get('x_mitre_aliases', [])
        if not aliases:
            aliases = [name]

        malware_tools.append({
            'id': mitre_id,
            'name': name,
            'type': obj.get('type'),
            'aliases': aliases,
            'labels': obj.get('labels', []),
        })

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_data = {
        'fetched_at': time.time(),
        'count': len(malware_tools),
        'malware_tools': malware_tools,
    }
    MALWARE_CACHE_FILE.write_text(json.dumps(cache_data, separators=(',', ':')))
    logger.info('Cached %d ATT&CK malware/tools to %s', len(malware_tools), MALWARE_CACHE_FILE)
    return malware_tools


def get_matrix_data(technique_counts: dict) -> dict:
    """Merge ATT&CK reference data with DB occurrence counts.

    Returns:
        {
            'tactics': [{id, name, technique_count}, ...],  # 14 items
            'techniques': [{id, name, tactics, count, is_subtechnique, parent_id}, ...],
            'max_count': int,
        }
    """
    all_techniques = get_attack_techniques()

    # Build enriched technique list with counts
    enriched = []
    for tech in all_techniques:
        count = technique_counts.get(tech['id'], 0)
        enriched.append({
            'id': tech['id'],
            'name': tech['name'],
            'tactics': tech['tactics'],
            'count': count,
            'is_subtechnique': tech['is_subtechnique'],
            'parent_id': tech.get('parent_id'),
        })

    max_count = max((t['count'] for t in enriched), default=0)

    # Build tactic summary
    tactic_info = []
    for tactic_slug in TACTIC_ORDER:
        tech_in_tactic = [t for t in enriched if tactic_slug in t['tactics']]
        tactic_info.append({
            'id': tactic_slug,
            'name': TACTIC_DISPLAY.get(tactic_slug, tactic_slug),
            'technique_count': len(tech_in_tactic),
        })

    return {
        'tactics': tactic_info,
        'techniques': enriched,
        'max_count': max_count,
    }


def build_navigator_layer(technique_counts: dict, technique_procedures: dict = None) -> dict:
    """Build an ATT&CK Navigator v4.5 layer JSON for export.

    Args:
        technique_counts: {technique_id: count}
        technique_procedures: Optional {technique_id: [procedure_text, ...]}
    """
    all_techniques = get_attack_techniques()
    max_count = max(technique_counts.values(), default=0)
    procs = technique_procedures or {}

    nav_techniques = []
    for tech in all_techniques:
        count = technique_counts.get(tech['id'], 0)
        score = 0
        if count > 0 and max_count > 0:
            # Score = (count for this technique / count of the highest technique) * 100
            # log1p used to prevent low-count techniques from being squished near zero
            score = math.log1p(count) / math.log1p(max_count) * 100

        procedures = procs.get(tech['id'], [])
        if procedures:
            comment = f"{count} occurrences:\n" + "\n".join(f"- {p}" for p in procedures)
        else:
            comment = f"{count} occurrences in threat intel tippers"

        entry = {
            'techniqueID': tech['id'],
            'score': round(score, 1),
            'comment': comment,
            'enabled': True,
            'showSubtechniques': False,
        }
        if count > 0:
            entry['color'] = _score_to_color(score)
        nav_techniques.append(entry)

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    return {
        'name': f'Threat Intel Coverage ({now})',
        'versions': {
            'attack': '16',
            'navigator': '4.5',
            'layer': '4.5',
        },
        'domain': 'enterprise-attack',
        'description': 'Heatmap of MITRE ATT&CK technique coverage from threat intelligence tippers',
        'sorting': 3,  # sort by score descending
        'layout': {
            'layout': 'side',
            'showID': True,
            'showName': True,
        },
        'gradient': {
            'colors': ['#ffffff', '#c6dbef', '#6baed6', '#2171b5', '#08306b'],
            'minValue': 0,
            'maxValue': 100,
        },
        'techniques': nav_techniques,
    }


def _score_to_color(score: float) -> str:
    """Map a 0-100 score to a blue gradient hex color."""
    stops = [
        (0, (255, 255, 255)),
        (25, (198, 219, 239)),
        (50, (107, 174, 214)),
        (75, (33, 113, 181)),
        (100, (8, 48, 107)),
    ]
    for i in range(len(stops) - 1):
        s1, c1 = stops[i]
        s2, c2 = stops[i + 1]
        if score <= s2:
            t = (score - s1) / (s2 - s1) if s2 != s1 else 0
            r = int(c1[0] + (c2[0] - c1[0]) * t)
            g = int(c1[1] + (c2[1] - c1[1]) * t)
            b = int(c1[2] + (c2[2] - c1[2]) * t)
            return f'#{r:02x}{g:02x}{b:02x}'
    return '#08306b'
