"""Detection Rules route blueprint.

This module provides a page to view all detection rules from:
- CrowdStrike (YARA rules, IOA rules, IOCs)
- QRadar (custom analytics rules)
- Tanium Signals
"""

import json
import logging
import math
import os
import tempfile
from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, request, send_file

import pandas as pd

from src.utils.logging_utils import log_web_activity
from src.utils.excel_formatting import apply_professional_formatting

logger = logging.getLogger(__name__)

detection_rules_bp = Blueprint('detection_rules', __name__)

# Path to rules cache files
RULES_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'data', 'rules_cache'
)


def _load_rules_cache(filename: str) -> dict:
    """Load rules from a cache file.

    Args:
        filename: Name of the cache file (e.g., 'crowdstrike_rules.json')

    Returns:
        Dictionary with rules data or empty structure on error.
        Includes 'load_error' key if loading failed.
    """
    filepath = os.path.join(RULES_CACHE_DIR, filename)
    platform_name = filename.replace('_rules.json', '')

    if not os.path.exists(filepath):
        logger.warning(f"Cache file not found: {filepath}")
        return {
            'platform': platform_name,
            'count': 0,
            'rules': [],
            'load_error': f'Cache file not found: {filename}'
        }

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            data['load_error'] = None  # Explicitly mark as successfully loaded
            return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filename}: {e}")
        return {
            'platform': platform_name,
            'count': 0,
            'rules': [],
            'load_error': f'Invalid JSON in {filename}'
        }
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        return {
            'platform': platform_name,
            'count': 0,
            'rules': [],
            'load_error': str(e)
        }


def _get_all_rules() -> dict:
    """Load all detection rules from cache files.

    Returns:
        Dictionary with rules organized by platform and summary stats
    """
    crowdstrike = _load_rules_cache('crowdstrike_rules.json')
    qradar = _load_rules_cache('qradar_rules.json')
    tanium = _load_rules_cache('tanium_rules.json')

    # Calculate stats
    cs_rules = crowdstrike.get('rules', [])
    qr_rules = qradar.get('rules', [])
    tn_rules = tanium.get('rules', [])

    # Rule type breakdown
    rule_types = {}
    for rule in cs_rules + qr_rules + tn_rules:
        rt = rule.get('rule_type', 'unknown')
        rule_types[rt] = rule_types.get(rt, 0) + 1

    # Severity breakdown
    severities = {}
    for rule in cs_rules + qr_rules + tn_rules:
        sev = rule.get('severity', '').lower() or 'unspecified'
        severities[sev] = severities.get(sev, 0) + 1

    return {
        'platforms': {
            'crowdstrike': {
                'name': 'CrowdStrike',
                'count': len(cs_rules),
                'updated_at': crowdstrike.get('updated_at', 'Unknown'),
                'rules': cs_rules,
                'icon': 'falcon',
                'load_error': crowdstrike.get('load_error')
            },
            'qradar': {
                'name': 'QRadar',
                'count': len(qr_rules),
                'updated_at': qradar.get('updated_at', 'Unknown'),
                'rules': qr_rules,
                'icon': 'radar',
                'load_error': qradar.get('load_error')
            },
            'tanium': {
                'name': 'Tanium Signals',
                'count': len(tn_rules),
                'updated_at': tanium.get('updated_at', 'Unknown'),
                'rules': tn_rules,
                'icon': 'signal',
                'load_error': tanium.get('load_error')
            }
        },
        'stats': {
            'total_rules': len(cs_rules) + len(qr_rules) + len(tn_rules),
            'rule_types': rule_types,
            'severities': severities
        }
    }


@detection_rules_bp.route('/detection-rules')
@log_web_activity
def detection_rules_page():
    """Render the detection rules viewer page."""
    return render_template('detection_rules.html')


@detection_rules_bp.route('/api/detection-rules')
@log_web_activity
def get_detection_rules():
    """API endpoint to fetch all detection rules."""
    try:
        data = _get_all_rules()
        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        logger.error(f"Error fetching detection rules: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@detection_rules_bp.route('/api/detection-rules/export', methods=['POST'])
@log_web_activity
def export_detection_rules():
    """Export filtered detection rules to Excel with professional formatting."""
    try:
        data = request.get_json()
        rules = data.get('rules', [])

        if not rules:
            return jsonify({'success': False, 'error': 'No rules to export'}), 400

        # Prepare data for DataFrame
        export_data = []
        for rule in rules:
            export_data.append({
                'Platform': rule.get('platformName', rule.get('platform', '')),
                'Rule ID': rule.get('rule_id', ''),
                'Name': rule.get('name', ''),
                'Description': rule.get('description', ''),
                'Rule Type': (rule.get('rule_type', '') or '').replace('_', ' ').title(),
                'Severity': (rule.get('severity', '') or '').upper(),
                'Status': 'Enabled' if rule.get('enabled') else 'Disabled',
                'Tags': ', '.join(filter(None, rule.get('tags', []))),
                'MITRE Techniques': ', '.join(rule.get('mitre_techniques', [])),
                'Malware Families': ', '.join(rule.get('malware_families', [])),
                'Threat Actors': ', '.join(rule.get('threat_actors', [])),
                'Created Date': rule.get('created_date', ''),
                'Modified Date': rule.get('modified_date', '')
            })

        # Create DataFrame and export to Excel
        df = pd.DataFrame(export_data)

        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
        temp_path = temp_file.name
        temp_file.close()

        # Write to Excel
        df.to_excel(temp_path, index=False, engine='openpyxl')

        # Apply professional formatting
        apply_professional_formatting(
            temp_path,
            column_widths={
                'platform': 15,
                'rule id': 20,
                'name': 50,
                'description': 60,
                'rule type': 15,
                'severity': 12,
                'status': 10,
                'tags': 40,
                'mitre techniques': 30,
                'malware families': 25,
                'threat actors': 25,
                'created date': 20,
                'modified date': 20
            },
            wrap_columns={'name', 'description', 'tags', 'mitre techniques'},
            date_columns={'created date', 'modified date'}
        )

        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f'detection_rules_{timestamp}.xlsx'

        return send_file(
            temp_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        logger.error(f"Error exporting detection rules: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@detection_rules_bp.route('/api/attack-reference')
def api_attack_reference():
    """ATT&CK technique reference data (names, tactics, parent/sub mapping)."""
    try:
        from services.mitre_attack_data import get_attack_techniques, TACTIC_ORDER, TACTIC_DISPLAY
        techniques = get_attack_techniques()
        tactics = [{'id': t, 'name': TACTIC_DISPLAY[t]} for t in TACTIC_ORDER]
        return jsonify({'success': True, 'techniques': techniques, 'tactics': tactics})
    except Exception as e:
        logger.error(f"Error fetching ATT&CK reference data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@detection_rules_bp.route('/api/detection-rules/navigator-layer', methods=['POST'])
@log_web_activity
def api_detection_rules_navigator_layer():
    """Build Navigator layer from client-supplied per-platform technique counts."""
    try:
        from services.mitre_attack_data import get_attack_techniques

        data = request.get_json()
        technique_counts = data.get('technique_counts', {})
        platform_counts = data.get('platform_counts', {})

        all_techniques = get_attack_techniques()
        max_count = max(technique_counts.values(), default=0)

        nav_techniques = []
        for tech in all_techniques:
            count = technique_counts.get(tech['id'], 0)
            score = 0
            if count > 0 and max_count > 0:
                score = math.log1p(count) / math.log1p(max_count) * 100

            # Build per-platform comment
            pc = platform_counts.get(tech['id'], {})
            parts = []
            if pc.get('crowdstrike', 0) > 0:
                parts.append(f"CS: {pc['crowdstrike']}")
            if pc.get('tanium', 0) > 0:
                parts.append(f"Tanium: {pc['tanium']}")
            if pc.get('qradar', 0) > 0:
                parts.append(f"QRadar: {pc['qradar']}")
            comment = f"{count} detection rules ({', '.join(parts)})" if parts else f"{count} detection rules"

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
        layer = {
            'name': f'Detection Rules Coverage ({now})',
            'versions': {
                'attack': '16',
                'navigator': '4.5',
                'layer': '4.5',
            },
            'domain': 'enterprise-attack',
            'description': 'Heatmap of MITRE ATT&CK technique coverage from detection rules (CrowdStrike, Tanium, QRadar)',
            'sorting': 3,
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

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        tmp.write(json.dumps(layer, indent=2).encode())
        tmp.close()

        return send_file(
            tmp.name,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'detection_rules_navigator_{timestamp}.json',
        )
    except Exception as e:
        logger.error(f"Error building detection rules Navigator layer: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


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
