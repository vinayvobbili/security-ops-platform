"""
Threat Intel Dashboard Handler

Thin wrapper over services.threat_intel_db for the web layer.
Handles sync locking and formats responses for the frontend.
"""

import logging
import threading

logger = logging.getLogger(__name__)

# Thread lock to prevent concurrent syncs
_rebuild_lock = threading.Lock()
_rebuild_in_progress = False


def get_dashboard_data(start_date=None, end_date=None) -> dict:
    """Read dashboard data from the SQLite database."""
    try:
        from services.threat_intel_db import get_dashboard_data as db_get_dashboard_data, has_data, get_sync_metadata

        if not has_data():
            return {
                'success': True,
                'has_data': False,
                'data': None,
                'last_synced_at': None,
            }

        data = db_get_dashboard_data(start_date=start_date, end_date=end_date)
        return {
            'success': True,
            'has_data': True,
            'data': data,
            'last_synced_at': get_sync_metadata('last_sync_at'),
        }

    except Exception as e:
        logger.error(f"Error reading dashboard data: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_sync_status() -> dict:
    """Return sync status for the UI."""
    try:
        from services.threat_intel_db import has_data, get_sync_metadata, get_db_path

        db_path = get_db_path()
        db_exists = db_path.exists()

        tipper_count = 0
        if db_exists and has_data():
            from services.threat_intel_db import get_connection
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM tippers")
                tipper_count = cursor.fetchone()[0]

        return {
            'success': True,
            'exists': db_exists,
            'tipper_count': tipper_count,
            'last_synced_at': get_sync_metadata('last_sync_at') if db_exists else None,
            'syncing': _rebuild_in_progress,
        }

    except Exception as e:
        logger.error(f"Error reading sync status: {e}")
        return {'success': False, 'error': str(e)}


def get_tippers_for_entity(entity_type: str, entity_value: str) -> dict:
    """Get source tippers for a specific entity occurrence."""
    try:
        from services.threat_intel_db import get_tippers_for_entity as db_get_tippers
        tippers = db_get_tippers(entity_type, entity_value)
        return {'success': True, 'tippers': tippers}
    except Exception as e:
        logger.error(f"Error getting tippers for entity {entity_type}={entity_value}: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def export_table(tab: str, query: str = '') -> str:
    """Export a threat intel table tab to a professionally formatted Excel file.

    Returns the path to the temporary .xlsx file.
    Includes AZDO Work Items column with comma-separated tipper IDs.
    """
    import tempfile

    import pandas as pd
    from services.threat_intel_db import export_entities
    from src.utils.excel_formatting import apply_professional_formatting

    rows = export_entities(tab, query, limit=5000)

    # Helper: format comma-separated azdo_ids with spaces for readability
    def fmt_azdo(r):
        ids = r.get('azdo_ids') or ''
        return ', '.join(ids.split(',')) if ids else ''

    # Build DataFrame with display-friendly columns
    if tab in ('domains', 'ips', 'hashes'):
        df = pd.DataFrame([{
            'Rank': i + 1,
            'Value': r['value'],
            'Occurrences': r['count'],
            'VT Verdict': r.get('vt_verdict') or '',
            'VT Detections': f"{r['vt_malicious']}/{r['vt_total']}" if r.get('vt_malicious') is not None and r.get('vt_total') is not None else '',
            'RF Risk Score': r.get('rf_risk_score') if r.get('rf_risk_score') is not None else '',
            'RF Risk Level': r.get('rf_risk_level') or '',
            'AZDO Work Items': fmt_azdo(r),
        } for i, r in enumerate(rows)])
    elif tab == 'cves':
        df = pd.DataFrame([{
            'Rank': i + 1,
            'CVE': r['cve'],
            'Occurrences': r['count'],
            'First Seen': r.get('first_seen') or '',
            'Last Seen': r.get('last_seen') or '',
            'AZDO Work Items': fmt_azdo(r),
        } for i, r in enumerate(rows)])
    elif tab == 'malware':
        df = pd.DataFrame([{
            'Rank': i + 1,
            'Name': r['name'],
            'Occurrences': r['count'],
            'AZDO Work Items': fmt_azdo(r),
        } for i, r in enumerate(rows)])
    elif tab == 'actors':
        df = pd.DataFrame([{
            'Rank': i + 1,
            'Actor': r['name'],
            'Region': r.get('region') or 'Unknown',
            'Occurrences': r['count'],
            'AZDO Work Items': fmt_azdo(r),
        } for i, r in enumerate(rows)])
    elif tab == 'ttps':
        df = pd.DataFrame([{
            'Rank': i + 1,
            'Technique ID': r['technique_id'],
            'Occurrences': r['count'],
            'AZDO Work Items': fmt_azdo(r),
        } for i, r in enumerate(rows)])
    elif tab == 'redteam':
        df = pd.DataFrame([{
            'Rank': i + 1,
            'Technique ID': r['technique_id'],
            'Submissions': r['count'],
            'Last Tested': r.get('last_tested') or '',
            'Submitters': r.get('submitters') or '',
        } for i, r in enumerate(rows)])
    else:
        df = pd.DataFrame()

    if df.empty:
        df = pd.DataFrame({'Info': ['No data found']})

    # Write to temp Excel file
    tmp = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
    tmp.close()
    df.to_excel(tmp.name, index=False, engine='openpyxl')

    # Column widths and wrap config per tab type
    col_widths = {
        'rank': 8, 'occurrences': 15,
        'value': 45, 'vt verdict': 15, 'vt detections': 16,
        'rf risk score': 16, 'rf risk level': 16,
        'cve': 22, 'first seen': 14, 'last seen': 14,
        'name': 40, 'actor': 35, 'region': 18, 'technique id': 20,
        'azdo work items': 40,
        'info': 30,
    }

    apply_professional_formatting(
        tmp.name,
        column_widths=col_widths,
        wrap_columns={'value', 'azdo work items'},
    )

    return tmp.name


def search_entities(tab: str, query: str) -> dict:
    """Search all entities of a given type matching a query string."""
    try:
        from services.threat_intel_db import search_entities as db_search
        results = db_search(tab, query)
        return {'success': True, 'results': results}
    except Exception as e:
        logger.error(f"Error searching entities tab={tab} q={query}: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_attack_matrix_data(actors=None, tipper_titles=None, tipper_ids=None, start_date=None, end_date=None) -> dict:
    """Build ATT&CK matrix data by merging DB counts with reference data."""
    try:
        from services.mitre_attack_data import get_matrix_data

        if any((actors, tipper_titles, tipper_ids)):
            from services.threat_intel_db import get_filtered_mitre_technique_counts
            counts = get_filtered_mitre_technique_counts(actors=actors, tipper_titles=tipper_titles, tipper_ids=tipper_ids)
        else:
            from services.threat_intel_db import get_all_mitre_technique_counts
            counts = get_all_mitre_technique_counts(start_date=start_date, end_date=end_date)

        matrix = get_matrix_data(counts)
        return {'success': True, **matrix}
    except Exception as e:
        logger.error(f"Error building ATT&CK matrix: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_atlas_matrix_data(start_date=None, end_date=None) -> dict:
    """Build ATLAS matrix data, merging DB detection counts with taxonomy."""
    try:
        from services.mitre_atlas_data import get_atlas_matrix_data as _build
        from services.threat_intel_db import get_all_atlas_technique_counts
        counts = get_all_atlas_technique_counts(start_date=start_date, end_date=end_date)
        matrix = _build(technique_counts=counts)
        return {'success': True, **matrix}
    except Exception as e:
        logger.error(f"Error building ATLAS matrix: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def export_navigator_layer(actors=None, tipper_titles=None, tipper_ids=None) -> dict:
    """Build Navigator v4.5 layer JSON for download."""
    try:
        from services.mitre_attack_data import build_navigator_layer
        from services.threat_intel_db import get_technique_procedures

        if any((actors, tipper_titles, tipper_ids)):
            from services.threat_intel_db import get_filtered_mitre_technique_counts
            counts = get_filtered_mitre_technique_counts(actors=actors, tipper_titles=tipper_titles, tipper_ids=tipper_ids)
        else:
            from services.threat_intel_db import get_all_mitre_technique_counts
            counts = get_all_mitre_technique_counts()

        procedures = get_technique_procedures(actors=actors, tipper_titles=tipper_titles, tipper_ids=tipper_ids)
        layer = build_navigator_layer(counts, technique_procedures=procedures)
        return {'success': True, 'layer': layer}
    except Exception as e:
        logger.error(f"Error building Navigator layer: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_attackiq_status() -> dict:
    """Get AttackIQ configuration status and assessment counts by status."""
    try:
        from services.attackiq import AttackIQClient
        aq = AttackIQClient()
        configured = aq.is_configured()

        assessment_counts = {}
        if configured:
            from services.threat_intel_db import get_connection
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT status, COUNT(*) as cnt
                    FROM attackiq_assessments
                    GROUP BY status
                """)
                assessment_counts = {r['status']: r['cnt'] for r in cursor.fetchall()}

        return {
            'success': True,
            'configured': configured,
            'assessment_counts': assessment_counts,
        }
    except Exception as e:
        logger.error(f"Error getting AttackIQ status: {e}", exc_info=True)
        return {'success': True, 'configured': False, 'assessment_counts': {}}


def get_actor_technique_map(start_date=None, end_date=None) -> dict:
    """Get actor-to-technique relationship map for visual insights."""
    try:
        from services.threat_intel_db import get_actor_technique_map as db_get_actor_technique_map
        data = db_get_actor_technique_map(start_date=start_date, end_date=end_date)
        return {'success': True, 'data': data}
    except Exception as e:
        logger.error(f"Error getting actor-technique map: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_malware_actor_map(start_date=None, end_date=None) -> dict:
    """Get malware-to-actor relationship map for visual insights."""
    try:
        from services.threat_intel_db import get_malware_actor_map as db_get_malware_actor_map
        data = db_get_malware_actor_map(start_date=start_date, end_date=end_date)
        return {'success': True, 'data': data}
    except Exception as e:
        logger.error(f"Error getting malware-actor map: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def create_attackiq_assessment_for_tipper(tipper_id: int) -> dict:
    """Manually trigger AttackIQ assessment creation for a single tipper."""
    try:
        from services.attackiq import AttackIQClient
        aq = AttackIQClient()
        if not aq.is_configured():
            return {'success': False, 'error': 'AttackIQ API not configured'}

        # Get tipper techniques from DB
        from services.threat_intel_db import get_connection, get_attackiq_assessment, upsert_attackiq_assessment
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title FROM tippers WHERE azdo_id = ?", (tipper_id,))
            row = cursor.fetchone()
            if not row:
                return {'success': False, 'error': f'Tipper {tipper_id} not found'}
            title = row['title']

            cursor.execute(
                "SELECT technique_id FROM tipper_mitre_techniques WHERE tipper_id = ?",
                (tipper_id,)
            )
            techniques = [r['technique_id'] for r in cursor.fetchall()]

        if not techniques:
            return {'success': False, 'error': f'Tipper {tipper_id} has no MITRE techniques'}

        # Check if assessment already exists
        existing = get_attackiq_assessment(tipper_id)
        if existing:
            return {
                'success': False,
                'error': f'Assessment already exists for tipper {tipper_id}',
                'assessment': existing,
            }

        # Create assessment
        result = aq.create_tipper_assessment(tipper_id, title, techniques)
        if result.get('error'):
            return {'success': False, 'error': result['error']}

        upsert_attackiq_assessment(
            tipper_id=tipper_id,
            assessment_id=result['assessment_id'],
            assessment_url=result.get('assessment_url', ''),
            test_id=result.get('test_id', ''),
            scenarios_matched=result.get('scenarios_matched', 0),
            status='created',
        )

        return {'success': True, 'result': result}

    except Exception as e:
        logger.error(f"Error creating AttackIQ assessment for tipper {tipper_id}: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def enrich_iocs(vt_limit=50, rf_limit=200) -> dict:
    """
    Trigger IOC enrichment with VT and RF data.

    Thread-locked to prevent concurrent enrichment runs.
    """
    global _rebuild_in_progress

    if not _rebuild_lock.acquire(blocking=False):
        return {'success': False, 'error': 'Sync or enrichment already in progress'}

    try:
        _rebuild_in_progress = True
        from services.threat_intel_db import enrich_top_iocs

        result = enrich_top_iocs(vt_limit=vt_limit, rf_limit=rf_limit)
        return {
            'success': True,
            'rf_enriched': result.get('rf_enriched', 0),
            'vt_enriched': result.get('vt_enriched', 0),
            'errors': result.get('errors', []),
        }
    except Exception as e:
        logger.error(f"Enrichment failed: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}
    finally:
        _rebuild_in_progress = False
        _rebuild_lock.release()
