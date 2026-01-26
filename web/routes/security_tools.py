"""Security tools routes: domain lookalike, VirusTotal, RecordedFuture."""

import logging

from flask import Blueprint, Response, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from services import domain_lookalike
from services.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)
security_tools_bp = Blueprint('security_tools', __name__)

# VirusTotal client singleton
_vt_client: VirusTotalClient | None = None


def _get_vt_client() -> VirusTotalClient | None:
    """Get VirusTotal client if configured."""
    global _vt_client
    if _vt_client is None:
        _vt_client = VirusTotalClient()
    return _vt_client if _vt_client.is_configured() else None


# --- Domain Lookalike ---

@security_tools_bp.route('/domain-lookalike')
@log_web_activity
def domain_lookalike_search():
    """Display domain lookalike search page."""
    return render_template('domain_lookalike_search.html')


@security_tools_bp.route('/api/domain-lookalikes')
@log_web_activity
def api_domain_lookalikes():
    """API endpoint to get lookalike domains.

    Returns results immediately without parking checks.
    Use /api/domain-lookalikes/parking SSE endpoint for streaming parking status.
    """
    try:
        domain = request.args.get('domain', '').strip()
        registered_only = request.args.get('registered_only', 'false').lower() == 'true'
        include_malicious_tlds = request.args.get('include_malicious_tlds', 'false').lower() == 'true'

        if not domain:
            return jsonify({'success': False, 'error': 'Domain parameter is required'}), 400

        result = domain_lookalike.get_domain_lookalikes(domain, registered_only, include_malicious_tlds)
        return jsonify(result)

    except Exception as exc:
        logger.error(f"Error in domain lookalike API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@security_tools_bp.route('/api/domain-lookalikes/parking')
def api_domain_lookalikes_parking():
    """SSE endpoint to stream parking status for domains.

    Query params:
        domains: Comma-separated list of domains to check

    Returns:
        Server-Sent Events stream with parking status for each domain
    """
    import json

    domains_param = request.args.get('domains', '').strip()

    if not domains_param:
        return jsonify({'success': False, 'error': 'domains parameter is required'}), 400

    domains = [d.strip() for d in domains_param.split(',') if d.strip()]

    if not domains:
        return jsonify({'success': False, 'error': 'No valid domains provided'}), 400

    if len(domains) > 500:
        return jsonify({'success': False, 'error': 'Maximum 500 domains allowed'}), 400

    def generate():
        """Generator that yields SSE events for each domain's parking status."""
        for domain_name in domains:
            try:
                parked = domain_lookalike.check_if_parked(domain_name)
                data = json.dumps({'domain': domain_name, 'parked': parked})
                yield f"data: {data}\n\n"
            except Exception as e:
                logger.error(f"Error checking parking for {domain_name}: {e}")
                data = json.dumps({'domain': domain_name, 'parked': None, 'error': str(e)})
                yield f"data: {data}\n\n"

        # Send completion event
        yield "data: {\"complete\": true}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


@security_tools_bp.route('/api/domain-whois')
@log_web_activity
def api_domain_whois():
    """API endpoint to get WHOIS information for a domain."""
    try:
        domain = request.args.get('domain', '').strip()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain parameter is required'}), 400

        result = domain_lookalike.get_domain_whois_info(domain)
        return jsonify(result)

    except Exception as exc:
        logger.error(f"Error in domain WHOIS API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


# --- RecordedFuture ---

@security_tools_bp.route('/api/domain-lookalikes/rf-enrich')
def api_domain_lookalikes_rf_enrich():
    """API endpoint to enrich domains with RecordedFuture threat intelligence.

    Query params:
        domains: Comma-separated list of domains to enrich

    Returns:
        JSON with RF risk scores and evidence rules for each domain
    """
    domains_param = request.args.get('domains', '').strip()

    if not domains_param:
        return jsonify({'success': False, 'error': 'domains parameter is required'}), 400

    domains = [d.strip() for d in domains_param.split(',') if d.strip()]

    if not domains:
        return jsonify({'success': False, 'error': 'No valid domains provided'}), 400

    if len(domains) > 1000:
        return jsonify({'success': False, 'error': 'Maximum 1000 domains allowed'}), 400

    try:
        from services.recorded_future import RecordedFutureClient

        client = RecordedFutureClient()
        if not client.is_configured():
            return jsonify({
                'success': False,
                'error': 'RecordedFuture API key not configured'
            }), 503

        # Enrich domains
        result = client.enrich_domains(domains)

        if "error" in result:
            return jsonify({'success': False, 'error': result['error']}), 502

        # Extract and format results
        enriched = client.extract_enrichment_results(result)

        # Build response map
        results_map = {}
        for item in enriched:
            results_map[item['value']] = {
                'risk_score': item.get('risk_score', 0),
                'risk_level': item.get('risk_level', 'Unknown'),
                'rules': item.get('rules', []),
                'evidence_count': item.get('evidence_count', 0),
            }

        # Count high risk
        high_risk_count = sum(1 for v in results_map.values() if v.get('risk_score', 0) >= 65)

        return jsonify({
            'success': True,
            'domains_enriched': len(results_map),
            'high_risk_count': high_risk_count,
            'results': results_map
        })

    except ImportError:
        return jsonify({
            'success': False,
            'error': 'RecordedFuture client not available'
        }), 503

    except Exception as exc:
        logger.error(f"Error in RF enrichment API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@security_tools_bp.route('/api/rf/enrich')
def api_rf_enrich():
    """General-purpose RecordedFuture enrichment API.

    Query params:
        ips: Comma-separated list of IP addresses
        domains: Comma-separated list of domains
        hashes: Comma-separated list of file hashes
        urls: Comma-separated list of URLs

    Returns:
        JSON with RF risk scores and evidence rules
    """
    try:
        from services.recorded_future import RecordedFutureClient

        client = RecordedFutureClient()
        if not client.is_configured():
            return jsonify({
                'success': False,
                'error': 'RecordedFuture API key not configured'
            }), 503

        # Parse parameters
        ips = [ip.strip() for ip in request.args.get('ips', '').split(',') if ip.strip()]
        domains = [d.strip() for d in request.args.get('domains', '').split(',') if d.strip()]
        hashes = [h.strip() for h in request.args.get('hashes', '').split(',') if h.strip()]
        urls = [u.strip() for u in request.args.get('urls', '').split(',') if u.strip()]

        if not any([ips, domains, hashes, urls]):
            return jsonify({
                'success': False,
                'error': 'At least one of ips, domains, hashes, or urls is required'
            }), 400

        total_iocs = len(ips) + len(domains) + len(hashes) + len(urls)
        if total_iocs > 1000:
            return jsonify({
                'success': False,
                'error': 'Maximum 1000 total IOCs allowed'
            }), 400

        # Call enrichment
        result = client.enrich(
            ips=ips if ips else None,
            domains=domains if domains else None,
            hashes=hashes if hashes else None,
            urls=urls if urls else None,
        )

        if "error" in result:
            return jsonify({'success': False, 'error': result['error']}), 502

        # Extract results
        enriched = client.extract_enrichment_results(result)

        return jsonify({
            'success': True,
            'total_enriched': len(enriched),
            'results': enriched
        })

    except ImportError:
        return jsonify({
            'success': False,
            'error': 'RecordedFuture client not available'
        }), 503

    except Exception as exc:
        logger.error(f"Error in RF enrichment API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


# --- VirusTotal ---

@security_tools_bp.route('/api/virustotal/domain/<domain>')
@log_web_activity
def api_virustotal_domain(domain: str):
    """API endpoint for on-demand VirusTotal domain lookup.

    Returns reputation data for a domain including threat level and detection stats.
    """
    try:
        vt = _get_vt_client()
        if not vt:
            return jsonify({
                'success': False,
                'error': 'VirusTotal not configured (missing API key)'
            }), 503

        logger.info(f"VT lookup requested for domain: {domain}")
        result = vt.lookup_domain(domain)

        if "error" in result:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400 if 'not found' in result['error'].lower() else 429 if 'rate limit' in result['error'].lower() else 500

        # Extract key reputation data
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Determine threat level
        if malicious >= 3:
            threat_level = "HIGH"
        elif malicious >= 1 or suspicious >= 3:
            threat_level = "MEDIUM"
        elif suspicious >= 1:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        return jsonify({
            'success': True,
            'domain': domain,
            'result': {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'threat_level': threat_level,
                'categories': attrs.get("categories", {}),
                'registrar': attrs.get("registrar", ""),
                'creation_date': attrs.get("creation_date"),
                'vt_link': f"https://www.virustotal.com/gui/domain/{domain}",
            }
        })

    except Exception as exc:
        logger.error(f"VT lookup error for {domain}: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500
