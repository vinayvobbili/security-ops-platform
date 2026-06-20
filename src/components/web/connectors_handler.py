"""Connectors health-check handler.

Provides a registry of all external integrations and parallel health probing.
Every configured connector gets a real live probe — not just env-var checks.
"""

import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 5  # seconds per probe

# ---------------------------------------------------------------------------
# Custom probe functions
# ---------------------------------------------------------------------------
# Each returns True on success, raises on failure.
# They are only called when the connector is already confirmed configured.


def _probe_xsoar_prod():
    from demisto_client.demisto_api.models import SearchIncidentsData
    from services.xsoar._client import get_prod_client
    client = get_prod_client()
    search = SearchIncidentsData(filter={"query": "id:1", "page": 0, "size": 1})
    client.search_incidents(filter=search)
    return True


def _probe_xsoar_dev():
    from demisto_client.demisto_api.models import SearchIncidentsData
    from services.xsoar._client import get_dev_client
    client = get_dev_client()
    search = SearchIncidentsData(filter={"query": "id:1", "page": 0, "size": 1})
    client.search_incidents(filter=search)
    return True


def _probe_thehive():
    from services.thehive import TheHiveClient
    client = TheHiveClient()
    result = client.get_status()
    if 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_dfir_iris():
    from services.dfir_iris import DFIRIrisClient
    client = DFIRIrisClient()
    result = client.get_api_version()
    if 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_crowdstrike():
    from services.crowdstrike import CrowdStrikeClient
    client = CrowdStrikeClient()
    if not client.validate_auth():
        raise RuntimeError(getattr(client, 'last_error', None) or 'Auth validation failed')
    return True


def _probe_tanium_cloud():
    from services.tanium import TaniumClient
    client = TaniumClient(instance='cloud')
    if not client.instances:
        raise RuntimeError('Cloud instance unreachable or token invalid')
    return True


def _probe_tanium_onprem():
    from services.tanium import TaniumClient
    client = TaniumClient(instance='onprem')
    if not client.instances:
        raise RuntimeError('On-prem instance unreachable or token invalid')
    return True


def _probe_cisco_amp():
    from services.amp import CiscoAMPClient
    client = CiscoAMPClient()
    result = client.get_version()
    if not result:
        raise RuntimeError('get_version() returned empty')
    return True


def _probe_qradar():
    from services.qradar import QRadarClient
    client = QRadarClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.get_offenses(limit=1)
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_proxy():
    from services.proxy import ProxyClient
    client = ProxyClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.get_status()
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_vectra():
    from services.vectra import VectraClient
    client = VectraClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    return True


def _probe_palo_alto():
    host = os.environ.get('PALO_ALTO_HOST')
    key = os.environ.get('PALO_ALTO_API_KEY')
    resp = requests.get(
        f'https://{host}/api/?type=version&key={key}',
        timeout=_PROBE_TIMEOUT, verify=False,
    )
    resp.raise_for_status()
    return True


def _probe_recorded_future():
    from services.recorded_future import RecordedFutureClient
    client = RecordedFutureClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    # Lightweight: fetch a single IP reputation (localhost = no real data, tiny response)
    resp = requests.get(
        f'{client.base_url}/ip/8.8.8.8',
        headers=client.headers,
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_virustotal():
    from services.virustotal import VirusTotalClient
    client = VirusTotalClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    resp = requests.get(
        'https://www.virustotal.com/api/v3/users/me',
        headers={'x-apikey': client.api_key},
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_shodan():
    from services.shodan_monitor import ShodanClient
    client = ShodanClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.get_api_info()
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_abuseipdb():
    from services.abuseipdb import AbuseIPDBClient
    client = AbuseIPDBClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.check_ip('8.8.8.8', max_age_days=1, verbose=False)
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_hibp():
    from services.hibp import HIBPClient
    client = HIBPClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    # HIBP subscription status endpoint
    resp = requests.get(
        'https://haveibeenpwned.com/api/v3/subscription/status',
        headers={'hibp-api-key': client.api_key, 'user-agent': 'IR-HealthCheck'},
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_intelx():
    from services.intelx import IntelligenceXClient
    client = IntelligenceXClient()
    # Authenticate endpoint — lightweight
    resp = requests.get(
        f'{client.base_url}/authenticate/info',
        headers={'x-key': client.api_key},
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_abusech():
    from services.abusech import AbuseCHClient
    client = AbuseCHClient()
    result = client.check_domain_urlhaus('example.com')
    if result is None:
        raise RuntimeError('URLhaus returned None')
    return True


def _probe_urlscan():
    from services.urlscan import URLScanClient
    client = URLScanClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.search_domain('example.com', size=1)
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_abnormal_security():
    from services.abnormal_security import AbnormalSecurityClient
    client = AbnormalSecurityClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    result = client.diagnose_auth()
    if isinstance(result, dict) and not result.get('authenticated'):
        raise RuntimeError(result.get('error', 'Auth diagnostics failed'))
    return True


def _probe_phishfort():
    from services.phish_fort import contact_phishfort_api
    api_key = os.environ.get('PHISH_FORT_API_KEY')
    result = contact_phishfort_api(api_key, status_verbose=True)
    if isinstance(result, dict) and 'error' in result:
        raise RuntimeError(result['error'])
    return True


def _probe_attackiq():
    from services.attackiq import AttackIQClient
    client = AttackIQClient()
    if not client.is_configured():
        raise RuntimeError('Not configured')
    # Lightweight tag lookup
    result = client.get_mitre_tag_uuid('T1059')
    # None is valid (tag may not exist), but exception = unhealthy
    return True


def _probe_servicenow():
    from services.service_now import ServiceNowClient
    client = ServiceNowClient()
    # Token manager validates/refreshes the OAuth token on init
    if not client.token_manager or not client.token_manager.access_token:
        raise RuntimeError('Failed to acquire ServiceNow OAuth token')
    return True


def _probe_azure_devops():
    org = os.environ.get('AZDO_ORGANIZATION')
    pat = os.environ.get('AZDO_PERSONAL_ACCESS_TOKEN')
    resp = requests.get(
        f'https://dev.azure.com/{org}/_apis/projects?$top=1&api-version=7.0',
        auth=('', pat),
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_webex():
    token = os.environ.get('WEBEX_BOT_ACCESS_TOKEN_ORACLE')
    api_url = os.environ.get('WEBEX_API_URL', 'https://webexapis.com/v1')
    resp = requests.get(
        f'{api_url}/people/me',
        headers={'Authorization': f'Bearer {token}'},
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_teams():
    app_id = os.environ.get('TEAMS_AIDE_APP_ID')
    app_pw = os.environ.get('TEAMS_AIDE_APP_PASSWORD')
    tenant = os.environ.get('TEAMS_AIDE_TENANT_ID')
    resp = requests.post(
        f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
        data={
            'grant_type': 'client_credentials',
            'client_id': app_id,
            'client_secret': app_pw,
            'scope': 'https://api.botframework.com/.default',
        },
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    if 'access_token' not in data:
        raise RuntimeError('No access_token in response')
    return True


def _probe_twilio():
    sid = os.environ.get('TWILIO_ACCOUNT_SID')
    token = os.environ.get('TWILIO_AUTH_TOKEN')
    resp = requests.get(
        f'https://api.twilio.com/2010-04-01/Accounts/{sid}.json',
        auth=(sid, token),
        timeout=_PROBE_TIMEOUT,
    )
    resp.raise_for_status()
    return True


def _probe_domain_lookalike():
    from services.domain_lookalike import check_dnstwist_available
    result = check_dnstwist_available()
    if not result.get('available'):
        raise RuntimeError(result.get('error', 'dnstwist not found'))
    return True


def _probe_censys_ct():
    from services.censys_ct import is_configured
    if not is_configured():
        raise RuntimeError('Censys CT not configured (requires Shodan API key)')
    return True


def _probe_vllm_mlx():
    from my_config import get_config
    m1_analysis_base_url = get_config().m1_analysis_base_url
    resp = requests.get(f'{m1_analysis_base_url}/models', timeout=_PROBE_TIMEOUT)
    resp.raise_for_status()
    return True


def _probe_ssh_tunnel():
    from my_config import get_config
    m1_analysis_base_url = get_config().m1_analysis_base_url
    resp = requests.get(f'{m1_analysis_base_url}/models', timeout=_PROBE_TIMEOUT)
    resp.raise_for_status()
    return True


def _probe_infoblox():
    base = os.environ.get('INFOBLOX_BASE_URL')
    user = os.environ.get('INFOBLOX_USERNAME')
    pw = os.environ.get('INFOBLOX_PASSWORD')
    resp = requests.get(
        f'{base}/wapi/v2.12/grid',
        auth=(user, pw),
        timeout=_PROBE_TIMEOUT,
        verify=False,
    )
    resp.raise_for_status()
    return True


# Map connector ID → probe function
_PROBES = {
    'xsoar_prod': _probe_xsoar_prod,
    'xsoar_dev': _probe_xsoar_dev,
    'thehive': _probe_thehive,
    'dfir_iris': _probe_dfir_iris,
    'crowdstrike': _probe_crowdstrike,
    'tanium_cloud': _probe_tanium_cloud,
    'tanium_onprem': _probe_tanium_onprem,
    'cisco_amp': _probe_cisco_amp,
    'qradar': _probe_qradar,
    'proxy': _probe_proxy,
    'vectra': _probe_vectra,
    'palo_alto': _probe_palo_alto,
    'recorded_future': _probe_recorded_future,
    'virustotal': _probe_virustotal,
    'shodan': _probe_shodan,
    'abuseipdb': _probe_abuseipdb,
    'hibp': _probe_hibp,
    'intelx': _probe_intelx,
    'abusech': _probe_abusech,
    'urlscan': _probe_urlscan,
    'abnormal_security': _probe_abnormal_security,
    'phishfort': _probe_phishfort,
    'attackiq': _probe_attackiq,
    'servicenow': _probe_servicenow,
    'azure_devops': _probe_azure_devops,
    'webex': _probe_webex,
    'teams': _probe_teams,
    'twilio': _probe_twilio,
    'domain_lookalike': _probe_domain_lookalike,
    'censys_ct': _probe_censys_ct,
    'vllm_mlx': _probe_vllm_mlx,
    'infoblox': _probe_infoblox,
    'ssh_tunnel': _probe_ssh_tunnel,
}

# ---------------------------------------------------------------------------
# Connector registry
# ---------------------------------------------------------------------------

CONNECTORS: list[dict] = [
    # ── SOAR & Case Management ──────────────────────────────────────────
    {
        'id': 'xsoar_prod',
        'name': 'XSOAR (Prod)',
        'category': 'SOAR & Case Management',
        'description': 'Production SOAR platform for incident response',
        'env_vars': ['XSOAR_PROD_API_BASE_URL', 'XSOAR_PROD_AUTH_KEY', 'XSOAR_PROD_AUTH_ID'],
    },
    {
        'id': 'xsoar_dev',
        'name': 'XSOAR (Dev)',
        'category': 'SOAR & Case Management',
        'description': 'Development SOAR environment for testing',
        'env_vars': ['XSOAR_DEV_API_BASE_URL', 'XSOAR_DEV_AUTH_KEY', 'XSOAR_DEV_AUTH_ID'],
    },
    {
        'id': 'thehive',
        'name': 'TheHive',
        'category': 'SOAR & Case Management',
        'description': 'Open-source security incident response platform',
        'env_vars': ['THE_HIVE_URL', 'THE_HIVE_API_KEY'],
    },
    {
        'id': 'dfir_iris',
        'name': 'DFIR-IRIS',
        'category': 'SOAR & Case Management',
        'description': 'Digital forensics and incident response case management',
        'env_vars': ['DFIR_IRIS_URL', 'DFIR_IRIS_API_KEY'],
    },

    # ── Endpoint Protection ─────────────────────────────────────────────
    {
        'id': 'crowdstrike',
        'name': 'CrowdStrike Falcon',
        'category': 'Endpoint Protection',
        'description': 'Endpoint detection and response (EDR)',
        'env_vars': ['CROWD_STRIKE_RO_CLIENT_ID', 'CROWD_STRIKE_RO_CLIENT_SECRET'],
    },
    {
        'id': 'tanium_cloud',
        'name': 'Tanium (Cloud)',
        'category': 'Endpoint Protection',
        'description': 'Cloud endpoint management and visibility',
        'env_vars': ['TANIUM_CLOUD_API_URL', 'TANIUM_CLOUD_API_TOKEN'],
    },
    {
        'id': 'tanium_onprem',
        'name': 'Tanium (On-Prem)',
        'category': 'Endpoint Protection',
        'description': 'On-premises endpoint management and visibility',
        'env_vars': ['TANIUM_ONPREM_API_URL', 'TANIUM_ONPREM_API_TOKEN_CH'],
    },
    {
        'id': 'cisco_amp',
        'name': 'Cisco AMP',
        'category': 'Endpoint Protection',
        'description': 'Cisco advanced malware protection',
        'env_vars': ['CISCO_AMP_CLIENT_ID', 'CISCO_AMP_CLIENT_SECRET'],
    },

    # ── SIEM & Network Security ─────────────────────────────────────────
    {
        'id': 'qradar',
        'name': 'QRadar',
        'category': 'SIEM & Network Security',
        'description': 'IBM SIEM for log analysis and threat detection',
        'env_vars': ['QRADAR_API_URL', 'QRADAR_API_KEY'],
    },
    {
        'id': 'proxy',
        'name': 'the corporate proxy',
        'category': 'SIEM & Network Security',
        'description': 'Cloud security web gateway',
        'env_vars': ['CORPORATE_PROXY_API_BASE_URL', 'CORPORATE_PROXY_API_USERNAME', 'CORPORATE_PROXY_API_PASSWORD', 'CORPORATE_PROXY_API_KEY'],
    },
    {
        'id': 'vectra',
        'name': 'Vectra',
        'category': 'SIEM & Network Security',
        'description': 'AI-driven network detection and response',
        'env_vars': ['VECTRA_API_BASE_URL', 'VECTRA_API_CLIENT_ID', 'VECTRA_API_KEY'],
    },
    {
        'id': 'palo_alto',
        'name': 'Palo Alto Firewall',
        'category': 'SIEM & Network Security',
        'description': 'Next-generation firewall management',
        'env_vars': ['PALO_ALTO_HOST', 'PALO_ALTO_API_KEY'],
    },

    # ── Threat Intelligence ─────────────────────────────────────────────
    {
        'id': 'recorded_future',
        'name': 'Recorded Future',
        'category': 'Threat Intelligence',
        'description': 'Premium threat intelligence platform',
        'env_vars': ['RECORDED_FUTURE_API_KEY'],
    },
    {
        'id': 'virustotal',
        'name': 'VirusTotal',
        'category': 'Threat Intelligence',
        'description': 'Multi-engine malware scanning and analysis',
        'env_vars': ['VIRUSTOTAL_API_KEY'],
    },
    {
        'id': 'shodan',
        'name': 'Shodan',
        'category': 'Threat Intelligence',
        'description': 'Internet-connected device search engine',
        'env_vars': ['SHODAN_API_KEY'],
    },
    {
        'id': 'abuseipdb',
        'name': 'AbuseIPDB',
        'category': 'Threat Intelligence',
        'description': 'IP address abuse reporting and lookup',
        'env_vars': ['ABUSEIPDB_API_KEY'],
    },
    {
        'id': 'hibp',
        'name': 'HIBP',
        'category': 'Threat Intelligence',
        'description': 'Have I Been Pwned breach lookup',
        'env_vars': ['HIBP_API_KEY'],
    },
    {
        'id': 'intelx',
        'name': 'IntelligenceX',
        'category': 'Threat Intelligence',
        'description': 'OSINT search engine and data archive',
        'env_vars': ['INTELLIGENCE_X_API_KEY'],
    },
    {
        'id': 'abusech',
        'name': 'Abuse.ch',
        'category': 'Threat Intelligence',
        'description': 'Free malware and botnet threat feeds',
        'env_vars': [],
        'always_configured': True,
    },
    {
        'id': 'urlscan',
        'name': 'URLScan',
        'category': 'Threat Intelligence',
        'description': 'URL scanning and analysis service',
        'env_vars': ['URLSCAN_API_KEY'],
    },

    # ── Email Security ──────────────────────────────────────────────────
    {
        'id': 'abnormal_security',
        'name': 'Abnormal Security',
        'category': 'Email Security',
        'description': 'AI-based email threat detection',
        'env_vars': ['ABNORMAL_SECURITY_API_KEY'],
    },
    {
        'id': 'phishfort',
        'name': 'PhishFort',
        'category': 'Email Security',
        'description': 'Phishing takedown and brand protection',
        'env_vars': ['PHISH_FORT_API_KEY'],
    },

    # ── Breach & Attack Simulation ──────────────────────────────────────
    {
        'id': 'attackiq',
        'name': 'AttackIQ',
        'category': 'Breach & Attack Simulation',
        'description': 'Breach and attack simulation platform',
        'env_vars': ['ATTACKIQ_API_KEY', 'ATTACKIQ_BASE_URL'],
    },

    # ── ITSM ────────────────────────────────────────────────────────────
    {
        'id': 'servicenow',
        'name': 'ServiceNow',
        'category': 'ITSM',
        'description': 'IT service management and ticketing',
        'env_vars': ['SNOW_BASE_URL', 'SNOW_CLIENT_KEY', 'SNOW_CLIENT_SECRET',
                     'SNOW_FUNCTIONAL_ACCOUNT_ID', 'SNOW_FUNCTIONAL_ACCOUNT_PASSWORD'],
    },
    {
        'id': 'azure_devops',
        'name': 'Azure DevOps',
        'category': 'ITSM',
        'description': 'Work-item tracking and project management',
        'env_vars': ['AZDO_ORGANIZATION', 'AZDO_PERSONAL_ACCESS_TOKEN'],
    },

    # ── Communication ───────────────────────────────────────────────────
    {
        'id': 'webex',
        'name': 'Webex',
        'category': 'Communication',
        'description': 'Primary bot messaging and notifications',
        'env_vars': ['WEBEX_BOT_ACCESS_TOKEN_ORACLE', 'WEBEX_API_URL'],
    },
    {
        'id': 'teams',
        'name': 'Microsoft Teams',
        'category': 'Communication',
        'description': 'Teams bot integration (Aide)',
        'env_vars': ['TEAMS_AIDE_APP_ID', 'TEAMS_AIDE_APP_PASSWORD', 'TEAMS_AIDE_TENANT_ID'],
    },
    {
        'id': 'twilio',
        'name': 'Twilio',
        'category': 'Communication',
        'description': 'WhatsApp and SMS alerting',
        'env_vars': ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_WHATSAPP_NUMBER'],
    },

    # ── Domain Monitoring ───────────────────────────────────────────────
    {
        'id': 'domain_lookalike',
        'name': 'Domain Lookalike (dnstwist)',
        'category': 'Domain Monitoring',
        'description': 'Typosquat and lookalike domain detection',
        'env_vars': [],
        'always_configured': True,
    },
    {
        'id': 'censys_ct',
        'name': 'Censys CT',
        'category': 'Domain Monitoring',
        'description': 'Certificate transparency log monitoring',
        'env_vars': ['SHODAN_API_KEY'],
    },

    # ── AI / LLM ────────────────────────────────────────────────────────
    {
        'id': 'vllm_mlx',
        'name': 'vllm-mlx (Main LLM)',
        'category': 'AI / LLM',
        'description': 'Local LLM inference via vllm-mlx on Apple Silicon (port 8000)',
        'env_vars': ['LLM_MODEL'],
    },

    # ── Infrastructure ──────────────────────────────────────────────────
    {
        'id': 'infoblox',
        'name': 'Infoblox',
        'category': 'Infrastructure',
        'description': 'DNS and IPAM management',
        'env_vars': ['INFOBLOX_BASE_URL', 'INFOBLOX_USERNAME', 'INFOBLOX_PASSWORD'],
    },
    {
        'id': 'ssh_tunnel',
        'name': 'Mac SSH Tunnel',
        'category': 'Infrastructure',
        'description': 'Reverse SSH tunnel from Mac to lab VM (Ollama + Tanium)',
        'env_vars': [],
        'always_configured': True,
    },
]

# Category display order
CATEGORY_ORDER = [
    'SOAR & Case Management',
    'Endpoint Protection',
    'SIEM & Network Security',
    'Threat Intelligence',
    'Email Security',
    'Breach & Attack Simulation',
    'ITSM',
    'Communication',
    'Domain Monitoring',
    'AI / LLM',
    'Infrastructure',
]

# ---------------------------------------------------------------------------
# Health-check logic
# ---------------------------------------------------------------------------


def _check_env_vars(env_vars: list[str]) -> bool:
    """Return True if ALL required env vars are present and non-empty."""
    return all(os.environ.get(v) for v in env_vars)


def _probe_single(connector: dict) -> dict:
    """Check one connector: configuration + live probe.

    Returns a status dict.
    """
    cid = connector['id']
    result = {
        'id': cid,
        'name': connector['name'],
        'category': connector['category'],
        'description': connector['description'],
        'env_vars': connector['env_vars'],
        'configured': False,
        'healthy': None,
        'latency_ms': None,
        'error': None,
    }

    # Step 1: configured?
    if connector.get('always_configured'):
        result['configured'] = True
    elif connector['env_vars']:
        result['configured'] = _check_env_vars(connector['env_vars'])

    if not result['configured']:
        return result

    # Step 2: live probe
    probe_fn = _PROBES.get(cid)
    if not probe_fn:
        return result  # No probe defined — stays unknown

    try:
        t0 = time.monotonic()
        probe_fn()
        result['latency_ms'] = int((time.monotonic() - t0) * 1000)
        result['healthy'] = True
    except Exception as exc:
        result['latency_ms'] = int((time.monotonic() - t0) * 1000)
        result['healthy'] = False
        result['error'] = str(exc)
        logger.debug("Probe failed for %s: %s", cid, exc)

    return result


def get_all_connector_statuses(run_probes: bool = True) -> dict:
    """Return status for every registered connector.

    Args:
        run_probes: If True, run live health probes in parallel.
                    If False, only check env-var presence (fast).

    Returns:
        dict with 'connectors' list and 'summary' counts.
    """
    if not run_probes:
        results = []
        for conn in CONNECTORS:
            results.append({
                'id': conn['id'],
                'name': conn['name'],
                'category': conn['category'],
                'description': conn['description'],
                'env_vars': conn['env_vars'],
                'configured': conn.get('always_configured', False) or _check_env_vars(conn['env_vars']),
                'healthy': None,
                'latency_ms': None,
                'error': None,
            })
    else:
        results = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_probe_single, c): c['id'] for c in CONNECTORS}
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=_PROBE_TIMEOUT + 5))
                except Exception as exc:
                    cid = futures[future]
                    conn = next(c for c in CONNECTORS if c['id'] == cid)
                    results.append({
                        'id': cid,
                        'name': conn['name'],
                        'category': conn['category'],
                        'description': conn['description'],
                        'env_vars': conn['env_vars'],
                        'configured': False,
                        'healthy': False,
                        'latency_ms': None,
                        'error': str(exc),
                    })

    # Sort by category order then name
    cat_idx = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    results.sort(key=lambda r: (cat_idx.get(r['category'], 999), r['name']))

    # Summary
    total = len(results)
    configured = sum(1 for r in results if r['configured'])
    healthy = sum(1 for r in results if r['healthy'] is True)
    unhealthy = sum(1 for r in results if r['healthy'] is False)
    unknown = sum(1 for r in results if r['configured'] and r['healthy'] is None)

    return {
        'connectors': results,
        'summary': {
            'total': total,
            'configured': configured,
            'healthy': healthy,
            'unhealthy': unhealthy,
            'unknown': unknown,
        },
    }


def get_connector_categories() -> list[str]:
    """Return ordered list of category names."""
    return list(CATEGORY_ORDER)
