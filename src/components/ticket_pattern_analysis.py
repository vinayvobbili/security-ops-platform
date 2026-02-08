"""Weekly ticket pattern analysis - generates AZDO user story from ticket cache stats.

Runs deterministic queries against the nightly ticket cache to identify top offenders
(hosts/users generating the most tickets), then uses a local LLM to generate a
human-readable summary for an AZDO user story.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import requests
from webexpythonsdk import WebexAPI

from services.azdo import create_wit

logger = logging.getLogger(__name__)

PATTERN_ANALYSIS_LEADS_PATH = Path(__file__).parent.parent.parent / 'data' / 'transient' / 're' / 'pattern_analysis_leads.json'


def load_pattern_analysis_leads() -> list[str]:
    """Load pattern analysis leads from JSON file."""
    with open(PATTERN_ANALYSIS_LEADS_PATH) as f:
        return json.load(f)


def save_pattern_analysis_leads(leads: list[str]) -> None:
    """Save pattern analysis leads to JSON file (rotated for round-robin)."""
    with open(PATTERN_ANALYSIS_LEADS_PATH, 'w') as f:
        json.dump(leads, f, indent=4)


def get_next_assignee() -> str:
    """Get next assignee using round-robin and rotate the list."""
    leads = load_pattern_analysis_leads()
    assignee = leads[0]
    # Rotate: move first lead to the end
    rotated = leads[1:] + [leads[0]]
    save_pattern_analysis_leads(rotated)
    return assignee

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2:0.5b"

# Risky keywords to flag in ticket names (avoid overly broad terms like "admin")
RISKY_KEYWORDS = [
    'data exposure', 'data leak', 'exfiltration',
    'privileged account', 'privilege escalation',
    'lateral movement', 'persistence',
    'ransomware', 'encrypt',
    'credential theft', 'credential dump',
    'breach', 'compromise',
    'pii', 'phi', 'pci',
    'unauthorized access', 'account takeover',
    'malware', 'backdoor', 'rootkit',
]


def load_ticket_cache() -> pd.DataFrame:
    """Load latest ticket cache as DataFrame."""
    from zoneinfo import ZoneInfo
    today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
    path = Path(__file__).parent.parent.parent / 'data' / 'transient' / 'secOps' / today / 'past_90_days_tickets.json'

    with open(path) as f:
        data = json.load(f)

    logger.info(f"Loaded {len(data['data'])} tickets from cache ({today})")
    return pd.DataFrame(data['data'])


def get_stats(df: pd.DataFrame, days: int = 7) -> dict:
    """Compute all stats deterministically from ticket cache."""
    from zoneinfo import ZoneInfo
    cutoff = datetime.now(ZoneInfo("America/New_York")) - timedelta(days=days)

    df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', utc=True)
    recent = df[df['created_dt'] >= cutoff].copy()

    # Filter out Unknown/empty/N/A hostnames for top_hosts
    valid_hosts = recent[
        (recent['hostname'].notna()) &
        (recent['hostname'] != 'Unknown') &
        (recent['hostname'].str.upper() != 'N/A') &
        (recent['hostname'].str.strip() != '')
    ]

    # Clean up owner names - replace empty with "Unassigned"
    recent['owner_display'] = recent['owner'].fillna('').replace('', 'Unassigned')

    # Filter resolution days to valid values only (positive, reasonable range)
    valid_resolution = recent[
        (recent['resolution_time_days'].notna()) &
        (recent['resolution_time_days'] >= 0) &
        (recent['resolution_time_days'] <= 365)  # Cap at 1 year
    ]['resolution_time_days']

    # Filter out Unknown/empty usernames for top_users
    valid_users = recent[
        (recent['username'].notna()) &
        (recent['username'] != 'Unknown') &
        (recent['username'].str.upper() != 'N/A') &
        (recent['username'].str.strip() != '')
    ]

    # Filter out Unknown/empty emails for top_emails
    top_emails = {}
    if 'email' in recent.columns:
        valid_emails = recent[
            (recent['email'].notna()) &
            (recent['email'] != 'Unknown') &
            (recent['email'].str.upper() != 'N/A') &
            (recent['email'].str.strip() != '')
        ]
        top_emails = valid_emails.groupby('email').size().nlargest(10).to_dict()

    # Get top hosts and users lists
    top_hosts = valid_hosts.groupby('hostname').size().nlargest(10).to_dict()
    top_users = valid_users.groupby('username').size().nlargest(10).to_dict()

    # Compute type breakdown for top hosts
    top_hosts_detail = {}
    for host in top_hosts.keys():
        host_tickets = valid_hosts[valid_hosts['hostname'] == host]
        type_breakdown = host_tickets.groupby('type').size().to_dict()
        severity_breakdown = host_tickets.groupby('severity_display').size().to_dict() if 'severity_display' in host_tickets.columns else {}
        top_hosts_detail[host] = {
            'count': top_hosts[host],
            'by_type': type_breakdown,
            'by_severity': severity_breakdown,
        }

    # Compute type breakdown for top users
    top_users_detail = {}
    for user in top_users.keys():
        user_tickets = valid_users[valid_users['username'] == user]
        type_breakdown = user_tickets.groupby('type').size().to_dict()
        severity_breakdown = user_tickets.groupby('severity_display').size().to_dict() if 'severity_display' in user_tickets.columns else {}
        top_users_detail[user] = {
            'count': top_users[user],
            'by_type': type_breakdown,
            'by_severity': severity_breakdown,
        }

    return {
        'period': f"Last {days} days",
        'total_tickets': len(recent),
        'top_hosts': top_hosts,
        'top_hosts_detail': top_hosts_detail,
        'top_users': top_users,
        'top_users_detail': top_users_detail,
        'top_emails': top_emails,
        'by_type': recent.groupby('type').size().to_dict(),
        'avg_resolution_days': round(valid_resolution.mean(), 1) if len(valid_resolution) > 0 else None,
        'sla_breaches': {
            'response': int(recent['has_breached_response_sla'].sum()),
            'containment': int(recent['has_breached_containment_sla'].sum()),
        },
        'by_severity': recent.groupby('severity_display').size().to_dict(),
        'risky_tickets': _find_risky(recent),
    }


def _find_risky(df: pd.DataFrame) -> list[dict]:
    """Find tickets with risky keywords in name field."""
    pattern = '|'.join(RISKY_KEYWORDS)
    mask = df['name'].str.contains(pattern, case=False, na=False)

    risky = df[mask][['id', 'name', 'hostname', 'type', 'severity_display']].head(20)
    return risky.to_dict('records')


def _get_llm_insight(stats: dict) -> str:
    """Get a brief insight from local LLM (1-2 sentences max)."""
    prompt = f"""Given these ticket stats, what is the single most important pattern or concern? Reply in 1-2 sentences only.

Top hosts: {list(stats['top_hosts'].keys())[:5]}
Top users: {list(stats['top_users'].keys())[:5]}
SLA breaches: {stats['sla_breaches']}
Total tickets: {stats['total_tickets']}
"""

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=60)
        resp.raise_for_status()
        return resp.json().get('response', '').strip()[:500]  # Cap at 500 chars
    except Exception as e:
        logger.error(f"LLM insight failed: {e}")
        return "_Unable to generate insight._"


def _format_top_list_html(data: dict, limit: int = 10) -> str:
    """Format a dict as an HTML list."""
    items = [f"<li><b>{k}</b>: {v}</li>" for k, v in list(data.items())[:limit]]
    return "<ul>" + "".join(items) + "</ul>" if items else "<p>None</p>"


def _format_detail_list_html(detail: dict, limit: int = 5) -> str:
    """Format detailed host/user breakdown as HTML with type and severity info."""
    items = []
    for name, info in list(detail.items())[:limit]:
        # Format type breakdown
        types_str = ", ".join(f"{t}: {c}" for t, c in sorted(info['by_type'].items(), key=lambda x: -x[1])[:3])
        # Format severity breakdown
        severity_str = ", ".join(f"{s}: {c}" for s, c in sorted(info['by_severity'].items(), key=lambda x: -x[1])[:3])

        item_html = f"<li><b>{name}</b> ({info['count']} tickets)"
        if types_str:
            item_html += f"<br>&nbsp;&nbsp;Types: {types_str}"
        if severity_str:
            item_html += f"<br>&nbsp;&nbsp;Severity: {severity_str}"
        item_html += "</li>"
        items.append(item_html)

    return "<ul>" + "".join(items) + "</ul>" if items else "<p>None</p>"


def generate_story_body(stats: dict) -> str:
    """Generate story body as HTML for AZDO."""
    insight = _get_llm_insight(stats)

    # Format risky tickets as HTML list
    risky_items = [
        f"<li><b>{t['id']}</b>: {t['name'][:80]}...</li>" if len(t['name']) > 80 else f"<li><b>{t['id']}</b>: {t['name']}</li>"
        for t in stats['risky_tickets'][:5]
    ]
    risky_list = "<ul>" + "".join(risky_items) + "</ul>" if risky_items else "<p>None flagged</p>"

    return f"""
<h2>📊 Weekly Ticket Pattern Analysis (Pokedex)</h2>

<p><b>Period:</b> {stats['period']} &nbsp;|&nbsp; <b>Total Tickets:</b> {stats['total_tickets']}</p>

<hr>

<p><b>Summary:</b><br>{insight}</p>

<hr>

<h3>🖥️ Top Hosts (Repeat Offenders)</h3>
{_format_detail_list_html(stats['top_hosts_detail'], limit=5)}

<h3>👤 Top Users (Affected Accounts)</h3>
{_format_detail_list_html(stats['top_users_detail'], limit=5)}

<h3>📧 Top Emails (Affected Addresses)</h3>
{_format_top_list_html(stats['top_emails'], limit=5)}

<h3>⏱️ SLA Breaches</h3>
<ul>
<li>Response: <b>{stats['sla_breaches']['response']}</b></li>
<li>Containment: <b>{stats['sla_breaches']['containment']}</b></li>
</ul>

<h3>📁 Tickets by Type (Top 5)</h3>
{_format_top_list_html(stats['by_type'], limit=5)}

<h3>⚠️ Risky Tickets Flagged ({len(stats['risky_tickets'])})</h3>
{risky_list}

<h3>📈 Severity Distribution</h3>
{_format_top_list_html(stats['by_severity'])}
"""


def run():
    """Main entry point for scheduled job."""
    from my_config import get_config
    config = get_config()

    logger.info("Starting weekly ticket pattern analysis")

    # 1. Load and analyze
    df = load_ticket_cache()
    stats = get_stats(df, days=7)
    logger.info(f"Computed stats: {stats['total_tickets']} tickets, {len(stats['top_hosts'])} top hosts")

    # 2. Generate narrative
    body = generate_story_body(stats)

    # 3. Append raw stats in collapsible section
    body += f"""
<hr>
<details>
<summary><b>📋 Raw Stats (click to expand)</b></summary>
<pre>{json.dumps(stats, indent=2, default=str)}</pre>
</details>
"""

    # 4. Create AZDO user story
    title = f"Weekly Ticket Pattern Analysis - {datetime.now().strftime('%Y-%m-%d')}"

    assignee = get_next_assignee()
    logger.info(f"Assigning user story to: {assignee}")

    work_item_id = create_wit(
        title=title,
        item_type="User Story",
        description=body,
        project="rea",
        submitter="Pokedex Automation",
        parent_url=config.azdo_rea_parent_url,
        iteration=config.azdo_rea_iteration,
        assignee=assignee,
        severity="2 - Medium",
        tags=["#ResponseIntelligence", "#InternalIntel"],
    )

    work_item_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_re_project}/_workitems/edit/{work_item_id}"
    logger.info(f"Created AZDO user story: {work_item_url}")

    # Send Webex notifications
    _send_webex_notifications(config, work_item_url, assignee, stats)

    return work_item_id


def _send_webex_notifications(config, work_item_url: str, assignee: str, stats: dict) -> None:
    """Send Webex notifications to Response Engineering room and test space."""
    try:
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_soar)

        message = (
            f"📊 **Weekly Ticket Pattern Analysis Created**\n\n"
            f"**Assignee:** {assignee}\n"
            f"**Total Tickets:** {stats['total_tickets']}\n"
            f"**SLA Breaches:** Response: {stats['sla_breaches']['response']}, "
            f"Containment: {stats['sla_breaches']['containment']}\n\n"
            f"🔗 [View User Story]({work_item_url})"
        )

        room_ids = [
            config.webex_room_id_response_engineering,
            config.webex_room_id_dev_test_space,
        ]

        for room_id in room_ids:
            if room_id:
                webex_api.messages.create(roomId=room_id, markdown=message)
                logger.info(f"Sent Webex notification to room: {room_id}")
            else:
                logger.warning("Webex room ID not configured, skipping notification")

    except Exception as e:
        logger.error(f"Failed to send Webex notification: {e}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    run()
