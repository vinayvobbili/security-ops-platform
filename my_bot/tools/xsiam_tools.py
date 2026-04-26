"""
XSIAM (Cortex XDR) Tools Module

the security assistant bot-facing tools for Palo Alto XSIAM/Cortex XDR: incidents, alerts, and
endpoint inventory. Auth uses the Advanced API Key (nonce + timestamp + SHA256)
flow implemented in services.xsiam.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

_ET = ZoneInfo("America/New_York")

from langchain_core.tools import tool

from services.xsiam import XsiamClient
from src.utils.tool_decorator import log_tool_call
from src.utils.llm_decorators import validate_args, IP_ADDRESS_PATTERN

_xsiam_client: Optional[XsiamClient] = None


def _get_client() -> Optional[XsiamClient]:
    global _xsiam_client
    if _xsiam_client is None:
        try:
            client = XsiamClient()
            if client.is_configured():
                _xsiam_client = client
            else:
                logging.warning("XSIAM client not configured (missing key/key-id/base URL)")
        except Exception as e:
            logging.error(f"Failed to initialize XSIAM client: {e}")
    return _xsiam_client


def _format_epoch_ms(epoch_ms) -> str:
    try:
        ts = int(epoch_ms) / 1000
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(_ET)
        hour = dt.strftime("%I").lstrip("0") or "12"
        return dt.strftime(f"%m/%d/%Y {hour}:%M %p %Z")
    except (ValueError, OSError, TypeError):
        return "Unknown"


@tool
@log_tool_call
def list_xsiam_incidents(
    hours_back: int = 24, status: str = "", limit: int = 10
) -> str:
    """List Palo Alto Cortex XSIAM cases (also called incidents in the API).

    USE THIS TOOL when the user asks for:
    - "XSIAM cases", "XDR cases", "Cortex cases", "Cortex XDR cases"
    - "XSIAM incidents", "XDR incidents", "Cortex incidents" (API-side terminology)
    - "Palo Alto incidents/cases", "new cases", "recent XDR/XSIAM cases"

    NOTE: The XSIAM UI calls these "cases", but the API still calls them "incidents".
    Both terms refer to the same thing — use this tool for either word.

    Do NOT use CrowdStrike tools for "XDR" requests. CrowdStrike is an EDR platform —
    use CS tools only when the user explicitly says "CrowdStrike", "CS", or "Falcon".
    Do NOT use QRadar offense tools here — QRadar is the SIEM offense system, not XDR.

    Returns case id (as a clickable link), description, severity, status, issue count, and creation time.

    Args:
        hours_back: Look-back window in hours (default 24, 0 = no time filter, max 720)
        status: Optional XSIAM status filter (e.g., "new", "under_investigation", "resolved_*")
        limit: Max incidents to return (default 10, max 100)
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    hours_back = max(0, min(hours_back, 720))
    limit = max(1, min(limit, 100))

    result = client.get_incidents(
        hours=hours_back if hours_back > 0 else None,
        status=status.strip() or None,
        limit=limit,
    )
    if "error" in result:
        return f"Error: {result['error']}"

    reply = result.get("reply", {}) if isinstance(result, dict) else {}
    incidents = reply.get("incidents", [])
    total_count = reply.get("total_count", len(incidents))

    if not incidents:
        time_note = f" in the last {hours_back}h" if hours_back > 0 else ""
        status_note = f" (status={status})" if status else ""
        return f"No XSIAM cases found{status_note}{time_note}."

    out = [
        "## XSIAM Cases",
        f"**Window:** last {hours_back}h" if hours_back else "**Window:** all",
        f"**Count:** {len(incidents)} of {total_count}",
        "",
    ]
    for inc in incidents:
        case_id = inc.get("incident_id", "Unknown")
        url = client.case_url(case_id)
        heading = f"Case [#{case_id}]({url})" if url else f"Case #{case_id}"
        out.append(
            "\n".join(
                [
                    f"### {heading}",
                    f"**Description:** {inc.get('description', 'N/A')}",
                    f"**Severity:** {inc.get('severity', 'Unknown')} | **Status:** {inc.get('status', 'Unknown')}",
                    f"**Issues:** {inc.get('alert_count', 0)} | **Hosts:** {len(inc.get('hosts') or [])}",
                    f"**Created:** {_format_epoch_ms(inc.get('creation_time'))}",
                ]
            )
        )
    return "\n\n".join(out)


@tool
@log_tool_call
def get_xsiam_incident(incident_id: str, alerts_limit: int = 25) -> str:
    """Get details for a specific Cortex XSIAM case (a.k.a. incident in the API), including related issues and key artifacts.

    USE THIS TOOL when the user mentions a specific case/incident ID in the context of:
    - "XSIAM case <id>", "XDR case <id>", "Cortex case <id>"
    - "XSIAM incident <id>", "XDR incident <id>" (API terminology, same thing)
    - The user wants the issues/artifacts for a specific Palo Alto case

    Do NOT use this for CrowdStrike incidents (those have a different ID format and use CS tools).

    Args:
        incident_id: The XSIAM incident ID
        alerts_limit: Max related alerts to include (default 25, max 100)
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    alerts_limit = max(1, min(alerts_limit, 100))
    result = client.get_incident_extra_data(str(incident_id).strip(), alerts_limit=alerts_limit)
    if "error" in result:
        return f"Error: {result['error']}"

    reply = result.get("reply", {}) if isinstance(result, dict) else {}
    inc = reply.get("incident", {})
    alerts = reply.get("alerts", {}).get("data", []) if isinstance(reply.get("alerts"), dict) else []
    artifacts = reply.get("file_artifacts", {}).get("data", []) if isinstance(reply.get("file_artifacts"), dict) else []
    net_artifacts = reply.get("network_artifacts", {}).get("data", []) if isinstance(reply.get("network_artifacts"), dict) else []

    if not inc:
        return f"No XSIAM case found for id `{incident_id}`."

    case_id = inc.get("incident_id", incident_id)
    url = client.case_url(case_id)
    title = f"XSIAM Case [#{case_id}]({url})" if url else f"XSIAM Case #{case_id}"

    out = [
        f"## {title}",
        f"**Description:** {inc.get('description', 'N/A')}",
        f"**Severity:** {inc.get('severity', 'Unknown')} | **Status:** {inc.get('status', 'Unknown')}",
        f"**Assigned:** {inc.get('assigned_user_pretty_name') or inc.get('assigned_user_mail') or 'Unassigned'}",
        f"**Created:** {_format_epoch_ms(inc.get('creation_time'))}",
        f"**Issues:** {inc.get('alert_count', len(alerts))} | **Hosts:** {len(inc.get('hosts') or [])} | **Users:** {len(inc.get('users') or [])}",
    ]

    if alerts:
        out.append("\n### Related Issues")
        for a in alerts[:10]:
            out.append(
                f"- **{a.get('name', 'Unknown')}** | sev={a.get('severity', '?')} | "
                f"src={a.get('source', '?')} | host={a.get('host_name', '?')} | "
                f"action={a.get('action', '?')}"
            )
        if len(alerts) > 10:
            out.append(f"- *... and {len(alerts) - 10} more issues*")

    if net_artifacts:
        out.append("\n### Network Artifacts")
        for n in net_artifacts[:10]:
            out.append(
                f"- {n.get('network_domain') or n.get('network_remote_ip') or 'unknown'} "
                f"({n.get('type', '?')})"
            )

    if artifacts:
        out.append("\n### File Artifacts")
        for f in artifacts[:10]:
            out.append(
                f"- `{f.get('file_name', 'unknown')}` "
                f"(sha256={(f.get('file_sha256') or '')[:16]}...)"
            )

    return "\n".join(out)


@tool
@log_tool_call
def update_xsiam_incident(
    incident_id: str,
    status: str = "",
    assigned_user_mail: str = "",
    severity: str = "",
    resolve_comment: str = "",
) -> str:
    """Update fields on a Cortex XSIAM case (a.k.a. incident in the API). Pass only the fields you want to change.

    Use this tool when the user explicitly asks to change a case's status,
    assignee, severity, or add a resolve comment. Accept either "case" or "incident"
    in the user's request — both refer to the same XSIAM object.

    Args:
        incident_id: The XSIAM case/incident ID
        status: New status (e.g., "new", "under_investigation", "resolved_true_positive",
                "resolved_false_positive", "resolved_known_issue", "resolved_duplicate",
                "resolved_security_testing", "resolved_other")
        assigned_user_mail: Email of the user to assign
        severity: New severity ("informational", "low", "medium", "high", "critical")
        resolve_comment: Comment when resolving
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    if not any([status, assigned_user_mail, severity, resolve_comment]):
        return "Error: Provide at least one field to update."

    result = client.update_incident(
        str(incident_id).strip(),
        status=status.strip() or None,
        assigned_user_mail=assigned_user_mail.strip() or None,
        severity=severity.strip() or None,
        resolve_comment=resolve_comment.strip() or None,
    )
    if "error" in result:
        return f"Error: {result['error']}"
    url = client.case_url(incident_id)
    label = f"[#{incident_id}]({url})" if url else f"#{incident_id}"
    return f"XSIAM case {label} updated."


@tool
@log_tool_call
def list_xsiam_alerts(hours_back: int = 24, severity: str = "", limit: int = 25) -> str:
    """List Cortex XSIAM issues (a.k.a. alerts in the API — multi-event detection alerts).

    USE THIS TOOL when the user asks for:
    - "XSIAM issues", "XDR issues", "Cortex issues" (XSIAM UI terminology)
    - "XSIAM alerts", "XDR alerts", "Cortex alerts" (API terminology, same thing)
    - Raw Palo Alto detection issues rather than the grouped case view

    NOTE: The XSIAM UI calls these "issues", but the API still calls them "alerts".
    Both terms refer to the same thing — use this tool for either word.

    Do NOT use CrowdStrike detection tools for "XDR issues/alerts" — CrowdStrike is EDR.
    Use CS tools only when the user explicitly says "CrowdStrike", "CS", or "Falcon".

    Args:
        hours_back: Look-back window in hours (default 24, 0 = no filter, max 720)
        severity: Optional severity filter ("informational", "low", "medium", "high", "critical")
        limit: Max alerts to return (default 25, max 100)
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    hours_back = max(0, min(hours_back, 720))
    limit = max(1, min(limit, 100))

    result = client.get_alerts(
        hours=hours_back if hours_back > 0 else None,
        severity=severity.strip() or None,
        limit=limit,
    )
    if "error" in result:
        return f"Error: {result['error']}"

    reply = result.get("reply", {}) if isinstance(result, dict) else {}
    alerts = reply.get("alerts", [])
    total_count = reply.get("total_count", len(alerts))

    if not alerts:
        return f"No XSIAM issues found in the last {hours_back}h."

    out = [
        "## XSIAM Issues",
        f"**Window:** last {hours_back}h | **Count:** {len(alerts)} of {total_count}",
        "",
    ]
    for a in alerts:
        out.append(
            "\n".join(
                [
                    f"### {a.get('name', 'Unknown alert')}",
                    f"**Severity:** {a.get('severity', '?')} | **Source:** {a.get('source', '?')}",
                    f"**Host:** {a.get('host_name', '?')} | **User:** {a.get('user_name', '?')}",
                    f"**Action:** {a.get('action', '?')} | **Category:** {a.get('category', '?')}",
                    f"**Time:** {_format_epoch_ms(a.get('detection_timestamp') or a.get('creation_time'))}",
                ]
            )
        )
    return "\n\n".join(out)


@tool
@log_tool_call
def get_xsiam_endpoint_by_hostname(hostname: str) -> str:
    """Look up a Cortex XSIAM endpoint by hostname.

    Returns endpoint id, OS, last-seen time, isolation status, and IP list.

    Args:
        hostname: Endpoint hostname (e.g., "DESKTOP-ABC123")
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    result = client.get_endpoint(hostname=hostname.strip())
    return _format_endpoint_result(result, key=f"hostname={hostname}")


@tool
@validate_args(ip=IP_ADDRESS_PATTERN)
@log_tool_call
def get_xsiam_endpoint_by_ip(ip: str) -> str:
    """Look up a Cortex XSIAM endpoint by IP address.

    Args:
        ip: IPv4 address
    """
    client = _get_client()
    if not client:
        return "Error: XSIAM service is not available."

    result = client.get_endpoint(ip=ip.strip())
    return _format_endpoint_result(result, key=f"ip={ip}")


def _format_endpoint_result(result: dict, key: str) -> str:
    if "error" in result:
        return f"Error: {result['error']}"
    reply = result.get("reply") if isinstance(result, dict) else None
    endpoints = reply if isinstance(reply, list) else (reply or {}).get("endpoints", [])
    if not endpoints:
        return f"No XSIAM endpoint found for {key}."

    out = [f"## XSIAM Endpoint Lookup ({key})", f"**Matches:** {len(endpoints)}", ""]
    for ep in endpoints[:5]:
        out.append(
            "\n".join(
                [
                    f"### {ep.get('endpoint_name', 'Unknown')}",
                    f"**ID:** `{ep.get('endpoint_id', '?')}`",
                    f"**OS:** {ep.get('os_type', '?')} {ep.get('os_version', '')}",
                    f"**Status:** {ep.get('endpoint_status', '?')} | "
                    f"**Isolation:** {ep.get('is_isolated', '?')}",
                    f"**Users:** {', '.join(ep.get('users') or []) or '?'}",
                    f"**IPs:** {', '.join(ep.get('ip', []) or []) or '?'}",
                    f"**Last seen:** {_format_epoch_ms(ep.get('last_seen'))}",
                ]
            )
        )
    if len(endpoints) > 5:
        out.append(f"\n*... and {len(endpoints) - 5} more matches*")
    return "\n\n".join(out)
