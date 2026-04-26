"""Adaptive cards for XSOAR Alert Triage."""

import re
from urllib.parse import quote


def _verdict_display(verdict: str) -> str:
    """Human-readable verdict label."""
    return {
        "true_positive_malicious": "Malicious True Positive",
        "true_positive_malicious_contained": "Malicious True Positive (Contained)",
        "true_positive_benign": "Benign True Positive",
        "false_positive": "False Positive",
    }.get(verdict, verdict)


def _format_percentage(value: float) -> str:
    return f"{value:.0%}" if value else "N/A"


def _severity_emoji(severity: str) -> str:
    """Map severity to an emoji indicator."""
    return {
        "Critical": "\U0001F534",  # red circle
        "High": "\U0001F7E0",      # orange circle
        "Medium": "\U0001F7E1",    # yellow circle
        "Low": "\U0001F7E2",       # green circle
        "Info": "\u2B55",          # hollow circle
    }.get(severity, "\u26AA")       # white circle


def _verdict_emoji(verdict: str) -> str:
    """Map verdict to an emoji."""
    if "malicious" in verdict:
        return "\U0001F6A8"  # rotating light
    if "benign" in verdict:
        return "\U0001F7E1"  # yellow circle
    if "false" in verdict:
        return "\u2705"      # green check
    return "\U0001F914"      # thinking face


def _build_qradar_search_url(
    hostname: str = "",
    username: str = "",
    hours: int = 4,
    ips: list = None,
    domains: list = None,
) -> str:
    """Build a QRadar console URL that re-runs the same AQL search used in triage."""
    try:
        from my_config import get_config
        cfg = get_config()
        console_url = cfg.qradar_console_url
        if not console_url:
            api_url = (cfg.qradar_api_url or '').rstrip('/')
            console_url = api_url[:-4] if api_url.endswith('/api') else api_url
        if not console_url:
            return ""
        console_url = console_url.rstrip('/')

        conditions = []
        if hostname:
            conditions.append(f"\"Computer Hostname\" ILIKE '%{hostname}%'")
        elif username:
            conditions.append(f"username ILIKE '%{username}%'")
        else:
            if ips:
                ip_list = ", ".join(f"'{ip}'" for ip in ips[:10])
                conditions.append(f"(sourceip IN ({ip_list}) OR destinationip IN ({ip_list}))")
            if domains:
                domain_clauses = " OR ".join(f"URL ILIKE '%{d}%'" for d in domains[:5])
                conditions.append(f"({domain_clauses})")

        if not conditions:
            return ""

        where = " OR ".join(conditions)
        aql = (
            "SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time, "
            "sourceip, destinationip, qidname(qid) AS event_name, "
            "logsourcetypename(devicetype) AS log_source, magnitude, username, URL "
            f"FROM events WHERE ({where}) AND magnitude >= 3 "
            f"ORDER BY starttime DESC LIMIT 25 LAST {hours} HOURS"
        )
        return (
            f"{console_url}/console/do/ariel/arielSearch"
            f"?appName=EventViewer&pageId=EventList"
            f"&dispatch=performSearch&value={quote(aql)}"
        )
    except Exception:
        return ""


def _build_snow_search_url(hostname: str, table: str = "incident") -> str:
    """Build a ServiceNow URL to view incidents or changes for a host CI."""
    try:
        from my_config import get_config
        cfg = get_config()
        instance_url = (cfg.snow_instance_url or "").rstrip("/")
        if not instance_url or not hostname:
            return ""
        short = hostname.split('.')[0]
        target = "incident_list.do" if table == "incident" else "change_request_list.do"
        return (
            f"{instance_url}/now/nav/ui/classic/params/target/{target}"
            f"?sysparm_query=cmdb_ci.nameLIKE{short}"
        )
    except Exception:
        return ""


def build_xsoar_triage_markdown(result) -> str:
    """Build a markdown message with full XSOAR triage details.

    This is the first message in a two-part notification:
    1. This markdown message with all ticket details, AI verdict, and similar tickets
    2. A follow-up adaptive card reply with action buttons only

    Args:
        result: XsoarTriageResult dataclass instance

    Returns:
        Markdown string for Webex message
    """
    from src.utils.xsoar_helpers import build_incident_url
    xsoar_url = build_incident_url(result.ticket_id)

    # Format timestamp as AM/PM ET
    timestamp = result.ticket_timestamp
    if timestamp:
        try:
            from datetime import datetime as _dt
            from pytz import timezone as _tz
            raw = str(timestamp)[:19].replace("T", " ")
            dt = _dt.strptime(raw, "%Y-%m-%d %H:%M:%S")
            # Assume source is UTC, convert to ET
            utc = _tz("UTC").localize(dt)
            et = utc.astimezone(_tz("US/Eastern"))
            timestamp = et.strftime("%m/%d/%Y %I:%M:%S %p ET")
        except Exception:
            timestamp = str(timestamp)[:19]

    sev_icon = _severity_emoji(result.severity)

    # Header with ID and Name on separate rows
    lines = [
        f"\U0001F6E1\uFE0F **XSOAR TICKET TRIAGE**",
        "",
        f"\U0001F3AB **ID:** [#{result.ticket_id}]({xsoar_url})",
        f"\U0001F4CC **Name:** {result.ticket_name}",
        f"\U0001F4CB **Type:** `{result.ticket_type}`",
        f"\U0001F3F7\uFE0F **Category:** `{result.security_category}`",
        f"{sev_icon} **Severity:** `{result.severity}`",
        f"\U0001F50D **Source:** `{result.detection_source}`",
    ]

    # Source alert link (QRadar offense or CrowdStrike detection)
    source_details = (result.enrichment or {}).get("source_details")
    if source_details and "error" not in source_details:
        source_url = source_details.get("source_url", "")
        if source_details.get("source") == "qradar" and source_url:
            offense_id = source_details.get("offense_id", "")
            lines.append(f"\U0001F517 **QRadar Offense:** [{offense_id}]({source_url})")
        elif source_details.get("source") == "crowdstrike":
            link = source_details.get("falcon_host_link", "") or source_url
            cs_name = source_details.get("display_name", "View in Falcon")
            if link:
                lines.append(f"\U0001F517 **CS Detection:** [{cs_name}]({link})")

    lines.extend([
        f"\U0001F4BB **Host:** `{result.hostname or 'N/A'}`",
        f"\U0001F464 **User:** `{result.username or 'N/A'}`",
        f"\U0001F46E **Owner:** `{result.ticket_owner or 'Unassigned'}`",
        f"\U0001F552 **Time:** `{timestamp}`",
    ])

    # Time context (business hours, weekend, after hours)
    time_ctx = getattr(result, "time_context", "")
    if time_ctx and "business hours" not in time_ctx.lower():
        # Only surface when noteworthy (outside business hours, weekend, etc.)
        lines.append(f"\U0001F319 **Time Context:** `{time_ctx}`")

    # Asset context from Tanium
    asset = getattr(result, "asset_context", {}) or {}
    if asset:
        os_info = asset.get("os_platform", "")
        status = asset.get("eid_status", "")
        has_epp = asset.get("has_epp")
        tags = asset.get("custom_tags", [])
        asset_parts = []
        if os_info:
            asset_parts.append(os_info)
        if status:
            asset_parts.append(status)
        if has_epp is False:
            asset_parts.append("\u26A0\uFE0F No EPP")
        if tags:
            asset_parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
        if asset_parts:
            lines.append(f"\U0001F5A5\uFE0F **Asset:** `{' | '.join(asset_parts)}`")

    # Full details in a scrollable code block (no wrapping — Webex scrolls horizontally)
    # Cap at 1500 chars to stay within Webex's ~7400 byte message limit
    details = result.raw_ticket.get("details", "") or ""
    if details:
        details_text = str(details).strip()
        if details_text:
            # Collapse consecutive blank lines into single newlines
            details_text = re.sub(r'\n\s*\n', '\n', details_text)
            if len(details_text) > 1500:
                details_text = details_text[:1500] + "\n... (truncated)"
            lines.append(f"\U0001F4DD **Details:**")
            lines.append("```")
            lines.append(details_text)
            lines.append("```")

    # Repeat offender flag
    repeat_count = getattr(result, "repeat_offender_count", 0)
    if repeat_count > 1:
        who = result.username or result.hostname or "entity"
        lines.append(f"\U0001F6A9 **Repeat offender:** {who} triggered **{repeat_count}** alerts in the past 7 days")

    # Ticket age / SLA pressure
    if result.ticket_timestamp:
        try:
            from datetime import datetime as _dt2, timezone as _utc
            raw_ts = str(result.ticket_timestamp)[:19].replace("T", " ")
            created_dt = _dt2.strptime(raw_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_utc.utc)
            age_hours = (_dt2.now(_utc.utc) - created_dt).total_seconds() / 3600
            prediction_check = getattr(result, "similar_ticket_prediction", None)
            avg_h = prediction_check.avg_resolution_hours if prediction_check else None
            age_str = f"{age_hours:.1f}h"
            if avg_h:
                lines.append(f"\u23F1\uFE0F **Open:** `{age_str}` (similar tickets avg `{avg_h:.1f}h`)")
            else:
                lines.append(f"\u23F1\uFE0F **Open:** `{age_str}`")
        except Exception:
            pass

    # ServiceNow change tickets for this host
    snow = getattr(result, "snow_context", {}) or {}
    changes = snow.get("changes", [])
    if changes:
        snow_chg_url = _build_snow_search_url(getattr(result, "hostname", ""), table="change_request")
        chg_header = f"[Active Change Tickets ({len(changes)})]({snow_chg_url})" if snow_chg_url else f"Active Change Tickets ({len(changes)})"
        lines.append(f"\U0001F7E2 **{chg_header}**")
        for chg in changes[:3]:
            num = chg.get("number", "?")
            desc = (chg.get("short_description", "") or "")[:80]
            state = chg.get("state", "")
            start = (chg.get("planned_start", "") or "")[:16].replace("T", " ")
            end = (chg.get("planned_end", "") or "")[:16].replace("T", " ")
            window = f"`{start}` → `{end}`" if start and end else ""
            lines.append(f"  - **{num}** `{state}` {window} — {desc}")
        lines.append("")

    lines.append("---")

    # What Happened / Why is this a concern
    what_happened = getattr(result, "llm_what_happened", "")
    why_concern = getattr(result, "llm_why_concern", "")
    if what_happened:
        lines.append(f"\U0001F4A5 **What Happened:** {what_happened}")
        lines.append("")
    if why_concern:
        lines.append(f"\u26A0\uFE0F **Why This Is a Concern:** {why_concern}")
        lines.append("")

    # Priority score — color-coded by urgency
    priority = getattr(result, "priority_score", 0)
    if priority:
        if priority >= 7:
            p_emoji = "\U0001F534\U0001F534\U0001F534"
            p_label = "CRITICAL"
        elif priority >= 4:
            p_emoji = "\U0001F7E0\U0001F7E0"
            p_label = "MEDIUM"
        else:
            p_emoji = "\U0001F7E2"
            p_label = "LOW"
        lines.append(f"> {p_emoji} **Priority: {priority}/10 — {p_label}**")
        lines.append("")

    # AI Verdict — color-coded emoji + confidence, blockquote accent
    verdict_label = _verdict_display(result.llm_verdict)
    confidence = _format_percentage(result.llm_confidence)
    if result.llm_verdict == "true_positive_malicious_contained":
        v_prefix = "\U0001F534\U0001F6E1\uFE0F"  # red circle + shield (contained threat)
    elif "malicious" in result.llm_verdict:
        v_prefix = "\U0001F534\U0001F6A8"  # red circle + siren
    elif "benign" in result.llm_verdict:
        v_prefix = "\U0001F7E1\U0001F7E1"  # yellow circles
    else:
        v_prefix = "\U0001F7E2\u2705"      # green circle + check
    lines.append(f"**AI Verdict:**")
    lines.append(f"> {v_prefix} {verdict_label} \u2014 {confidence}")

    # Show intent + outcome when available (v2 triage) so analysts see the reasoning
    if getattr(result, "llm_intent", "") and getattr(result, "llm_outcome", ""):
        lines.append(f"> \u2937\uFE0F intent: **{result.llm_intent}** \u00B7 outcome: **{result.llm_outcome}**")
    lines.append("")

    # Verdict disagreement flag — highly visible when AI contradicts history
    if getattr(result, "verdict_conflicts_history", False):
        conflict_detail = getattr(result, "verdict_conflict_detail", "")
        lines.append(f"\u26A0\uFE0F **AI verdict conflicts with historical pattern** \u2014 {conflict_detail}")
        lines.append("")

    # Evidence basis — what the verdict is grounded in
    evidence = getattr(result, "evidence_basis", "")
    if evidence:
        if "description-only" in evidence.lower():
            lines.append(f"\U0001F4CA **Evidence basis:** \u26A0\uFE0F {evidence}")
        else:
            lines.append(f"\U0001F4CA **Evidence basis:** {evidence}")
        lines.append("")

    # Recommended action
    action = getattr(result, "llm_recommended_action", "")
    action_detail = getattr(result, "llm_recommended_action_detail", "")
    if action:
        action_emoji = {
            "close_ticket": "\u2705",
            "escalate": "\U0001F6A8",
            "investigate": "\U0001F50D",
        }.get(action, "\u27A1\uFE0F")
        if action_detail:
            # Ensure each numbered step gets its own line
            formatted_detail = re.sub(r'(\d+)\.\s', r'\n\1. ', action_detail).strip()
            lines.append(f"**Next Steps:** {action_emoji} {formatted_detail}")
        else:
            action_label = {
                "close_ticket": "Close Ticket",
                "escalate": "Escalate",
                "investigate": "Investigate",
            }.get(action, action)
            lines.append(f"**Next Steps:** {action_emoji} {action_label}")
        lines.append("")

    # Auto-close candidate flag — only for benign/FP verdicts, never for malicious
    prediction = getattr(result, "similar_ticket_prediction", None)
    is_benign_verdict = result.llm_verdict in ("false_positive", "true_positive_benign")
    is_autoclose = (
        is_benign_verdict
        and result.llm_confidence >= 0.85
        and prediction and prediction.sample_size >= 3
        and _is_all_ignored_or_fp(prediction)
    )
    if is_autoclose:
        lines.append(f"\U0001F7E2 **High-confidence auto-close candidate** \u2014 {prediction.sample_size}/{prediction.sample_size} similar tickets were closed")
        lines.append("")

    lines.append(f"> {result.llm_summary}")
    lines.append("")

    # Enrichment highlights
    enrichment = getattr(result, "enrichment", {}) or {}
    enrichment_lines = _build_enrichment_highlights(enrichment)
    if enrichment_lines:
        lines.append("\U0001F9EA **Enrichment Highlights**")
        lines.extend(enrichment_lines)
        lines.append("")

    # Entity intel from all enrichment sources
    entity_intel_lines = _build_entity_intel_section(result)
    if entity_intel_lines:
        lines.append("\U0001F50E **Entity Intel**")
        lines.extend(entity_intel_lines)
        lines.append("")

    # IOC cross-correlation (campaign detection)
    ioc_correlated = getattr(result, "ioc_correlated_tickets", [])
    if ioc_correlated:
        lines.append(f"\U0001F6A8 **IOC Cross-Correlation** \u2014 same IOCs found in **{len(ioc_correlated)}** other recent tickets:")
        for ct in ioc_correlated[:5]:
            ct_id = ct.get("id", "?")
            ct_name = (ct.get("name", "?") or "?")[:50]
            ct_host = ct.get("hostname", "") or "N/A"
            ct_created = (str(ct.get("created_date", "")) or "")[:10]
            ct_id_part = f"[#{ct_id}]({build_incident_url(ct_id)})" if ct_id != "?" else f"#{ct_id}"
            lines.append(f"  - {ct_id_part} \u00b7 host=`{ct_host}` \u00b7 {ct_created} \u2014 {ct_name}")
        lines.append("")

    # Risk / Mitigating factors
    lines.append("\U0001F525 **Risk Factors**")
    if result.llm_risk_factors:
        for f in result.llm_risk_factors[:5]:
            lines.append(f"  - \u26A0\uFE0F {f}")
    else:
        lines.append("  - _(none)_")
    lines.append("")

    lines.append("\U0001F6E1\uFE0F **Mitigating Factors**")
    if result.llm_mitigating_factors:
        for f in result.llm_mitigating_factors[:5]:
            lines.append(f"  - \u2705 {f}")
    else:
        lines.append("  - _(none)_")
    lines.append("")

    # Similar ticket prediction
    if prediction and prediction.sample_size > 0:
        cold = " \u26A0\uFE0F _cold start_" if prediction.is_cold_start else ""
        lines.append("---")
        lines.append(f"\U0001F52E **Similar Tickets** ({prediction.sample_size}){cold}")

        # Consensus summary
        top_reasons = prediction.top_close_reasons
        if top_reasons:
            top_reason = max(top_reasons, key=top_reasons.get)
            top_pct = top_reasons[top_reason] / prediction.sample_size
            avg_h = prediction.avg_resolution_hours
            avg_str = f", avg resolution `{avg_h:.1f}h`" if avg_h else ""
            # Truncate long close reasons (some have full analyst notes in the field)
            reason_display = (top_reason[:60] + "...") if len(top_reason) > 60 else top_reason
            lines.append(f"> {top_reasons[top_reason]}/{prediction.sample_size} were **{reason_display}**{avg_str}")
        lines.append("")

        for ticket in prediction.similar_tickets[:5]:
            meta = ticket.get("metadata", {})
            ticket_id = meta.get("id", "")
            name = meta.get("name", "Unknown")[:60]
            sim_pct = f"{ticket.get('similarity_score', 0):.0%}"
            raw_impact = meta.get("impact", "") or meta.get("close_reason", "") or "N/A"
            impact = (raw_impact[:40] + "...") if len(raw_impact) > 40 else raw_impact
            res_h = meta.get("resolution_hours", 0)
            res_str = f"{res_h:.0f}h" if res_h else "N/A"
            created = (meta.get("created_date", "") or "")[:10]
            owner = (meta.get("owner", "") or "").split("@")[0]
            # Multi-dimensional match badges
            badge_str = _format_similarity_badges(ticket)
            # Fixed-width columns first, variable name last
            id_part = f"[#{ticket_id}]({build_incident_url(ticket_id)})" if ticket_id else f"#{ticket_id}"
            lines.append(f"  - {id_part} `{sim_pct}`{badge_str} \u00b7 **{impact}** \u00b7 `{res_str}` \u00b7 {created} \u00b7 {owner} \u2014 {name}")

    # Tuning recommendation (noise reduction)
    tuning = getattr(result, "tuning_recommendation", "")
    if tuning:
        lines.append("---")
        lines.append(f"\U0001F507 **Tuning Recommendation**")
        lines.append(f"> {tuning}")

    return "\n".join(lines)


def build_xsoar_triage_note(result) -> str:
    """Build the long-form triage note posted into the XSOAR ticket war room.

    This is a SUPERSET of build_xsoar_triage_markdown(): it contains
    everything the Webex markdown contains (so an analyst opening the ticket
    sees the same overview the Sentinel room sees), plus additional
    structured enrichment sections that don't fit in Webex's character
    budget. As more enrichment is added (Gap 2-7 in the AI Sentinel triage
    plan — baselines, process-tree correlation, host context, dual-use
    tools, investigation pivots), each new section is appended here.

    The Webex side keeps calling build_xsoar_triage_markdown() unchanged.

    Args:
        result: XsoarTriageResult dataclass instance

    Returns:
        Markdown string for the XSOAR /xsoar/entry/note write
    """
    parts = [build_xsoar_triage_markdown(result)]

    # Smoking-gun facts (Gap 1) — pulled from the source CrowdStrike payload
    sg_lines = _build_smoking_gun_facts_section(result)
    if sg_lines:
        parts.append("")
        parts.append("---")
        parts.extend(sg_lines)

    # CS baseline (Gap 2) — has this user/host done this before? Behavior
    # delta context, distinct from smoking-gun facts (which are about the
    # current alert). Lives at source_details['cs_baseline'], not under
    # smoking_gun_facts, so render it as its own section.
    baseline_lines = _build_cs_baseline_section(result)
    if baseline_lines:
        parts.append("")
        parts.append("---")
        parts.extend(baseline_lines)

    # CS process-tree correlation (Gap 3) — other host detections in +/- 2h
    # that share a process tree / graph / aggregate / incident lead with
    # this anchor. Surfaces the rest of the chain so the analyst sees the
    # full incident play-out without pivoting into Falcon.
    tree_lines = _build_cs_process_tree_section(result)
    if tree_lines:
        parts.append("")
        parts.append("---")
        parts.extend(tree_lines)

    # CS lateral-movement target host context (Gap 4) — outbound private-IP
    # destinations from the anchor + linked chain resolved to CS host
    # metadata. Pivots "outbound to 10.x.x.x:5985" to "Production server
    # SZWBT134AHA in JP-Tokyo OU."
    lateral_lines = _build_cs_lateral_targets_section(result)
    if lateral_lines:
        parts.append("")
        parts.append("---")
        parts.extend(lateral_lines)

    # IOC threat-intel checks (Gap 5b) — anchor + chain hashes / public
    # IPs / DNS domains looked up in the local tipper TI store. Hits =
    # this exact IOC has been triaged in a prior tipper; zero hits across
    # many checked IOCs is a meaningful FP-leaning datapoint.
    ioc_ti_lines = _build_cs_ioc_ti_section(result)
    if ioc_ti_lines:
        parts.append("")
        parts.append("---")
        parts.extend(ioc_ti_lines)

    # Cross-source correlation (Gap 7) — open QRadar offenses on the
    # same host/user/lateral-targets as the CS anchor. Tells the analyst
    # whether a SIEM rule independently corroborates the EDR signal, or
    # whether this is single-source noise.
    xs_lines = _build_cross_source_section(result)
    if xs_lines:
        parts.append("")
        parts.append("---")
        parts.extend(xs_lines)

    # Tool trace — what the LLM actually ran during triage. Surfaces the
    # evidence trail (SNOW / QRadar / Vectra / AD / IOC lookups) so the
    # analyst can see what was already checked.
    tool_trace_lines = _build_tool_trace_section(result)
    if tool_trace_lines:
        parts.append("")
        parts.append("---")
        parts.extend(tool_trace_lines)

    # Verifier critique — only rendered when the critic flagged something.
    # Shown right after the tool trace so the analyst can see "what the AI
    # checked" and "what another LLM thought it missed" side-by-side.
    critique_lines = _build_critique_section(result)
    if critique_lines:
        parts.append("")
        parts.append("---")
        parts.extend(critique_lines)

    # Investigation pivots — residual human-only questions (tool-surface
    # gaps: contact user, review custom script, physical verification).
    # Placed last so the analyst sees a clear "where to start" list right
    # above their workspace.
    pivot_lines = _build_investigation_pivots_section(result)
    if pivot_lines:
        parts.append("")
        parts.append("---")
        parts.extend(pivot_lines)

    return "\n".join(parts)


def _build_smoking_gun_facts_section(result) -> list:
    """Render the structured CS smoking-gun facts as a markdown section.

    Returns an empty list if the source isn't CrowdStrike or the smoking-gun
    facts dict is missing — keeps the note clean for non-CS sources.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    sg = source.get("smoking_gun_facts") or {}
    if not sg:
        return []

    lines = ["\U0001F50D **Smoking-gun facts** _(extracted from the CrowdStrike alert payload)_", ""]

    # Process tree as ASCII chain + per-process detail
    tree = sg.get("process_tree") or []
    if tree:
        chain = " \u2192 ".join(f"`{p.get('filename') or '?'}`" for p in tree)
        lines.append(f"**Process tree:** {chain}")
        lines.append("")
        for p in tree:
            label = p.get("level", "")
            fn = p.get("filename", "?")
            cmd = (p.get("cmdline", "") or "").strip()
            user = p.get("user_name", "")
            sha = p.get("sha256", "")
            lines.append(f"- **{label}** \u2014 `{fn}`")
            if cmd:
                # Code-fenced so long cmdlines wrap reasonably
                lines.append(f"    - cmd: `{cmd[:200]}`")
            if user:
                lines.append(f"    - user: `{user}`")
            if sha and sha != "0" * 64:
                lines.append(f"    - sha256: `{sha}`")
        lines.append("")

    # Files accessed from non-standard paths (the loaded-modules smoking gun)
    faof = sg.get("files_accessed_of_interest") or []
    fa_total = sg.get("files_accessed_total", 0)
    if faof:
        lines.append(
            f"**Files accessed from non-standard paths** \u2014 "
            f"{len(faof)} flagged of {fa_total} total:"
        )
        for f in faof:
            fn = f.get("filename", "?")
            fp = f.get("filepath", "")
            lines.append(f"- \u26A0\uFE0F `{fn}` \u2014 `{fp}`")
        lines.append("")
    elif fa_total:
        lines.append(
            f"**Files accessed:** {fa_total} total, _none from non-standard paths_"
        )
        lines.append("")

    # Files written to non-standard paths (the dropper signal)
    fwof = sg.get("files_written_of_interest") or []
    fw_total = sg.get("files_written_total", 0)
    if fwof:
        lines.append(
            f"**Files written to non-standard paths** \u2014 "
            f"{len(fwof)} flagged of {fw_total} total:"
        )
        for f in fwof:
            fn = f.get("filename", "?")
            fp = f.get("filepath", "")
            lines.append(f"- \u26A0\uFE0F `{fn}` \u2014 `{fp}`")
        lines.append("")
    elif fw_total:
        lines.append(
            f"**Files written:** {fw_total} total, _none to non-standard paths_"
        )
        lines.append("")

    # DNS requests — high-signal domain context
    dns = sg.get("dns_requests") or []
    dns_total = sg.get("dns_requests_total", 0)
    if dns:
        lines.append(
            f"**DNS requests** ({len(dns)} unique domains, {dns_total} total queries):"
        )
        for d in dns:
            lines.append(f"- `{d}`")
        lines.append("")

    # Network accesses
    nets = sg.get("network_accesses") or []
    net_total = sg.get("network_accesses_total", 0)
    if nets:
        lines.append(f"**Network accesses** ({len(nets)} of {net_total} shown):")
        for n in nets:
            direction = n.get("direction", "")
            proto = n.get("protocol", "")
            local = f"{n.get('local_address', '?')}:{n.get('local_port', '?')}"
            remote = f"{n.get('remote_address', '?')}:{n.get('remote_port', '?')}"
            lines.append(f"- {direction} {proto} `{local}` \u2192 `{remote}`")
        lines.append("")

    # Quarantined files
    qf = sg.get("quarantined_files") or []
    if qf:
        lines.append(f"**Quarantined files** ({len(qf)}):")
        for q in qf:
            lines.append(f"- `{q.get('filename', '?')}` \u2014 state=`{q.get('state', '')}`")
        lines.append("")

    # Pattern disposition (was anything actually blocked?)
    disp = sg.get("pattern_disposition", "")
    blocked = sg.get("pattern_disposition_blocked", False)
    if disp:
        if blocked:
            action_label = "\U0001F6E1\uFE0F BLOCKED / PREVENTED"
        else:
            action_label = "\U0001F441\uFE0F OBSERVATION ONLY (no block taken)"
        lines.append(f"**Pattern disposition:** {disp} \u2014 {action_label}")
        lines.append("")

    # Prevalence — rare binaries are much more interesting than common ones
    prev = sg.get("prevalence") or {}
    local_prev = prev.get("local", "")
    global_prev = prev.get("global", "")
    if local_prev or global_prev:
        lines.append(
            f"**Prevalence:** local = `{local_prev or 'unknown'}` \u00b7 "
            f"global = `{global_prev or 'unknown'}`"
        )
        lines.append("")

    # Structured MITRE list — multiple techniques per detection
    mitre_list = sg.get("mitre_attack") or []
    if len(mitre_list) > 1:
        lines.append(f"**Additional MITRE techniques on this detection** ({len(mitre_list)}):")
        for m in mitre_list:
            pid = m.get("pattern_id", "")
            tac = m.get("tactic", "")
            tac_id = m.get("tactic_id", "")
            tech = m.get("technique", "")
            tech_id = m.get("technique_id", "")
            lines.append(
                f"- Pattern `{pid}`: {tac} (`{tac_id}`) / {tech} (`{tech_id}`)"
            )
        lines.append("")

    # Dual-use security/research tools detected in the file paths / cmdlines.
    # This puts a NAME on tools the analyst would otherwise have to recognize
    # from a folder path. Name recognition is the foothold, not the verdict.
    dual_use = sg.get("dual_use_tools_detected") or []
    if dual_use:
        lines.append(
            f"\U0001F9F0 **Dual-use tools identified** ({len(dual_use)})"
        )
        lines.append(
            "_Well-known security / research tools matched against file paths and "
            "cmdlines. Many have legitimate uses — name recognition is the foothold, "
            "not the verdict._"
        )
        lines.append("")
        for tool in dual_use:
            name = tool.get("name", "?")
            author = tool.get("author", "")
            cat = tool.get("category", "")
            cat_emoji = {
                "research": "\U0001F52C",     # microscope
                "recon": "\U0001F50D",        # magnifying glass
                "credential": "\U0001F511",   # key
                "lateral": "\u27A1\uFE0F",    # right arrow
                "c2": "\U0001F4E1",           # satellite antenna
                "network": "\U0001F310",      # globe
                "pivot": "\U0001F501",        # repeat
            }.get(cat, "\u2699\uFE0F")        # gear
            lines.append(f"- {cat_emoji} **{name}** _(category: {cat}, by {author})_")
            legit = tool.get("legitimate_use", "")
            if legit:
                lines.append(f"    - **Legitimate use:** {legit}")
            abuse = tool.get("common_abuse", "")
            if abuse:
                lines.append(f"    - **Common abuse:** {abuse}")
            nxt = tool.get("if_malicious_next", "")
            if nxt:
                lines.append(f"    - **If malicious, look at next:** {nxt}")
            ev = tool.get("evidence", []) or []
            if ev:
                lines.append(f"    - **Evidence:**")
                for e in ev[:5]:
                    lines.append(f"        - `{e}`")
        lines.append("")

    return lines


def _build_cs_baseline_section(result) -> list:
    """Render CS baseline (per-user/per-pattern + recent-by-user/host) as
    a markdown section in the XSOAR ticket note.

    Returns an empty list if the source isn't CrowdStrike or the baseline
    dict is missing — keeps the note clean for non-CS sources. Each
    sub-query (user_pattern / user_recent / host_recent) renders
    independently so a partial failure still shows the rest.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    baseline = source.get("cs_baseline") or {}
    if not baseline or "error" in baseline:
        return []

    user_lbl = baseline.get("user_name", "") or "?"
    host_lbl = baseline.get("hostname", "") or "?"
    pid_lbl = baseline.get("pattern_id", "") or "?"

    lines = [
        "\U0001F4CA **CS baseline** _(behavior delta — has this user or host done this before?)_",
        "",
    ]

    # ---- 1. User x pattern intersection (the headline number) ----
    up = baseline.get("user_pattern") or {}
    if up:
        lookback = up.get("lookback_days", 0)
        if "error" in up:
            lines.append(
                f"**User x pattern** \u2014 _query failed: {up['error']}_"
            )
        else:
            count = up.get("count", 0)
            trunc = "+" if up.get("truncated") else ""
            if count == 0:
                lines.append(
                    f"**User x pattern** \u2014 \u2728 `{user_lbl}` has "
                    f"**NEVER** triggered Pattern `{pid_lbl}` in the last "
                    f"{lookback}d. _This is the first occurrence._"
                )
            else:
                last_days = up.get("last_seen_days_ago")
                last_str = f", last seen **{last_days}d ago**" if last_days is not None else ""
                first_seen = (up.get("first_seen") or "")[:10]
                first_str = f" (first seen `{first_seen}`)" if first_seen else ""
                lines.append(
                    f"**User x pattern** \u2014 \U0001F501 `{user_lbl}` has "
                    f"triggered Pattern `{pid_lbl}` **{count}{trunc} time(s)** "
                    f"in the last {lookback}d{last_str}{first_str}. "
                    f"_Recurring behavior \u2014 weigh against intent._"
                )
        lines.append("")

    # ---- 2. User recent (other patterns from same user) ----
    ur = baseline.get("user_recent") or {}
    if ur:
        lookback = ur.get("lookback_days", 0)
        if "error" in ur:
            lines.append(
                f"**User recent** \u2014 _query failed: {ur['error']}_"
            )
        else:
            count = ur.get("count", 0)
            trunc = "+" if ur.get("truncated") else ""
            if count == 0:
                lines.append(
                    f"**User recent** \u2014 `{user_lbl}` has had **no other** "
                    f"CS detections in the last {lookback}d."
                )
            else:
                lines.append(
                    f"**User recent** \u2014 `{user_lbl}` has had "
                    f"**{count}{trunc}** other CS detection(s) in the last "
                    f"{lookback}d:"
                )
                for p in ur.get("top_patterns") or []:
                    pid = p.get("pattern_id", "?")
                    pname = p.get("name", "") or "?"
                    pcount = p.get("count", 0)
                    lines.append(f"- `{pid}` {pname} \u2014 {pcount}\u00d7")
        lines.append("")

    # ---- 3. Host recent (other patterns from same host) ----
    hr = baseline.get("host_recent") or {}
    if hr:
        lookback = hr.get("lookback_days", 0)
        if "error" in hr:
            lines.append(
                f"**Host recent** \u2014 _query failed: {hr['error']}_"
            )
        else:
            count = hr.get("count", 0)
            trunc = "+" if hr.get("truncated") else ""
            if count == 0:
                lines.append(
                    f"**Host recent** \u2014 `{host_lbl}` has had **no other** "
                    f"CS detections in the last {lookback}d."
                )
            else:
                lines.append(
                    f"**Host recent** \u2014 `{host_lbl}` has had "
                    f"**{count}{trunc}** other CS detection(s) in the last "
                    f"{lookback}d:"
                )
                for p in hr.get("top_patterns") or []:
                    pid = p.get("pattern_id", "?")
                    pname = p.get("name", "") or "?"
                    pcount = p.get("count", 0)
                    lines.append(f"- `{pid}` {pname} \u2014 {pcount}\u00d7")
        lines.append("")

    return lines


# Map linkage labels to short, scannable display strings used in the
# ticket-note timeline. Order is irrelevant -- the lookup is by key.
_LINKAGE_DISPLAY = {
    "same_tree": "same tree",
    "same_process_graph": "same process graph",
    "same_aggregate": "same aggregate",
    "same_lead": "same incident lead",
    "time_adjacent": "time-adjacent",
}


def _build_cs_process_tree_section(result) -> list:
    """Render the CS process-tree correlation as a markdown timeline.

    The linked chain (graph/lead-linked siblings) is the headline -- those
    detections are very likely the same incident playing out in stages.
    Time-adjacent siblings are shown after as a weaker secondary signal.
    Returns an empty list if the source isn't CrowdStrike or no correlation
    data is present.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    ptc = source.get("cs_process_tree") or {}
    if not ptc or "error" in ptc:
        return []
    linked = ptc.get("linked_chain") or []
    adjacent = ptc.get("time_adjacent") or []
    if not linked and not adjacent:
        return []

    window = ptc.get("window_minutes", 0)
    host = ptc.get("hostname", "") or "?"
    lines = [
        "\U0001F517 **CS process-tree correlation** "
        f"_(other CS detections on `{host}` within +/- {window} min)_",
        "",
    ]

    if linked:
        lines.append(
            f"**Linked chain** \u2014 {len(linked)} sibling detection(s) share a "
            f"process tree / graph / aggregate / incident lead with this anchor:"
        )
        lines.append("")
        for s in linked:
            offset = s.get("minutes_offset", 0)
            sign = "+" if offset >= 0 else ""
            pid = s.get("pattern_id", "?")
            name = s.get("name", "") or "?"
            link_label = _LINKAGE_DISPLAY.get(
                s.get("linkage", ""), s.get("linkage", "?"),
            )
            link_detail = s.get("linkage_detail", "")
            user = s.get("user_name", "")
            sev = s.get("severity_name", "")
            cmd = (s.get("cmdline", "") or "").strip()
            ts = (s.get("created_timestamp", "") or "")[:19]
            head = (
                f"- **[{sign}{offset}m]** `{ts}` \u2014 Pattern `{pid}` "
                f"**{name}**"
            )
            if sev:
                head += f" _({sev})_"
            lines.append(head)
            lines.append(f"    - linkage: **{link_label}** \u2014 `{link_detail}`")
            if user:
                lines.append(f"    - user: `{user}`")
            if cmd:
                lines.append(f"    - cmd: `{cmd[:200]}`")
        lines.append("")
    else:
        lines.append(
            f"**Linked chain** \u2014 _none_. No other host detections in this "
            f"window share a tree / graph / aggregate / lead with the anchor."
        )
        lines.append("")

    if adjacent:
        lines.append(
            f"**Time-adjacent** \u2014 {len(adjacent)} sibling detection(s) on "
            f"this host with no graph linkage to the anchor _(weaker signal "
            f"\u2014 chronologically near but not provably part of the same "
            f"chain)_:"
        )
        lines.append("")
        for s in adjacent[:5]:
            offset = s.get("minutes_offset", 0)
            sign = "+" if offset >= 0 else ""
            pid = s.get("pattern_id", "?")
            name = s.get("name", "") or "?"
            user = s.get("user_name", "")
            ts = (s.get("created_timestamp", "") or "")[:19]
            line = (
                f"- **[{sign}{offset}m]** `{ts}` \u2014 Pattern `{pid}` "
                f"**{name}**"
            )
            if user:
                line += f" \u2014 user `{user}`"
            lines.append(line)
        if len(adjacent) > 5:
            lines.append(f"- _\u2026 and {len(adjacent) - 5} more_")
        lines.append("")

    return lines


def _build_cs_lateral_targets_section(result) -> list:
    """Render CS lateral-movement target hosts as a markdown section.

    Each resolved target is one bullet with hostname, IP:port, OS,
    OU path, and the source alert(s) that touched it. Unresolved IPs
    (no CS host record found) are listed separately so the analyst
    knows the gap exists.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    lt = source.get("cs_lateral_targets") or {}
    if not lt or "error" in lt:
        return []
    targets = lt.get("targets") or []
    unresolved = lt.get("unresolved") or []
    if not targets and not unresolved:
        return []

    lines = [
        "\u27A1\uFE0F **CS lateral-movement targets** _(internal IPs from "
        "this alert chain resolved to host context)_",
        "",
    ]

    if targets:
        lines.append(
            f"**Resolved {len(targets)} internal target host(s):**"
        )
        lines.append("")
        for t in targets:
            ip = t.get("target_ip", "?")
            port = t.get("target_port", "")
            proto = t.get("protocol", "")
            dev = t.get("target_device") or {}
            hostname = dev.get("hostname", "?")
            product = dev.get("product_type_desc", "")
            os_ver = dev.get("os_version", "")
            domain = dev.get("machine_domain", "")
            ou = dev.get("ou") or []
            tags = dev.get("tags") or []
            groups = dev.get("groups") or []
            status = dev.get("status", "")
            last_seen = (dev.get("last_seen", "") or "")[:19]
            site = dev.get("site_name", "")

            # Headline: hostname + product type makes it instantly clear
            # whether this is workstation->server lateral movement (the
            # interesting case) or workstation->workstation.
            head = f"- \U0001F5A5\uFE0F **`{hostname}`**"
            if product:
                head += f" _({product})_"
            head += f" \u2014 `{ip}:{port}`"
            if proto:
                head += f" {proto}"
            lines.append(head)

            if os_ver:
                lines.append(f"    - OS: `{os_ver}`")
            if domain:
                lines.append(f"    - Domain: `{domain}`")
            if ou:
                lines.append(f"    - OU: `{' / '.join(ou)}`")
            if site:
                lines.append(f"    - Site: `{site}`")
            if status:
                status_emoji = "\u26A0\uFE0F " if status.lower() != "normal" else ""
                lines.append(f"    - Status: {status_emoji}`{status}`")
            if last_seen:
                lines.append(f"    - Last seen: `{last_seen}`")
            if tags:
                lines.append(f"    - Tags: {', '.join(f'`{t}`' for t in tags[:8])}")
            if groups:
                lines.append(f"    - Groups: {', '.join(f'`{g}`' for g in groups[:5])}")

            # Source attribution -- which alert in the chain made this
            # connection. Critical for the maruyama case where the
            # lateral move is in a sibling, not the anchor.
            sources = t.get("source_alerts") or []
            for s in sources:
                role = s.get("role", "")
                pid = s.get("pattern_id", "")
                name = s.get("name", "") or "?"
                if role == "anchor":
                    lines.append(
                        f"    - From: **anchor alert** \u2014 Pattern `{pid}` {name}"
                    )
                else:
                    offset = s.get("minutes_offset", 0)
                    sign = "+" if offset >= 0 else ""
                    linkage = s.get("linkage", "")
                    link_str = f", {linkage}" if linkage else ""
                    lines.append(
                        f"    - From: **chain sibling [{sign}{offset}m{link_str}]** "
                        f"\u2014 Pattern `{pid}` {name}"
                    )
        lines.append("")

    if unresolved:
        lines.append(
            f"**Unresolved internal IPs** ({len(unresolved)}, no CS host record):"
        )
        lines.append("")
        for u in unresolved[:5]:
            ip = u.get("target_ip", "?")
            port = u.get("target_port", "")
            proto = u.get("protocol", "")
            err = u.get("lookup_error", "")
            line = f"- `{ip}:{port}`"
            if proto:
                line += f" {proto}"
            line += f" \u2014 _{err}_"
            lines.append(line)
        if len(unresolved) > 5:
            lines.append(f"- _\u2026 and {len(unresolved) - 5} more_")
        lines.append("")

    return lines


def _build_cs_ioc_ti_section(result) -> list:
    """Render IOC threat-intel hits as a markdown section.

    The section appears even when there are zero hits -- the absence of
    hits across many checked IOCs is itself useful (FP-leaning datapoint).
    Each hit shows the matching prior tipper(s) so the analyst can pivot
    directly to that work item.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    ti = source.get("cs_ioc_ti") or {}
    if not ti or "error" in ti:
        return []
    total_checked = ti.get("total_checked", 0)
    if total_checked == 0:
        # Nothing to check (no hashes/ips/domains in the chain) -- skip
        # rather than render a noisy "0/0" line.
        return []
    total_hits = ti.get("total_hits", 0)

    h_n = ti.get("hashes", {}).get("checked", 0)
    i_n = ti.get("ips", {}).get("checked", 0)
    d_n = ti.get("domains", {}).get("checked", 0)
    skipped = ti.get("domains", {}).get("skipped_benign", 0)

    lines = [
        "\U0001F9EC **IOC threat-intel checks** _(local tipper TI store)_",
        "",
    ]

    if total_hits == 0:
        skip_str = ""
        if skipped:
            skip_str = (
                f" \u00b7 **{skipped}** known-benign domain(s) skipped "
                f"(microsoft.com, akamai.com, etc.)"
            )
        lines.append(
            f"\u2705 **0 of {total_checked} checked IOCs** matched a prior "
            f"tipper. _Hashes: {h_n} \u00b7 IPs: {i_n} \u00b7 Domains: {d_n}{skip_str}_"
        )
        lines.append("")
        lines.append(
            "_FP-leaning datapoint \u2014 these IOCs have not been seen "
            "in prior triaged tippers._"
        )
        lines.append("")
        return lines

    lines.append(
        f"\u26A0\uFE0F **{total_hits} of {total_checked} IOCs** matched a "
        f"prior tipper \u2014 strong escalation signal. "
        f"_(Hashes: {h_n} \u00b7 IPs: {i_n} \u00b7 Domains: {d_n})_"
    )
    lines.append("")

    for sub_key, sub_label, emoji in (
        ("hashes", "Hash", "\U0001F9EC"),
        ("ips", "IP", "\U0001F310"),
        ("domains", "Domain", "\U0001F517"),
    ):
        sub = ti.get(sub_key) or {}
        hits = sub.get("hits") or []
        if not hits:
            continue
        lines.append(f"**{emoji} {sub_label} hits ({len(hits)})**")
        lines.append("")
        for hit in hits:
            val = hit.get("value", "")
            tipper_count = hit.get("tipper_count", 0)
            display = val if sub_key != "hashes" else f"`{val[:32]}\u2026`"
            if sub_key != "hashes":
                display = f"`{val}`"
            lines.append(
                f"- {display} \u2014 **{tipper_count}** prior tipper(s):"
            )
            for t in hit.get("tippers", []):
                tid = t.get("azdo_id", "?")
                title = t.get("title", "")[:100]
                created = t.get("created_date", "")
                url = t.get("url", "")
                date_str = f" `[{created}]`" if created else ""
                if url:
                    lines.append(
                        f"    - [#{tid}]({url}){date_str} {title}"
                    )
                else:
                    lines.append(
                        f"    - #{tid}{date_str} {title}"
                    )
        lines.append("")

    return lines


def _build_cross_source_section(result) -> list:
    """Render cross-source (QRadar) correlation as a markdown section.

    Surfaces open QRadar offenses that match any of the entities the CS
    alert cares about: the anchor source host, the anchor source user,
    and any lateral-movement target hostnames resolved by Gap 4. Each
    matched offense is annotated with its time offset from the CS
    anchor so the analyst can judge whether the two alerts describe the
    same underlying activity.

    An empty entity list is rendered as nothing (we have nothing to say).
    A non-empty entity list with zero matches is rendered as a clear
    "no corroborating SIEM signal" datapoint -- that's useful on its own.
    """
    enrichment = getattr(result, "enrichment", {}) or {}
    source = enrichment.get("source_details") or {}
    if source.get("source") != "crowdstrike":
        return []
    cs_xs = source.get("cs_cross_source") or {}
    if not cs_xs or "error" in cs_xs:
        return []

    entities = cs_xs.get("entities_checked") or []
    if not entities:
        return []

    total_matched = cs_xs.get("total_matched", 0)
    lookback_days = cs_xs.get("lookback_days", 0)
    offenses = cs_xs.get("offenses") or []
    query_errors = cs_xs.get("query_errors") or {}

    lines = [
        "\U0001F517 **Cross-source correlation** _(open QRadar offenses "
        "matching CS entities)_",
        "",
    ]

    # Entity summary -- what was actually searched
    ent_bits = []
    for e in entities:
        etype = e.get("type", "?")
        value = e.get("value", "?")
        role = e.get("role", "")
        bit = f"{etype}=`{value}`"
        if role == "lateral_target":
            bit += " _(lateral target)_"
        ent_bits.append(bit)
    lines.append(f"**Entities checked ({len(entities)}):** {', '.join(ent_bits)}")
    lines.append("")

    if total_matched == 0:
        lines.append(
            f"\u2705 **0 open QRadar offenses** matched these entities "
            f"in the last {lookback_days}d."
        )
        lines.append("")
        lines.append(
            "_No corroborating SIEM signal \u2014 this CS detection is "
            "single-source noise from QRadar's perspective._"
        )
        lines.append("")
        if query_errors:
            lines.append(
                f"_Note: {len(query_errors)} entity lookup(s) failed "
                f"(partial result)._"
            )
            lines.append("")
        return lines

    trunc = "+" if cs_xs.get("truncated") else ""
    lines.append(
        f"\u26A0\uFE0F **{total_matched}{trunc} open QRadar offense(s)** "
        f"matched in the last {lookback_days}d \u2014 sorted by time "
        f"proximity to the CS anchor."
    )
    lines.append("")

    for o in offenses:
        oid = o.get("offense_id", "?")
        desc = (o.get("description", "") or "").strip()
        mag = o.get("magnitude", 0)
        sev = o.get("severity", 0)
        rel = o.get("relevance", 0)
        cred = o.get("credibility", 0)
        ev_count = o.get("event_count", 0)
        hours = o.get("hours_from_anchor")
        offense_source = o.get("offense_source", "")
        offense_type = o.get("offense_type_str", "")
        matched_entities = o.get("matched_entities") or []
        rule_names = o.get("rule_names") or []
        categories = o.get("categories") or []
        log_sources = o.get("log_sources") or []

        offset_str = ""
        if hours is not None:
            sign = "+" if hours >= 0 else ""
            if abs(hours) < 1:
                offset_str = f" \u00b7 `[{sign}{round(hours * 60)}min from CS anchor]`"
            else:
                offset_str = f" \u00b7 `[{sign}{round(hours, 1)}h from CS anchor]`"

        head = (
            f"- \U0001F4CC **Offense #{oid}** \u00b7 mag=`{mag}` \u00b7 "
            f"sev=`{sev}` \u00b7 rel=`{rel}` \u00b7 cred=`{cred}`{offset_str}"
        )
        lines.append(head)

        if desc:
            lines.append(f"    - _{desc[:250]}_")
        if offense_type:
            lines.append(f"    - Type: `{offense_type}`")
        if offense_source:
            lines.append(f"    - Offense source: `{offense_source}`")
        if matched_entities:
            mb = [
                f"{m.get('type', '?')}=`{m.get('value', '?')}`"
                + (
                    " _(lateral target)_"
                    if m.get("role") == "lateral_target"
                    else ""
                )
                for m in matched_entities
            ]
            lines.append(f"    - Matched: {', '.join(mb)}")
        if rule_names:
            lines.append(
                f"    - Rules: {', '.join(f'`{r}`' for r in rule_names[:3])}"
            )
        if categories:
            lines.append(
                f"    - Categories: {', '.join(f'`{c}`' for c in categories[:3])}"
            )
        if log_sources:
            lines.append(
                f"    - Log sources: {', '.join(f'`{ls}`' for ls in log_sources[:3])}"
            )
        if ev_count:
            lines.append(f"    - Events: `{ev_count}`")
    lines.append("")

    if query_errors:
        lines.append(
            f"_Note: {len(query_errors)} entity lookup(s) failed "
            f"(partial result)._"
        )
        lines.append("")

    return lines


_CRITIQUE_ALIGNMENT_EMOJI = {
    "aligned": "✅",        # ✅
    "partial": "⚠️",  # ⚠️
    "contradicted": "\U0001F6A8",  # 🚨
}


def _build_critique_section(result) -> list:
    """Render the independent verifier's critique whenever the critic ran.

    Shown for every ticket where XSOAR_TRIAGE_CRITIC=1 produced a critique —
    including "aligned" (the verifier blessed the trace). Omitted only when
    the critic did not run (flag off or router LLM unavailable), detected by
    an empty alignment field. The flagged bit is preserved in the
    SentinelTriage JSON for analytics but no longer gates display.
    """
    alignment = getattr(result, "llm_critique_alignment", "") or ""
    if not alignment:
        return []
    concerns = getattr(result, "llm_critique_concerns", None) or []
    unused = getattr(result, "llm_critique_unused_pivots", None) or []
    rationale = getattr(result, "llm_critique_rationale", "") or ""

    emoji = _CRITIQUE_ALIGNMENT_EMOJI.get(alignment, "\U0001F50D")  # 🔍
    lines = [
        f"{emoji} **Verifier critique** _(alignment: {alignment or 'unknown'})_",
        "",
    ]
    if rationale:
        lines.append(f"> {rationale}")
        lines.append("")
    if concerns:
        lines.append("**Concerns:**")
        for c in concerns:
            lines.append(f"- {c}")
        lines.append("")
    if unused:
        lines.append("**Pivots the verifier thought were missed:**")
        for p in unused:
            lines.append(f"- `{p}`")
        lines.append("")
    return lines


def _build_tool_trace_section(result) -> list:
    """Render the tool calls the LLM made during triage.

    Surfaces what the AI actually ran — ServiceNow / QRadar / Vectra / AD /
    Varonis / IOC lookups — so analysts can see the evidence trail behind the
    verdict instead of having to re-run those checks themselves.
    """
    trace = getattr(result, "llm_tool_calls", None) or []
    if not trace:
        return []

    lines = [
        f"\U0001F6E0 **What the AI checked** _({len(trace)} tool call"
        f"{'s' if len(trace) != 1 else ''})_",
        "",
    ]
    for i, call in enumerate(trace, 1):
        tool = call.get("tool", "?")
        args = call.get("args", {}) or {}
        preview = (call.get("result_preview", "") or "").strip()
        arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
        if len(arg_str) > 120:
            arg_str = arg_str[:117] + "..."
        lines.append(f"{i}. `{tool}({arg_str})`")
        if preview:
            first_line = preview.splitlines()[0].strip()
            if len(first_line) > 180:
                first_line = first_line[:177] + "..."
            lines.append(f"    > {first_line}")
    lines.append("")
    return lines


def _build_investigation_pivots_section(result) -> list:
    """Render the LLM's investigation_pivots as a numbered checklist.

    Empty list when there are no pivots (close_ticket verdicts) so the
    section is omitted entirely. Pivots are now residual human-only
    questions — things the LLM's tool surface couldn't answer.
    """
    pivots = getattr(result, "llm_investigation_pivots", None) or []
    if not pivots:
        return []

    action = getattr(result, "llm_recommended_action", "") or ""
    action_emoji = {
        "investigate": "\U0001F50D",  # magnifier
        "escalate": "\U0001F6A8",     # rotating light
    }.get(action, "\U0001F4CB")        # clipboard

    lines = [
        f"{action_emoji} **Residual questions** _(things a human still needs "
        f"to do — outside the AI's tool surface)_",
        "",
    ]
    for i, pivot in enumerate(pivots, 1):
        text = (pivot or "").strip()
        if not text:
            continue
        lines.append(f"{i}. {text}")
    lines.append("")
    return lines


def _is_all_ignored_or_fp(prediction) -> bool:
    """Check if all similar tickets were closed as Ignore or False Positive."""
    if not prediction or not prediction.top_close_reasons:
        return False
    benign_count = sum(
        v for k, v in prediction.top_close_reasons.items()
        if k.lower() in ("ignore", "false positive", "resolved - fp", "resolved", "duplicate")
    )
    return benign_count / prediction.sample_size >= 0.8


def _build_enrichment_highlights(enrichment: dict) -> list:
    """Extract notable IOC scores from enrichment data for card display."""
    lines = []
    vt = enrichment.get("virustotal", {})
    if vt and "error" not in vt:
        for h, data in vt.get("hashes", {}).items():
            mal = data.get("malicious", 0)
            total = data.get("total", 0)
            if mal > 0:
                lines.append(f"  - \U0001F9EC **VT Hash** `{h[:16]}...`: `{mal}/{total}` ({data.get('threat_level', 'N/A')})")
        for ip, data in vt.get("ips", {}).items():
            mal = data.get("malicious", 0)
            if mal > 0:
                lines.append(f"  - \U0001F310 **VT IP** `{ip}`: `{mal}/{data.get('total', 0)}`")
        for d, data in vt.get("domains", {}).items():
            mal = data.get("malicious", 0)
            if mal > 0:
                lines.append(f"  - \U0001F310 **VT Domain** `{d}`: `{mal}/{data.get('total', 0)}`")
    abuse = enrichment.get("abuseipdb", {})
    if abuse and "error" not in abuse:
        for ip, data in abuse.items():
            score = data.get("abuse_confidence_score", 0)
            if score > 0:
                lines.append(f"  - \U0001F6AB **AbuseIPDB** `{ip}`: confidence `{score}/100`, {data.get('total_reports', 0)} reports")
    rf = enrichment.get("recorded_future", {})
    if rf and "error" not in rf:
        for val, data in rf.items():
            risk = data.get("risk_score", 0)
            if risk and risk > 0:
                lines.append(f"  - \U0001F52E **Recorded Future** `{val}`: risk `{risk}` ({data.get('risk_level', 'N/A')})")
    return lines


def _format_similarity_badges(ticket: dict) -> str:
    """Build compact badge string showing which dimensions matched.

    Returns e.g. ' [rule+3 IOCs+host]' or '' if no breakdown available.
    """
    breakdown = ticket.get("similarity_breakdown")
    if not breakdown:
        return ""
    badges = []
    if getattr(breakdown, 'detection_rule_match', 0) > 0:
        badges.append("rule")
    ioc_count = getattr(breakdown, 'shared_ioc_count', 0)
    if ioc_count > 0:
        badges.append(f"{ioc_count} IOC{'s' if ioc_count > 1 else ''}")
    if getattr(breakdown, 'category_type_match', 0) > 0:
        badges.append("cat")
    if getattr(breakdown, 'host_user_match', 0) > 0:
        if getattr(breakdown, 'matched_host', ''):
            badges.append("host")
        else:
            badges.append("user")
    return f" [{'+'.join(badges)}]" if badges else ""


def _build_entity_intel_section(result) -> list:
    """Build lines for the Entity Intel section covering all enrichment sources."""
    lines = []

    # --- Vectra NDR ---
    vectra = getattr(result, "vectra_context", {}) or {}
    if vectra and "error" not in vectra:
        host_e = vectra.get("host_entity")
        acct_e = vectra.get("account_entity")
        if host_e or acct_e:
            lines.append("  **Vectra NDR**")
        if host_e:
            threat = host_e.get("threat", 0)
            certainty = host_e.get("certainty", 0)
            level = host_e.get("threat_level", "")
            det_count = host_e.get("detection_count", 0)
            prioritized = " \U0001F534 Prioritized" if host_e.get("is_prioritized") else ""
            lines.append(
                f"  \U0001F5A5\uFE0F Host: T:`{threat}` C:`{certainty}` ({level})"
                f" · {det_count} detection{'s' if det_count != 1 else ''}{prioritized}"
            )
            for d in (host_e.get("active_detections") or [])[:3]:
                dtype = d.get("type", "?")
                cat = d.get("category", "")
                dt = d.get("threat", 0)
                dc = d.get("certainty", 0)
                lines.append(f"    - {cat}: {dtype} (T:{dt}/C:{dc})")
        if acct_e:
            threat = acct_e.get("threat", 0)
            certainty = acct_e.get("certainty", 0)
            level = acct_e.get("threat_level", "")
            det_count = acct_e.get("detection_count", 0)
            prioritized = " \U0001F534 Prioritized" if acct_e.get("is_prioritized") else ""
            lines.append(
                f"  \U0001F464 Account: T:`{threat}` C:`{certainty}` ({level})"
                f" · {det_count} detection{'s' if det_count != 1 else ''}{prioritized}"
            )
            for d in (acct_e.get("active_detections") or [])[:3]:
                dtype = d.get("type", "?")
                cat = d.get("category", "")
                dt = d.get("threat", 0)
                dc = d.get("certainty", 0)
                lines.append(f"    - {cat}: {dtype} (T:{dt}/C:{dc})")

    # --- QRadar entity activity ---
    qr = getattr(result, "qradar_entity_activity", {}) or {}
    if qr and "error" not in qr:
        event_count = qr.get("event_count", 0)
        hours = qr.get("hours", 4)
        ls_summary = qr.get("log_source_summary", {})
        events = qr.get("events", [])
        hostname = getattr(result, "hostname", "")
        username = getattr(result, "username", "")
        enrichment_ips = []
        enrichment_domains = []
        if not hostname and not username:
            enrichment = getattr(result, "enrichment", {}) or {}
            seen_ips = set()
            for ip in (enrichment.get("virustotal") or {}).get("ips", {}).keys():
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    enrichment_ips.append(ip)
            for ip in (enrichment.get("abuseipdb") or {}).keys():
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    enrichment_ips.append(ip)
            seen_domains = set()
            for d in (enrichment.get("virustotal") or {}).get("domains", {}).keys():
                if d not in seen_domains:
                    seen_domains.add(d)
                    enrichment_domains.append(d)
            # RF keys can be IPs or domains — include only non-IP values
            import re as _re
            _ip_pat = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
            for val in (enrichment.get("recorded_future") or {}).keys():
                if not _ip_pat.match(val) and val not in seen_domains:
                    seen_domains.add(val)
                    enrichment_domains.append(val)
        qr_url = _build_qradar_search_url(
            hostname=hostname,
            username=username,
            hours=hours,
            ips=enrichment_ips or None,
            domains=enrichment_domains or None,
        )
        qr_label = f"[QRadar]({qr_url})" if qr_url else "QRadar"
        if event_count > 0:
            ls_parts = ", ".join(
                f"{ls} ({n})" for ls, n in
                sorted(ls_summary.items(), key=lambda x: -x[1])[:4]
            )
            lines.append(f"  **{qr_label}** (last {hours}h — {event_count} events)")
            if ls_parts:
                lines.append(f"  Log sources: {ls_parts}")
            for ev in events[:5]:
                mag = ev.get("magnitude", "")
                name = (ev.get("event_name", "") or "")[:60]
                src = ev.get("sourceip", "")
                dst = ev.get("destinationip", "")
                flow = f"`{src}` → `{dst}`" if src or dst else ""
                mag_str = f"[mag:{mag}] " if mag else ""
                lines.append(f"    - {mag_str}{name} {flow}".rstrip())
        else:
            lines.append(f"  **{qr_label}** (last {hours}h — no events)")

    # --- Varonis ---
    varonis = getattr(result, "varonis_context", {}) or {}
    if varonis and "error" not in varonis:
        user_alerts = varonis.get("user_alerts")
        data_activity = varonis.get("data_activity")
        if user_alerts is not None or data_activity is not None:
            lines.append("  **Varonis DatAlert**")
        if user_alerts:
            alerts_list = user_alerts if isinstance(user_alerts, list) else (
                user_alerts.get("alerts", []) if isinstance(user_alerts, dict) else []
            )
            if alerts_list:
                lines.append(f"  \U0001F464 User alerts ({len(alerts_list)})")
                for a in alerts_list[:3]:
                    name = (
                        a.get("name", a.get("alertName", a.get("description", str(a))))
                        if isinstance(a, dict) else str(a)
                    )[:80]
                    sev = a.get("severity", "") if isinstance(a, dict) else ""
                    sev_str = f" `{sev}`" if sev else ""
                    lines.append(f"    - {name}{sev_str}")
            elif isinstance(user_alerts, dict) and user_alerts:
                lines.append(f"  \U0001F464 User alerts: {str(user_alerts)[:120]}")
        if data_activity:
            activity_list = data_activity if isinstance(data_activity, list) else (
                data_activity.get("activity", data_activity.get("events", []))
                if isinstance(data_activity, dict) else []
            )
            if activity_list:
                lines.append(f"  \U0001F5C2\uFE0F Data activity ({len(activity_list)} events)")
                for a in activity_list[:3]:
                    desc = (
                        a.get("description", a.get("path", a.get("resource", str(a))))
                        if isinstance(a, dict) else str(a)
                    )[:80]
                    lines.append(f"    - {desc}")
            elif isinstance(data_activity, dict) and data_activity:
                lines.append(f"  \U0001F5C2\uFE0F Data activity: {str(data_activity)[:120]}")

    # --- Active Directory ---
    ad = getattr(result, "ad_context", {}) or {}
    if ad and "error" not in ad:
        user_obj = ad.get("user")
        comp_obj = ad.get("computer")
        if user_obj or comp_obj:
            lines.append("  **Active Directory**")
        if user_obj and isinstance(user_obj, dict):
            display = user_obj.get("displayName", user_obj.get("name", ""))
            dept = user_obj.get("department", "")
            enabled = user_obj.get("enabled", user_obj.get("userAccountControl", ""))
            last_logon = (str(user_obj.get("lastLogon", user_obj.get("lastLogonDate", ""))) or "")[:16]
            groups = user_obj.get("groups", user_obj.get("memberOf", []))
            dn = user_obj.get("distinguishedName", user_obj.get("dn", ""))
            meta = " · ".join(filter(None, [display, dept]))
            enabled_str = ""
            if enabled is not None and enabled != "":
                enabled_str = " · Enabled" if str(enabled).lower() in ("true", "enabled", "512") else " · \u26A0\uFE0F Disabled"
            logon_str = f" · Last logon `{last_logon}`" if last_logon else ""
            lines.append(f"  \U0001F464 User: {meta}{enabled_str}{logon_str}")
            if groups:
                group_list = groups if isinstance(groups, list) else [groups]
                group_names = [
                    (g.split(",")[0].replace("CN=", "") if isinstance(g, str) and "CN=" in g else str(g))
                    for g in group_list[:5]
                ]
                lines.append(f"    Groups: {', '.join(group_names)}")
            if dn:
                lines.append(f"    OU: `{dn[:100]}`")
        if comp_obj and isinstance(comp_obj, dict):
            os_name = comp_obj.get("operatingSystem", comp_obj.get("os", ""))
            enabled = comp_obj.get("enabled", comp_obj.get("userAccountControl", ""))
            last_logon = (str(comp_obj.get("lastLogon", comp_obj.get("lastLogonDate", ""))) or "")[:16]
            dn = comp_obj.get("distinguishedName", comp_obj.get("dn", ""))
            enabled_str = ""
            if enabled is not None and enabled != "":
                enabled_str = " · Enabled" if str(enabled).lower() in ("true", "enabled", "4096") else " · \u26A0\uFE0F Disabled"
            logon_str = f" · Last logon `{last_logon}`" if last_logon else ""
            lines.append(f"  \U0001F5A5\uFE0F Computer: `{os_name}`{enabled_str}{logon_str}")
            if dn:
                lines.append(f"    OU: `{dn[:100]}`")

    # --- SNOW incidents (changes are rendered separately above) ---
    snow = getattr(result, "snow_context", {}) or {}
    snow_url = _build_snow_search_url(getattr(result, "hostname", ""))
    snow_label = f"[ServiceNow]({snow_url})" if snow_url else "ServiceNow"
    incidents = snow.get("incidents", [])
    if incidents:
        lines.append(f"  **{snow_label}** (last 72h — {len(incidents)} incident{'s' if len(incidents) != 1 else ''})")
        for inc in incidents[:3]:
            num = inc.get("number", "?")
            desc = (inc.get("short_description", "") or "")[:70]
            state = inc.get("state", "")
            pri = inc.get("priority", "")
            meta = " · ".join(filter(None, [pri, state]))
            lines.append(f"  - {num} {meta} — {desc}")
    elif snow and "error" not in snow:
        lines.append(f"  **{snow_label}** (no incidents or changes)")

    return lines


def build_xsoar_triage_card(result) -> dict:
    """Build a minimal adaptive card with action buttons only.

    This is the second message (reply) in a two-part notification.
    The first message is a markdown message with full triage details.

    Args:
        result: XsoarTriageResult dataclass instance

    Returns:
        Adaptive card JSON dict with action buttons
    """
    from src.utils.xsoar_helpers import build_incident_url
    xsoar_url = build_incident_url(result.ticket_id)
    alert_id = f"xsoar:{result.ticket_id}"

    verdict_label = _verdict_display(result.llm_verdict)
    confidence = _format_percentage(result.llm_confidence)

    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "Container",
                "style": "emphasis",
                "items": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "\U0001F6E1\uFE0F",
                                        "size": "Medium",
                                    },
                                ],
                                "verticalContentAlignment": "Center",
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": f"[XSOAR #{result.ticket_id}]({xsoar_url})",
                                        "weight": "Bolder",
                                        "size": "Medium",
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": f"{verdict_label} [{confidence}]",
                                        "size": "Small",
                                        "color": "Attention" if "malicious" in result.llm_verdict else (
                                            "Warning" if "benign" in result.llm_verdict else "Good"
                                        ),
                                        "spacing": "None",
                                        "isSubtle": True,
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
            {
                "type": "ActionSet",
                "spacing": "Medium",
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "\u2705 Close Ticket",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_close",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                            "suggested_close_reason": getattr(result, "suggested_close_reason", "") or "",
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F6A8 Escalate",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_escalate",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F4DD Add Note",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_note",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F50D Investigate",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_investigate",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                            "xsoar_url": xsoar_url,
                        },
                    },
                ],
            },
            {
                "type": "TextBlock",
                "text": "Response Actions",
                "size": "Small",
                "weight": "Bolder",
                "isSubtle": True,
                "spacing": "Medium",
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F512 Contain Host",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_contain_host",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                            "hostname": result.hostname or "",
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F6AB Disable AD Account",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_disable_ad_account",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                            "username": result.username or "",
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F6D1 Block IOC",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_block_ioc",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                        },
                    },
                    {
                        "type": "Action.Submit",
                        "title": "\U0001F511 Reset Password",
                        "data": {
                            "callback_keyword": "sentinel_xsoar_reset_password",
                            "alert_id": alert_id,
                            "xsoar_ticket_id": result.ticket_id,
                            "username": result.username or "",
                        },
                    },
                ],
            },
        ],
    }

    return card
