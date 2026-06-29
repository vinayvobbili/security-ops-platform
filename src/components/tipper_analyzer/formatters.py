"""Formatting functions for tipper analysis output."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from .models import NoveltyAnalysis, IOCHuntResult, ToolHuntResult, BehavioralHuntResult
from .utils import (
    defang_ioc,
    linkify_work_items_html,
    split_by_history,
    format_tipper_refs,
    get_risk_emoji,
    get_risk_colors,
)


def _escape_aql_value(value: str) -> str:
    """Escape a value for safe interpolation into AQL query strings."""
    return value.replace("'", "''")


def _get_falcon_console_link(query_type: str, fql_query: str) -> Optional[Tuple[str, str]]:
    """Generate a clickable Falcon console link for a CrowdStrike FQL query.

    Args:
        query_type: The type of query (e.g., 'IP Detection Search (Detects API)')
        fql_query: The FQL filter string

    Returns:
        Tuple of (url, link_text) or None if not a linkable query type or console URL not configured
    """
    from my_config import get_config

    # Skip ThreatGraph API calls - they're not FQL
    if 'ThreatGraph' in query_type or 'ThreatGraph' in fql_query:
        return None

    # Get Falcon console URL from config
    config = get_config()
    falcon_base = config.cs_falcon_console_url
    if not falcon_base:
        return None  # Console URL not configured

    # Remove trailing slash if present
    falcon_base = falcon_base.rstrip('/')

    # URL-encode the FQL query
    encoded_fql = quote(fql_query, safe='')

    # Map query types to Falcon console URLs
    if 'Detection' in query_type or 'Detects' in query_type:
        url = f"{falcon_base}/activity/detections?filter={encoded_fql}"
        link_text = "Open in Falcon Detections"
    elif 'Alert' in query_type:
        url = f"{falcon_base}/alerts?filter={encoded_fql}"
        link_text = "Open in Falcon Alerts"
    elif 'Hash' in query_type or 'Filename' in query_type:
        url = f"{falcon_base}/activity/detections?filter={encoded_fql}"
        link_text = "Open in Falcon Detections"
    elif 'Intel' in query_type or 'Falcon X' in query_type:
        url = f"{falcon_base}/intelligence/indicators?filter={encoded_fql}"
        link_text = "Open in Falcon Intelligence"
    else:
        # Default to event search for unknown types
        url = f"{falcon_base}/investigate/events?filter={encoded_fql}"
        link_text = "Open in Falcon Event Search"

    return (url, link_text)


def _get_falcon_logscale_link(cql_query: str, window: str = "30d") -> Optional[str]:
    """True deep-link into Falcon Advanced Event Search (LogScale) that lands the
    analyst on the pre-filled query's results — no copy-paste.

    Thin wrapper over the shared ``services.hunt_links`` builder so the tipper
    AZDO output and every other desk produce the identical URL (one
    implementation — deep-link convergence, see project_hunt_engine_kernel).
    """
    from services import hunt_links
    return hunt_links.falcon_logscale_url(cql_query, window=window)


def _get_qradar_console_link(aql_query: str) -> Optional[Tuple[str, str]]:
    """Generate a clickable QRadar console link for an AQL query.

    Returns a ``(url, link_text)`` tuple (or None) for back-compat with the
    tipper formatters; the URL itself comes from the shared
    ``services.hunt_links`` builder.
    """
    from services import hunt_links
    url = hunt_links.qradar_console_url(aql_query)
    if not url:
        return None
    return (url, "Open in QRadar Log Activity")


def _format_similarity_compact(ticket: dict) -> str:
    """Format similarity as a compact string with multi-signal breakdown.

    Examples:
        "72% [IOC:3 TTP:2 Actor:APT29]"
        "91%"  (no breakdown available)
    """
    breakdown = ticket.get('similarity_breakdown')
    similarity = ticket.get('similarity', 0)

    if not breakdown:
        return f"{similarity:.0%}" if similarity else ""

    parts = [f"{breakdown.composite_score:.0%}"]
    details = []
    if breakdown.shared_ioc_count:
        details.append(f"IOC:{breakdown.shared_ioc_count}")
    if breakdown.shared_ttp_count:
        details.append(f"TTP:{breakdown.shared_ttp_count}")
    if breakdown.shared_actors:
        details.append(f"Actor:{','.join(breakdown.shared_actors[:2])}")
    if breakdown.shared_malware:
        details.append(f"Malware:{','.join(breakdown.shared_malware[:2])}")
    if details:
        parts.append(f"[{' '.join(details)}]")
    return ' '.join(parts)


def _format_similarity_html(ticket: dict) -> str:
    """Format similarity as HTML with multi-signal detail for AZDO display.

    Returns a cell content string with the composite score prominent
    and individual signals in smaller text below.
    """
    breakdown = ticket.get('similarity_breakdown')
    similarity = ticket.get('similarity', 0)

    if not breakdown:
        return f"<strong>{similarity:.0%}</strong>" if similarity else ""

    lines = [f"<strong>{breakdown.composite_score:.0%}</strong>"]
    detail_parts = []
    if breakdown.shared_ioc_count:
        detail_parts.append(f"IOC: {breakdown.shared_ioc_count} shared")
    else:
        detail_parts.append(f"IOC: 0")
    if breakdown.shared_ttp_count:
        detail_parts.append(f"TTP: {breakdown.shared_ttp_count}")
    if breakdown.shared_actors:
        detail_parts.append(f"Actor: {', '.join(breakdown.shared_actors[:2])}")
    if breakdown.shared_malware:
        detail_parts.append(f"Malware: {', '.join(breakdown.shared_malware[:2])}")
    if detail_parts:
        lines.append(
            '<span style="font-size: 11px; color: #666;">'
            + '<br/>'.join(detail_parts)
            + '</span>'
        )
    return '<br/>'.join(lines)


def _recency_label(tipper_ids: List[str], history_dates: Dict[str, str]) -> str:
    """Compute a recency label from the most recent tipper date.

    Returns a string like '3 days ago' or '' if no dates available.
    """
    if not history_dates:
        return ""
    # Find most recent date among the tipper_ids
    most_recent = None
    for tid in tipper_ids:
        date_str = history_dates.get(tid, "")
        if not date_str:
            continue
        try:
            # AZDO dates are ISO format, e.g. "2026-01-20T15:30:00Z" or with offset
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if most_recent is None or dt > most_recent:
                most_recent = dt
        except (ValueError, TypeError):
            continue
    if most_recent is None:
        return ""
    now = datetime.now(timezone.utc)
    delta = now - most_recent
    days = delta.days
    if days == 0:
        return "today"
    elif days == 1:
        return "1 day ago"
    elif days < 30:
        return f"{days} days ago"
    elif days < 365:
        months = days // 30
        return f"{months} {'month' if months == 1 else 'months'} ago"
    else:
        return f"{days // 365}+ years ago"


def format_analysis_brief(analysis: NoveltyAnalysis, source: str = "on-demand", hunt_result: 'IOCHuntResult | None' = None) -> str:
    """Format analysis as a condensed summary for Webex. Full details go to AZDO.

    Args:
        analysis: NoveltyAnalysis object
        source: "hourly", "command", or "on-demand"
        hunt_result: Optional IOCHuntResult from IOC hunt
    """
    # Source indicator
    if source == "hourly":
        source_label = "🕐 **New Tipper Alert** (Hourly Scan)"
    elif source == "command":
        source_label = "🔍 **Tipper Analysis**"
    else:
        source_label = "🔍 **On-Demand Analysis**"

    # Novelty score visualization (compact)
    score_bar = "█" * analysis.novelty_score + "░" * (10 - analysis.novelty_score)

    output = f"""{source_label}

**#{analysis.tipper_id}** - {analysis.tipper_title}

**Score:** [{score_bar}] {analysis.novelty_score}/10 — {analysis.novelty_label}

{analysis.summary}

**Recommendation:** {analysis.recommendation}
"""

    # Brief highlights (counts only)
    highlights = []
    rf = analysis.rf_enrichment
    if rf and rf.get('high_risk_iocs'):
        highlights.append(f"{len(rf['high_risk_iocs'])} high-risk IOCs")
    if analysis.current_malware:
        highlights.append(f"{len(analysis.current_malware)} malware families")
    if analysis.related_tickets:
        highlights.append(f"{len(analysis.related_tickets)} related tickets")
    if hunt_result and hunt_result.total_hits > 0:
        highlights.append(f"⚠️ **{hunt_result.total_hits} IOC hits found in environment**")

    if highlights:
        output += f"\n_Key signals: {' | '.join(highlights)}_\n"

    output += "\n_📝 Full analysis, IOC details, and hunt results posted to AZDO work item._\n"

    return output


def format_analysis_for_display(analysis: NoveltyAnalysis, source: str = "on-demand") -> str:
    """Format analysis result for human-readable display (Webex).

    Args:
        analysis: NoveltyAnalysis object
        source: "hourly" for scheduled job, "command" for bot command, "on-demand" for manual request
    """
    # Novelty score visualization
    score_bar = "█" * analysis.novelty_score + "░" * (10 - analysis.novelty_score)

    # Format created date for display
    created_display = f" (Created: {analysis.created_date})" if analysis.created_date else ""

    # Source indicator
    if source == "hourly":
        source_label = "🕐 **New Tipper Alert** (Hourly Scan)"
    elif source == "command":
        source_label = "🔍 **Tipper Analysis**"
    else:
        source_label = "🔍 **On-Demand Analysis**"

    output = f"""
{source_label}

**TIPPER NOVELTY ANALYSIS**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Tipper:** #{analysis.tipper_id}{created_display}
**Title:**
{analysis.tipper_title}

**NOVELTY SCORE:** [{score_bar}] {analysis.novelty_score}/10 - {analysis.novelty_label}

**SUMMARY:**
{analysis.summary}

**🆕 WHAT'S NEW:**
"""
    if analysis.what_is_new:
        for item in analysis.what_is_new:
            output += f"  • {item}\n"
    else:
        output += "  (No new threat actors, TTPs, techniques, or malware identified)\n"

    output += "\n**📋 WHAT'S FAMILIAR:**\n"
    if analysis.what_is_familiar:
        for item in analysis.what_is_familiar:
            output += f"  • {item}\n"
    else:
        output += "  (No similar patterns found in history)\n"

    output += "\n**🔗 RELATED TICKETS:**\n"
    if analysis.related_tickets:
        for ticket in analysis.related_tickets:
            title = ticket.get('title', '')
            similarity = ticket.get('similarity', 0)
            breakdown = ticket.get('similarity_breakdown')
            # Build similarity display with multi-signal breakdown
            sim_str = _format_similarity_compact(ticket)
            # Format created date compactly
            raw_date = ticket.get('created_date', '')
            if raw_date:
                try:
                    dt = datetime.fromisoformat(raw_date.replace('Z', '+00:00'))
                    created_str = dt.strftime('%m/%d/%Y')
                except Exception:
                    created_str = raw_date[:10]
            else:
                created_str = ''
            state = ticket.get('state', '')
            assigned_to = ticket.get('assigned_to', '')
            # Show first name + last initial for space
            if assigned_to and ' ' in assigned_to:
                parts = assigned_to.split()
                assigned_to = f"{parts[0]} {parts[-1][0]}."
            tags = ticket.get('tags', '')
            # Filter out ubiquitous tags that appear on all tippers
            if tags:
                tags = '; '.join(t.strip() for t in tags.split(';') if t.strip().upper() != 'CTI')
            if tags and len(tags) > 20:
                tags = tags[:18] + '..'
            # Strip "[PRIORITY] CTI Threat Tipper: " prefix from title
            if '] CTI Threat Tipper: ' in title:
                title = title.split('] CTI Threat Tipper: ', 1)[1]
            display_title = title[:50] + '...' if len(title) > 50 else title
            # Use raw #{id} — the outer linkify_work_items_markdown call handles hyperlinking
            details = [sim_str, created_str, state, assigned_to, tags]
            details_str = ' · '.join(d for d in details if d)
            output += f"  • #{ticket['id']} ({details_str}): {display_title}\n"
    else:
        output += "  (No semantically related tickets found)\n"

    # Add threat intelligence section
    rf = analysis.rf_enrichment
    has_extracted = rf and rf.get('extracted_actors')
    has_rf_actors = rf and rf.get('actors')
    has_rf_iocs = rf and rf.get('high_risk_iocs')
    has_malware = bool(analysis.current_malware)

    if has_extracted or has_rf_actors or has_rf_iocs or has_malware:
        output += "\n**🔮 THREAT INTELLIGENCE:**\n"

        # Show extracted actors with local alias info
        if has_extracted:
            output += "\n  **Threat Actors:**\n"
            for actor in rf['extracted_actors']:
                name = actor.get('name', 'Unknown')
                common_name = actor.get('common_name', '')
                region = actor.get('region', '')
                aliases = actor.get('aliases_display', '')

                if common_name and common_name != name:
                    output += f"  • **{name}** → {common_name}\n"
                else:
                    output += f"  • **{name}**\n"

                if region:
                    output += f"    Region: {region}\n"
                if aliases:
                    output += f"    AKA: {aliases}\n"

        # Show RF actor intel if available
        if has_rf_actors:
            output += "\n  **Recorded Future Intel:**\n"
            for actor in rf['actors']:
                name = actor.get('name', 'Unknown')
                risk = actor.get('risk_score', 'N/A')
                categories = actor.get('categories', [])

                output += f"  • **{name}** (RF Risk: {risk}/99)\n"
                if categories:
                    output += f"    Category: {', '.join(categories)}\n"

        # Show malware families (compact summary)
        if analysis.current_malware:
            new_malware, familiar_malware = split_by_history(
                analysis.current_malware, analysis.malware_history or {}
            )
            if new_malware:
                output += f"\n  **🆕 New Malware/Tools:** {', '.join(new_malware[:5])}\n"
            if familiar_malware:
                familiar_names = [m for m, _ in familiar_malware[:3]]
                output += f"  **📋 Familiar:** {', '.join(familiar_names)}"
                if len(familiar_malware) > 3:
                    output += f" (+{len(familiar_malware) - 3} more)"
                output += "\n"

        # Show IOC summary (compact for Webex, full tables go to AZDO)
        if has_rf_iocs or analysis.total_iocs_extracted:
            total_extracted = sum(analysis.total_iocs_extracted.values()) if analysis.total_iocs_extracted else 0
            high_risk_count = len(rf.get('high_risk_iocs', [])) if rf else 0

            if high_risk_count > 0:
                new_iocs, familiar_iocs = split_by_history(
                    rf['high_risk_iocs'],
                    analysis.ioc_history or {},
                    key_fn=lambda x: x.get('value', '').lower()
                )

                # Compact IOC summary
                output += "\n  **IOC Summary:**\n"
                if new_iocs:
                    # Show top 3 highest-risk new IOCs
                    top_new = sorted(new_iocs, key=lambda x: x.get('risk_score', 0), reverse=True)[:3]
                    output += f"  • 🔍 **{len(new_iocs)} First-Time IOCs** "
                    top_display = ", ".join(
                        f"`{defang_ioc(ioc.get('value', '')[:25], ioc.get('ioc_type', ''))}`"
                        for ioc in top_new
                    )
                    output += f"(top: {top_display})\n"
                if familiar_iocs:
                    output += f"  • 📋 **{len(familiar_iocs)} Familiar IOCs** (seen in prior tippers)\n"

            if total_extracted > 0:
                output += f"  _ℹ️ {total_extracted} total IOCs extracted, {high_risk_count} high-risk_\n"

    # Add MITRE coverage summary with technique-to-rule table
    output += "\n**🎯 MITRE ATT&CK Coverage:**\n"
    if analysis.mitre_techniques:
        covered_count = len(analysis.mitre_covered)
        gap_count = len(analysis.mitre_gaps)
        total = len(analysis.mitre_techniques)

        if gap_count > 0:
            output += f"  {covered_count}/{total} techniques covered, ⚠️ **{gap_count} gap(s)**\n"
        else:
            output += f"  ✅ All {total} techniques have detection rules\n"

        # Show covered techniques with their rules (using mitre_rules from analyzer)
        if analysis.mitre_covered:
            output += "```\n"
            output += f"{'Technique':<12} {'Status':<10} {'Detection Rule(s)':<50}\n"
            output += f"{'-'*12} {'-'*10} {'-'*50}\n"
            for tech in analysis.mitre_covered[:8]:
                rules = analysis.mitre_rules.get(tech.upper(), [])
                if rules:
                    platform_short = {"qradar": "Q", "crowdstrike": "CS", "tanium": "T"}
                    rules_str = ", ".join(
                        f"[{platform_short.get(r.get('platform', ''), '?')}] {r.get('name', '')[:35]}"
                        for r in rules[:2]
                    )
                    if len(rules) > 2:
                        rules_str += f" (+{len(rules) - 2})"
                else:
                    rules_str = "(coverage detected)"
                # Truncate rules_str if too long
                if len(rules_str) > 50:
                    rules_str = rules_str[:47] + "..."
                output += f"{tech:<12} {'COVERED':<10} {rules_str}\n"
            if len(analysis.mitre_covered) > 8:
                output += f"... and {len(analysis.mitre_covered) - 8} more covered\n"
            output += "```\n"

        # Show gaps if any
        if analysis.mitre_gaps:
            output += f"  ⚠️ **Gaps (no rules):** {', '.join(analysis.mitre_gaps[:5])}\n"
            if len(analysis.mitre_gaps) > 5:
                output += f"     (+{len(analysis.mitre_gaps) - 5} more)\n"
    else:
        output += "  _(No MITRE techniques identified in this tipper)_\n"

    # Add detection rules coverage section (compact for Webex)
    if analysis.existing_rules:
        from .rules.formatters import format_rules_for_display_section
        rules_section = format_rules_for_display_section(analysis.existing_rules)
        if rules_section:
            output += rules_section

    output += f"""
**💡 RECOMMENDATION:**
{analysis.recommendation}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    # Add note about AZDO posting for hourly scans and command requests
    if source in ("hourly", "command"):
        output += "_📝 Full analysis with all IOCs has been posted to the AZDO work item._\n"

    # Show LLM generation time if available
    if analysis.generation_time > 0:
        output += f"_⏱ LLM analysis: {analysis.generation_time:.1f}s_\n"

    return output


def format_analysis_for_azdo(analysis: NoveltyAnalysis) -> str:
    """Format analysis as HTML for AZDO comment."""
    # Score bar using HTML entities
    filled = "&#9608;" * analysis.novelty_score  # █
    empty = "&#9617;" * (10 - analysis.novelty_score)  # ░

    # Color-coded score banner
    if analysis.novelty_score >= 7:
        banner_bg = "#fde8e8"
        banner_border = "#e53e3e"
        banner_color = "#c53030"
    elif analysis.novelty_score >= 4:
        banner_bg = "#fefce8"
        banner_border = "#d69e2e"
        banner_color = "#b7791f"
    else:
        banner_bg = "#e8f5e9"
        banner_border = "#38a169"
        banner_color = "#276749"

    html = f"""<div style="font-family: Consolas, monospace;">
<h3>🤖 Tipper Novelty Analysis (Pokedex)</h3>
<div style="background-color: {banner_bg}; border-left: 4px solid {banner_border}; padding: 10px 14px; margin: 8px 0;">
<span style="color: {banner_color}; font-size: 14px;"><strong>Novelty Score:</strong> [{filled}{empty}] <strong>{analysis.novelty_score}/10 &mdash; {analysis.novelty_label}</strong></span>
</div>

<p><strong>Summary:</strong><br/>{analysis.summary}</p>

<p><strong>🆕 What's New:</strong></p>
<ul>
"""
    if analysis.what_is_new:
        for item in analysis.what_is_new:
            # Linkify any work item references in the item
            linked_item = linkify_work_items_html(item)
            html += f"<li>{linked_item}</li>\n"
    else:
        html += "<li><em>No new threat actors, TTPs, techniques, or malware identified</em></li>\n"

    html += """</ul>

<p><strong>📋 What's Familiar:</strong></p>
<ul>
"""
    if analysis.what_is_familiar:
        for item in analysis.what_is_familiar:
            # Linkify any work item references in the item
            linked_item = linkify_work_items_html(item)
            html += f"<li>{linked_item}</li>\n"
    else:
        html += "<li><em>No similar patterns found in history</em></li>\n"

    html += "</ul>\n"

    if analysis.related_tickets:
        html += "<p><strong>🔗 Related Tickets:</strong></p>\n"
        html += '<table style="border-collapse: collapse; width: 100%; margin-bottom: 10px;">\n'
        html += (
            '<tr style="background-color: #e3f2fd;">'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 80px;">ID</th>'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 120px;">Match Signals</th>'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 90px;">Created</th>'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 70px;">Status</th>'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 100px;">Owner</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Tags</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Name</th>'
            '</tr>\n'
        )
        for t in analysis.related_tickets:
            sim_html = _format_similarity_html(t)
            title = t.get('title', '')
            if '] CTI Threat Tipper: ' in title:
                title = title.split('] CTI Threat Tipper: ', 1)[1]
            display_title = title[:50] + '...' if len(title) > 50 else title
            ticket_id = t['id']
            ticket_link = linkify_work_items_html(f'#{ticket_id}')
            # Format created date
            raw_date = t.get('created_date', '')
            if raw_date:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(raw_date.replace('Z', '+00:00'))
                    created_str = dt.strftime('%m/%d/%Y')
                except Exception:
                    created_str = raw_date[:10]
            else:
                created_str = ''
            state = t.get('state', '')
            assigned_to = t.get('assigned_to', '')
            tags = t.get('tags', '')
            # Filter out ubiquitous tags that appear on all tippers
            if tags:
                tags = ';'.join(t_tag.strip() for t_tag in tags.split(';') if t_tag.strip().upper() != 'CTI')
            # Show tags as small badges
            tag_badges = ''
            if tags:
                for tag in tags.split(';')[:3]:
                    tag = tag.strip()
                    if tag:
                        tag_badges += (
                            f'<span style="background-color: #e8eaf6; padding: 1px 5px; '
                            f'border-radius: 3px; font-size: 11px; margin: 1px;">{tag}</span> '
                        )
                remaining = len(tags.split(';')) - 3
                if remaining > 0:
                    tag_badges += f'<em style="font-size: 11px;">(+{remaining})</em>'
            html += (
                f'<tr>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{ticket_link}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc; text-align: center;">{sim_html}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{created_str}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{state}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{assigned_to}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{tag_badges}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{display_title}</td>'
                f'</tr>\n'
            )
        html += "</table>\n"

    # Add threat intelligence section
    rf = analysis.rf_enrichment
    has_extracted = rf and rf.get('extracted_actors')
    has_rf_actors = rf and rf.get('actors')
    has_rf_iocs = rf and rf.get('high_risk_iocs')
    has_malware = bool(analysis.current_malware)

    if has_extracted or has_rf_actors or has_rf_iocs or has_malware:
        html += "\n<p><strong>🔮 Threat Intelligence:</strong></p>\n"

        # Show extracted actors with local alias info
        if has_extracted:
            html += "<p><em>Threat Actors:</em></p>\n<ul>\n"
            for actor in rf['extracted_actors']:
                name = actor.get('name', 'Unknown')
                common_name = actor.get('common_name', '')
                region = actor.get('region', '')
                aliases = actor.get('aliases_display', '')

                if common_name and common_name != name:
                    actor_html = f"<strong>{name}</strong> → {common_name}"
                else:
                    actor_html = f"<strong>{name}</strong>"

                if region:
                    actor_html += f" ({region})"
                if aliases:
                    actor_html += f"<br/>&nbsp;&nbsp;AKA: <em>{aliases}</em>"
                html += f"<li>{actor_html}</li>\n"
            html += "</ul>\n"

        # Show RF actor intel if available
        if has_rf_actors:
            html += "<p><em>Recorded Future Intel:</em></p>\n<ul>\n"
            for actor in rf['actors']:
                name = actor.get('name', 'Unknown')
                risk = actor.get('risk_score', 'N/A')
                categories = actor.get('categories', [])

                actor_html = f"<strong>{name}</strong> (RF Risk: {risk}/99)"
                if categories:
                    actor_html += f" [{', '.join(categories)}]"
                html += f"<li>{actor_html}</li>\n"
            html += "</ul>\n"

        # Show malware families (new vs familiar)
        if analysis.current_malware:
            new_malware, familiar_malware = split_by_history(
                analysis.current_malware, analysis.malware_history or {}
            )
            if new_malware:
                html += "<p><em>🆕 New Malware/Tools:</em></p>\n<ul>\n"
                for malware in new_malware:
                    html += f"<li>{malware}</li>\n"
                html += "</ul>\n"
            if familiar_malware:
                html += f"<details><summary><em>📋 Familiar Malware/Tools ({len(familiar_malware)})</em></summary>\n<ul>\n"
                for malware, seen_in in familiar_malware:
                    recency = _recency_label(seen_in, analysis.history_dates)
                    recency_html = f" &mdash; <em>{recency}</em>" if recency else ""
                    html += f"<li>{malware} (seen in {format_tipper_refs(seen_in, html=True)}{recency_html})</li>\n"
                html += "</ul>\n</details>\n"

        # Show IOCs (new vs familiar) - AZDO gets full list in tables
        if has_rf_iocs or analysis.total_iocs_extracted:
            total_extracted = sum(analysis.total_iocs_extracted.values()) if analysis.total_iocs_extracted else 0
            high_risk_count = len(rf.get('high_risk_iocs', [])) if rf else 0

            if high_risk_count > 0:
                new_iocs, familiar_iocs = split_by_history(
                    rf['high_risk_iocs'],
                    analysis.ioc_history or {},
                    key_fn=lambda x: x.get('value', '').lower()
                )
                if new_iocs:
                    html += "<p><em>🔍 First-Time IOCs</em> (not seen in previous tippers):</p>\n"
                    html += '<table style="border-collapse: collapse; width: 100%;">\n'
                    html += '<tr style="background-color: #e0e0e0;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IOC</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Type</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">RF Risk</th></tr>\n'
                    for ioc in new_iocs:
                        ioc_type = ioc.get('ioc_type', 'Unknown')
                        value = ioc.get('value', 'Unknown')
                        risk_score = ioc.get('risk_score', 0)
                        risk_level = ioc.get('risk_level', 'Unknown')
                        # Color code by risk level - text and background
                        risk_color, row_bg = get_risk_colors(risk_score)
                        html += f'<tr style="background-color: {row_bg};"><td style="border: 1px solid #ddd; padding: 8px;"><code>{value}</code></td><td style="border: 1px solid #ddd; padding: 8px;">{ioc_type}</td><td style="border: 1px solid #ddd; padding: 8px; color: {risk_color};"><strong>{risk_score}/99</strong> ({risk_level})</td></tr>\n'
                    html += "</table>\n"
                if familiar_iocs:
                    html += f"<details><summary><em>📋 Familiar IOCs ({len(familiar_iocs)})</em></summary>\n"
                    html += '<table style="border-collapse: collapse; width: 100%;">\n'
                    html += '<tr style="background-color: #e0e0e0;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IOC</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Type</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">RF Risk</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Seen In</th></tr>\n'
                    for ioc, seen_in in familiar_iocs:
                        ioc_type = ioc.get('ioc_type', 'Unknown')
                        value = ioc.get('value', 'Unknown')
                        risk_score = ioc.get('risk_score', 0)
                        risk_level = ioc.get('risk_level', 'Unknown')
                        risk_color, row_bg = get_risk_colors(risk_score)
                        recency = _recency_label(seen_in, analysis.history_dates)
                        seen_in_html = format_tipper_refs(seen_in, html=True)
                        if recency:
                            seen_in_html += f"<br/><span style='color: #666; font-size: 11px;'>{recency}</span>"
                        html += f'<tr style="background-color: {row_bg};"><td style="border: 1px solid #ddd; padding: 8px;"><code>{value}</code></td><td style="border: 1px solid #ddd; padding: 8px;">{ioc_type}</td><td style="border: 1px solid #ddd; padding: 8px; color: {risk_color};"><strong>{risk_score}/99</strong> ({risk_level})</td><td style="border: 1px solid #ddd; padding: 8px;">{seen_in_html}</td></tr>\n'
                    html += "</table>\n</details>\n"

            # Add note about total IOCs extracted
            if total_extracted > 0:
                html += f"<p><em>ℹ️ {high_risk_count} high-risk IOCs of {total_extracted} total extracted from description</em></p>\n"

    # Add detection rules coverage section
    if analysis.existing_rules:
        from .rules.formatters import format_rules_for_azdo
        rules_html = format_rules_for_azdo(analysis.existing_rules)
        if rules_html:
            html += rules_html

    # Add MITRE ATT&CK coverage gap analysis with technique-to-rule table
    html += "\n<h4>&#x1F3AF; MITRE ATT&CK Coverage:</h4>\n"
    if analysis.mitre_techniques:
        covered_count = len(analysis.mitre_covered)
        gap_count = len(analysis.mitre_gaps)
        total = len(analysis.mitre_techniques)

        if gap_count > 0:
            html += f"<p><strong>{covered_count}/{total}</strong> techniques covered, <span style='color: #c62828;'><strong>{gap_count} gap(s)</strong></span></p>\n"
        else:
            html += f"<p>&#x2705; <strong>All {total} techniques have detection rules</strong></p>\n"

        # Show detailed table of covered techniques with their rules (using mitre_rules from analyzer)
        if analysis.mitre_covered:
            html += '<table style="border-collapse: collapse; width: 100%; margin-bottom: 10px;">\n'
            html += (
                '<tr style="background-color: #e8f5e9;">'
                '<th style="padding: 6px; border: 1px solid #ccc; width: 100px;">Technique</th>'
                '<th style="padding: 6px; border: 1px solid #ccc; width: 80px;">Status</th>'
                '<th style="padding: 6px; border: 1px solid #ccc;">Detection Rule(s)</th>'
                '</tr>\n'
            )
            platform_labels = {"qradar": "QRadar", "crowdstrike": "CrowdStrike", "tanium": "Tanium"}
            for tech in analysis.mitre_covered:
                tech_link = f'<a href="https://attack.mitre.org/techniques/{tech.replace(".", "/")}/" target="_blank" style="color: #2e7d32;">{tech}</a>'
                rules = analysis.mitre_rules.get(tech.upper(), [])
                if rules:
                    rules_html = "<ul style='margin: 0; padding-left: 18px;'>"
                    for r in rules[:3]:
                        platform = platform_labels.get(r.get('platform', ''), r.get('platform', '?'))
                        name = r.get('name', 'Unknown')
                        truncated_name = name[:50] + "..." if len(name) > 50 else name
                        rtype = r.get('rule_type', 'rule')
                        rules_html += f"<li><strong>[{platform}]</strong> {truncated_name} <em>({rtype})</em></li>"
                    if len(rules) > 3:
                        rules_html += f"<li><em>+{len(rules) - 3} more rules</em></li>"
                    rules_html += "</ul>"
                else:
                    rules_html = "<em>Rule coverage detected</em>"
                html += (
                    f'<tr style="background-color: #f1f8e9;">'
                    f'<td style="padding: 6px; border: 1px solid #ccc;">{tech_link}</td>'
                    f'<td style="padding: 6px; border: 1px solid #ccc; color: #2e7d32;"><strong>COVERED</strong></td>'
                    f'<td style="padding: 6px; border: 1px solid #ccc;">{rules_html}</td>'
                    f'</tr>\n'
                )
            html += "</table>\n"

        # Show gaps as red badges
        if analysis.mitre_gaps:
            gap_badges = " ".join(
                f'<span style="background-color: #ffcdd2; color: #c62828; padding: 2px 6px; '
                f'border-radius: 3px; font-size: 11px; margin: 1px;">'
                f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/" '
                f'target="_blank" style="color: #c62828; text-decoration: none;">&#x26A0; {t}</a></span>'
                for t in analysis.mitre_gaps[:10]
            )
            html += f"<p><strong>Gaps</strong> (no detection rules): {gap_badges}</p>\n"
    else:
        html += "<p><em>(No MITRE techniques identified in this tipper)</em></p>\n"

    # Add Actionable Next Steps section
    if analysis.actionable_steps:
        html += "\n<h4>&#x1F4CB; Actionable Next Steps</h4>\n"
        html += '<table style="border-collapse: collapse; width: 100%; margin-bottom: 10px;">\n'
        html += (
            '<tr style="background-color: #e3f2fd;">'
            '<th style="padding: 6px; border: 1px solid #ccc; width: 80px;">Priority</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Action</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Details</th>'
            '</tr>\n'
        )
        priority_colors = {
            'HIGH': ('#c62828', '#ffebee'),
            'MEDIUM': ('#f57c00', '#fff3e0'),
            'LOW': ('#388e3c', '#e8f5e9'),
        }
        for step in analysis.actionable_steps:
            priority = step.get('priority', 'MEDIUM')
            text_color, bg_color = priority_colors.get(priority, ('#666', '#f5f5f5'))
            html += (
                f'<tr style="background-color: {bg_color};">'
                f'<td style="padding: 6px; border: 1px solid #ccc; text-align: center;">'
                f'<strong style="color: {text_color};">{priority}</strong></td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;"><strong>{step.get("action", "")}</strong></td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{step.get("detail", "")}</td>'
                f'</tr>\n'
            )
        html += "</table>\n"

    # Linkify any work item references in the recommendation
    linked_recommendation = linkify_work_items_html(analysis.recommendation)
    html += f"""
<p><strong>💡 Recommendation:</strong><br/>{linked_recommendation}</p>
<hr/>
<p><em>Generated by Pokedex Tipper Analyzer</em></p>
</div>"""

    return html


def format_hunt_results_for_webex(result: IOCHuntResult, tipper_id: str, azdo_url: str = "") -> str:
    """Format IOC hunt results as concise markdown for Webex follow-up message.

    Args:
        result: IOCHuntResult with hits from all tools
        tipper_id: The tipper work item ID
        azdo_url: AZDO work item URL for the link
    """
    qradar_days = result.search_hours_qradar // 24
    crowdstrike_days = result.search_hours_crowdstrike // 24
    xsiam_days = result.search_hours_xsiam // 24
    # Only mention a tool in the lookback footer if it actually ran
    lookback_parts = [f"QRadar: {qradar_days}d", f"CrowdStrike: {crowdstrike_days}d"]
    if result.xsiam:
        lookback_parts.append(f"XSIAM: {xsiam_days}d")
    lookback_str = ", ".join(lookback_parts)

    if result.total_hits == 0:
        output = f"✅ **IOC Hunt Complete** — #{tipper_id}\n"
        output += f"No hits found. Searched {result.total_iocs_searched} IOCs ({lookback_str}).\n"
        if azdo_url:
            output += f"_📝 Results posted to [#{tipper_id}]({azdo_url})_\n"
        return output

    output = f"🚨 **IOC Hunt Complete** — #{tipper_id} — **{result.total_hits} hit(s) found!**\n\n"

    # Collect all hits into a flat list for the table
    rows = []  # (ioc_value, ioc_type, tool_name, event_count)
    for tool_result, tool_short in [
        (result.qradar, "QRadar"),
        (result.crowdstrike, "CrowdStrike"),
        (result.abnormal, "Abnormal"),
        (result.xsiam, "XSIAM"),
    ]:
        if not tool_result or tool_result.total_hits == 0:
            continue
        for hit in tool_result.ip_hits:
            # Handle different count fields: QRadar uses event_count, CrowdStrike uses detection/alert/network
            count = (hit.get('event_count') or
                     hit.get('detection_count', 0) + hit.get('alert_count', 0) + hit.get('network_hosts_count', 0))
            rows.append((defang_ioc(hit['ip'], 'ip'), "IP", tool_short, count))
        for hit in tool_result.domain_hits:
            rows.append((defang_ioc(hit['domain'], 'domain'), "domain", tool_short,
                         hit.get('event_count') or hit.get('threat_count', 0)))
        for hit in tool_result.url_hits:
            # URL paths like registry.npmjs.org/openclaw/
            # Handle both QRadar (event_count) and CrowdStrike (host_count)
            rows.append((defang_ioc(hit['url'], 'domain'), "URL", tool_short,
                         hit.get('event_count') or hit.get('host_count', 0)))
        for hit in tool_result.filename_hits:
            # Malicious filenames like install.ps1
            rows.append((hit['filename'], "file", tool_short,
                         hit.get('detection_count', 0)))
        for hit in tool_result.hash_hits:
            rows.append((hit['hash'], "hash", tool_short,
                         hit.get('event_count') or hit.get('detection_count', 0)))
        for hit in tool_result.email_hits:
            rows.append((hit['email'], "email", tool_short, hit['threat_count']))

    if rows:
        output += "```\n"
        output += f"{'IOC':<52} {'Type':<8} {'Tool':<13} {'Events':<8}\n"
        output += f"{'-'*52} {'-'*8} {'-'*13} {'-'*8}\n"
        for ioc_val, ioc_type, tool, count in rows[:15]:
            display_val = ioc_val[:49] + "..." if len(ioc_val) > 52 else ioc_val
            output += f"{display_val:<52} {ioc_type:<8} {tool:<13} {count:<8}\n"
        if len(rows) > 15:
            output += f"... and {len(rows) - 15} more\n"
        output += "```\n"

    output += f"\n_Searched {result.total_iocs_searched} IOCs ({lookback_str})._\n"

    # Note any access/permission issues
    if result.access_issues:
        for issue in result.access_issues:
            output += f"_⚠️ {issue}_\n"

    if azdo_url:
        output += f"_📝 Full details posted to [#{tipper_id}]({azdo_url})_\n"

    return output


def format_single_tool_hunt_for_azdo(
    tool_result: ToolHuntResult,
    tipper_id: str,
    tipper_title: str,
    search_hours: int,
    total_iocs_searched: int,
    searched_iocs: dict = None,
    rf_enrichment: dict = None,
) -> str:
    """Format a single tool's hunt results as HTML for AZDO comment.

    Args:
        tool_result: ToolHuntResult for one tool (QRadar, CrowdStrike, or Abnormal)
        tipper_id: Tipper work item ID
        tipper_title: Tipper title for context
        search_hours: Hours searched back
        total_iocs_searched: Total IOCs that were searched
        searched_iocs: Dict with searched_domains, searched_ips, etc.
        rf_enrichment: Optional RF enrichment dict with 'iocs' list for risk scores
    """
    from urllib.parse import quote
    from my_config import get_config

    config = get_config()
    searched_iocs = searched_iocs or {}

    # Tool-specific icons
    tool_icons = {
        'QRadar': '&#x1F50D;',      # Magnifying glass
        'CrowdStrike': '&#x1F985;',  # Eagle
        'Abnormal': '&#x1F4E7;',     # Email
        'XSIAM': '&#x1F9ED;',        # Compass
    }
    tool_icon = tool_icons.get(tool_result.tool_name, '&#x1F50D;')

    # Determine status: error, hits, or clean
    has_errors = bool(tool_result.errors)
    if has_errors and tool_result.total_hits == 0:
        status_icon = "&#x26A0;"  # Warning
        status_text = f"<span style='color: #c62828;'><strong>{tool_result.tool_name} hunt failed</strong></span>"
    elif tool_result.total_hits == 0:
        status_icon = "&#x2705;"  # Green check
        status_text = f"No IOC hits found in {tool_result.tool_name}"
    else:
        status_icon = "&#x1F6A8;"  # Red siren
        status_text = f"<strong>{tool_result.total_hits} IOC(s) found in {tool_result.tool_name}!</strong>"

    # Build RF risk lookup
    rf_lookup = {}
    if rf_enrichment and rf_enrichment.get('iocs'):
        for ioc in rf_enrichment['iocs']:
            val = ioc.get('value', '').lower()
            if val:
                rf_lookup[val] = ioc

    # QRadar console URL for deep links
    qradar_base = (config.qradar_console_url or config.qradar_api_url or '').rstrip('/')
    if qradar_base.endswith('/api'):
        qradar_console = qradar_base[:-4]
    else:
        qradar_console = qradar_base

    def _rf_risk_cell(ioc_value: str) -> str:
        rf = rf_lookup.get(ioc_value.lower())
        if not rf:
            return "<td style='padding: 6px; border: 1px solid #ccc; color: #999;'>N/A</td>"
        score = rf.get('risk_score', 0)
        level = rf.get('risk_level', 'Unknown')
        if score >= 65:
            color = '#d32f2f'
        elif score >= 25:
            color = '#f57c00'
        else:
            color = '#388e3c'
        rules_list = rf.get('rules', [])
        tooltip = '; '.join(rules_list[:3]) if rules_list else ''
        return (
            f"<td style='padding: 6px; border: 1px solid #ccc;' title='{tooltip}'>"
            f"<strong style='color: {color};'>{score}/99</strong> ({level})</td>"
        )

    def _qradar_search_link(ioc_value: str, ioc_type: str, count: int) -> str:
        if not qradar_console or tool_result.tool_name != 'QRadar':
            return str(count)
        days = search_hours // 24
        escaped = _escape_aql_value(ioc_value)
        if ioc_type == 'domain':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{escaped.lower()}%' OR LOWER(\"TSLD\") LIKE '%{escaped.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'url':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{escaped.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'ip':
            aql = f"SELECT * FROM events WHERE sourceip = '{escaped}' OR destinationip = '{escaped}' LAST {days} DAYS"
        elif ioc_type == 'hash':
            aql = f"SELECT * FROM events WHERE \"MD5 Hash\" = '{escaped}' OR \"SHA256 Hash\" = '{escaped}' LAST {days} DAYS"
        else:
            return str(count)
        encoded_aql = quote(aql, safe='')
        url = f"{qradar_console}/console/do/ariel/arielSearch?appName=Viewer&pageId=EventList&dispatch=performSearch&value={encoded_aql}"
        return f"<a href='{url}' target='_blank'>{count} events</a>"

    html_parts = [
        "<div style='font-family: Segoe UI, sans-serif; font-size: 13px;'>",
        f"<h3>{tool_icon} {tool_result.tool_name} IOC Hunt Results</h3>",
        f"<p>{status_icon} {status_text}</p>",
        f"<p><em>Searched {total_iocs_searched} IOCs over last {search_hours} hours ({search_hours // 24} days)</em></p>",
    ]

    # Show IOCs searched in a clean multi-column table format
    ioc_sections = []
    if searched_iocs.get('domains'):
        ioc_sections.append(('Domains', searched_iocs['domains'], 'domain'))
    if searched_iocs.get('urls'):
        ioc_sections.append(('URLs', searched_iocs['urls'], 'url'))
    if searched_iocs.get('filenames'):
        ioc_sections.append(('Filenames', searched_iocs['filenames'], 'filename'))
    if searched_iocs.get('ips'):
        ioc_sections.append(('IPs', searched_iocs['ips'], 'ip'))
    if searched_iocs.get('hashes'):
        ioc_sections.append(('Hashes', searched_iocs['hashes'], 'hash'))

    if ioc_sections:
        html_parts.append("<details open><summary><strong>IOCs Searched</strong></summary>")
        html_parts.append("<div style='font-size: 12px; margin: 8px 0;'>")

        for section_name, items, ioc_type in ioc_sections:
            html_parts.append(f"<p style='margin: 12px 0 4px 0;'><strong>{section_name}:</strong></p>")
            # Use a 3-column table for readability
            html_parts.append("<table style='border-collapse: collapse; width: 100%; font-size: 11px;'>")
            # Calculate rows needed for 3 columns
            cols = 3
            rows_needed = (len(items) + cols - 1) // cols
            for row_idx in range(rows_needed):
                html_parts.append("<tr>")
                for col_idx in range(cols):
                    item_idx = row_idx + col_idx * rows_needed
                    if item_idx < len(items):
                        item = items[item_idx]
                        # Truncate hashes for display
                        display_val = f"{item[:16]}..." if ioc_type == 'hash' else item
                        # Wrap in <code> to prevent auto-linking
                        html_parts.append(
                            f"<td style='padding: 3px 8px; border: 1px solid #ddd; "
                            f"background-color: #f8f8f8;'><code>{display_val}</code></td>"
                        )
                    else:
                        html_parts.append("<td style='border: 1px solid #ddd;'></td>")
                html_parts.append("</tr>")
            html_parts.append("</table>")

        html_parts.append("</div></details>")

    th_style = "padding: 6px; border: 1px solid #ccc;"
    td_style = "padding: 6px; border: 1px solid #ccc;"

    # IP Hits
    if tool_result.ip_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>IP</th>"
            f"<th style='{th_style}'>Events</th>"
            f"<th style='{th_style}'>Direction</th>"
            f"<th style='{th_style}'>RF Risk</th>"
            f"<th style='{th_style}'>Sources</th>"
            f"<th style='{th_style}'>Users</th>"
            f"<th style='{th_style}'>Hosts</th></tr>"
        )
        for hit in tool_result.ip_hits:
            ip = hit['ip']
            # Build count display - show breakdown for CrowdStrike (detects/alerts + network hosts)
            detection_count = hit.get('detection_count', 0)
            alert_count = hit.get('alert_count', 0)
            network_hosts = hit.get('network_hosts_count', 0)
            event_count = hit.get('event_count', 0)

            if detection_count or alert_count or network_hosts:
                # CrowdStrike format - show breakdown
                parts = []
                if detection_count + alert_count > 0:
                    parts.append(f"{detection_count + alert_count} detects")
                if network_hosts > 0:
                    parts.append(f"{network_hosts} hosts")
                count = detection_count + alert_count + network_hosts
                count_display = ', '.join(parts) if parts else str(count)
            else:
                # QRadar/other format
                count = event_count
                count_display = _qradar_search_link(ip, 'ip', count)

            direction = hit.get('direction', '')
            sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
            users = hit.get('users', [])
            hosts = hit.get('hosts', []) or hit.get('hostnames', [])
            users_display = ', '.join(users[:3]) + (f" (+{len(users) - 3})" if len(users) > 3 else "")
            hosts_display = ', '.join(hosts[:3]) + (f" (+{len(hosts) - 3})" if len(hosts) > 3 else "")
            html_parts.append(
                f"<tr style='background-color: #ffe6e6;'>"
                f"<td style='{td_style}'><code>{ip}</code></td>"
                f"<td style='{td_style}'>{count_display}</td>"
                f"<td style='{td_style}'>{direction}</td>"
                f"{_rf_risk_cell(ip)}"
                f"<td style='{td_style}'>{sources}</td>"
                f"<td style='{td_style}; font-size: 11px;'>{users_display}</td>"
                f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td></tr>"
            )
        html_parts.append("</table>")

    # Domain Hits
    if tool_result.domain_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>Domain</th>"
            f"<th style='{th_style}'>Events</th>"
            f"<th style='{th_style}'>RF Risk</th>"
            f"<th style='{th_style}'>Sources</th>"
            f"<th style='{th_style}'>Users</th></tr>"
        )
        for hit in tool_result.domain_hits:
            domain = hit['domain']
            count = hit.get('event_count') or hit.get('threat_count') or hit.get('intel_count', 0)
            sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
            users = hit.get('users', [])
            users_display = ', '.join(users[:3]) + (f" (+{len(users) - 3})" if len(users) > 3 else "")
            count_display = _qradar_search_link(domain, 'domain', count)
            html_parts.append(
                f"<tr style='background-color: #ffe6e6;'>"
                f"<td style='{td_style}'><code>{domain}</code></td>"
                f"<td style='{td_style}'>{count_display}</td>"
                f"{_rf_risk_cell(domain)}"
                f"<td style='{td_style}'>{sources}</td>"
                f"<td style='{td_style}; font-size: 11px;'>{users_display}</td></tr>"
            )
        html_parts.append("</table>")

    # URL Hits
    if tool_result.url_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>URL Path</th>"
            f"<th style='{th_style}'>Events</th>"
            f"<th style='{th_style}'>Sources</th>"
            f"<th style='{th_style}'>Hosts</th></tr>"
        )
        for hit in tool_result.url_hits:
            url = hit['url']
            count = hit.get('event_count') or hit.get('host_count', 0)
            sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
            hosts = hit.get('hosts', []) or hit.get('hostnames', [])
            hosts_display = ', '.join(hosts[:3]) + (f" (+{len(hosts) - 3})" if len(hosts) > 3 else "")
            url_display = url if len(url) <= 50 else url[:47] + '...'
            count_display = _qradar_search_link(url.replace('https://', ''), 'url', count)
            html_parts.append(
                f"<tr style='background-color: #fff3e6;'>"
                f"<td style='{td_style}'><code>{url_display}</code></td>"
                f"<td style='{td_style}'>{count_display}</td>"
                f"<td style='{td_style}'>{sources}</td>"
                f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td></tr>"
            )
        html_parts.append("</table>")

    # Filename Hits
    if tool_result.filename_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>Filename</th>"
            f"<th style='{th_style}'>Detections</th>"
            f"<th style='{th_style}'>Hosts</th></tr>"
        )
        for hit in tool_result.filename_hits:
            filename = hit['filename']
            count = hit.get('detection_count', 0)
            hosts = hit.get('hostnames', [])
            hosts_display = ', '.join(hosts[:5]) + (f" (+{len(hosts) - 5})" if len(hosts) > 5 else "")
            html_parts.append(
                f"<tr style='background-color: #e6f3ff;'>"
                f"<td style='{td_style}'><code>{filename}</code></td>"
                f"<td style='{td_style}'>{count}</td>"
                f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td></tr>"
            )
        html_parts.append("</table>")

    # Hash Hits
    if tool_result.hash_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>Hash</th>"
            f"<th style='{th_style}'>Type</th>"
            f"<th style='{th_style}'>Events</th>"
            f"<th style='{th_style}'>RF Risk</th>"
            f"<th style='{th_style}'>Hosts</th></tr>"
        )
        for hit in tool_result.hash_hits:
            file_hash = hit['hash']
            count = hit.get('event_count') or hit.get('detection_count', 0)
            hosts = hit.get('hostnames', [])
            hosts_display = ', '.join(hosts[:3]) + (f" (+{len(hosts) - 3})" if len(hosts) > 3 else "")
            count_display = _qradar_search_link(file_hash, 'hash', count)
            html_parts.append(
                f"<tr style='background-color: #ffe6e6;'>"
                f"<td style='{td_style}'><code>{file_hash[:32]}...</code></td>"
                f"<td style='{td_style}'>{hit.get('hash_type', 'HASH')}</td>"
                f"<td style='{td_style}'>{count_display}</td>"
                f"{_rf_risk_cell(file_hash)}"
                f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td></tr>"
            )
        html_parts.append("</table>")

    # Email Hits (Abnormal)
    if tool_result.email_hits:
        html_parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
        html_parts.append(
            f"<tr style='background-color: #f0f0f0;'>"
            f"<th style='{th_style}'>Email</th>"
            f"<th style='{th_style}'>Threats</th>"
            f"<th style='{th_style}'>Attack Types</th></tr>"
        )
        for hit in tool_result.email_hits:
            html_parts.append(
                f"<tr style='background-color: #ffe6e6;'>"
                f"<td style='{td_style}'><code>{hit['email']}</code></td>"
                f"<td style='{td_style}'>{hit['threat_count']}</td>"
                f"<td style='{td_style}'>{', '.join(hit.get('attack_types', []))}</td></tr>"
            )
        html_parts.append("</table>")

    # Errors - show prominently if tool failed, collapsed otherwise
    if tool_result.errors:
        if has_errors and tool_result.total_hits == 0:
            # Tool failed completely - show error prominently with red banner
            html_parts.append(
                "<div style='background-color: #ffebee; border-left: 4px solid #c62828; "
                "padding: 10px; margin: 10px 0;'>"
                "<strong style='color: #c62828;'>&#x26A0; Hunt Failed</strong><ul style='margin: 5px 0 0 0;'>"
            )
            for err in tool_result.errors[:5]:
                html_parts.append(f"<li>{err}</li>")
            html_parts.append("</ul></div>")
        else:
            # Some errors but also some results - collapse errors
            html_parts.append("<details><summary>&#x26A0; Errors</summary><ul style='color: #666;'>")
            for err in tool_result.errors[:3]:
                html_parts.append(f"<li>{err}</li>")
            html_parts.append("</ul></details>")

    # Separate LogScale queries from FQL/API queries
    logscale_queries = [q for q in (tool_result.queries or []) if q.get('query_type') == 'logscale']
    api_queries = [q for q in (tool_result.queries or []) if q.get('query_type') != 'logscale']

    # Event Search queries (LogScale) - shown prominently for analysts
    if logscale_queries and tool_result.tool_name == 'CrowdStrike':
        # Check if any queries were executed successfully
        executed_queries = [q for q in logscale_queries if q.get('execution_status') == 'executed']
        manual_queries = [q for q in logscale_queries if q.get('execution_status') != 'executed']

        if executed_queries:
            # Show executed queries with results
            total_events = sum(q.get('event_count', 0) for q in executed_queries)
            html_parts.append(f"<h4>&#x1F50E; Event Search Results ({total_events} events found)</h4>")

            for q in executed_queries:
                query_type = q.get('type', 'Event Search')
                query_text = q.get('query', '')
                event_count = q.get('event_count', 0)
                sample_events = q.get('sample_events', [])
                escaped_query = query_text.replace('<', '&lt;').replace('>', '&gt;')

                # Status badge based on event count
                if event_count > 0:
                    status_badge = f"<span style='background-color: #ffcdd2; color: #c62828; padding: 2px 8px; border-radius: 4px; font-size: 10px; margin-left: 8px;'>&#x26A0; {event_count} events</span>"
                else:
                    status_badge = "<span style='background-color: #c8e6c9; color: #2e7d32; padding: 2px 8px; border-radius: 4px; font-size: 10px; margin-left: 8px;'>&#x2705; No hits</span>"

                html_parts.append(f"<p><strong>{query_type}:</strong>{status_badge}</p>")
                html_parts.append(
                    f"<pre style='background-color: #e3f2fd; padding: 10px; font-size: 11px; "
                    f"overflow-x: auto; white-space: pre-wrap; border-left: 4px solid #1976d2;'>{escaped_query}</pre>"
                )
                cs_link = _get_falcon_logscale_link(query_text)
                if cs_link:
                    html_parts.append(f"<p><a href='{cs_link}' target='_blank' style='color: #1976d2;'>&#x1F517; Open in Falcon Event Search</a></p>")

                # Show sample events if any
                if sample_events:
                    html_parts.append("<details><summary>Sample Events (first 5)</summary>")
                    html_parts.append("<ul style='font-size: 11px;'>")
                    for event in sample_events[:5]:
                        # Extract key fields from event
                        timestamp = event.get('@timestamp', event.get('timestamp', 'N/A'))
                        hostname = event.get('ComputerName', event.get('hostname', 'N/A'))
                        event_type = event.get('#event_simpleName', event.get('event_type', 'N/A'))
                        summary = f"{timestamp} | {hostname} | {event_type}"
                        html_parts.append(f"<li><code>{summary}</code></li>")
                    html_parts.append("</ul></details>")

        if manual_queries:
            # Show queries that need manual execution
            if executed_queries:
                html_parts.append("<h4>&#x1F4CB; Additional Queries (manual execution)</h4>")
            else:
                html_parts.append("<h4>&#x1F50E; Event Search Queries (for deeper investigation)</h4>")
            html_parts.append("<p><em>Open each query straight in Falcon Event Search, or copy it to hunt across raw telemetry:</em></p>")

            for q in manual_queries:
                query_type = q.get('type', 'Event Search')
                query_text = q.get('query', '')
                escaped_query = query_text.replace('<', '&lt;').replace('>', '&gt;')
                html_parts.append(f"<p><strong>{query_type}:</strong></p>")
                html_parts.append(
                    f"<pre style='background-color: #e3f2fd; padding: 10px; font-size: 11px; "
                    f"overflow-x: auto; white-space: pre-wrap; border-left: 4px solid #1976d2;'>{escaped_query}</pre>"
                )
                cs_link = _get_falcon_logscale_link(query_text)
                if cs_link:
                    html_parts.append(f"<p><a href='{cs_link}' target='_blank' style='color: #1976d2;'>&#x1F517; Open in Falcon Event Search</a></p>")

    # API queries executed (FQL) - collapsed for reference
    if api_queries:
        html_parts.append("<details><summary>&#x1F50D; API Queries Executed</summary>")
        for q in api_queries:
            query_type = q.get('type', 'Search')
            query_text = q.get('query', '')
            escaped_query = query_text.replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f"<p><strong>{query_type}:</strong></p>")
            html_parts.append(f"<pre style='background-color: #f5f5f5; padding: 8px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;'>{escaped_query}</pre>")
            # Add clickable console links based on tool
            if tool_result.tool_name == 'CrowdStrike':
                falcon_link = _get_falcon_console_link(query_type, query_text)
                if falcon_link:
                    url, link_text = falcon_link
                    html_parts.append(f"<p><a href='{url}' target='_blank' style='color: #1976d2;'>&#x1F517; {link_text}</a></p>")
            elif tool_result.tool_name == 'QRadar':
                qradar_link = _get_qradar_console_link(query_text)
                if qradar_link:
                    url, link_text = qradar_link
                    html_parts.append(f"<p><a href='{url}' target='_blank' style='color: #1976d2;'>&#x1F517; {link_text}</a></p>")
        html_parts.append("</details>")

    html_parts.append(f"<p><em>Generated by Pokedex IOC Hunter</em></p>")
    html_parts.append("</div>")

    return "\n".join(html_parts)


def format_hunt_results_for_azdo(result: IOCHuntResult, rf_enrichment: dict = None) -> str:
    """Format IOC hunt results as HTML for AZDO comment.

    Args:
        result: IOCHuntResult with hits from all tools
        rf_enrichment: Optional RF enrichment dict with 'iocs' list for risk scores
    """
    from urllib.parse import quote
    from my_config import get_config

    config = get_config()

    if result.total_hits == 0:
        status_icon = "&#x2705;"  # Green check
        status_text = "No IOC hits found in environment"
    else:
        status_icon = "&#x1F6A8;"  # Red siren
        status_text = f"<strong>{result.total_hits} IOC(s) found in environment!</strong>"

    # Build RF risk lookup: ioc_value (lowercase) -> {risk_score, risk_level, rules}
    rf_lookup = {}
    if rf_enrichment and rf_enrichment.get('iocs'):
        for ioc in rf_enrichment['iocs']:
            val = ioc.get('value', '').lower()
            if val:
                rf_lookup[val] = ioc

    # QRadar console URL for deep links
    qradar_base = (config.qradar_console_url or config.qradar_api_url or '').rstrip('/')
    # Strip /api suffix if present to get console URL
    if qradar_base.endswith('/api'):
        qradar_console = qradar_base[:-4]
    else:
        qradar_console = qradar_base

    def _rf_risk_cell(ioc_value: str) -> str:
        """Generate RF risk HTML for a given IOC value."""
        rf = rf_lookup.get(ioc_value.lower())
        if not rf:
            return "<td style='padding: 6px; border: 1px solid #ccc; color: #999;'>N/A</td>"
        score = rf.get('risk_score', 0)
        level = rf.get('risk_level', 'Unknown')
        # Color code by risk level
        if score >= 65:
            color = '#d32f2f'  # Red
        elif score >= 25:
            color = '#f57c00'  # Orange
        else:
            color = '#388e3c'  # Green
        rules_list = rf.get('rules', [])
        tooltip = '; '.join(rules_list[:3]) if rules_list else ''
        return (
            f"<td style='padding: 6px; border: 1px solid #ccc;' title='{tooltip}'>"
            f"<strong style='color: {color};'>{score}/99</strong> ({level})</td>"
        )

    def _qradar_search_link(ioc_value: str, ioc_type: str, count: int) -> str:
        """Generate QRadar AQL search link for an IOC."""
        if not qradar_console:
            return str(count)
        days = result.search_hours_qradar // 24
        escaped = _escape_aql_value(ioc_value)
        if ioc_type == 'domain':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{escaped.lower()}%' OR LOWER(\"TSLD\") LIKE '%{escaped.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'url':
            # URL paths like registry.npmjs.org/openclaw/
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{escaped.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'ip':
            aql = f"SELECT * FROM events WHERE sourceip = '{escaped}' OR destinationip = '{escaped}' LAST {days} DAYS"
        elif ioc_type == 'hash':
            aql = f"SELECT * FROM events WHERE \"MD5 Hash\" = '{escaped}' OR \"SHA256 Hash\" = '{escaped}' LAST {days} DAYS"
        else:
            return str(count)
        encoded_aql = quote(aql, safe='')
        url = f"{qradar_console}/console/do/ariel/arielSearch?appName=Viewer&pageId=EventList&dispatch=performSearch&value={encoded_aql}"
        return f"<a href='{url}' target='_blank'>{count} events</a>"

    qradar_days = result.search_hours_qradar // 24
    crowdstrike_days = result.search_hours_crowdstrike // 24
    html_parts = [
        "<div style='font-family: Segoe UI, sans-serif; font-size: 13px;'>",
        f"<h3>{status_icon} IOC Hunt &mdash; Indicator Sweep</h3>",
        "<p><em>Automated lookup of the tipper's known indicators (IPs, domains, hashes, "
        "filenames) across deployed tooling. For behavioral/TTP hunting see the "
        "&#x1F9ED; Behavioral Threat Hunt comment.</em></p>",
        f"<p>{status_text}</p>",
        f"<p><em>Searched {result.total_iocs_searched} IOCs (QRadar: {qradar_days} days, CrowdStrike: {crowdstrike_days} days)</em></p>",
    ]

    # Show what IOCs were searched in a clean multi-column table format
    ioc_sections = []
    if result.searched_domains:
        ioc_sections.append(('Domains', result.searched_domains, 'domain'))
    if result.searched_urls:
        ioc_sections.append(('URLs', result.searched_urls, 'url'))
    if result.searched_filenames:
        ioc_sections.append(('Filenames', result.searched_filenames, 'filename'))
    if result.searched_ips:
        ioc_sections.append(('IPs', result.searched_ips, 'ip'))
    if result.searched_hashes:
        ioc_sections.append(('Hashes', result.searched_hashes, 'hash'))

    if ioc_sections:
        html_parts.append("<details><summary><strong>IOCs Searched</strong></summary>")
        html_parts.append("<div style='font-size: 12px; margin: 8px 0;'>")

        for section_name, items, ioc_type in ioc_sections:
            html_parts.append(f"<p style='margin: 12px 0 4px 0;'><strong>{section_name}:</strong></p>")
            # Use a 3-column table for readability
            html_parts.append("<table style='border-collapse: collapse; width: 100%; font-size: 11px;'>")
            # Calculate rows needed for 3 columns
            cols = 3
            rows_needed = (len(items) + cols - 1) // cols
            for row_idx in range(rows_needed):
                html_parts.append("<tr>")
                for col_idx in range(cols):
                    item_idx = row_idx + col_idx * rows_needed
                    if item_idx < len(items):
                        item = items[item_idx]
                        # Truncate hashes for display
                        display_val = f"{item[:16]}..." if ioc_type == 'hash' else item
                        # Wrap in <code> to prevent auto-linking
                        html_parts.append(
                            f"<td style='padding: 3px 8px; border: 1px solid #ddd; "
                            f"background-color: #f8f8f8;'><code>{display_val}</code></td>"
                        )
                    else:
                        html_parts.append("<td style='border: 1px solid #ddd;'></td>")
                html_parts.append("</tr>")
            html_parts.append("</table>")

        html_parts.append("</div></details>")

    # Add environment exposure summary if there are hits
    if result.total_hits > 0:
        exposure_parts = []
        if result.unique_hosts > 0:
            exposure_parts.append(f"<strong>{result.unique_hosts}</strong> unique host(s)")
        if result.unique_sources:
            exposure_parts.append(f"<strong>{len(result.unique_sources)}</strong> log source(s): {', '.join(result.unique_sources[:5])}")
        if exposure_parts:
            html_parts.append(
                f"<div style='background-color: #fff3e0; border-left: 4px solid #f57c00; padding: 8px; margin: 8px 0;'>"
                f"<strong>&#x26A0; Environment Exposure:</strong> {' | '.join(exposure_parts)}"
                f"</div>"
            )

    # Helper to format a tool's results
    def format_tool_section(tool_result: ToolHuntResult, tool_icon: str, tool_key: str):
        if not tool_result or tool_result.total_hits == 0:
            return []

        parts = []

        th_style = "padding: 6px; border: 1px solid #ccc;"
        td_style = "padding: 6px; border: 1px solid #ccc;"

        # IP Hits
        if tool_result.ip_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>IP</th>"
                f"<th style='{th_style}'>Events</th>"
                f"<th style='{th_style}'>Direction</th>"
                f"<th style='{th_style}'>RF Risk</th>"
                f"<th style='{th_style}'>Sources</th>"
                f"<th style='{th_style}'>Affected Users</th>"
                f"<th style='{th_style}'>Affected Hosts</th>"
                f"<th style='{th_style}'>Context</th>"
                f"<th style='{th_style}'>First Seen</th>"
                f"<th style='{th_style}'>Last Seen</th></tr>"
            )
            for hit in tool_result.ip_hits:
                ip = hit['ip']
                count = hit['event_count']
                direction = hit.get('direction', '')
                sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
                # Format users and hosts
                users = hit.get('users', [])
                hosts = hit.get('hosts', [])
                users_display = ', '.join(users[:3])
                if len(users) > 3:
                    users_display += f" (+{len(users) - 3} more)"
                hosts_display = ', '.join(hosts[:3])
                if len(hosts) > 3:
                    hosts_display += f" (+{len(hosts) - 3} more)"
                # Format context as semicolon-separated list
                context_list = hit.get('context', [])
                context = '; '.join(context_list[:2]) if context_list else ''
                if tool_key == 'qradar':
                    count_display = _qradar_search_link(ip, 'ip', count)
                else:
                    count_display = str(count)
                parts.append(
                    f"<tr style='background-color: #ffe6e6;'>"
                    f"<td style='{td_style}'><code>{ip}</code></td>"
                    f"<td style='{td_style}'>{count_display}</td>"
                    f"<td style='{td_style}'>{direction}</td>"
                    f"{_rf_risk_cell(ip)}"
                    f"<td style='{td_style}'>{sources}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{users_display}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{context}</td>"
                    f"<td style='{td_style}'>{hit.get('first_seen', 'N/A')}</td>"
                    f"<td style='{td_style}'>{hit.get('last_seen', 'N/A')}</td></tr>"
                )
            parts.append("</table>")

        # Domain Hits
        if tool_result.domain_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>Domain</th>"
                f"<th style='{th_style}'>Events</th>"
                f"<th style='{th_style}'>RF Risk</th>"
                f"<th style='{th_style}'>Sources</th>"
                f"<th style='{th_style}'>Affected Users</th>"
                f"<th style='{th_style}'>Email Recipients</th>"
                f"<th style='{th_style}'>Context</th>"
                f"<th style='{th_style}'>First Seen</th>"
                f"<th style='{th_style}'>Last Seen</th></tr>"
            )
            for hit in tool_result.domain_hits:
                domain = hit['domain']
                count = hit.get('event_count') or hit.get('threat_count', 0)
                sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
                # Format users and recipients
                users = hit.get('users', [])
                recipients = hit.get('recipients', [])
                users_display = ', '.join(users[:3])
                if len(users) > 3:
                    users_display += f" (+{len(users) - 3} more)"
                recipients_display = ', '.join(recipients[:3])
                if len(recipients) > 3:
                    recipients_display += f" (+{len(recipients) - 3} more)"
                # Format context as semicolon-separated list
                context_list = hit.get('context', [])
                context = '; '.join(context_list[:2]) if context_list else ''
                if tool_key == 'qradar':
                    count_display = _qradar_search_link(domain, 'domain', count)
                else:
                    count_display = str(count)
                parts.append(
                    f"<tr style='background-color: #ffe6e6;'>"
                    f"<td style='{td_style}'><code>{domain}</code></td>"
                    f"<td style='{td_style}'>{count_display}</td>"
                    f"{_rf_risk_cell(domain)}"
                    f"<td style='{td_style}'>{sources}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{users_display}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{recipients_display}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{context}</td>"
                    f"<td style='{td_style}'>{hit.get('first_seen', 'N/A')}</td>"
                    f"<td style='{td_style}'>{hit.get('last_seen', 'N/A')}</td></tr>"
                )
            parts.append("</table>")

        # URL Hits (paths like registry.npmjs.org/openclaw/)
        if tool_result.url_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>URL Path</th>"
                f"<th style='{th_style}'>Events</th>"
                f"<th style='{th_style}'>Sources</th>"
                f"<th style='{th_style}'>Users</th>"
                f"<th style='{th_style}'>Hosts</th>"
                f"<th style='{th_style}'>First Seen</th>"
                f"<th style='{th_style}'>Last Seen</th></tr>"
            )
            for hit in tool_result.url_hits:
                url = hit['url']
                # Handle both QRadar format (event_count) and CrowdStrike format (host_count)
                count = hit.get('event_count') or hit.get('host_count', 0)
                sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
                users = hit.get('users', [])
                # Handle both 'hosts' (QRadar) and 'hostnames' (CrowdStrike)
                hosts = hit.get('hosts', []) or hit.get('hostnames', [])
                users_display = ', '.join(users[:3])
                if len(users) > 3:
                    users_display += f" (+{len(users) - 3} more)"
                hosts_display = ', '.join(hosts[:3])
                if len(hosts) > 3:
                    hosts_display += f" (+{len(hosts) - 3} more)"
                # Truncate long URLs for display
                url_display = url if len(url) <= 60 else url[:57] + '...'
                if tool_key == 'qradar':
                    count_display = _qradar_search_link(url.replace('https://', ''), 'url', count)
                else:
                    count_display = f"{count} hosts" if hit.get('host_count') else str(count)
                parts.append(
                    f"<tr style='background-color: #fff3e6;'>"  # Light orange for URL paths
                    f"<td style='{td_style}'><code>{url_display}</code></td>"
                    f"<td style='{td_style}'>{count_display}</td>"
                    f"<td style='{td_style}'>{sources}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{users_display}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{hosts_display}</td>"
                    f"<td style='{td_style}'>{hit.get('first_seen', 'N/A')}</td>"
                    f"<td style='{td_style}'>{hit.get('last_seen', 'N/A')}</td></tr>"
                )
            parts.append("</table>")

        # Filename Hits (CrowdStrike)
        if tool_result.filename_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>Filename</th>"
                f"<th style='{th_style}'>Detections</th>"
                f"<th style='{th_style}'>Affected Hosts</th></tr>"
            )
            for hit in tool_result.filename_hits:
                filename = hit['filename']
                count = hit.get('detection_count', 0)
                hostnames = ', '.join(hit.get('hostnames', [])[:5])
                if len(hit.get('hostnames', [])) > 5:
                    hostnames += f" (+{len(hit['hostnames']) - 5} more)"
                parts.append(
                    f"<tr style='background-color: #e6f3ff;'>"  # Light blue for filenames
                    f"<td style='{td_style}'><code>{filename}</code></td>"
                    f"<td style='{td_style}'>{count}</td>"
                    f"<td style='{td_style}; font-size: 11px;'>{hostnames}</td></tr>"
                )
            parts.append("</table>")

        # Hash Hits
        if tool_result.hash_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>Hash</th>"
                f"<th style='{th_style}'>Type</th>"
                f"<th style='{th_style}'>Events</th>"
                f"<th style='{th_style}'>RF Risk</th>"
                f"<th style='{th_style}'>Details</th></tr>"
            )
            for hit in tool_result.hash_hits:
                file_hash = hit['hash']
                count = hit.get('event_count') or hit.get('detection_count', 0)
                details = ', '.join(hit.get('hostnames', [])[:3]) or ''
                if tool_key == 'qradar':
                    count_display = _qradar_search_link(file_hash, 'hash', count)
                else:
                    count_display = str(count)
                parts.append(
                    f"<tr style='background-color: #ffe6e6;'>"
                    f"<td style='{td_style}'><code>{file_hash[:32]}...</code></td>"
                    f"<td style='{td_style}'>{hit['hash_type']}</td>"
                    f"<td style='{td_style}'>{count_display}</td>"
                    f"{_rf_risk_cell(file_hash)}"
                    f"<td style='{td_style}'>{details}</td></tr>"
                )
            parts.append("</table>")

        # Email Hits (Abnormal)
        if tool_result.email_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>Email</th>"
                f"<th style='{th_style}'>Threats</th>"
                f"<th style='{th_style}'>Attack Types</th></tr>"
            )
            for hit in tool_result.email_hits:
                parts.append(
                    f"<tr style='background-color: #ffe6e6;'>"
                    f"<td style='{td_style}'><code>{hit['email']}</code></td>"
                    f"<td style='{td_style}'>{hit['threat_count']}</td>"
                    f"<td style='{td_style}'>{', '.join(hit.get('attack_types', []))}</td></tr>"
                )
            parts.append("</table>")

        return parts

    # Add each tool's results wrapped in collapsible sections
    for tool_result, tool_icon, tool_key in [
        (result.qradar, "&#x1F50D;", "qradar"),
        (result.crowdstrike, "&#x1F985;", "crowdstrike"),
        (result.abnormal, "&#x1F4E7;", "abnormal"),
        (result.xsiam, "&#x1F9ED;", "xsiam"),
    ]:
        if not tool_result:
            continue
        section_parts = format_tool_section(tool_result, tool_icon, tool_key)
        if section_parts:
            hits = tool_result.total_hits
            telemetry = getattr(tool_result, 'logscale_events_found', 0) or 0
            summary_suffix = f"{hits} hit(s)"
            if telemetry > 0:
                summary_suffix += f" + {telemetry} LogScale telemetry event(s)"
            html_parts.append(f"<details><summary>{tool_icon} <strong>{tool_result.tool_name}</strong> &mdash; {summary_suffix}</summary>")
            html_parts.extend(section_parts)
            html_parts.append("</details>")

    # Tools with no hits (only show if no errors for that tool)
    # Check if errors contain tool-specific messages
    qradar_errors = [e for e in result.errors if 'domain combined search' in e.lower() or 'ip combined search' in e.lower() or 'qradar' in e.lower()]
    crowdstrike_errors = [e for e in result.errors if 'crowdstrike' in e.lower()]
    abnormal_errors = [e for e in result.errors if 'abnormal' in e.lower()]
    xsiam_errors = [e for e in result.errors if 'xsiam' in e.lower() or 'xql' in e.lower()]

    no_hits = []
    if result.qradar and result.qradar.total_hits == 0 and not qradar_errors:
        no_hits.append("QRadar")
    if result.crowdstrike and result.crowdstrike.total_hits == 0 and not crowdstrike_errors:
        no_hits.append("CrowdStrike")
    if result.abnormal and result.abnormal.total_hits == 0 and not abnormal_errors:
        no_hits.append("Abnormal")
    if result.xsiam and result.xsiam.total_hits == 0 and not xsiam_errors:
        no_hits.append("XSIAM")
    if no_hits:
        html_parts.append(f"<p><em>No hits in: {', '.join(no_hits)}</em></p>")

    # Raw LogScale telemetry events (CrowdStrike): not scored as hits, but worth surfacing
    # so "no hits" doesn't imply the IOC was never seen in the environment.
    cs_telemetry = getattr(result.crowdstrike, 'logscale_events_found', 0) if result.crowdstrike else 0
    if cs_telemetry > 0:
        html_parts.append(
            f"<p><em>&#x1F4E1; CrowdStrike LogScale: {cs_telemetry} telemetry event(s) matched "
            f"(not counted as scored hits &mdash; see Event Search Queries below for context).</em></p>"
        )

    # Errors
    if result.errors:
        html_parts.append("<details><summary>&#x26A0; Errors</summary><ul style='color: #666;'>")
        for err in result.errors[:5]:
            html_parts.append(f"<li>{err}</li>")
        html_parts.append("</ul></details>")

    # Collect all queries, separating LogScale from API queries
    logscale_queries = []
    api_queries = []

    if result.qradar and result.qradar.queries:
        for q in result.qradar.queries:
            api_queries.append(('QRadar', q.get('type', 'Search'), q.get('query', '')))

    if result.crowdstrike and result.crowdstrike.queries:
        for q in result.crowdstrike.queries:
            if q.get('query_type') == 'logscale':
                logscale_queries.append(('CrowdStrike', q.get('type', 'Search'), q.get('query', '')))
            else:
                api_queries.append(('CrowdStrike', q.get('type', 'Search'), q.get('query', '')))

    if result.xsiam and result.xsiam.queries:
        for q in result.xsiam.queries:
            api_queries.append(('XSIAM', q.get('type', 'XQL'), q.get('query', '')))

    # Event Search queries (LogScale) - collapsed for reference
    if logscale_queries:
        html_parts.append("<details><summary>&#x1F50E; <strong>Event Search Queries</strong> (for deeper investigation)</summary>")
        html_parts.append("<p><em>Open each query straight in Falcon Event Search, or copy it to hunt across raw telemetry:</em></p>")

        for tool, query_type, query in logscale_queries:
            escaped_query = query.replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f"<p><strong>{query_type}:</strong></p>")
            html_parts.append(
                f"<pre style='background-color: #e3f2fd; padding: 10px; font-size: 11px; "
                f"overflow-x: auto; white-space: pre-wrap; border-left: 4px solid #1976d2;'>{escaped_query}</pre>"
            )
            cs_link = _get_falcon_logscale_link(query)
            if cs_link:
                html_parts.append(f"<p><a href='{cs_link}' target='_blank' style='color: #1976d2;'>&#x1F517; Open in Falcon Event Search</a></p>")
        html_parts.append("</details>")

    # API queries executed - collapsed for reference
    if api_queries:
        html_parts.append("<details><summary>&#x1F50D; API Queries Executed</summary>")
        for tool, query_type, query in api_queries:
            escaped_query = query.replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f"<p><strong>{tool} - {query_type}:</strong></p>")
            html_parts.append(f"<pre style='background-color: #f5f5f5; padding: 8px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;'>{escaped_query}</pre>")
            # Add clickable console links based on tool
            if tool == 'CrowdStrike':
                falcon_link = _get_falcon_console_link(query_type, query)
                if falcon_link:
                    url, link_text = falcon_link
                    html_parts.append(f"<p><a href='{url}' target='_blank' style='color: #1976d2;'>&#x1F517; {link_text}</a></p>")
            elif tool == 'QRadar':
                qradar_link = _get_qradar_console_link(query)
                if qradar_link:
                    url, link_text = qradar_link
                    html_parts.append(f"<p><a href='{url}' target='_blank' style='color: #1976d2;'>&#x1F517; {link_text}</a></p>")
        html_parts.append("</details>")

    html_parts.append(f"<p><em>Hunt completed: {result.hunt_time}</em></p>")
    html_parts.append("<p><em>Generated by Pokedex IOC Hunter</em></p>")
    html_parts.append("</div>")

    return "\n".join(html_parts)


def format_exposure_for_webex(cve_ids: List[str], records: List, tipper_id: str, azdo_url: str = "") -> str:
    """Short markdown summary for the Webex room — called only when there are findings.

    Shows a one-line headline, the top confirmed exposures grouped by CVE, and a
    link back to the AZDO story where the full table lives.
    """
    if not records:
        return ""  # option A: silent on empty

    confirmed = [r for r in records if r.confidence == "confirmed"]
    potential = [r for r in records if r.confidence == "potential"]
    assets = len({r.asset for r in records})

    out = f"🚨 **CVE Exposure** — #{tipper_id} — "
    bits = []
    if confirmed:
        bits.append(f"**{len(confirmed)} confirmed**")
    if potential:
        bits.append(f"{len(potential)} potential")
    out += " · ".join(bits)
    out += f" across {assets} asset(s)\n\n"

    # Per-CVE headline lines, confirmed first, cap at 5 CVEs for readability
    from collections import defaultdict
    by_cve: dict = defaultdict(list)
    for r in records:
        by_cve[r.cve_id].append(r)

    # Rank CVEs: most confirmed first, then potential count
    cve_order = sorted(
        by_cve.keys(),
        key=lambda c: (
            -sum(1 for r in by_cve[c] if r.confidence == "confirmed"),
            -len(by_cve[c]),
        ),
    )
    for cve_id in cve_order[:5]:
        rows = by_cve[cve_id]
        c = sum(1 for r in rows if r.confidence == "confirmed")
        p = len(rows) - c
        sev = rows[0].severity or "—"
        score = rows[0].cvss_score
        score_str = f" {score}" if score is not None else ""
        # Show first confirmed asset as the example, flag prod environment loudly
        example = next((r for r in rows if r.confidence == "confirmed"), rows[0])
        env = getattr(example, "environment", None)
        env_tag = ""
        if env:
            env_tag = f" **[{env.upper()}]**" if "prod" in env.lower() else f" _[{env}]_"
        # Count prod assets across all rows for this CVE — surface impact
        prod_count = sum(1 for r in rows if (getattr(r, "environment", "") or "").lower().startswith("prod"))
        prod_str = f" · **{prod_count} in PROD**" if prod_count else ""
        out += (
            f"- **{cve_id}** ({sev}{score_str}) — {c} confirmed, {p} potential{prod_str} · "
            f"e.g. `{example.app}` {example.version} on `{example.asset}`{env_tag}\n"
        )
    if len(cve_order) > 5:
        out += f"- _…and {len(cve_order) - 5} more CVE(s)_\n"

    if azdo_url:
        out += f"\n_📝 Full table posted to [#{tipper_id}]({azdo_url})_"
    return out


def format_exposure_for_azdo(cve_ids: List[str], result: "CorrelationResult") -> str:
    """Format CVE exposure correlator output as HTML for an AZDO comment.

    Four cases:
      1. scanned=False, skip_reason="no_input" → tipper had no CVEs and no
         vulnerable_products; analyzer chose not to look anything up. Post a
         short stub so the audit trail shows we considered it.
      2. scanned=False, skip_reason="no_usable_cpes" → NVD gave no usable CPEs;
         Tanium was never queried.
      3. scanned=True, records=[] → real clean scan.
      4. records non-empty → findings table.
    """
    records = result.records
    html: list = ['<div style="font-family: Arial, sans-serif;">']
    cve_list = ", ".join(cve_ids) if cve_ids else "—"

    if not records and not result.scanned and result.skip_reason == "no_input":
        html.append("<h3>&#x1F50D; CVE Exposure Check</h3>")
        html.append(
            "<p><strong>Nothing to check.</strong> No CVEs or vulnerable "
            "products were identified in this tipper, so no Tanium scan was run.</p>"
        )
        html.append("</div>")
        return "\n".join(html)

    if not records and not result.scanned:
        html.append("<h3>&#x1F50D; CVE Exposure Check</h3>")
        html.append(
            "<p>&#x26A0;&#xFE0F; <strong>Not checked.</strong> "
            "NVD returned no endpoint-software CPEs for these CVE(s) "
            "(typically firmware/hardware-only advisories), so no Tanium scan was run.</p>"
        )
        html.append(f"<p style='color: #666;'>CVE(s): <code>{cve_list}</code></p>")
        html.append(f"<p style='color: #666;'><em>Skip reason: <code>{result.skip_reason or 'unknown'}</code></em></p>")
        html.append("</div>")
        return "\n".join(html)

    if not records:
        html.append("<h3>&#x1F50D; CVE Exposure Check</h3>")
        html.append(f"<p>&#x2705; <strong>No assets with affected software found.</strong></p>")
        html.append(f"<p style='color: #666;'>Checked CVE(s): <code>{cve_list}</code></p>")
        html.append("<p><em>Source: Tanium Installed Applications · NVD CPE</em></p>")
        html.append("</div>")
        return "\n".join(html)

    confirmed = [r for r in records if r.confidence == "confirmed"]
    potential = [r for r in records if r.confidence == "potential"]

    html.append("<h3>&#x1F6A8; CVE Exposure Check</h3>")
    html.append(
        f"<p><strong>{len(confirmed)} confirmed</strong> · "
        f"<strong>{len(potential)} potential</strong> exposure(s) found across "
        f"<strong>{len({r.asset for r in records})}</strong> asset(s).</p>"
    )
    html.append(f"<p style='color: #666;'>CVE(s) checked: <code>{cve_list}</code></p>")

    # Group by CVE, confirmed first
    from collections import defaultdict
    by_cve: dict = defaultdict(list)
    for r in records:
        by_cve[r.cve_id].append(r)

    for cve_id in sorted(by_cve.keys()):
        rows = by_cve[cve_id]
        rows.sort(key=lambda r: (0 if r.confidence == "confirmed" else 1, r.asset))
        sev = rows[0].severity or "—"
        score = rows[0].cvss_score
        score_str = f" ({score})" if score is not None else ""
        html.append(f"<h4><code>{cve_id}</code> — {sev}{score_str} · {len(rows)} match(es)</h4>")
        html.append("<table style='border-collapse: collapse; margin-bottom: 12px;'>")
        html.append(
            "<tr style='background: #f4f4f4;'>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Confidence</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Asset</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Env</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>OS / CI</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>App</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Version</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Match</th>"
            "</tr>"
        )
        for r in rows:
            color = "#d32f2f" if r.confidence == "confirmed" else "#f57c00"
            badge = (
                f"<strong style='color: {color};'>"
                f"{'CONFIRMED' if r.confidence == 'confirmed' else 'POTENTIAL'}</strong>"
            )
            env = getattr(r, "environment", None) or "—"
            env_color = "#d32f2f" if env and "prod" in env.lower() else "#444"
            ci = getattr(r, "ci_class", None)
            os_ci = f"{r.os or '—'}{f' / {ci}' if ci else ''}"
            html.append(
                "<tr>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{badge}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{r.asset}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc; color: {env_color};'>{env}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{os_ci}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{r.app}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{r.version or '—'}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc; font-size: 90%;'>{r.reason}</td>"
                "</tr>"
            )
        html.append("</table>")

    html.append("<p><em>Source: Tanium Installed Applications · NVD CPE. "
                "Confirmed = vendor+product+version all match; potential = vendor or version uncertain.</em></p>")
    html.append("</div>")
    return "\n".join(html)


def format_veracode_exposure_for_azdo(veracode: dict) -> str:
    """Format Veracode SCA exposure (CVE -> affected apps) as an AZDO HTML block.

    Returns "" when there is nothing worth posting (not configured / no CVEs
    checked), so the caller can simply append the result. When Veracode was
    checked but found nothing, posts a short clean-scan note for the audit trail.
    """
    if not veracode or not veracode.get("configured"):
        return ""
    html: list = ['<div style="font-family: Arial, sans-serif;">']
    if veracode.get("error"):
        html.append("<h3>&#x1F6E1; Veracode SCA Exposure</h3>")
        html.append(f"<p>&#x26A0;&#xFE0F; <strong>Not checked.</strong> {veracode['error']}</p>")
        html.append("</div>")
        return "\n".join(html)

    cves = veracode.get("cves") or {}
    packages = veracode.get("packages") or {}
    if not veracode.get("exposed"):
        html.append("<h3>&#x1F6E1; Veracode SCA Exposure</h3>")
        html.append("<p>&#x2705; <strong>No applications carry an affected component.</strong></p>")
        if packages:
            # A package miss is "no open finding references it", not proof of
            # absence from every SBOM — say so for the audit trail.
            html.append(
                "<p><em>No open Veracode SCA finding references the named package(s); "
                "this does not rule out a clean (un-flagged) copy in an application SBOM.</em></p>"
            )
        html.append("<p><em>Source: Veracode Software Composition Analysis findings.</em></p>")
        html.append("</div>")
        return "\n".join(html)

    n = veracode.get("affected_app_count", 0)
    html.append("<h3>&#x1F6A8; Veracode SCA Exposure</h3>")
    html.append(
        f"<p><strong>{n} application(s)</strong> carry an open-source component matching "
        f"this tipper ({len(cves)} CVE(s), {len(packages)} named package(s)).</p>"
    )

    def _exposure_table(apps: list, with_cve: bool = False) -> None:
        html.append("<table style='border-collapse: collapse; margin-bottom: 12px;'>")
        headers = (
            "<th style='padding: 6px; border: 1px solid #ccc;'>Application</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Component</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Version</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Severity</th>"
        )
        if with_cve:
            headers += "<th style='padding: 6px; border: 1px solid #ccc;'>CVE</th>"
        html.append(f"<tr style='background: #f4f4f4;'>{headers}</tr>")
        for a in apps:
            row = (
                "<tr>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{a.get('application') or '—'}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('component') or '—'}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('version') or '—'}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{a.get('severity_label') or '—'}</td>"
            )
            if with_cve:
                row += f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('cve_id') or '—'}</code></td>"
            row += "</tr>"
            html.append(row)
        html.append("</table>")

    for cve_id in sorted(cves.keys()):
        apps = cves[cve_id]
        distinct_apps = len({(a.get("app_id") or a.get("application")) for a in apps})
        html.append(
            f"<h4><code>{cve_id}</code> — {distinct_apps} application(s), "
            f"{len(apps)} component finding(s)</h4>"
        )
        _exposure_table(apps)
    for pkg in sorted(packages.keys()):
        apps = packages[pkg]
        distinct_apps = len({(a.get("app_id") or a.get("application")) for a in apps})
        html.append(
            f"<h4>Package <code>{pkg}</code> — {distinct_apps} application(s), "
            f"{len(apps)} finding(s)</h4>"
        )
        _exposure_table(apps, with_cve=True)
    html.append("<p><em>Source: Veracode Software Composition Analysis findings.</em></p>")
    html.append("</div>")
    return "\n".join(html)


def format_veracode_exposure_for_webex(veracode: dict) -> str:
    """Format Veracode SCA exposure as a Webex markdown block. Empty when no exposure."""
    if not veracode or not veracode.get("exposed"):
        return ""
    cves = veracode.get("cves") or {}
    packages = veracode.get("packages") or {}
    n = veracode.get("affected_app_count", 0)
    lines = [f"🛡️ **Veracode SCA:** {n} application(s) carry a component matching this tipper."]
    for cve_id in sorted(cves.keys()):
        names = sorted({a.get("application") or "?" for a in cves[cve_id]})
        shown = ", ".join(names[:15])
        if len(names) > 15:
            shown += f", +{len(names) - 15} more"
        lines.append(f"- **{cve_id}** → {shown}")
    for pkg in sorted(packages.keys()):
        names = sorted({a.get("application") or "?" for a in packages[pkg]})
        shown = ", ".join(names[:15])
        if len(names) > 15:
            shown += f", +{len(names) - 15} more"
        lines.append(f"- pkg **{pkg}** → {shown}")
    return "\n".join(lines)


def format_jfrog_exposure_for_azdo(jfrog: dict) -> str:
    """Format JFrog Xray exposure (CVE -> affected artifacts) as an AZDO HTML block.

    Returns "" when there is nothing worth posting (not configured / no CVEs
    checked). When Xray was checked but found nothing, posts a short clean-scan
    note for the audit trail. Mirrors format_veracode_exposure_for_azdo.
    """
    if not jfrog or not jfrog.get("configured"):
        return ""
    # Stay completely silent on any error (not authorized / unreachable / building)
    # — unlike Veracode we do NOT post a "Not checked" note, so the pending-
    # permission state never adds noise to leadership-visible tipper comments.
    if jfrog.get("error"):
        return ""
    html: list = ['<div style="font-family: Arial, sans-serif;">']

    cves = jfrog.get("cves") or {}
    if not jfrog.get("exposed"):
        html.append("<h3>&#x1F4E6; JFrog Xray Exposure</h3>")
        html.append("<p>&#x2705; <strong>No JFrog artifacts carry an affected component.</strong></p>")
        html.append("<p><em>Source: JFrog Xray security violations (High/Critical).</em></p>")
        html.append("</div>")
        return "\n".join(html)

    n = jfrog.get("affected_artifact_count", 0)
    html.append("<h3>&#x1F6A8; JFrog Xray Exposure</h3>")
    html.append(
        f"<p><strong>{n} artifact(s)</strong> in JFrog carry a High/Critical component "
        f"affected by this tipper ({len(cves)} CVE(s)).</p>"
    )
    for cve_id in sorted(cves.keys()):
        arts = cves[cve_id]
        distinct = len({a.get("artifact") for a in arts})
        html.append(f"<h4><code>{cve_id}</code> — {distinct} artifact(s)</h4>")
        html.append("<table style='border-collapse: collapse; margin-bottom: 12px;'>")
        html.append(
            "<tr style='background: #f4f4f4;'>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Artifact</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Repo</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Component</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Version</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Severity</th>"
            "<th style='padding: 6px; border: 1px solid #ccc;'>Fix</th></tr>"
        )
        for a in arts:
            html.append(
                "<tr>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{a.get('artifact') or '—'}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{a.get('repo') or '—'}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('component') or '—'}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('version') or '—'}</code></td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'>{a.get('severity') or '—'}</td>"
                f"<td style='padding: 6px; border: 1px solid #ccc;'><code>{a.get('fix_versions') or '—'}</code></td>"
                "</tr>"
            )
        html.append("</table>")
    html.append("<p><em>Source: JFrog Xray security violations (High/Critical).</em></p>")
    html.append("</div>")
    return "\n".join(html)


def format_jfrog_exposure_for_webex(jfrog: dict) -> str:
    """Format JFrog Xray exposure as a Webex markdown block. Empty when no exposure."""
    if not jfrog or not jfrog.get("exposed"):
        return ""
    cves = jfrog.get("cves") or {}
    n = jfrog.get("affected_artifact_count", 0)
    lines = [f"📦 **JFrog Xray:** {n} artifact(s) carry a High/Critical component matching this tipper."]
    for cve_id in sorted(cves.keys()):
        names = sorted({a.get("artifact") or "?" for a in cves[cve_id]})
        shown = ", ".join(names[:10])
        if len(names) > 10:
            shown += f", +{len(names) - 10} more"
        lines.append(f"- **{cve_id}** → {shown}")
    return "\n".join(lines)


# ── Behavioral Threat Hunt formatters ─────────────────────────────────────────
# Deliberately distinct from the IOC-hunt formatters above so the AzDO/Webex
# reader can tell an indicator sweep apart from an LLM-authored behavioral hunt.

_BH_STATUS = {
    "executed": ("&#x1F6A8;", "Hits"),
    "no_hits": ("&#x2705;", "No hits"),
    "skipped_validation": ("&#x26A0;", "Skipped (failed validation)"),
    "skipped_deadline": ("&#x23F1;", "Skipped (time budget) &mdash; run manually"),
    "error": ("&#x274C;", "Error"),
    "pending": ("&#x23F3;", "Pending"),
}

# query_type -> (display name, short dialect tag, <pre> border, <pre> background)
_DIALECT_LABELS = {
    "logscale": ("CrowdStrike LogScale", "CQL", "#fb8c00", "#fff3e0"),
    "xql": ("Cortex XSIAM", "XQL", "#00897b", "#e0f2f1"),
}


def format_behavioral_hunt_for_azdo(result: BehavioralHuntResult) -> str:
    """Format a behavioral threat hunt as a COMPACT, collapsed HTML AzDO comment.

    The whole report lives inside one collapsed <details> so the work-item stays
    visually small — a single summary line until expanded — then hunts are grouped
    by SIEM dialect (CQL / XQL). Clearly labelled LLM-authored / TTP hunting,
    distinct from the IOC sweep.
    """
    days = max(1, result.search_hours // 24)
    with_hits = [h for h in result.hunts if h.status == "executed"]
    model = result.llm_model or "local LLM"

    if not result.hunts:
        reason = result.errors[0] if result.errors else "no behavioral hunts were produced"
        return (
            "<div style='font-family: Segoe UI, sans-serif; font-size: 13px;'>"
            f"<p>&#x1F9ED; <strong>Behavioral Threat Hunt</strong> (TTP, LLM-authored) &mdash; "
            f"{_BH_STATUS['error'][0]} no hunts executed &mdash; {reason}.</p></div>"
        )

    head_icon = "&#x1F6A8;" if with_hits else "&#x2705;"
    summary = (
        f"{head_icon} <strong>Behavioral Threat Hunt</strong> (TTP, LLM-authored) &mdash; "
        f"{result.queries_generated} authored · {result.queries_executed} run · "
        f"{len(with_hits)} with hits · {result.total_hits} event(s) "
        f"&mdash; <em>{result.platform}</em>"
    )

    parts = [
        "<div style='font-family: Segoe UI, sans-serif; font-size: 13px;'>",
        f"<details><summary>{summary}</summary>",
        "<p style='color:#666; font-size:12px;'><em>Hunts the adversary's "
        "<strong>techniques/behaviors</strong> derived from the tipper narrative &mdash; "
        "not the known indicators (those are in the IOC Hunt comment). Queries authored by "
        f"{model}, validated, then auto-run (last {days} days). Review before acting.</em></p>",
    ]

    # Group hunts by dialect, preserving first-seen order.
    order = []
    for h in result.hunts:
        if h.query_type not in order:
            order.append(h.query_type)

    for qt in order:
        name, tag, border, bg = _DIALECT_LABELS.get(qt, (qt, qt.upper(), "#999", "#f5f5f5"))
        group = [h for h in result.hunts if h.query_type == qt]
        ghits = len([h for h in group if h.status == "executed"])
        parts.append(
            f"<p style='margin:8px 0 2px;'><strong>{name}</strong> "
            f"<span style='color:#888;'>({tag}) &mdash; {len(group)} hunt(s), {ghits} with hits</span></p>"
        )
        for h in group:
            icon, label = _BH_STATUS.get(h.status, _BH_STATUS["pending"])
            technique = f" · <strong>{h.attack_technique}</strong>" if h.attack_technique else ""
            line = f"{icon} {h.title} &mdash; {label}"
            if h.status == "executed":
                line += f" ({h.hit_count} event(s))"
            if h.attempts > 1:
                line += f" · {h.attempts} attempt(s)"
            parts.append(f"<details><summary>{line}</summary>")
            if h.hypothesis:
                parts.append(f"<p><em>Hypothesis:</em> {h.hypothesis}{technique}</p>")
            if h.status == "executed" and h.hostnames:
                shown = ", ".join(f"<code>{x}</code>" for x in h.hostnames)
                parts.append(f"<p><em>Hosts:</em> {shown}</p>")
            if h.detail:
                parts.append(f"<p style='color:#666;'><em>{h.detail}</em></p>")
            escaped = (h.query or "").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(
                f"<pre style='background:{bg}; padding:10px; font-size:11px; "
                f"overflow-x:auto; white-space:pre-wrap; border-left:4px solid {border};'>"
                f"{escaped}</pre>"
            )
            parts.append("</details>")

    if result.errors:
        parts.append("<details><summary>&#x26A0; Notes</summary><ul style='color:#666;'>")
        for e in result.errors[:5]:
            parts.append(f"<li>{e}</li>")
        parts.append("</ul></details>")

    parts.append(
        "<p style='color:#999; font-size:11px;'><em>Auto-generated behavioral hunts are a "
        "starting point &mdash; review the query and hits before acting.</em></p>"
    )
    parts.append("</details></div>")
    return "\n".join(parts)


def format_behavioral_hunt_for_webex(result: BehavioralHuntResult, tipper_id: str, azdo_url: str = "") -> str:
    """Concise Webex markdown summary for a behavioral threat hunt."""
    with_hits = [h for h in result.hunts if h.status == "executed"]
    if not result.hunts:
        reason = result.errors[0] if result.errors else "no hunts produced"
        return f"🧭 **Behavioral Threat Hunt** — #{tipper_id}\nNo hunts executed — {reason}.\n"

    if with_hits:
        out = (f"🚨 **Behavioral Threat Hunt** — #{tipper_id} — "
               f"**{len(with_hits)} hunt(s) with hits, {result.total_hits} event(s)!**\n\n")
        for h in with_hits:
            tech = f" ({h.attack_technique})" if h.attack_technique else ""
            tag = _DIALECT_LABELS.get(h.query_type, ("", h.query_type.upper()))[1]
            out += f"- 🧭 **{h.title}**{tech} `[{tag}]` — {h.hit_count} event(s)"
            if h.hostnames:
                out += f" on {len(h.hostnames)} host(s)"
            out += "\n"
    else:
        out = (f"✅ **Behavioral Threat Hunt** — #{tipper_id}\n"
               f"{result.queries_executed} LLM-authored hunt(s) ran, no hits.\n")

    skipped = [h for h in result.hunts if h.status in ("skipped_validation", "error")]
    if skipped:
        out += f"\n_⚠️ {len(skipped)} hunt(s) not executed (validation/errors)._\n"
    if azdo_url:
        out += f"_📝 Full hunts + queries on [#{tipper_id}]({azdo_url})_\n"
    return out
