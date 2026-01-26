"""Formatting functions for tipper analysis output."""

from datetime import datetime, timezone
from typing import Dict, List

from .models import NoveltyAnalysis, IOCHuntResult, ToolHuntResult
from .utils import (
    defang_ioc,
    linkify_work_items_html,
    split_by_history,
    format_tipper_refs,
    get_risk_emoji,
    get_risk_colors,
)


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
        output += "  (Nothing significantly new identified)\n"

    output += "\n**📋 WHAT'S FAMILIAR:**\n"
    if analysis.what_is_familiar:
        for item in analysis.what_is_familiar:
            output += f"  • {item}\n"
    else:
        output += "  (No similar patterns found in history)\n"

    output += "\n**🔗 RELATED TICKETS:**\n"
    if analysis.related_tickets:
        for ticket in analysis.related_tickets:
            output += f"  • #{ticket['id']}\n"
    else:
        output += "  (No related tickets)\n"

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

        # Show malware families (new vs familiar)
        if analysis.current_malware:
            new_malware, familiar_malware = split_by_history(
                analysis.current_malware, analysis.malware_history or {}
            )
            if new_malware:
                output += "\n  **🆕 New Malware/Tools:**\n"
                for malware in new_malware:
                    output += f"  • {malware}\n"
            if familiar_malware:
                output += "\n  **📋 Familiar Malware/Tools:**\n"
                for malware, seen_in in familiar_malware:
                    output += f"  • {malware} (seen in {format_tipper_refs(seen_in)})\n"

        # Show IOCs (new vs familiar) - use code block table for readability
        if has_rf_iocs or analysis.total_iocs_extracted:
            # Calculate totals for the note
            total_extracted = sum(analysis.total_iocs_extracted.values()) if analysis.total_iocs_extracted else 0
            high_risk_count = len(rf.get('high_risk_iocs', [])) if rf else 0

            if high_risk_count > 0:
                new_iocs, familiar_iocs = split_by_history(
                    rf['high_risk_iocs'],
                    analysis.ioc_history or {},
                    key_fn=lambda x: x.get('value', '').lower()
                )

                # First-time IOCs section (not seen in previous tippers)
                if new_iocs:
                    output += "\n  **🔍 First-Time IOCs** _(not seen in previous tippers)_**:**\n```\n"
                    output += f"{'IOC':<66} {'Type':<8} {'Risk':<18}\n"
                    output += f"{'-'*66} {'-'*8} {'-'*18}\n"
                    for ioc in new_iocs[:15]:
                        ioc_type = ioc.get('ioc_type', 'Unknown')
                        value = defang_ioc(ioc.get('value', 'Unknown'), ioc_type)
                        risk_score = ioc.get('risk_score', 0)
                        # Truncate long values
                        display_value = value[:63] + "..." if len(value) > 66 else value
                        risk_str = f"{risk_score}/99 ({ioc.get('risk_level', 'Unknown')})"
                        emoji = get_risk_emoji(risk_score)
                        output += f"{emoji} {display_value:<64} {ioc_type:<8} {risk_str:<18}\n"
                    if len(new_iocs) > 15:
                        output += f"... and {len(new_iocs) - 15} more\n"
                    output += "```\n"

                # Familiar IOCs section as table
                if familiar_iocs:
                    output += "\n  **📋 Familiar IOCs:**\n```\n"
                    output += f"{'IOC':<66} {'Type':<8} {'Risk':<18} {'Seen In':<20}\n"
                    output += f"{'-'*66} {'-'*8} {'-'*18} {'-'*20}\n"
                    for ioc, seen_in in familiar_iocs[:15]:
                        ioc_type = ioc.get('ioc_type', 'Unknown')
                        value = defang_ioc(ioc.get('value', 'Unknown'), ioc_type)
                        risk_score = ioc.get('risk_score', 0)
                        display_value = value[:63] + "..." if len(value) > 66 else value
                        risk_str = f"{risk_score}/99 ({ioc.get('risk_level', 'Unknown')})"
                        refs = format_tipper_refs(seen_in, max_refs=2)
                        emoji = get_risk_emoji(risk_score)
                        output += f"{emoji} {display_value:<64} {ioc_type:<8} {risk_str:<18} {refs:<20}\n"
                    if len(familiar_iocs) > 15:
                        output += f"... and {len(familiar_iocs) - 15} more\n"
                    output += "```\n"
                else:
                    output += "\n  **📋 Familiar IOCs:** None - all IOCs are new\n"

            # Add note about total IOCs extracted
            if total_extracted > 0:
                output += f"\n  _ℹ️ {high_risk_count} high-risk IOCs shown of {total_extracted} total extracted from description_\n"

    # Add detection rules coverage section
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
        html += "<li><em>Nothing significantly new identified</em></li>\n"

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
        html += "<p><strong>🔗 Related Tickets:</strong> "
        # Create hyperlinks for related tickets
        ticket_links = [linkify_work_items_html(f"#{t['id']}") for t in analysis.related_tickets]
        html += ", ".join(ticket_links)
        html += "</p>\n"

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
                    html += '<tr style="background-color: #e0e0e0;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IOC</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Type</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Risk</th></tr>\n'
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
                    html += '<tr style="background-color: #e0e0e0;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IOC</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Type</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Risk</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Seen In</th></tr>\n'
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
    days = result.search_hours // 24

    if result.total_hits == 0:
        output = f"✅ **IOC Hunt Complete** — #{tipper_id}\n"
        output += f"No hits found. Searched {result.total_iocs_searched} IOCs over {days} days.\n"
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
    ]:
        if not tool_result or tool_result.total_hits == 0:
            continue
        for hit in tool_result.ip_hits:
            rows.append((defang_ioc(hit['ip'], 'ip'), "IP", tool_short, hit['event_count']))
        for hit in tool_result.domain_hits:
            rows.append((defang_ioc(hit['domain'], 'domain'), "domain", tool_short,
                         hit.get('event_count') or hit.get('threat_count', 0)))
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

    output += f"\n_Searched {result.total_iocs_searched} IOCs over {days} days._\n"
    if azdo_url:
        output += f"_📝 Full details posted to [#{tipper_id}]({azdo_url})_\n"

    return output


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
    qradar_base = (config.qradar_api_url or '').rstrip('/')
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
        days = result.search_hours // 24
        if ioc_type == 'domain':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{ioc_value.lower()}%' OR LOWER(\"TSLD\") LIKE '%{ioc_value.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'ip':
            aql = f"SELECT * FROM events WHERE sourceip = '{ioc_value}' OR destinationip = '{ioc_value}' LAST {days} DAYS"
        elif ioc_type == 'hash':
            aql = f"SELECT * FROM events WHERE \"MD5 Hash\" = '{ioc_value}' OR \"SHA256 Hash\" = '{ioc_value}' LAST {days} DAYS"
        else:
            return str(count)
        encoded_aql = quote(aql, safe='')
        url = f"{qradar_console}/console/do/ariel/arielSearch?appName=Viewer&pageId=EventList&dispatch=performSearch&value={encoded_aql}"
        return f"<a href='{url}' target='_blank'>{count} events</a>"

    html_parts = [
        "<div style='font-family: Segoe UI, sans-serif; font-size: 13px;'>",
        f"<h3>{status_icon} IOC Hunt Results</h3>",
        f"<p>{status_text}</p>",
        f"<p><em>Searched {result.total_iocs_searched} IOCs over last {result.search_hours} hours ({result.search_hours // 24} days)</em></p>",
    ]

    # Helper to format a tool's results
    def format_tool_section(tool_result: ToolHuntResult, tool_icon: str, tool_key: str):
        if not tool_result or tool_result.total_hits == 0:
            return []

        parts = [f"<h4>{tool_icon} {tool_result.tool_name} ({tool_result.total_hits} hits)</h4>"]

        th_style = "padding: 6px; border: 1px solid #ccc;"
        td_style = "padding: 6px; border: 1px solid #ccc;"

        # IP Hits
        if tool_result.ip_hits:
            parts.append("<table style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
            parts.append(
                f"<tr style='background-color: #f0f0f0;'>"
                f"<th style='{th_style}'>IP</th>"
                f"<th style='{th_style}'>Events</th>"
                f"<th style='{th_style}'>RF Risk</th>"
                f"<th style='{th_style}'>Sources</th>"
                f"<th style='{th_style}'>First Seen</th>"
                f"<th style='{th_style}'>Last Seen</th></tr>"
            )
            for hit in tool_result.ip_hits:
                ip = hit['ip']
                count = hit['event_count']
                sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
                if tool_key == 'qradar':
                    count_display = _qradar_search_link(ip, 'ip', count)
                else:
                    count_display = str(count)
                parts.append(
                    f"<tr style='background-color: #ffe6e6;'>"
                    f"<td style='{td_style}'><code>{ip}</code></td>"
                    f"<td style='{td_style}'>{count_display}</td>"
                    f"{_rf_risk_cell(ip)}"
                    f"<td style='{td_style}'>{sources}</td>"
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
                f"<th style='{th_style}'>First Seen</th>"
                f"<th style='{th_style}'>Last Seen</th></tr>"
            )
            for hit in tool_result.domain_hits:
                domain = hit['domain']
                count = hit.get('event_count') or hit.get('threat_count', 0)
                sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
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
                    f"<td style='{td_style}'>{hit.get('first_seen', 'N/A')}</td>"
                    f"<td style='{td_style}'>{hit.get('last_seen', 'N/A')}</td></tr>"
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

    # Add each tool's results
    if result.qradar:
        html_parts.extend(format_tool_section(result.qradar, "&#x1F50D;", "qradar"))
    if result.crowdstrike:
        html_parts.extend(format_tool_section(result.crowdstrike, "&#x1F985;", "crowdstrike"))
    if result.abnormal:
        html_parts.extend(format_tool_section(result.abnormal, "&#x1F4E7;", "abnormal"))

    # Tools with no hits
    no_hits = []
    if result.qradar and result.qradar.total_hits == 0:
        no_hits.append("QRadar")
    if result.crowdstrike and result.crowdstrike.total_hits == 0:
        no_hits.append("CrowdStrike")
    if result.abnormal and result.abnormal.total_hits == 0:
        no_hits.append("Abnormal")
    if no_hits:
        html_parts.append(f"<p><em>No hits in: {', '.join(no_hits)}</em></p>")

    # Errors
    if result.errors:
        html_parts.append("<details><summary>Errors</summary><ul style='color: #666;'>")
        for err in result.errors[:5]:
            html_parts.append(f"<li>{err}</li>")
        html_parts.append("</ul></details>")

    html_parts.append(f"<p><em>Hunt completed: {result.hunt_time}</em></p>")
    html_parts.append("<p><em>Generated by Pokedex IOC Hunter</em></p>")
    html_parts.append("</div>")

    return "\n".join(html_parts)
