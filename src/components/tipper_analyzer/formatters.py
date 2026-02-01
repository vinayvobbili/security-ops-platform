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
            similarity_pct = f"({similarity:.0%})" if similarity else ""
            if title:
                # Strip "[PRIORITY] CTI Threat Tipper: " prefix
                if '] CTI Threat Tipper: ' in title:
                    title = title.split('] CTI Threat Tipper: ', 1)[1]
                # Truncate long titles
                display_title = title[:70] + '...' if len(title) > 70 else title
                output += f"  • #{ticket['id']} {similarity_pct}: {display_title}\n"
            else:
                output += f"  • #{ticket['id']} {similarity_pct}\n"
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
    if analysis.mitre_techniques:
        covered_count = len(analysis.mitre_covered)
        gap_count = len(analysis.mitre_gaps)
        total = len(analysis.mitre_techniques)

        output += "\n**🎯 MITRE ATT&CK Coverage:**\n"
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
        html += "<p><strong>🔗 Related Tickets:</strong></p>\n<ul>\n"
        for t in analysis.related_tickets:
            similarity = t.get('similarity', 0)
            similarity_pct = f" ({similarity:.0%} similar)" if similarity else ""
            title = t.get('title', '')
            # Strip "[PRIORITY] CTI Threat Tipper: " prefix for cleaner display
            if '] CTI Threat Tipper: ' in title:
                title = title.split('] CTI Threat Tipper: ', 1)[1]
            display_title = title[:60] + '...' if len(title) > 60 else title
            ticket_id = t['id']
            ticket_link = linkify_work_items_html(f'#{ticket_id}')
            html += f"<li>{ticket_link}{similarity_pct}: {display_title}</li>\n"
        html += "</ul>\n"

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
    if analysis.mitre_techniques:
        html += "\n<h4>&#x1F3AF; MITRE ATT&CK Coverage Analysis</h4>\n"

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

    output += f"\n_Searched {result.total_iocs_searched} IOCs over {days} days._\n"
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
    qradar_base = (config.qradar_api_url or '').rstrip('/')
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
        if ioc_type == 'domain':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{ioc_value.lower()}%' OR LOWER(\"TSLD\") LIKE '%{ioc_value.lower()}%' LAST {days} DAYS"
        elif ioc_type == 'url':
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{ioc_value.lower()}%' LAST {days} DAYS"
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
        f"<h3>{tool_icon} {tool_result.tool_name} IOC Hunt Results</h3>",
        f"<p>{status_icon} {status_text}</p>",
        f"<p><em>Searched {total_iocs_searched} IOCs over last {search_hours} hours ({search_hours // 24} days)</em></p>",
    ]

    # Show IOCs searched (each type on its own line for prominence)
    ioc_lines = []
    if searched_iocs.get('domains'):
        domains = searched_iocs['domains']
        domains_display = ', '.join(f"<code>{d}</code>" for d in domains)
        ioc_lines.append(f"<strong>Domains:</strong> {domains_display}")
    if searched_iocs.get('urls'):
        urls = searched_iocs['urls']
        urls_display = ', '.join(f"<code>{u}</code>" for u in urls)
        ioc_lines.append(f"<strong>URLs:</strong> {urls_display}")
    if searched_iocs.get('filenames'):
        filenames = searched_iocs['filenames']
        filenames_display = ', '.join(f"<code>{f}</code>" for f in filenames)
        ioc_lines.append(f"<strong>Filenames:</strong> {filenames_display}")
    if searched_iocs.get('ips'):
        ips = searched_iocs['ips']
        ips_display = ', '.join(f"<code>{ip}</code>" for ip in ips)
        ioc_lines.append(f"<strong>IPs:</strong> {ips_display}")
    if searched_iocs.get('hashes'):
        hashes = searched_iocs['hashes']
        hashes_display = ', '.join(f"<code>{h[:16]}...</code>" for h in hashes)
        ioc_lines.append(f"<strong>Hashes:</strong> {hashes_display}")

    if ioc_lines:
        html_parts.append("<div style='font-size: 12px; color: #444; margin: 8px 0;'>")
        for line in ioc_lines:
            html_parts.append(f"<p style='margin: 4px 0;'>{line}</p>")
        html_parts.append("</div>")

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
            count = hit.get('event_count') or hit.get('detection_count') or hit.get('alert_count', 0)
            direction = hit.get('direction', '')
            sources = ', '.join(hit.get('sources', [])) if hit.get('sources') else ''
            users = hit.get('users', [])
            hosts = hit.get('hosts', []) or hit.get('hostnames', [])
            users_display = ', '.join(users[:3]) + (f" (+{len(users) - 3})" if len(users) > 3 else "")
            hosts_display = ', '.join(hosts[:3]) + (f" (+{len(hosts) - 3})" if len(hosts) > 3 else "")
            count_display = _qradar_search_link(ip, 'ip', count)
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

    # Queries executed
    if tool_result.queries:
        html_parts.append("<details><summary>&#x1F50D; Queries Executed</summary>")
        for q in tool_result.queries:
            escaped_query = q.get('query', '').replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f"<p><strong>{q.get('type', 'Search')}:</strong></p>")
            html_parts.append(f"<pre style='background-color: #f5f5f5; padding: 8px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;'>{escaped_query}</pre>")
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
        elif ioc_type == 'url':
            # URL paths like registry.npmjs.org/openclaw/
            aql = f"SELECT * FROM events WHERE LOWER(\"URL\") LIKE '%{ioc_value.lower()}%' LAST {days} DAYS"
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

    # Show what IOCs were searched (all values, collapsible)
    ioc_list_parts = []
    if result.searched_domains:
        domains_display = ', '.join(f"<code>{d}</code>" for d in result.searched_domains)
        ioc_list_parts.append(f"<strong>Domains:</strong> {domains_display}")
    if result.searched_urls:
        urls_display = ', '.join(f"<code>{u}</code>" for u in result.searched_urls)
        ioc_list_parts.append(f"<strong>URLs:</strong> {urls_display}")
    if result.searched_filenames:
        filenames_display = ', '.join(f"<code>{f}</code>" for f in result.searched_filenames)
        ioc_list_parts.append(f"<strong>Filenames:</strong> {filenames_display}")
    if result.searched_ips:
        ips_display = ', '.join(f"<code>{ip}</code>" for ip in result.searched_ips)
        ioc_list_parts.append(f"<strong>IPs:</strong> {ips_display}")
    if result.searched_hashes:
        hashes_display = ', '.join(f"<code>{h[:16]}...</code>" for h in result.searched_hashes)
        ioc_list_parts.append(f"<strong>Hashes:</strong> {hashes_display}")

    if ioc_list_parts:
        html_parts.append("<details><summary>IOCs Searched</summary><ul style='margin: 4px 0;'>")
        for part in ioc_list_parts:
            html_parts.append(f"<li>{part}</li>")
        html_parts.append("</ul></details>")

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

    # Add each tool's results
    if result.qradar:
        html_parts.extend(format_tool_section(result.qradar, "&#x1F50D;", "qradar"))
    if result.crowdstrike:
        html_parts.extend(format_tool_section(result.crowdstrike, "&#x1F985;", "crowdstrike"))
    if result.abnormal:
        html_parts.extend(format_tool_section(result.abnormal, "&#x1F4E7;", "abnormal"))

    # Tools with no hits (only show if no errors for that tool)
    # Check if errors contain tool-specific messages
    qradar_errors = [e for e in result.errors if 'domain combined search' in e.lower() or 'ip combined search' in e.lower() or 'qradar' in e.lower()]
    crowdstrike_errors = [e for e in result.errors if 'crowdstrike' in e.lower()]
    abnormal_errors = [e for e in result.errors if 'abnormal' in e.lower()]

    no_hits = []
    if result.qradar and result.qradar.total_hits == 0 and not qradar_errors:
        no_hits.append("QRadar")
    if result.crowdstrike and result.crowdstrike.total_hits == 0 and not crowdstrike_errors:
        no_hits.append("CrowdStrike")
    if result.abnormal and result.abnormal.total_hits == 0 and not abnormal_errors:
        no_hits.append("Abnormal")
    if no_hits:
        html_parts.append(f"<p><em>No hits in: {', '.join(no_hits)}</em></p>")

    # Errors
    if result.errors:
        html_parts.append("<details><summary>&#x26A0; Errors</summary><ul style='color: #666;'>")
        for err in result.errors[:5]:
            html_parts.append(f"<li>{err}</li>")
        html_parts.append("</ul></details>")

    # Queries executed (for transparency/verification)
    all_queries = []
    if result.qradar and result.qradar.queries:
        for q in result.qradar.queries:
            all_queries.append(('QRadar', q.get('type', 'Search'), q.get('query', '')))
    if result.crowdstrike and result.crowdstrike.queries:
        for q in result.crowdstrike.queries:
            all_queries.append(('CrowdStrike', q.get('type', 'Search'), q.get('query', '')))

    if all_queries:
        html_parts.append("<details><summary>&#x1F50D; Queries Executed</summary>")
        for tool, query_type, query in all_queries:
            # Escape HTML in query and format as code block
            escaped_query = query.replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f"<p><strong>{tool} - {query_type}:</strong></p>")
            html_parts.append(f"<pre style='background-color: #f5f5f5; padding: 8px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;'>{escaped_query}</pre>")
        html_parts.append("</details>")

    html_parts.append(f"<p><em>Hunt completed: {result.hunt_time}</em></p>")
    html_parts.append("<p><em>Generated by Pokedex IOC Hunter</em></p>")
    html_parts.append("</div>")

    return "\n".join(html_parts)
