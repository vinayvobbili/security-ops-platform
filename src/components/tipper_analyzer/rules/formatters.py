"""Formatting functions for detection rules catalog output."""

from typing import List, Dict

from .models import RuleCatalogSearchResult, RuleSearchResult, CatalogSyncResult


def format_rules_for_display(result: RuleCatalogSearchResult) -> str:
    """Format search results for Webex/terminal display (markdown).

    Args:
        result: RuleCatalogSearchResult from catalog search

    Returns:
        Formatted markdown string
    """
    if not result.has_results:
        platform_note = f" (platform: {result.platform_filter})" if result.platform_filter else ""
        return f"No detection rules found for: **{result.query}**{platform_note}"

    platform_note = f" | Platform: {result.platform_filter}" if result.platform_filter else ""
    output = f"**Detection Rules** matching \"{result.query}\"{platform_note}\n"
    output += f"Found **{result.total_found}** matching rule(s):\n\n"

    for i, sr in enumerate(result.results, 1):
        rule = sr.rule
        # Platform emoji
        platform_emoji = {"qradar": "Q", "crowdstrike": "CS", "tanium": "T"}.get(rule.platform, "?")
        # Severity indicator
        sev_indicator = ""
        if rule.severity:
            sev_map = {"critical": "!!!", "high": "!!", "medium": "!", "low": ""}
            sev_indicator = f" [{rule.severity.upper()}]" if rule.severity in sev_map else ""

        enabled_str = "" if rule.enabled else " (DISABLED)"
        score_pct = int(sr.score * 100)

        output += f"  {i}. **[{platform_emoji}]** {rule.name}{sev_indicator}{enabled_str} ({score_pct}% match)\n"

        # Show additional context if available
        details = []
        if rule.rule_type:
            details.append(f"Type: {rule.rule_type}")
        if rule.mitre_techniques:
            details.append(f"MITRE: {', '.join(rule.mitre_techniques[:5])}")
        if rule.malware_families:
            details.append(f"Malware: {', '.join(rule.malware_families[:3])}")
        if rule.threat_actors:
            details.append(f"Actors: {', '.join(rule.threat_actors[:3])}")
        if details:
            output += f"     _{' | '.join(details)}_\n"

    return output


def _mitre_link(technique_id: str) -> str:
    """Generate an HTML link to MITRE ATT&CK for a technique ID."""
    # T1005 -> /techniques/T1005/
    # T1005.001 -> /techniques/T1005/001/
    tid = technique_id.strip().upper()
    path = tid.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{path}/"
    return (
        f'<a href="{url}" target="_blank" style="background-color: #e8eaf6; color: #3949ab; '
        f'padding: 1px 5px; border-radius: 3px; font-size: 11px; text-decoration: none;">{tid}</a>'
    )


def _get_falcon_console_url() -> str:
    """Derive Falcon console URL from CrowdStrike API base URL."""
    # Matches the base_url in services/crowdstrike.py CrowdStrikeClient
    return "https://falcon.us-2.crowdstrike.com"


def _get_rule_link(rule) -> str:
    """Get a console link for a detection rule based on platform and type."""
    if rule.platform == "crowdstrike":
        falcon_url = _get_falcon_console_url()
        if rule.rule_type == "ioa_rule":
            return f"{falcon_url}/custom-ioa/"
        elif rule.rule_type == "ioc":
            return f"{falcon_url}/iocs/indicators/"
    return ""


def format_rules_for_azdo(rules_by_term: Dict[str, RuleCatalogSearchResult]) -> str:
    """Format detection rules coverage as HTML for AZDO comments.

    Args:
        rules_by_term: Dict mapping search terms to their results

    Returns:
        HTML string for AZDO comment
    """
    if not rules_by_term:
        return ""

    # Check if there are any results at all
    has_any_results = any(r.has_results for r in rules_by_term.values())
    if not has_any_results:
        return ""

    html = "<h4>&#x1F6E1; Existing Detection Rules Coverage</h4>\n"

    for term, result in rules_by_term.items():
        if not result.has_results:
            html += f"<p><em>No rules found for: {term}</em></p>\n"
            continue

        html += f"<p><strong>{term}</strong> ({result.total_found} rules):</p>\n"
        html += '<table style="border-collapse: collapse; width: 100%; margin-bottom: 10px;">\n'
        html += (
            '<tr style="background-color: #e8f4e8;">'
            '<th style="padding: 6px; border: 1px solid #ccc;">Platform</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Rule</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Type</th>'
            '<th style="padding: 6px; border: 1px solid #ccc;">Severity</th>'
            '</tr>\n'
        )

        for sr in result.results[:5]:  # Top 5 per term for AZDO
            rule = sr.rule
            platform_label = rule.platform.replace("crowdstrike", "CrowdStrike").replace("qradar", "QRadar").replace("tanium", "Tanium")
            severity_display = rule.severity.capitalize() if rule.severity else "N/A"

            # Build rule cell: linked name + description + MITRE techniques
            rule_link = _get_rule_link(rule)
            rule_cell = f'<a href="{rule_link}" target="_blank">{rule.name}</a>' if rule_link else rule.name
            if rule.description:
                # Truncate long descriptions
                desc = rule.description if len(rule.description) <= 120 else rule.description[:117] + "..."
                rule_cell += f'<br/><span style="color: #666; font-size: 11px;">{desc}</span>'
            if rule.mitre_techniques:
                mitre_badges = " ".join(_mitre_link(t) for t in rule.mitre_techniques[:5])
                rule_cell += f"<br/>{mitre_badges}"

            html += (
                f'<tr>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{platform_label}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{rule_cell}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{rule.rule_type}</td>'
                f'<td style="padding: 6px; border: 1px solid #ccc;">{severity_display}</td>'
                f'</tr>\n'
            )

        html += "</table>\n"

    # Show placeholders for platforms not yet integrated
    platforms_with_rules = set()
    for result in rules_by_term.values():
        for sr in result.results:
            platforms_with_rules.add(sr.rule.platform)

    pending_platforms = []
    if "qradar" not in platforms_with_rules:
        pending_platforms.append("QRadar (custom rules &amp; saved searches)")
    if "tanium" not in platforms_with_rules:
        pending_platforms.append("Tanium (Threat Response signals)")

    if pending_platforms:
        html += '<p style="color: #666; font-style: italic;">&#x1F6A7; Coming soon: '
        html += ", ".join(pending_platforms)
        html += "</p>\n"

    return html


def format_rules_for_display_section(rules_by_term: Dict[str, RuleCatalogSearchResult]) -> str:
    """Format detection rules coverage as markdown for the display (Webex) output.

    Args:
        rules_by_term: Dict mapping search terms to their results

    Returns:
        Markdown string section
    """
    if not rules_by_term:
        return ""

    has_any_results = any(r.has_results for r in rules_by_term.values())
    if not has_any_results:
        return ""

    output = "\n**EXISTING DETECTION RULES:**\n"

    for term, result in rules_by_term.items():
        if not result.has_results:
            continue

        output += f"\n  _{term}_ ({result.total_found} rules):\n"
        for sr in result.results[:3]:  # Top 3 per term for Webex
            rule = sr.rule
            platform_short = {"qradar": "Q", "crowdstrike": "CS", "tanium": "T"}.get(rule.platform, "?")
            output += f"  - [{platform_short}] {rule.name}"
            if rule.severity:
                output += f" ({rule.severity})"
            output += "\n"

    # Show placeholders for platforms not yet integrated
    platforms_with_rules = set()
    for result in rules_by_term.values():
        for sr in result.results:
            platforms_with_rules.add(sr.rule.platform)

    pending = []
    if "qradar" not in platforms_with_rules:
        pending.append("QRadar")
    if "tanium" not in platforms_with_rules:
        pending.append("Tanium")
    if pending:
        output += f"  _Coming soon: {', '.join(pending)} rules_\n"

    return output


def format_sync_result(result: CatalogSyncResult) -> str:
    """Format sync result for display.

    Args:
        result: CatalogSyncResult from sync operation

    Returns:
        Formatted string
    """
    output = "**Rules Catalog Sync Result**\n\n"
    output += f"Total rules: **{result.total_rules}** | Upserted: **{result.total_upserted}**\n\n"

    for p in result.platforms:
        status_icon = "OK" if p.success else "FAILED"
        output += f"  - **{p.platform}**: {p.rules_fetched} rules ({status_icon})"
        if p.error:
            output += f" - {p.error}"
        output += "\n"

    return output


def format_catalog_stats(stats: Dict) -> str:
    """Format catalog stats for display.

    Args:
        stats: Dict from catalog.get_stats()

    Returns:
        Formatted string
    """
    if stats.get("status") == "empty":
        return "Rules catalog is **empty**. Run `rules --sync` to populate it."

    output = "**Rules Catalog Stats**\n\n"
    output += f"Total rules: **{stats['total']}**\n"
    output += f"Status: {stats['status']}\n\n"
    output += "Platform breakdown:\n"

    for platform, count in stats.get("platforms", {}).items():
        label = platform.replace("crowdstrike", "CrowdStrike").replace("qradar", "QRadar").replace("tanium", "Tanium")
        output += f"  - {label}: {count}\n"

    return output
