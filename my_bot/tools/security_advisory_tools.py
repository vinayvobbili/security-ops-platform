"""Security-advisory (cs-advisories) tools for Sleuth.

LLM-callable wrappers around the /cs-advisories backend (services.github_advisories
+ services.github_advisories_db). Let an analyst ask Sleuth to:
  - search the critical open-source / package-compromise advisory queue
  - pull one advisory's details, direct package/repo links, and team sign-offs
  - group a supply-chain campaign by package scope (e.g. @mastra) and check the
    whole set against our environment in one shot (Veracode SCA)
  - record a team's validation sign-off, or bulk-clear a whole campaign

Read tools are tagged readonly (exposed on the public /sleuth + MCP surface).
Write tools (sign-off / bulk-clear) are tagged mutating (fail-closed: not exposed
publicly) and attribute the change to "sleuth-agent"; the web UI at
https://gdnr.the-company.com/cs-advisories remains the human path with real identity.
"""

import logging

from my_bot.tools._tagging import readonly_tool, mutating_tool
from src.utils.tool_decorator import log_tool_call

from services import github_advisories as ga
from services import github_advisories_db as db

logger = logging.getLogger(__name__)

_BASE = "https://gdnr.the-company.com/cs-advisories"
_AGENT_ACTOR = "sleuth-agent"


def _fmt_packages(pkgs: list[str], limit: int = 12) -> str:
    pkgs = pkgs or []
    head = ", ".join(pkgs[:limit])
    return head + (f" (+{len(pkgs) - limit} more)" if len(pkgs) > limit else "") if head else "—"


def _valid_teams() -> dict[str, str]:
    return {t["team"]: t["label"] for t in db.list_signoff_teams()}


@readonly_tool
@log_tool_call
def search_security_advisories(query: str = "", limit: int = 20) -> str:
    """Search the critical security-advisory queue (cs-advisories).

    Covers GitHub reviewed-critical advisories, malicious-package advisories
    (npm/PyPI/etc.), and CISA KEV. Matches the query against advisory ID, CVE,
    affected package names, and the summary (case-insensitive substring).

    Use this when asked things like:
    - "Any advisories for <package/CVE>?"
    - "Is <package> in our advisory queue?"
    - "What package-compromise advisories are open?"

    Args:
        query: Package name, scope (e.g. @mastra), CVE, advisory ID, or keyword.
               Empty returns the most recent advisories.
        limit: Max rows to return (default 20).

    Returns a compact list with ID, severity, status, packages, and a link.
    """
    q = (query or "").strip().lower()
    try:
        advs = db.list_advisories()
    except Exception as e:  # noqa: BLE001
        return f"Could not read the advisory queue: {e}"
    if q:
        def _match(a):
            hay = " ".join([
                str(a.get("source_id") or ""), str(a.get("cve_id") or ""),
                str(a.get("summary") or ""), " ".join(a.get("packages") or []),
            ]).lower()
            return q in hay
        advs = [a for a in advs if _match(a)]
    if not advs:
        return f"No advisories match {query!r}." if q else "The advisory queue is empty."
    advs = advs[: max(1, min(limit, 100))]
    lines = [f"{len(advs)} advisor{'y' if len(advs) == 1 else 'ies'}"
             + (f" matching {query!r}" if q else "") + ":"]
    for a in advs:
        sid = a.get("source_id") or a.get("uid")
        lines.append(
            f"- {sid} [{a.get('severity') or 'critical'} · {a.get('status') or 'new'}]"
            f" {a.get('cve_id') or ''}".rstrip()
            + f"\n  packages: {_fmt_packages(a.get('packages') or [])}"
            + f"\n  {(a.get('summary') or '').strip()[:160]}"
            + f"\n  {_BASE}/{sid}"
        )
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def get_security_advisory(advisory_id: str) -> str:
    """Full details for one security advisory: severity, affected packages, direct
    package/repo links, and the per-team validation sign-off state.

    Use this when asked to "look at advisory X", "are we exposed to X", "who has
    cleared X", etc.

    Args:
        advisory_id: The advisory ID (e.g. a GHSA-, MAL-, or CVE- id).

    Returns a markdown summary plus the web link.
    """
    adv = db.get_advisory(advisory_id)
    if not adv:
        return f"No advisory found for {advisory_id!r}."
    sid = adv.get("source_id") or adv.get("uid")
    out = [
        f"Advisory {sid} — {adv.get('severity') or 'critical'} · status {adv.get('status') or 'new'}",
        f"CVE: {adv.get('cve_id') or 'none'} · ecosystem: {adv.get('ecosystem') or 'n/a'}",
        f"Summary: {(adv.get('summary') or '').strip()[:300]}",
        f"Affected packages: {_fmt_packages(adv.get('packages') or [], limit=30)}",
    ]
    links = ga.advisory_package_links(adv)
    reg = [f"{l['name']} → {l['registry_url']}" for l in links if l.get("registry_url")]
    if reg:
        out.append("Package links:\n  " + "\n  ".join(reg[:30]))
    repos = sorted({l["repo_url"] for l in links if l.get("repo_url")})
    if repos:
        out.append("Source repo(s): " + ", ".join(repos))
    sos = db.get_team_signoffs(sid)
    teams = _valid_teams()
    cleared = sum(1 for s in sos.values() if s.get("status") == "clear")
    out.append(f"Team validation: {cleared} of {len(teams)} cleared")
    for team, label in teams.items():
        s = sos.get(team)
        st = s.get("status") if s else "pending"
        note = f" — {s['note']}" if (s and s.get("note")) else ""
        out.append(f"  {label}: {st}{note}")
    out.append(f"{_BASE}/{sid}")
    return "\n".join(out)


@readonly_tool
@log_tool_call
def get_advisory_package_links(advisory_id: str) -> str:
    """Direct links to each vulnerable package in an advisory (registry page per
    ecosystem + upstream GitHub repo when referenced).

    Use this for OSS Governance / blocking workflows — to pivot straight to the
    package (and feed a blocking tool like RPT), instead of only the advisory page.

    Args:
        advisory_id: The advisory ID.
    """
    adv = db.get_advisory(advisory_id)
    if not adv:
        return f"No advisory found for {advisory_id!r}."
    links = ga.advisory_package_links(adv)
    if not links:
        return f"{advisory_id}: no affected packages recorded."
    rows = []
    for l in links:
        bits = [l["name"]]
        if l.get("ecosystem"):
            bits.append(f"({l['ecosystem']})")
        if l.get("registry_url"):
            bits.append(l["registry_url"])
        if l.get("repo_url"):
            bits.append(f"repo: {l['repo_url']}")
        rows.append("- " + " ".join(bits))
    return f"{advisory_id} — {len(links)} package(s):\n" + "\n".join(rows)


@readonly_tool
@log_tool_call
def group_advisory_packages(query: str) -> str:
    """Group advisories whose packages match a token (e.g. an npm scope @mastra),
    so a whole supply-chain campaign can be assessed together instead of one by one.

    Use this when a campaign drops many look-alike packages: "how many @mastra
    packages are in the queue?", "group the X campaign".

    Args:
        query: Package scope or name fragment (e.g. @mastra).

    Returns the advisory + package counts and the package list.
    """
    g = ga.package_group(query)
    if not g["advisory_count"]:
        return f"No advisories match {query!r}."
    return (
        f"{g['advisory_count']} advisor{'y' if g['advisory_count'] == 1 else 'ies'}, "
        f"{g['package_count']} package(s)"
        + (f" across {', '.join(g['ecosystems'])}" if g["ecosystems"] else "") + ".\n"
        f"Packages: {_fmt_packages(g['packages'], limit=40)}\n"
        f"Next: check_advisory_environment_exposure({query!r}) to see if any are in our environment."
    )


@readonly_tool
@log_tool_call
def check_advisory_environment_exposure(query: str) -> str:
    """Check whether the packages in a matched advisory group are present in our
    environment, via Veracode SCA, in one shot.

    Use this to answer "are we exposed to the @mastra campaign?" before deciding to
    clear it. A miss = no open Veracode SCA finding references the package (strong,
    but not absolute proof of absence from every SBOM).

    Args:
        query: Package scope or name fragment (e.g. @mastra).
    """
    g = ga.package_group(query)
    if not g["advisory_count"]:
        return f"No advisories match {query!r}."
    c = ga.group_environment_check(g["packages"])
    if not c.get("checked"):
        return f"Environment check unavailable: {c.get('error') or 'unknown'}"
    if c.get("indexing"):
        return "Veracode SCA index is building — try again shortly."
    if not c.get("configured"):
        return "Veracode SCA is not configured in this environment."
    if c.get("exposed"):
        present = ", ".join(c.get("present_packages") or [])
        return (f"⚠️ EXPOSED: {c['affected_app_count']} application(s) carry "
                f"{len(c.get('present_packages') or [])} of these packages: {present}. "
                f"Do NOT bulk-clear — investigate the affected apps.")
    return (f"✅ Not present: none of the {c['package_count']} packages in the "
            f"{query!r} group appear in our environment (no open Veracode SCA findings). "
            f"Safe to clear the group.")


@mutating_tool
@log_tool_call
def set_advisory_team_signoff(advisory_id: str, team: str, status: str, note: str = "") -> str:
    """Record one team's validation sign-off on an advisory (clear / not_clear /
    pending) with an optional note.

    Args:
        advisory_id: The advisory ID.
        team: Team key — one of the configured validating teams (e.g.
              oss_governance, detection_engineering, package_compromise_assessment,
              soc_threat_intel). Run get_security_advisory to see current teams.
        status: One of: clear, not_clear, pending.
        note: Optional note (what was checked / exposure / ticket #).
    """
    teams = _valid_teams()
    if team not in teams:
        return f"Unknown team {team!r}. Valid teams: {', '.join(teams)}."
    if status not in ("clear", "not_clear", "pending"):
        return f"Invalid status {status!r}. Use clear, not_clear, or pending."
    if not db.get_advisory(advisory_id):
        return f"No advisory found for {advisory_id!r}."
    if not db.set_team_signoff(advisory_id, team, status, note, _AGENT_ACTOR):
        return "Could not record the sign-off."
    return f"Recorded {teams[team]} = {status} on {advisory_id}."


@mutating_tool
@log_tool_call
def bulk_clear_advisory_group(query: str, team: str, note: str = "") -> str:
    """Bulk-clear a whole campaign: mark one team's sign-off = clear across every
    advisory whose packages match the query. Use AFTER confirming with
    check_advisory_environment_exposure that none are present in our environment.

    Args:
        query: Package scope or name fragment (e.g. @mastra).
        team: Team key signing off (see set_advisory_team_signoff).
        note: Optional note recorded on every advisory in the group.
    """
    teams = _valid_teams()
    if team not in teams:
        return f"Unknown team {team!r}. Valid teams: {', '.join(teams)}."
    g = ga.package_group(query)
    if not g["members"]:
        return f"No advisories match {query!r}."
    auto = (note or "").strip() or f"Bulk-cleared via Sleuth group '{query}' — not present in environment."
    keys = [m["source_id"] or m["uid"] for m in g["members"]]
    n = db.bulk_set_team_signoff(keys, team, "clear", auto, _AGENT_ACTOR)
    return f"Cleared {n} advisor{'y' if n == 1 else 'ies'} matching {query!r} as {teams[team]}."
