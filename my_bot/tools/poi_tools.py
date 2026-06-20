"""Person-of-Interest OSINT investigation tool.

LLM-callable wrapper around services.poi_scanner. Runs a fast (~60-90s)
investigation that combines:
  - HIBP breach lookup for the email
  - holehe email account-existence sweep
  - maigret username footprint (top-60 most popular sites for speed)
  - Google dork link block for the name

Returns a compact markdown summary plus a link to the full /person-of-interest
web report where the investigation is persisted.

Targets on the internal exception list are silently skipped and the tool
returns a generic "no findings" message — no DB row, no leakage.
"""

import logging

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

from services.poi_scanner import PUBLIC_BASE_URL, run_investigation_sync
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)


@mutating_tool
@log_tool_call
def investigate_person_of_interest(
    name: str = "",
    username: str = "",
    email: str = "",
    reason: str = "",
) -> str:
    """Run an OSINT investigation on a person of interest.

    Pulls breach data, email account existence, and username footprint across
    popular social/dev/forum sites. Provide whichever identifiers you have —
    at least one of name, username, or email is required. More identifiers
    produce a richer report.

    Use this for:
    - Insider-threat triage when investigating a known employee or external party
    - Pre-engagement OSINT on a person who appears in a ticket
    - "Who is this account?" lookups when only a username or email is known

    Do NOT use this for:
    - Casual curiosity about colleagues
    - Investigating yourself or arbitrary public figures
    - Anything outside an authorized investigation

    Each call is logged with the requester's identity for audit purposes.
    Investigations are persisted at https://gdnr.the-company.com/person-of-interest
    where the full report (breach details, claimed profile URLs, etc.) is viewable.

    Args:
        name: Full name of the person (e.g. "Jane Doe"). Optional.
        username: Username or social handle (e.g. "janedoe42"). Optional.
        email: Email address (e.g. "jane@example.com"). Optional.
        reason: Brief justification for the investigation. Optional but encouraged.
    """
    name = (name or "").strip()
    username = (username or "").strip()
    email = (email or "").strip()
    reason = (reason or "").strip()

    if not (name or username or email):
        return "❌ Provide at least one identifier: name, username, or email."

    try:
        result = run_investigation_sync(
            name=name, username=username, email=email, reason=reason,
            requester="sleuth-tool", fast=True,
        )
    except Exception as e:
        logger.error("POI investigation failed: %s", e, exc_info=True)
        return f"❌ Investigation failed: {e}"

    if result is None:
        return "✅ Investigation complete. No notable findings."

    s = result.get("summary", {})
    r = result.get("results", {})
    inv_id = result.get("id")
    duration = result.get("duration_s")

    lines = [
        f"## OSINT Report #{inv_id}",
        "",
        f"**Targets:** " + ", ".join(filter(None, [
            f"name *{name}*" if name else "",
            f"username `{username}`" if username else "",
            f"email `{email}`" if email else "",
        ])),
        f"**Duration:** {duration}s",
        "",
        "### Highlights",
    ]

    b = s.get("hibp_breach_count")
    if b is not None:
        lines.append(f"- 🚨 HIBP breaches: **{b}**")
        if b and r.get("hibp", {}).get("breaches"):
            top = r["hibp"]["breaches"][:8]
            top_names = [(br.get("name") if isinstance(br, dict) else str(br)) for br in top]
            lines.append(f"  - {', '.join(top_names)}" + ("…" if len(r["hibp"]["breaches"]) > 8 else ""))

    h = s.get("holehe_hit_count")
    if h is not None:
        lines.append(f"- 📧 Email accounts found: **{h}**")
        if h and r.get("holehe", {}).get("hits"):
            top_hits = r["holehe"]["hits"][:10]
            lines.append(f"  - {', '.join(top_hits)}" + ("…" if len(r["holehe"]["hits"]) > 10 else ""))

    m = s.get("maigret_claimed_count")
    if m is not None:
        lines.append(f"- 🌐 Claimed usernames: **{m}** (top-60 sites checked)")
        if m and r.get("maigret", {}).get("claimed"):
            top_sites = [c["site"] for c in r["maigret"]["claimed"][:10]]
            lines.append(f"  - {', '.join(top_sites)}" + ("…" if len(r["maigret"]["claimed"]) > 10 else ""))

    lines.append("")
    lines.append(f"📄 **Full report:** {PUBLIC_BASE_URL}/person-of-interest/{inv_id}")

    return "\n".join(lines)
