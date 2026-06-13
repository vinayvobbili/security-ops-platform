"""
qa_tickets.py

Nightly LLM-based QA review of closed security incident tickets.

Samples tickets closed today (one per impact group), fetches ticket details
and investigation notes, submits each to the local LLM for quality review,
and posts a consolidated summary to the QA Tickets Webex room.

Runs nightly via ir_scheduler at 05:00 ET.
"""

import logging
import random
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytz
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

logger = logging.getLogger(__name__)

CONFIG = get_config()
EASTERN = pytz.timezone('US/Eastern')
WEBEX_CHAR_LIMIT = 6800

DB_PATH = Path(__file__).parent.parent.parent / 'data' / 'transient' / 'qa_verdicts.db'

CRITERIA_LABELS = [
    'Impact Classification', 'Detection Source', 'Investigation Thoroughness',
    'User Contact', 'SLA Compliance', 'Close Notes Quality', 'Red Flags',
    'MITRE ATT&CK Coverage',
]

_STATUS_MAP = {0: 'Pending', 1: 'Active', 2: 'Closed', 3: 'Archived'}


def _get_yesterdays_closed_tickets(handler: TicketHandler) -> list[dict]:
    """Fetch tickets closed yesterday (Eastern time), excluding jobs, IOC Hunts, and unowned."""
    now = datetime.now(EASTERN)
    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_midnight = today_midnight - timedelta(days=1)

    def _fmt(dt: datetime) -> str:
        s = dt.strftime('%Y-%m-%dT%H:%M:%S%z')
        return s[:-2] + ':' + s[-2:]  # -0400 -> -04:00

    query = (
        f'status:closed -category:job type:{CONFIG.team_name} '
        f'-owner:"" -type:"{CONFIG.team_name} IOC Hunt" '
        f'closed:>="{_fmt(yesterday_midnight)}" closed:<"{_fmt(today_midnight)}"'
    )
    return handler.get_tickets(query)


def _sample_by_impact(tickets: list[dict]) -> tuple[list[dict], dict[str, int]]:
    """Group by impact, pick one random ticket per group. Skip 'Security Testing'.

    Returns (sampled_tickets, impact_counts) where impact_counts maps
    each impact level to its total closed count.
    """
    by_impact: dict[str, list[dict]] = {}
    for ticket in tickets:
        impact = ticket.get('CustomFields', {}).get('impact', 'Unknown')
        by_impact.setdefault(impact, []).append(ticket)

    impact_counts = {impact: len(group) for impact, group in by_impact.items()}

    sampled = []
    for impact, group in by_impact.items():
        if impact == 'Security Testing':
            continue
        sampled.append(random.choice(group))
    return sampled, impact_counts


def _strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    return re.sub(r'<[^>]+>', '', text) if text else ''


def _find_similar_well_handled(ticket: dict) -> str | None:
    """Find a similar closed ticket that was well-handled (has close notes).

    Returns a formatted markdown snippet, or None if no good match found.
    """
    try:
        from src.components.xsoar_ticket_indexer import XsoarTicketIndexer

        indexer = XsoarTicketIndexer()
        query_text = f"{ticket.get('name', '')} {_strip_html(ticket.get('details', '') or '')[:300]} {ticket.get('type', '')}"

        # Constrain to same impact class — semantic match across different outcomes
        # (BTP vs FP vs Ignore) is not a "well-handled" reference, just a name-twin.
        target_impact = (ticket.get('CustomFields', {}) or {}).get('impact', '')
        if not target_impact:
            return None
        where = {"impact": target_impact}
        results = indexer.find_similar_tickets(query_text, k=10, min_similarity=0.80, where=where)

        ticket_id = str(ticket.get('id', ''))
        for r in results:
            meta = r.get('metadata', {})
            # Skip self, skip tickets without close notes
            if meta.get('id') == ticket_id:
                continue
            close_reason = meta.get('close_reason', '') or ''
            if not close_reason or close_reason.strip() in ('', 'null', 'N/A'):
                continue

            sim = r.get('similarity_score', 0)
            ref_id = meta.get('id', '?')
            ref_name = (meta.get('name', '') or '')[:60]
            ref_impact = meta.get('impact', '?')
            ref_url = f"{CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ref_id}"
            res_hours = meta.get('resolution_hours')
            res_str = f"{res_hours:.1f}h" if res_hours else '?'

            return (
                f"📚 Similar well-handled ticket: [X#{ref_id}]({ref_url}) — {ref_name} "
                f"({sim:.0%} match · {ref_impact} · {res_str} · {close_reason})"
            )
        return None
    except Exception as e:
        logger.warning(f"Similar ticket lookup failed: {e}")
        return None


def _extract_mitre_context(ticket: dict, notes: list[dict]) -> str:
    """Extract MITRE ATT&CK technique IDs from ticket text and resolve names."""
    try:
        from src.utils.entity_extractor import extract_mitre_techniques
        from services.mitre_attack_data import get_attack_techniques

        all_text = ' '.join(filter(None, [
            ticket.get('name', ''),
            _strip_html(ticket.get('details', '') or ''),
            ' '.join((n.get('note_text', '') or '') for n in notes),
        ]))
        technique_ids = extract_mitre_techniques(all_text)
        if not technique_ids:
            return '(No MITRE ATT&CK techniques referenced in ticket details or notes)'

        tech_lookup = {t['id']: t for t in get_attack_techniques()}
        lines = []
        for tid in technique_ids:
            info = tech_lookup.get(tid)
            if info:
                tactics = ', '.join(info.get('tactics', []))
                lines.append(f"- {tid}: {info['name']} [{tactics}]")
            else:
                lines.append(f"- {tid}: (unknown technique)")
        return '\n'.join(lines)
    except Exception as e:
        logger.warning(f"MITRE extraction failed: {e}")
        return '(MITRE technique extraction unavailable)'


def _build_qa_prompt(ticket: dict, notes: list[dict]) -> str:
    """Build the LLM prompt for QA evaluation of a single ticket."""
    cf = ticket.get('CustomFields', {})
    details_raw = ticket.get('details', '') or ''
    details = _strip_html(details_raw)[:2000]

    notes_text = ''
    if notes:
        note_lines = []
        for n in notes[:10]:
            text = (n.get('note_text', '') or '')[:500]
            note_lines.append(f"[{n.get('created_at', '?')}] {n.get('author', '?')}: {text}")
        notes_text = '\n'.join(note_lines)
    else:
        notes_text = '(No investigation notes found)'

    mitre_context = _extract_mitre_context(ticket, notes)
    impact = cf.get('impact', 'Unknown')
    detectionsource = cf.get('detectionsource', 'Unknown') or 'Unknown'
    securitycategory = cf.get('securitycategory', 'Unknown') or 'Unknown'
    isusercontacted = cf.get('isusercontacted', 'Unknown')
    close_reason = ticket.get('closeReason', '') or ''
    close_notes = _strip_html(ticket.get('closeNotes', '') or '')[:1000]
    hostname = cf.get('hostname', '') or ticket.get('hostname', '') or ''
    username = cf.get('username', '') or ticket.get('username', '') or ''

    return f"""You are a critical security operations QA auditor. Find gaps, missed steps, and weak practices. Be skeptical and direct — but internally consistent.

CORE RULES:
1. Use ONLY the data below. If a field says "No", it means No. Do not speculate.
2. A PASS needs positive evidence, not just absence of problems.
3. Your criterion 1 verdict sets the frame. If you call it BTP, criteria 4-6 must treat it as BTP throughout. If MTP, apply compromise-level scrutiny throughout. Never contradict yourself across criteria.

IMPACT TAXONOMY — "adversary" = whoever CAUSED the behavior, not the end user:
- MTP: a real adversary caused real malicious activity — malware, phishing, C2, supply chain attack. Even if the user was an innocent victim.
- BTP: detection fired correctly but the activity was non-malicious — pentest, admin tool, automation, authorized testing. No adversary involved.
- EDR detections use threat-oriented language by default ("suspicious", "non-standard parent", "common malware technique"). This is boilerplate framing, not evidence. The analyst's classification reflects their post-investigation assessment.
- An unfamiliar process name is not a malicious indicator. Reclassify ONLY if you see concrete contradictory evidence (known malware family in a BTP, user-initiated admin action in an MTP).

## Ticket Data
- ID: {ticket.get('id', '?')} | Name: {ticket.get('name', '?')} | Type: {ticket.get('type', '?')}
- Impact: {impact} | Detection Source: {detectionsource} | Category: {securitycategory}
- Status: {_STATUS_MAP.get(ticket.get('status'), ticket.get('status', '?'))} | Created: {ticket.get('created', '?')} | Closed: {ticket.get('closed', '?')}
- Close Reason: {close_reason} | Close Notes: {close_notes}
- Hostname: {hostname} | Username: {username} | User Contacted: {isusercontacted}
- Details: {details}

### Investigation Notes ({len(notes)} notes)
{notes_text}

### MITRE ATT&CK Techniques Referenced
{mitre_context}

## Criteria

1. **Impact**: Is "{impact}" correct? Only flag with concrete contradictory evidence. Do not reclassify based on unfamiliar process names or EDR detection language.

2. **Detection Source**: Documented and consistent with ticket type?

3. **Investigation**: Look for original analyst reasoning — what they checked, ruled out, concluded, and why. Copy-pasted CrowdStrike alerts, VirusTotal results, or playbook output is data collection, not investigation. A correct conclusion without documented reasoning is a CONCERN.

4. **User Contact**: "{isusercontacted}" — this is whether the analyst personally contacted the user during investigation. Containment auto-notifies the user separately; that does not count here.
  - MTP: "No" is FAIL — analyst must inform user of compromise.
  - BTP with sufficient context (logs, process chain, third-party confirmation from regional team/manager): "No" is PASS.
  - BTP with no supporting evidence for the benign determination: CONCERN.

5. **SLA**: Created {ticket.get('created', '?')}, closed {ticket.get('closed', '?')}. Evaluate against severity. "0001-01-01T00:00:00Z" = XSOAR zero time (never stamped), not corruption.

6. **Close Notes**: Must explain what happened and what was done. Generic ("resolved", "handled") = FAIL. Close fields are only populated on closed tickets — if status is not "Closed", empty fields are expected.

7. **Red Flags**: Issues NOT covered in 1-6. Contradictions, data errors, field mismatches. If nothing new, PASS.

8. **MITRE**: Are the right techniques documented? Flag missing applicable techniques or zero references on non-trivial incidents.

## Output Format

Example A (MTP ticket):
1. **Impact** ✅ **PASS** — Correct; malware confirmed.
2. **Detection Source** ✅ **PASS** — Consistent with ticket type.
3. **Investigation** ⚠️ **CONCERN** — Notes show the finding but not the analyst's investigative steps.
💡 **Tip:** Document what was checked and ruled out.
4. **User Contact** ❌ **FAIL** — No contact despite confirmed compromise.
💡 **Tip:** Notify user and advise on credential reset.
5. **SLA** ✅ **PASS** — Within timeframe for severity.
6. **Close Notes** ⚠️ **CONCERN** — Outcome stated but no remediation detail.
💡 **Tip:** Include specific actions taken.
7. **Red Flags** ✅ **PASS** — No additional concerns.
8. **MITRE** ⚠️ **CONCERN** — T1059 activity but no techniques referenced.
💡 **Tip:** Add applicable technique IDs.
🟡 **NEEDS REVIEW**
📋 **Key Takeaways:** Document investigative steps and add MITRE references.

Example B (BTP ticket):
1. **Impact** ✅ **PASS** — Correct; user activity confirmed benign.
2. **Detection Source** ✅ **PASS** — Consistent with ticket type.
3. **Investigation** ⚠️ **CONCERN** — Analyst confirmed benign but only pasted CrowdStrike output.
💡 **Tip:** Add a note explaining how benign intent was confirmed.
4. **User Contact** ✅ **PASS** — Regional team confirmed intent; direct contact not needed.
5. **SLA** ✅ **PASS** — Within timeframe for severity.
6. **Close Notes** ✅ **PASS** — Resolution explains the benign activity.
7. **Red Flags** ✅ **PASS** — No additional concerns.
8. **MITRE** ✅ **PASS** — Techniques appropriately documented.
🟢 **GOOD**
📋 **Key Takeaways:** Add analyst reasoning to notes instead of relying solely on pasted enrichment.

Rules:
- Criteria 1-8 in EXACT numerical order.
- PASS: one terse sentence. CONCERN/FAIL: one sentence + 💡 Tip on next line.
- Overall rating (🟢 GOOD / 🟡 NEEDS REVIEW / 🔴 POOR) is MANDATORY.
- 📋 Key Takeaways is MANDATORY — at least one concrete improvement. Not praise.
- Under 350 words."""


def _call_llm(prompt: str) -> str:
    """Send prompt to the analysis LLM and return response text.

    Routes to GPT-4.1 (``create_llm``), which is the non-tool
    analysis path; m1 GLM is the built-in fallback if the LLM gateway is unreachable. QA
    review is non-agentic prose, and GPT-4.1 also dodges the m1 nightly-batch
    contention that this job (running at 05:00) used to read-time-out on.
    """
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage
        resp = create_llm().invoke([HumanMessage(content=prompt)])
        content = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
        if not content:
            raise ValueError("empty completion content")
        return content[:3000]
    except Exception as e:
        logger.error(f"LLM QA review failed ({e})")
        return "_LLM review unavailable._"


def _format_summary_header(total_closed: int, sampled_count: int,
                           date_str: str, impact_counts: dict[str, int],
                           sampled_impacts: set[str]) -> str:
    """Format the header summary message."""
    lines = [
        f"📋 **Nightly Ticket QA Review — {date_str}**\n",
        f"🎫 Tickets closed yesterday: **{total_closed}**",
        f"🔍 Tickets sampled for QA: **{sampled_count}**\n",
    ]
    if impact_counts:
        lines.append("**Breakdown by impact:**")
        for impact, count in sorted(impact_counts.items(), key=lambda x: -x[1]):
            sampled = '✔ sampled' if impact in sampled_impacts else 'not sampled'
            lines.append(f"- **{impact}**: {count} closed ({sampled})")
    return '\n'.join(lines)


def _format_ticket_review(ticket: dict, llm_review: str,
                          similar_ref: str | None = None) -> str:
    """Format a single ticket's QA review as a Webex markdown message."""
    ticket_id = ticket.get('id', '?')
    name = (ticket.get('name', '') or '')[:60]
    impact = ticket.get('CustomFields', {}).get('impact', '?')
    ticket_type = ticket.get('type', '?')
    url = f"{CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket_id}"

    ref_block = f"\n\n{similar_ref}" if similar_ref else ''
    msg = (
        f"---\n"
        f"🔎 **QA Review: X#{ticket_id}** — {name}\n"
        f"📌 **Impact:** {impact} · **Type:** {ticket_type}\n"
        f"🔗 [View in XSOAR]({url})\n\n"
        f"{llm_review}{ref_block}\n\n"
        f"---"
    )
    if len(msg) > WEBEX_CHAR_LIMIT:
        msg = msg[:WEBEX_CHAR_LIMIT - 20] + '\n\n_[Truncated]_'
    return msg


def _send_webex(room_id: str, markdown: str) -> None:
    """Send a Webex message. Truncate if over limit."""
    try:
        webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)
        webex_api.messages.create(roomId=room_id, markdown=markdown)
    except Exception as e:
        logger.error(f"Failed to send Webex message: {e}")


def _init_db() -> sqlite3.Connection:
    """Initialize the QA verdicts database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS qa_verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            review_date TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            impact TEXT,
            criterion TEXT NOT NULL,
            verdict TEXT NOT NULL,
            overall TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_verdicts_date ON qa_verdicts(review_date)
    """)
    conn.commit()
    return conn


def _parse_verdicts(llm_review: str) -> tuple[list[tuple[str, str]], str]:
    """Parse PASS/CONCERN/FAIL verdicts and overall rating from LLM review text.

    Returns ([(criterion_label, verdict), ...], overall_rating).
    """
    verdicts = []
    for label in CRITERIA_LABELS:
        verdict = 'UNKNOWN'
        if '**PASS**' in llm_review or '✅' in llm_review:
            # Search near the criterion number for its specific verdict
            pass
        # Use a simpler approach: scan for numbered criteria lines
    # Parse each criterion by looking for emoji markers in order
    verdict_pattern = re.compile(r'(✅|⚠️|❌)\s*\*\*(PASS|CONCERN|FAIL)\*\*')
    matches = verdict_pattern.findall(llm_review)
    for i, (_, verdict) in enumerate(matches):
        label = CRITERIA_LABELS[i] if i < len(CRITERIA_LABELS) else f'Criterion {i+1}'
        verdicts.append((label, verdict))

    overall = 'UNKNOWN'
    overall_pattern = re.compile(r'(🟢|🟡|🔴)\s*\*\*(GOOD|NEEDS REVIEW|POOR)\*\*')
    overall_match = overall_pattern.search(llm_review)
    if overall_match:
        overall = overall_match.group(2)

    return verdicts, overall


def _store_verdicts(ticket_id: str, impact: str, review_date: str,
                    verdicts: list[tuple[str, str]], overall: str) -> None:
    """Store parsed verdicts in SQLite."""
    try:
        conn = _init_db()
        for criterion, verdict in verdicts:
            conn.execute(
                "INSERT INTO qa_verdicts (review_date, ticket_id, impact, criterion, verdict, overall) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (review_date, ticket_id, impact, criterion, verdict, overall)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to store QA verdicts: {e}")


def weekly_summary() -> None:
    """Post a weekly QA trends summary to Webex. Scheduled Fridays."""
    room_id = CONFIG.webex_room_id_qa_tickets
    if not room_id:
        return

    try:
        conn = _init_db()
        week_ago = (datetime.now(EASTERN) - timedelta(days=7)).strftime('%Y-%m-%d')

        # Total tickets reviewed
        total = conn.execute(
            "SELECT COUNT(DISTINCT ticket_id) FROM qa_verdicts WHERE review_date >= ?",
            (week_ago,)
        ).fetchone()[0]

        if total == 0:
            conn.close()
            logger.info("No QA reviews this week. Skipping weekly summary.")
            return

        # Overall rating distribution
        overall_rows = conn.execute(
            "SELECT overall, COUNT(DISTINCT ticket_id) FROM qa_verdicts "
            "WHERE review_date >= ? GROUP BY overall ORDER BY COUNT(DISTINCT ticket_id) DESC",
            (week_ago,)
        ).fetchall()

        # Criterion-level breakdown: count of CONCERN + FAIL per criterion
        issue_rows = conn.execute(
            "SELECT criterion, verdict, COUNT(*) FROM qa_verdicts "
            "WHERE review_date >= ? AND verdict IN ('CONCERN', 'FAIL') "
            "GROUP BY criterion, verdict ORDER BY COUNT(*) DESC",
            (week_ago,)
        ).fetchall()

        # Pass rate per criterion
        rate_rows = conn.execute(
            "SELECT criterion, "
            "  SUM(CASE WHEN verdict = 'PASS' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as pass_rate "
            "FROM qa_verdicts WHERE review_date >= ? "
            "GROUP BY criterion ORDER BY pass_rate ASC",
            (week_ago,)
        ).fetchall()

        conn.close()

        # Format message
        overall_map = {r: '🟢' for r, _ in overall_rows}
        overall_map.update({'GOOD': '🟢', 'NEEDS REVIEW': '🟡', 'POOR': '🔴'})
        overall_lines = [f"  {overall_map.get(r, '⚪')} {r}: **{c}**" for r, c in overall_rows]

        rate_lines = []
        for criterion, pass_rate in rate_rows:
            bar = '🟢' if pass_rate >= 80 else '🟡' if pass_rate >= 50 else '🔴'
            rate_lines.append(f"- **{criterion}**: {bar} {pass_rate:.0f}%")

        issue_summary = {}
        for criterion, verdict, count in issue_rows:
            issue_summary.setdefault(criterion, []).append(f"{count} {verdict}")

        top_issues = sorted(issue_summary.items(), key=lambda x: sum(
            int(v.split()[0]) for v in x[1]), reverse=True)[:5]

        msg_lines = [
            f"📊 **Weekly Ticket QA Trends — Week of {week_ago}**\n",
            f"🎫 Tickets reviewed: **{total}**\n",
            "**Overall Ratings:**",
            *overall_lines,
            "",
            "**Pass Rate by Criterion:**",
            *rate_lines,
        ]

        if top_issues:
            msg_lines.append("\n**Top Areas for Improvement:**")
            for criterion, counts in top_issues:
                msg_lines.append(f"- **{criterion}**: {', '.join(counts)}")

        _send_webex(room_id, '\n'.join(msg_lines))
        logger.info(f"Weekly QA summary posted: {total} tickets reviewed")

    except Exception as e:
        logger.error(f"Weekly QA summary failed: {e}")


def run() -> None:
    """Main entry point for nightly LLM QA review. Scheduled by ir_scheduler."""
    room_id = CONFIG.webex_room_id_qa_tickets
    if not room_id:
        logger.warning("QA tickets room not configured (WEBEX_ROOM_ID_QA_TICKETS). Skipping.")
        return

    handler = TicketHandler(XsoarEnvironment.PROD)

    yesterday = datetime.now(EASTERN) - timedelta(days=1)
    date_str = yesterday.strftime('%m/%d/%Y')
    review_date = yesterday.strftime('%Y-%m-%d')

    tickets = _get_yesterdays_closed_tickets(handler)
    if not tickets:
        logger.info("No tickets closed yesterday. Posting heads-up to Webex.")
        _send_webex(room_id, f"📋 **Nightly Ticket QA Review — {date_str}**\n\n🎫 No closed tickets yesterday. Nothing to review today.")
        return

    sampled, impact_counts = _sample_by_impact(tickets)
    if not sampled:
        logger.info("No eligible tickets after sampling. Posting heads-up to Webex.")
        _send_webex(room_id, f"📋 **Nightly Ticket QA Review — {date_str}**\n\n🎫 {len(tickets)} closed ticket(s) yesterday, but none eligible for QA sampling (all in excluded categories).")
        return

    sampled_impacts = {
        t.get('CustomFields', {}).get('impact', 'Unknown') for t in sampled
    }
    header = _format_summary_header(len(tickets), len(sampled), date_str,
                                    impact_counts, sampled_impacts)
    _send_webex(room_id, header)

    for ticket in sampled:
        ticket_id = ticket.get('id', 'unknown')
        try:
            notes = handler.get_user_notes(ticket_id)
        except Exception as e:
            logger.warning(f"Failed to fetch notes for ticket {ticket_id}: {e}")
            notes = []

        prompt = _build_qa_prompt(ticket, notes)
        llm_review = _call_llm(prompt)
        similar_ref = _find_similar_well_handled(ticket)
        message = _format_ticket_review(ticket, llm_review, similar_ref)
        _send_webex(room_id, message)

        # Store verdicts for weekly trend tracking
        verdicts, overall = _parse_verdicts(llm_review)
        impact = ticket.get('CustomFields', {}).get('impact', 'Unknown')
        _store_verdicts(ticket_id, impact, review_date, verdicts, overall)

    logger.info(f"QA review complete: {len(sampled)} tickets reviewed out of {len(tickets)} closed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    run()
