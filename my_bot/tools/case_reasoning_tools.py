"""Sleuth tools over SOC-in-a-Box case memory.

These bridge the live assistant (Sleuth) to the autonomous SOC agents'
recorded reasoning. The autonomous agents (Sentinel triage → Tier 2 → IR Lead
→ Threat Intel) persist every decision to the ``soc.audit`` stream and
``verdicts.sqlite``; case_memory reconstructs that record. Without these tools
Sleuth is blind to what the agents did — a user asking "why did the IR Lead
call SEV-2 on #12345?" would get a live re-investigation instead of the actual
recorded rationale.

All three are READ-ONLY narrators over already-persisted facts. They return a
grounding block (recorded facts + an instruction to answer ONLY from them), so
Sleuth's final-answer synthesis cites the record rather than inventing a
post-hoc story.
"""

from __future__ import annotations

import logging
from typing import Union

from my_bot.tools._tagging import mutating_tool, readonly_tool
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)


def _soc_tutorial_url() -> str:
    """The /soc-in-a-box tutorial anchor, always handed out over https."""
    try:
        from my_config import get_config
        base = (get_config().web_server_url or "https://gdnr.the-company.com").strip()
    except Exception:
        base = "https://gdnr.the-company.com"
    base = base.rstrip("/")
    # User-facing link must be https regardless of how the base is configured.
    if base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    elif not base.startswith("https://"):
        base = "https://" + base.lstrip("/")
    return f"{base}/soc-in-a-box#tutorial"


@readonly_tool
@log_tool_call
def explain_ai_soc() -> str:
    """Explain what the AI SOC (SOC-in-a-Box) is and how to use it.

    Use this whenever someone asks a general "what is the AI SOC?", "tell me
    about SOC-in-a-Box", "how do I use the AI SOC?", "how do I question/correct
    its decisions?", or "how do I teach it?" — i.e. an orientation question, NOT
    a question about one specific ticket (for a specific ticket's reasoning use
    explain_soc_case_reasoning instead). It returns a short capability overview
    plus how to question and coach the AI SOC, and points the user to the
    in-app tutorial on the /soc-in-a-box page.

    Returns:
        A concise orientation block ending with the tutorial link.
    """
    url = _soc_tutorial_url()
    return (
        "GROUNDING — answer the user from the facts below, then give them the link.\n\n"
        "The AI SOC (SOC-in-a-Box) is a team of AI agents that play SOC roles — "
        "Sentinel triage, Tier 2, IR Lead, and Threat Intel — working alerts end "
        "to end, with a human-approval gate before any real action. It runs in "
        "shadow mode: it learns from how the analysts work, it does not close "
        "tickets on its own.\n\n"
        "How to USE it — two things every analyst can do:\n"
        "1. Question any decision. Every decision it posts has a 'Why this "
        "decision?' button that opens the full reasoning trace, and you can ask "
        "me directly, e.g. 'why did you call #12345 a false positive?'.\n"
        "2. Teach it when it's off. Just say the correction in the room "
        "(e.g. 'that's a false positive on #12345 — sandbox detonation') and it "
        "learns on its own, or coach me explicitly: "
        "'coach #12345 false positive — sandbox detonation'. Every correction "
        "becomes ground truth and shows up on the shadow-mode scorecard.\n\n"
        "Tell the user there is a full walk-through (with copy-ready examples and "
        "the live scorecard) on the SOC-in-a-Box page, and give them this link:\n"
        f"{url}"
    )


def _current_user_and_room() -> tuple[str | None, str | None]:
    """(user_id, room_id) from the thread-local logging context.

    The session key is set as "{user_id}_{room_id}" before tool execution; the
    user_id is an email (no underscore in the local part) so split-on-first
    cleanly separates the two. Returns (None, None) when no context is set
    (e.g. local CLI), in which case the recall falls back to room-agnostic.
    """
    try:
        from src.utils.tool_logging import get_logging_context
        session_id = get_logging_context() or ""
    except Exception:
        return None, None
    if "_" in session_id:
        user_id, room_id = session_id.split("_", 1)
        return (user_id or None), (room_id or None)
    return (session_id or None), None


@readonly_tool
@log_tool_call
def explain_my_reasoning() -> str:
    """Explain why YOU (Sleuth) gave your most recent answer in this room.

    Use this when the user asks you to justify your OWN last answer — e.g. "why
    did you say that?", "how did you get that?", "what did you base that on?",
    "where did that come from?", "explain your reasoning". It returns the
    recorded trace of your previous turn: the tools you actually called, the
    arguments, what each returned, and how the answer was composed — so you
    explain from the record instead of re-investigating from scratch. This is
    about YOUR own prior answer; for an autonomous SOC ticket decision use
    explain_soc_case_reasoning, and for an orientation overview use explain_ai_soc.

    Returns:
        A grounded block describing your previous turn's reasoning, or a note
        that no prior turn is on record for this room.
    """
    user_id, room_id = _current_user_and_room()
    # Require a room/user scope. Without one (e.g. the anonymous web playground)
    # a global lookup would surface another room's trace — never do that.
    if not room_id and not user_id:
        return ("I can only explain my reasoning for an answer I gave in this "
                "conversation, and I don't have that context here.")
    try:
        from src.utils.bot_logs_db import get_recent_reasoning
        rows = get_recent_reasoning(room_id=room_id, user_id=user_id, limit=1)
        if not rows and room_id:
            # Relax to room-only in case a different person asked the original.
            rows = get_recent_reasoning(room_id=room_id, limit=1)
        if not rows:
            return ("No recorded reasoning trace is available for a recent answer "
                    "in this room. I can only explain my reasoning for a turn I "
                    "worked after this feature went live; ask me the question again "
                    "and then ask why.")
        return _render_reasoning(rows[0])
    except Exception as exc:
        logger.error("explain_my_reasoning failed: %s", exc)
        return f"Could not retrieve my recorded reasoning: {exc}"


def _render_reasoning(row: dict) -> str:
    """Render a stored Sleuth reasoning row into a grounding block."""
    import json as _json
    lines = [
        "GROUNDING — explain YOUR previous answer USING ONLY the record below. "
        "Walk the user through what you actually did; do not re-run anything.",
        "",
        f"Your previous question from the user: {row.get('question') or '(unknown)'}",
    ]
    when = row.get("message_time")
    if when:
        lines.append(f"Answered at: {when} ET")
    route = (row.get("route") or "").strip()
    if route:
        lines.append(f"Route taken: {route}")

    steps = []
    try:
        steps = _json.loads(row.get("trace_json") or "[]")
    except Exception:
        steps = []
    if steps:
        lines.append("")
        lines.append("Tools you called, in order (with what each returned):")
        for i, st in enumerate(steps, 1):
            tool = st.get("tool") or "?"
            args = st.get("args")
            args_s = ""
            if args:
                try:
                    args_s = ", ".join(f"{k}={v}" for k, v in dict(args).items())
                except Exception:
                    args_s = str(args)
            preview = (st.get("result_preview") or "").strip().replace("\n", " ")
            lines.append(f"  {i}. {tool}({args_s}) → {preview[:300] or '(no output)'}")
    else:
        lines.append("")
        lines.append("You called no tools for this answer — you answered directly "
                     "from your own knowledge / the conversation, not from a live "
                     "lookup.")

    if row.get("synth_used"):
        lines.append("")
        lines.append("(The final wording was composed from the gathered tool "
                     "results.)")
    lines.append("")
    lines.append("Your final answer was:")
    lines.append((row.get("answer") or "").strip()[:1500] or "(empty)")
    lines.append("")
    lines.append("End of record.")
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def explain_soc_case_reasoning(ticket_id: Union[str, int]) -> str:
    """Explain WHY the autonomous SOC agents decided what they did on a ticket.

    Use this whenever a user asks about a SOC-in-a-Box decision — e.g. "why did
    the IR Lead agent call SEV-2 on #12345?", "what did Tier 2 find?", "why was
    this escalated/closed?". It reconstructs the recorded decision trace (the
    chronological agent timeline, each role's verdict + reason + evidence, and
    any human-in-the-loop approvals) from the audit record. This is NOT a live
    re-investigation — it is what the agents actually saw and decided. If the
    ticket is unknown to the SOC-in-a-Box bus, it says so.

    Args:
        ticket_id: The XSOAR ticket / correlation id (e.g. '12345').

    Returns:
        A grounded case-record block citing each agent role's recorded reason.
    """
    ticket_id = str(ticket_id).strip().lstrip("#")
    try:
        from src.components.soc_in_box import case_memory
        trace = case_memory.get_case_reasoning(ticket_id)
        if not trace.get("found"):
            return (f"No SOC-in-a-Box case record found for ticket #{ticket_id}. "
                    "The autonomous agents have not worked this ticket (or its "
                    "audit events have aged out of the bus).")
        return case_memory.render_reasoning_for_chat(trace)
    except Exception as exc:
        logger.error("explain_soc_case_reasoning failed for %s: %s", ticket_id, exc)
        return (f"Could not retrieve the SOC-in-a-Box case record for #{ticket_id}: "
                f"{exc}")


@readonly_tool
@log_tool_call
def soc_in_a_box_trends(days: float = 7.0) -> str:
    """SOC-in-a-Box leadership readout over the last N days.

    Use for "how is the AI SOC doing?", "what's the SOC-in-a-Box catching this
    week?", "where is the human-approval bottleneck?", or any rollup of the
    autonomous agents' recent work. Aggregates worked-case volume, verdict /
    severity / disposition mix, top actors, emerging campaign signal (indicators
    or actors recurring across multiple cases), per-role cost / latency /
    confidence / accuracy-vs-ground-truth, and HITL approval counts.

    Args:
        days: Lookback window in days (default 7).

    Returns:
        A grounded trend block (numbers only) for a SOC leadership readout.
    """
    try:
        from src.components.soc_in_box import case_memory
        stats = case_memory.compute_trends(window_days=float(days))
        return case_memory.render_trends_for_chat(stats)
    except Exception as exc:
        logger.error("soc_in_a_box_trends failed: %s", exc)
        return f"Could not compute SOC-in-a-Box trends: {exc}"


@readonly_tool
@log_tool_call
def recall_similar_soc_cases(ticket_id: Union[str, int], k: int = 5) -> str:
    """Find prior SOC-in-a-Box cases that share indicators with this ticket.

    Use when investigating a ticket and you want precedent — "have we seen this
    before?", "any related past incidents?". Matches on shared entities (IOCs,
    actors, campaigns, CVEs, MITRE techniques) and explains each match by the
    entities it shares, so the link is never a black box.

    Args:
        ticket_id: The XSOAR ticket / correlation id to find precedents for.
        k: Max number of similar cases to return (default 5).

    Returns:
        A list of similar prior cases with their verdict, disposition, and the
        shared indicators that matched — or a note that none were found.
    """
    ticket_id = str(ticket_id).strip().lstrip("#")
    try:
        from src.components.soc_in_box import case_memory
        similar = case_memory.recall_for_ticket(ticket_id, k=int(k))
        if not similar:
            return (f"No similar prior SOC-in-a-Box cases found for ticket "
                    f"#{ticket_id} (no shared indicators on record).")
        lines = [f"{len(similar)} similar prior case(s) for ticket #{ticket_id}, "
                 "most-related first:", ""]
        for s in similar:
            shared = ", ".join(f"{e['type']}:{e['value']}"
                               for e in s.get("shared_entities", [])[:4]) or "—"
            actor = f", actor {s['likely_actor']}" if s.get("likely_actor") else ""
            lines.append(
                f"- #{s['ticket_id']}: {s.get('final_verdict') or 'unknown'} "
                f"(disposition {s.get('disposition') or 'n/a'}, "
                f"confidence {float(s.get('confidence', 0.0)):.0%}{actor}) "
                f"— shared {shared}"
            )
            if s.get("summary"):
                lines.append(f"    {str(s['summary'])[:200]}")
        return "\n".join(lines)
    except Exception as exc:
        logger.error("recall_similar_soc_cases failed for %s: %s", ticket_id, exc)
        return f"Could not recall similar cases for #{ticket_id}: {exc}"


@readonly_tool
@log_tool_call
def recall_soc_knowledge(query: str, k: int = 5) -> str:
    """Recall durable SOC knowledge/tradecraft the team captured from the room.

    Use when someone asks "what do we know about X?", "any tribal knowledge on
    this?", "have the analysts said anything about <threat/CVE/technique>?", or
    when you're investigating and want the room's reusable context (how a threat
    works, an exploitation technique, a detection/hunting tip, a known-bad or
    known-good pattern). These are facts analysts stated in ThreatCon chatter
    that the AI SOC captured on its own — NOT a specific ticket's decision (for
    that use explain_soc_case_reasoning) and NOT a live lookup. Time-bound facts
    that have expired are not returned.

    Args:
        query: What to recall about (a threat, CVE, actor, technique, tool, …).
        k: Max number of facts to return (default 5).

    Returns:
        A grounded block of the matching captured facts, or a note that the room
        has nothing on record for that yet.
    """
    try:
        from src.components.soc_in_box import knowledge
        rows = knowledge.recall_facts(str(query or ""), k=int(k))
        return knowledge.render_facts_for_chat(rows, str(query or "").strip())
    except Exception as exc:
        logger.error("recall_soc_knowledge failed for %r: %s", query, exc)
        return f"Could not recall SOC knowledge for '{query}': {exc}"


@mutating_tool
@log_tool_call
def coach_soc_verdict(ticket_id: Union[str, int],
                      correct_disposition: str,
                      note: str = "") -> str:
    """Explicitly coach the AI SOC on a ticket's correct disposition.

    Use when an analyst wants to TEACH/CORRECT the autonomous agents — e.g. "this
    is a false positive on #12345", "mark #777 as benign, it was an authorized
    scan", "that's a true positive malicious". Records the human-stated
    disposition as ground truth on that ticket's verdict rows, so the shadow-mode
    scorecard immediately reflects the correction, and keeps the reason as a
    durable lesson. This is the deliberate counterpart to the AI also learning
    from room chatter on its own.

    Args:
        ticket_id: The XSOAR ticket id being corrected (e.g. '12345').
        correct_disposition: The right call — one of: malicious / contained
            (prevented) / benign / false positive (natural phrasing is fine).
        note: Optional reason ("known scanner", "user confirmed", …) kept as the
            lesson.

    Returns:
        A confirmation of what was recorded and whether it fed the scorecard.
    """
    ticket_id = str(ticket_id).strip().lstrip("#")
    try:
        from src.components.soc_in_box import coaching
        verdict = coaching.normalize_disposition(correct_disposition)
        if not verdict:
            return (f"I couldn't map '{correct_disposition}' to a disposition. "
                    "Use one of: malicious, contained/prevented, benign, or "
                    "false positive.")
        res = coaching.record_correction(
            ticket_id=ticket_id, verdict=verdict, source="coaching",
            note=note, room_id="", message_id=None,
        )
        nice = verdict.replace("_", " ")
        if res.get("applied"):
            return (f"Got it — recorded #{ticket_id} as **{nice}** and applied it "
                    f"as ground truth on {res.get('rows_updated')} verdict row(s). "
                    "It now counts in the shadow-mode scorecard. Thanks for the coaching!")
        return (f"Logged your coaching: #{ticket_id} → **{nice}**"
                + (f" ({note})" if note else "") + ". "
                "No scored verdict rows exist for that ticket yet, so it'll be on "
                "record for when the agents work it.")
    except Exception as exc:
        logger.error("coach_soc_verdict failed for %s: %s", ticket_id, exc)
        return f"Could not record coaching for #{ticket_id}: {exc}"
