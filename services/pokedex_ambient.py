"""Pokedex ambient mode — proactive, suggestion-only room watcher.

The Webex bot is normally *reactive*: it only acts when @-mentioned, because
in group spaces Webex's data gateway only pushes mention events to a bot
account over the websocket. Ambient mode adds a *proactive* path that does NOT
rely on the websocket at all — it polls ``messages.list`` (read via a
*service-account* OAuth token with ``spark:messages_read``; a bot token 403s on
group-room reads, proven 2026-06-24) on a scheduler tick, runs one toolless
relevance pass on the LLM over each new human message, and — only when the
message clears a confidence bar — posts a threaded *suggestion card* offering
to run a triage. It NEVER acts on its own: the suggestion is a proposal with a
button; the actual investigation still flows through the normal RBAC-gated
agentic path when a human clicks it. So ambient adds zero new tool-execution
surface and cannot fire a destructive tool.

Design constraints baked in here:
  * OFF by default. Gated on ``POKEDEX_AMBIENT_ENABLED`` so a deploy is inert
    until the flag is flipped. Slice 1 is meant to run on the dev-test space
    only for tuning the threshold against real chatter.
  * Light + decoupled. One toolless ``create_llm`` relevance call per new
    message, never the full agentic loop. Running the gate on a separate LLM —
    not the local router — keeps ambient from competing with the tool-calling
    investigation path for scarce capacity, and stays fast even when the
    investigation LLM is saturated. The LLM self-falls-back if the gateway is
    down.
  * Idempotent. A per-room cursor + a processed-message ledger (SQLite, in the
    data-isolated ``data/`` dir) guarantee a message is classified — and at most
    suggested on — exactly once, even across scheduler restarts.
  * Bot-directed messages are skipped: anything that @-mentions Pokedex or comes
    from a bot account already has (or will get) the normal reactive path.

Entry point for the scheduler is :func:`scan_ambient_rooms`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, asdict
from itertools import islice
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# --- Configuration (all env-overridable; safe defaults) ----------------------

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "pokedex_ambient.db"

# Newest N messages to pull per room per tick. The cursor keeps us from
# re-processing, so this only bounds the catch-up window after downtime.
_DEFAULT_LOOKBACK = 20

# Confidence at/above which we surface a suggestion card. Tuned conservatively
# high to start — ambient should under-speak, not spam. Lower it from telemetry.
_DEFAULT_THRESHOLD = 0.72

# Bot name fragments used to detect bot-directed messages (handled by the
# normal reactive path) so ambient stays out of their way.
_BOT_NAME_FRAGMENTS = ("pokedex", "dnr_pokedex")

_RELEVANCE_SYSTEM_PROMPT = """You are the relevance gate for a SOC assistant that \
watches a security operations chat room. For each message decide whether the SOC \
bot should proactively offer to help. The bot is good at: triaging IOCs (IPs, \
domains, file hashes, URLs), looking up hosts/endpoints, checking CVEs against \
the fleet, investigating user accounts, and analyzing suspected phishing/malware.

Offer help ONLY when the message contains a concrete security artifact or an \
explicit analyst need the bot can act on. Do NOT offer help for chit-chat, \
status updates, opinions, scheduling, or messages already addressed to a person.

Set "requires_approval" to true ONLY when the message asks the bot to TAKE a \
changing or enforcement action — block a URL/IP/domain, isolate or contain a host, \
quarantine or delete a file, close a case, run a command on an endpoint, or launch \
an attack simulation. For read-only asks — enrich an indicator, look up a host, \
check a CVE, investigate an account, or report the STATUS of something (e.g. \
"containment status") — set it false. When unsure, default to false.

Respond with ONLY a JSON object, no prose, no code fences:
{"relevant": <true|false>, "score": <0.0-1.0>, "category": "<ioc|host|cve|account|phishing|malware|other|none>", "entity": "<the specific artifact, or empty>", "reason": "<one short clause>", "suggested_action": "<what the bot would offer to do, imperative, <=12 words>", "requires_approval": <true|false>}"""

# Batch variant: same judgement, but scores MANY messages in one call so a busy
# room costs one LLM request per tick instead of N. Per-message calls hammered
# the gateway's rate limit (429s seen in an early dry-pass 2026-06-24).
_BATCH_SYSTEM_PROMPT = """You are the relevance gate for a SOC assistant that \
watches a security operations chat room. You are given a NUMBERED list of \
messages. For EACH message decide whether the SOC bot should proactively offer \
to help. The bot is good at: triaging IOCs (IPs, domains, file hashes, URLs), \
looking up hosts/endpoints, checking CVEs against the fleet, investigating user \
accounts, and analyzing suspected phishing/malware.

Offer help ONLY when a message contains a concrete security artifact or an \
explicit analyst need the bot can act on. Do NOT offer help for chit-chat, \
status updates, opinions, scheduling, or messages already addressed to a person.

Set "requires_approval" to true ONLY when a message asks the bot to TAKE a \
changing or enforcement action — block a URL/IP/domain, isolate or contain a host, \
quarantine or delete a file, close a case, run a command on an endpoint, or launch \
an attack simulation. For read-only asks — enrich an indicator, look up a host, \
check a CVE, investigate an account, or report the STATUS of something (e.g. \
"containment status") — set it false. When unsure, default to false.

Respond with ONLY a JSON array, no prose, no code fences. Return exactly one \
object per input message, in order, each tagged with its 0-based "index":
[{"index": <int>, "relevant": <true|false>, "score": <0.0-1.0>, "category": "<ioc|host|cve|account|phishing|malware|other|none>", "entity": "<the specific artifact, or empty>", "reason": "<one short clause>", "suggested_action": "<what the bot would offer to do, imperative, <=12 words>", "requires_approval": <true|false>}]"""


@dataclass
class Suggestion:
    """Outcome of classifying one message."""

    relevant: bool
    score: float
    category: str
    entity: str
    reason: str
    suggested_action: str
    # True only when the message asks the bot to TAKE a changing/enforcement action
    # (block, isolate/contain a host, quarantine, close a case, run a command, launch
    # a simulation). Read-only asks (enrich, look up, check status, assess) are False.
    # Drives auto-run vs human-in-the-loop card: reads auto-run, writes need a click.
    requires_approval: bool = False
    # The original triggering message text, set by scan_room after classification so
    # _run_query can prefer the analyst's actual question over a synthetic directive.
    source_text: str = ""

    @classmethod
    def irrelevant(cls, reason: str = "below bar") -> "Suggestion":
        return cls(False, 0.0, "none", "", reason, "")


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _ambient_enabled() -> bool:
    return _env_flag("POKEDEX_AMBIENT_ENABLED", default=False)


def _post_enabled() -> bool:
    """Dry-run switch: when off, classify + log but never post a card.

    Lets us tune the threshold against live traffic before the room sees a
    single suggestion. Defaults ON (posting) once ambient itself is enabled.
    """
    return _env_flag("POKEDEX_AMBIENT_POST", default=True)


def _autorun_enabled() -> bool:
    """When on (default), read-only suggestions AUTO-RUN and post the answer; only
    destructive-intent messages get a human-in-the-loop card. Off → everything is a
    card (the original suggestion-only posture). Gated by _post_enabled() either way."""
    return _env_flag("POKEDEX_AMBIENT_AUTORUN", default=True)


def _autorun_cap() -> int:
    """Max auto-runs per room per tick — bounds a tick's wall-clock (each auto-run is
    a full agentic investigation). Over the cap, a read falls back to a card so it's
    deferred, never silently dropped."""
    try:
        return max(0, int(os.getenv("POKEDEX_AMBIENT_AUTORUN_MAX", "3")))
    except (TypeError, ValueError):
        return 3


def _ambient_rooms() -> list[str]:
    """Rooms to watch. Defaults to the dev-test space only (slice 1 scope)."""
    raw = os.getenv("POKEDEX_AMBIENT_ROOMS", "").strip()
    if raw:
        return [r.strip() for r in raw.split(",") if r.strip()]
    try:
        from my_config import get_config
        room = getattr(get_config(), "webex_room_id_dev_test_space", "") or ""
        return [room] if room else []
    except Exception:
        return []


def _threshold() -> float:
    try:
        return float(os.getenv("POKEDEX_AMBIENT_THRESHOLD", str(_DEFAULT_THRESHOLD)))
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD


def _lookback() -> int:
    try:
        return int(os.getenv("POKEDEX_AMBIENT_LOOKBACK", str(_DEFAULT_LOOKBACK)))
    except (TypeError, ValueError):
        return _DEFAULT_LOOKBACK


# --- Persistence -------------------------------------------------------------


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), timeout=30)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ambient_cursor ("
        " room_id TEXT PRIMARY KEY,"
        " last_created TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ambient_processed ("
        " message_id TEXT PRIMARY KEY,"
        " room_id TEXT NOT NULL,"
        " created TEXT,"
        " relevant INTEGER,"
        " score REAL,"
        " category TEXT,"
        " suggested INTEGER DEFAULT 0)"
    )
    # One row per suggestion card that has been actioned. The PRIMARY KEY makes a
    # claim atomic: only the first click can INSERT, so a second analyst clicking
    # the same card (even in the same second) loses the race and never re-runs.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ambient_claims ("
        " card_message_id TEXT PRIMARY KEY,"
        " actor TEXT,"
        " action TEXT,"
        " claimed_at TEXT)"
    )
    return conn


def _get_cursor(conn: sqlite3.Connection, room_id: str) -> Optional[str]:
    row = conn.execute(
        "SELECT last_created FROM ambient_cursor WHERE room_id = ?", (room_id,)
    ).fetchone()
    return row[0] if row else None


def _set_cursor(conn: sqlite3.Connection, room_id: str, created: str) -> None:
    conn.execute(
        "INSERT INTO ambient_cursor (room_id, last_created) VALUES (?, ?) "
        "ON CONFLICT(room_id) DO UPDATE SET last_created = excluded.last_created "
        "WHERE excluded.last_created > ambient_cursor.last_created",
        (room_id, created),
    )


def _already_processed(conn: sqlite3.Connection, message_id: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM ambient_processed WHERE message_id = ?", (message_id,)
        ).fetchone()
        is not None
    )


def _record(
    conn: sqlite3.Connection,
    message_id: str,
    room_id: str,
    created: str,
    s: Suggestion,
    suggested: bool,
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO ambient_processed "
        "(message_id, room_id, created, relevant, score, category, suggested) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (message_id, room_id, created, int(s.relevant), s.score, s.category, int(suggested)),
    )


# --- Classification ----------------------------------------------------------


def _suggestion_from_dict(data: dict) -> Suggestion:
    """Build a Suggestion from one parsed verdict object, clamping the score."""
    try:
        score = float(data.get("score", 0.0))
    except (TypeError, ValueError):
        score = 0.0
    score = max(0.0, min(1.0, score))
    return Suggestion(
        relevant=bool(data.get("relevant", False)),
        score=score,
        category=str(data.get("category", "none") or "none"),
        entity=str(data.get("entity", "") or ""),
        reason=str(data.get("reason", "") or ""),
        suggested_action=str(data.get("suggested_action", "") or ""),
        requires_approval=bool(data.get("requires_approval", False)),
    )


def _parse_classification(content: str) -> Suggestion:
    """Parse a single JSON verdict, defensively.

    The model occasionally wraps JSON in prose or a code fence. Extract the first
    balanced object and fail closed (irrelevant) on any parse error so a
    malformed verdict can never produce a false suggestion.
    """
    if not content:
        return Suggestion.irrelevant("empty verdict")
    # Strip code fences / locate the JSON object.
    match = re.search(r"\{.*\}", content.strip(), re.DOTALL)
    if not match:
        return Suggestion.irrelevant("no json in verdict")
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return Suggestion.irrelevant("unparseable verdict")
    return _suggestion_from_dict(data)


def _parse_batch(content: str, expected: int) -> Optional[list[Suggestion]]:
    """Parse a JSON array of verdicts into ``expected`` Suggestions, by index.

    Returns None on total failure (no array / unparseable / nothing mapped) so
    the caller can fall back to per-message classification. A single missing
    slot does NOT reject the whole batch — that one item fails closed instead.
    """
    if not content:
        return None
    match = re.search(r"\[.*\]", content.strip(), re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    out: list[Optional[Suggestion]] = [None] * expected
    mapped = 0
    for pos, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        idx = item.get("index", pos)
        try:
            idx = int(idx)
        except (TypeError, ValueError):
            idx = pos
        if 0 <= idx < expected and out[idx] is None:
            out[idx] = _suggestion_from_dict(item)
            mapped += 1
    if mapped == 0:
        return None  # nothing usable — let caller retry per-message
    return [s if s is not None else Suggestion.irrelevant("missing in batch") for s in out]


def classify_message(text: str, llm=None) -> Suggestion:
    """Run the relevance gate on one message. ``llm`` is injectable for tests.

    Returns a :class:`Suggestion`; ``relevant``/``score`` reflect the model's
    verdict and are NOT yet thresholded — :func:`scan_room` applies the bar.
    """
    text = (text or "").strip()
    if len(text) < 4:
        return Suggestion.irrelevant("too short")
    if llm is None:
        # Toolless classification → a fast LLM instead of the local router. This
        # keeps ambient's per-message load off the local LLM, which is reserved
        # for the tool-calling investigation path. The LLM self-falls-back if the
        # gateway is unreachable, so this never hard-fails.
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm(temperature=0.0)
    from langchain_core.messages import HumanMessage, SystemMessage

    try:
        resp = llm.invoke(
            [
                SystemMessage(content=_RELEVANCE_SYSTEM_PROMPT),
                HumanMessage(content=text[:2000]),
            ]
        )
        content = getattr(resp, "content", "") or ""
    except Exception as e:  # network / timeout — fail closed, no suggestion
        logger.warning(f"[ambient] classification call failed: {e}")
        return Suggestion.irrelevant("llm error")
    return _parse_classification(content)


def classify_messages_batch(texts: list[str], llm=None) -> list[Suggestion]:
    """Classify many messages in ONE LLM call, returning a Suggestion per input.

    This is the production path: a busy room would otherwise fire one LLM
    request per message and trip the gateway's rate limit (429s observed in
    an early dry-pass). Batching makes a tick cost a single request.

    Output is index-aligned with ``texts``. Trivially short messages never reach
    the model. On any batch-level failure (call error, unparseable array, or
    nothing mapped) it degrades to per-message :func:`classify_message` so a bad
    batch is slower, never silently dropped.
    """
    results: list[Optional[Suggestion]] = [None] * len(texts)
    if not texts:
        return []

    # Only real candidates consume a slot in the prompt; short ones short-circuit.
    to_send: list[tuple[int, str]] = []
    for i, t in enumerate(texts):
        t = (t or "").strip()
        if len(t) < 4:
            results[i] = Suggestion.irrelevant("too short")
        else:
            to_send.append((i, t))
    if not to_send:
        return [r or Suggestion.irrelevant() for r in results]

    if llm is None:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm(temperature=0.0)
    from langchain_core.messages import HumanMessage, SystemMessage

    numbered = "\n".join(f"[{n}] {t[:1000]}" for n, (_i, t) in enumerate(to_send))
    verdicts: Optional[list[Suggestion]] = None
    try:
        resp = llm.invoke(
            [
                SystemMessage(content=_BATCH_SYSTEM_PROMPT),
                HumanMessage(content=numbered),
            ]
        )
        verdicts = _parse_batch(getattr(resp, "content", "") or "", len(to_send))
    except Exception as e:
        logger.warning(f"[ambient] batch classification failed: {e}")

    if verdicts is None:
        logger.info("[ambient] batch unusable — falling back to per-message")
        for i, t in to_send:
            results[i] = classify_message(t, llm=llm)
    else:
        for local_n, (i, _t) in enumerate(to_send):
            results[i] = verdicts[local_n]
    return [r or Suggestion.irrelevant() for r in results]


# --- Message filtering -------------------------------------------------------


def _is_bot_directed(text: str, mentioned_emails: list[str], bot_email: str) -> bool:
    """True if the message is aimed at the bot (handled by the reactive path)."""
    if bot_email and bot_email.lower() in {m.lower() for m in mentioned_emails}:
        return True
    low = (text or "").lower()
    return any(frag in low for frag in _BOT_NAME_FRAGMENTS)


# --- Suggestion card ---------------------------------------------------------


# A category-specific, UNAMBIGUOUS directive for the 'Run it' query. We do NOT
# reuse the model's free-text ``suggested_action`` verbatim because it can collide
# with other agent intents — e.g. "Triage this IP" was read as "triage TICKET
# <ip>" and hit an XSOAR incident lookup (400 "Could not find incident"). These
# phrasings steer the agent to ENRICH/ASSESS the artifact, never to look up a case.
_CATEGORY_DIRECTIVE = {
    "ioc": "Enrich and assess this indicator (reputation, sightings, verdict)",
    "host": "Look up and assess this host/endpoint",
    "cve": "Assess this CVE and our exposure to it",
    "account": "Investigate this user account for risk",
    "phishing": "Analyze this suspected phishing",
    "malware": "Analyze this suspected malware",
}


def _looks_like_request(text: str, entity: str) -> bool:
    """True if the message is a real ask (a question/sentence), not a bare artifact.

    Dumb non-semantic backstop — NOT a classifier: a '?' or several words beyond
    the artifact itself means the analyst phrased an actual request we should run
    verbatim ('what is the containment status of US12345'). A bare paste of just
    the indicator ('185.220.101.5') has nothing left once the entity is removed,
    so we synthesize a directive for it instead.
    """
    t = (text or "").strip()
    if not t:
        return False
    if "?" in t:
        return True
    rest = t.replace((entity or "").strip(), " ").split()
    return len(rest) >= 3


def _run_query(s: Suggestion) -> str:
    """The natural-language instruction the 'Run it' / auto-run executes.

    Prefer the analyst's ACTUAL message when it's a real request — running it
    verbatim preserves specific intent (e.g. 'containment status', not a generic
    host lookup) and routes to the right tool. Only when the message is a bare
    artifact (an indicator pasted with no ask) do we synthesize an unambiguous,
    category-keyed directive — which also avoids the loaded word 'triage' being
    read as a ticket lookup.
    """
    text = (s.source_text or "").strip()
    entity = (s.entity or "").strip()
    if text and _looks_like_request(text, entity):
        return text
    directive = _CATEGORY_DIRECTIVE.get((s.category or "").strip().lower())
    if not directive:
        directive = (s.suggested_action or "Investigate this").strip()
    return f"{directive}: {entity}" if entity else directive


def _build_suggestion_card(s: Suggestion) -> dict:
    """A minimal adaptive card: what we noticed + an opt-in Run button.

    The Run action carries a ready-to-run query so the card-action handler can
    route it into the normal agentic path under the CLICKING user's identity —
    inheriting the per-user RBAC gate (:mod:`my_bot.auth.pokedex_rbac`) verbatim.
    """
    entity_line = f"**{s.entity}**" if s.entity else "this"
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.2",
        "body": [
            {
                "type": "TextBlock",
                "text": "🔍 Pokedex noticed something",
                "weight": "Bolder",
                "size": "Medium",
                "color": "Accent",
            },
            {
                "type": "TextBlock",
                "text": f"I can {s.suggested_action or 'take a look'} for {entity_line}.",
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": f"_{s.reason}_ · confidence {s.score:.0%}",
                "wrap": True,
                "isSubtle": True,
                "spacing": "Small",
            },
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "Run it",
                "data": {
                    "ambient_action": "run",
                    "entity": s.entity,
                    "category": s.category,
                    "suggested_action": s.suggested_action,
                    "query": _run_query(s),
                },
            },
            {
                "type": "Action.Submit",
                "title": "Dismiss",
                "data": {"ambient_action": "dismiss"},
            },
        ],
    }


def _post_suggestion(api, room_id: str, parent_id: Optional[str], s: Suggestion) -> bool:
    try:
        kwargs = {
            "roomId": room_id,
            "text": f"Pokedex can {s.suggested_action or 'help'}: {s.entity}".strip(),
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": _build_suggestion_card(s),
                }
            ],
        }
        if parent_id:
            kwargs["parentId"] = parent_id
        api.messages.create(**kwargs)
        return True
    except Exception as e:
        logger.warning(f"[ambient] failed to post suggestion card: {e}")
        return False


# --- Action execution (the 'Run it' click) -----------------------------------


def _now_eastern() -> str:
    try:
        from datetime import datetime
        import pytz
        return datetime.now(pytz.timezone("US/Eastern")).strftime("%-I:%M %p %Z")
    except Exception:
        return ""


def _display_name(email: str) -> str:
    """A friendly first name from an email local-part (best-effort, no API call)."""
    local = (email or "").split("@")[0]
    if not local:
        return "there"
    first = re.split(r"[._-]", local)[0]
    return first.capitalize() if first else "there"


def _resolve_first_name(api, msg) -> str:
    """The asker's real first name for the auto-run trace.

    Prefer the Webex display name (a people lookup on the sender's personId, since
    listed messages don't carry it); fall back to the email local-part. Best-effort
    — a flast-style email can't yield a clean first name, but the answer also threads
    under the asker's message, so context is never lost."""
    pid = getattr(msg, "personId", "") or ""
    if pid and api is not None:
        try:
            person = api.people.get(pid)
            dn = (getattr(person, "displayName", "") or "").strip()
            if dn:
                return dn.split()[0]
        except Exception as e:
            logger.debug(f"[ambient] people lookup failed: {e}")
    # No clean first name — prefer the full email over a mangled local-part
    # (a flast-style address like "jdoe" capitalizes to "Jdoe", which reads worse
    # than just showing the address). Prefer first name OR <personEmail>.
    return (getattr(msg, "personEmail", "") or "").strip() or "there"


def _format_for_webex(text: str) -> str:
    """Apply the same Webex hygiene the reactive bot path uses (defang, links)."""
    try:
        from my_bot.utils.webex_format import (
            convert_markdown_tables, linkify_xsoar_tickets, defang_urls,
            defang_ips, eastern_timestamps,
        )
        from my_config import get_config
        base = getattr(get_config(), "xsoar_prod_ui_base_url", "") or ""
        text = convert_markdown_tables(text)
        text = linkify_xsoar_tickets(text, base)
        text = defang_urls(text)
        text = eastern_timestamps(text)
        text = defang_ips(text)
    except Exception as e:
        logger.debug(f"[ambient] webex formatting skipped: {e}")
    if len(text) > 7000:
        text = text[:6900] + "\n\n*[Response truncated for message limits]*"
    return text


def _question_ref(s: Suggestion) -> str:
    """A short reference to what the analyst asked, for a self-contained reply.

    Prefer a trimmed quote of their actual message; fall back to the entity."""
    q = (s.source_text or "").strip()
    if q:
        return q if len(q) <= 90 else q[:87] + "…"
    return (s.entity or "your question").strip()


def _post_autorun_answer(post_api, room_id: str, asker_name: str,
                         question_ref: str, text: str,
                         parent_id: Optional[str] = None) -> bool:
    """Post an auto-run answer into the room, addressed to the asker by name.

    Two modes:
    * THREADED (``parent_id`` set) — posted as a reply under the asker's question
      via the OAuth service-account identity, which can read the parent. The thread
      already carries the question, so we just greet by name and answer, like a
      senior analyst replying in-thread.
    * STANDALONE (``parent_id`` is None) — the bot path. A Webex *bot* cannot create
      a threaded reply under a message it can't read (Webex 400 'Parent activity ID
      not found or invalid'; see [[reference_webex_bot_cannot_read_group_messages]]),
      so the message is made self-contained instead — name the asker AND quote their
      question — which reads like a reply even without true threading."""
    name = asker_name or "there"
    ref = (question_ref or "").strip()
    if parent_id:
        # Threaded: the reply is already attached to the asker's question, so the
        # name greeting + question re-quote are redundant — just answer, like a
        # senior analyst replying in-thread. This path posts via the OAuth USER
        # identity (the only identity that can thread under an unreadable group
        # message); Webex itself bylines it as "<You> via Pokedex Ambient Reader",
        # so the automated origin is already explicit in the sender chrome — no
        # in-body AI marker needed.
        body = text
    else:
        # Standalone (bot path): no thread to carry context, so make it
        # self-contained — name the asker and quote what they asked.
        head = f"**{name}**, re: _{ref}_ —" if ref else f"**{name}** —"
        body = f"{head}\n\n{text}"
    try:
        kwargs = {"roomId": room_id, "markdown": body}
        if parent_id:
            kwargs["parentId"] = parent_id
        post_api.messages.create(**kwargs)
        return True
    except Exception as e:
        logger.warning(f"[ambient] failed to post auto-run answer: {e}")
        return False


def claim_ambient_card(card_message_id: str, actor: str, action: str) -> tuple[bool, str]:
    """Atomically claim a suggestion card so only the FIRST click acts on it.

    Returns ``(won, holder)``. ``won`` is True only for the click that first
    inserted the row; every later click for the same card gets ``(False, <the
    first actor's email>)`` and must NOT run. The PRIMARY-KEY insert is the race
    guard — two analysts clicking the same card resolve to exactly one winner.

    A missing card id (shouldn't happen for a real click) is allowed through so a
    bookkeeping gap never blocks a legitimate action.
    """
    card_message_id = (card_message_id or "").strip()
    if not card_message_id:
        return True, (actor or "")
    conn = _connect()
    try:
        from datetime import datetime, timezone
        cur = conn.execute(
            "INSERT OR IGNORE INTO ambient_claims "
            "(card_message_id, actor, action, claimed_at) VALUES (?, ?, ?, ?)",
            (card_message_id, actor or "", action or "", datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        if cur.rowcount == 1:
            return True, (actor or "")
        row = conn.execute(
            "SELECT actor FROM ambient_claims WHERE card_message_id = ?", (card_message_id,)
        ).fetchone()
        return False, (row[0] if row and row[0] else "another analyst")
    finally:
        conn.close()


def build_resolved_card(inputs: dict, actor: str, action: str) -> dict:
    """An action-less card that REPLACES a suggestion once it's been clicked.

    No ``actions`` array → no buttons → it can never be clicked again. It records
    who actioned it and when, so the room sees the card is closed (and by whom)
    instead of a still-clickable button.
    """
    entity = (inputs.get("entity") or "").strip()
    ent = f"**{entity}**" if entity else "this"
    who = (actor or "someone").split("@")[0] or (actor or "someone")
    when = _now_eastern()
    if action == "dismiss":
        head, color, line = "✕ Dismissed", "Warning", f"Dismissed by {who}"
    else:
        head, color, line = "▶ Handled", "Good", f"Run by {who}"
    if when:
        line += f" · {when}"
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.2",
        "body": [
            {"type": "TextBlock", "text": head, "weight": "Bolder", "color": color, "size": "Medium"},
            {"type": "TextBlock", "text": f"Pokedex suggestion for {ent}.", "wrap": True, "isSubtle": True, "spacing": "Small"},
            {"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"},
        ],
    }


def run_ambient_action(inputs: dict, actor_email: str, room_id: str) -> dict:
    """Execute a click on an ambient suggestion card.

    The button runs the suggested investigation through the SAME agentic path the
    reactive @-mention uses (:func:`my_bot.core.my_model.ask`), carrying the
    CLICKING user's identity — NOT the bot's, NOT the original author's. So the
    existing per-user RBAC gate (:mod:`my_bot.auth.pokedex_rbac`) applies verbatim:
    reads + benign writes run open to any analyst, while a URL block / live RTR /
    case-close hits the same admin gate against THIS clicker's capabilities. No new
    authorization logic lives here — identity goes in, the gate is inherited.

    Returns ``{"status": "ran"|"dismissed"|"denied"|"error", "text": <reply>,
    "query": <what ran>}``. Never raises.
    """
    action = (inputs or {}).get("ambient_action", "")
    if action == "dismiss":
        return {"status": "dismissed", "text": "", "query": ""}
    if action != "run":
        return {"status": "error", "text": "", "query": ""}

    actor = (actor_email or "").strip()
    if not actor or "@" not in actor:
        # Fail closed: no resolvable identity → no investigation. A real card click
        # always carries the actor's email; a missing one means something is off,
        # and running anonymously would bypass the RBAC identity entirely.
        logger.warning("[ambient] run action with no actor identity — refusing")
        return {
            "status": "denied",
            "text": "I couldn't confirm who clicked, so I didn't run anything.",
            "query": "",
        }

    query = (inputs.get("query") or "").strip()
    if not query:
        # Rebuild from carried fields if a prebuilt query is absent (older card).
        sa = (inputs.get("suggested_action") or "take a look").strip()
        ent = (inputs.get("entity") or "").strip()
        query = (f"{sa}: {ent}".strip() if ent else sa).strip().rstrip(":").strip()
    if not query:
        return {"status": "error", "text": "", "query": ""}

    logger.info("[ambient] RUN by %s in %s — query=%r", actor, room_id, query)
    text = _invoke_agent(query, actor, room_id, read_only=False)
    if text is None:
        return {
            "status": "error",
            "text": "I hit an error running that — try mentioning me directly.",
            "query": query,
        }
    return {"status": "ran", "text": text, "query": query}


def _invoke_agent(query: str, actor: str, room_id: str, read_only: bool) -> Optional[str]:
    """Run a query through the agent as ``actor``; return the answer text (or None).

    ``read_only=True`` arms a hard guard in :mod:`my_bot.auth.pokedex_rbac` that
    DENIES every destructive tool for the duration regardless of who ``actor`` is —
    the invariant for the AUTO-RUN path: an action the room never clicked on can
    never block, isolate, quarantine, or close anything. The human-click path runs
    with ``read_only=False`` so the clicker's real capabilities apply.
    """
    armed = False
    try:
        if read_only:
            try:
                from my_bot.auth.pokedex_rbac import set_autorun_readonly
                set_autorun_readonly(True)
                armed = True
            except Exception as e:
                # If we cannot arm the read-only guard, refuse to auto-run rather
                # than run unguarded — fail closed on the safety mechanism.
                logger.error("[ambient] cannot arm read-only guard, skipping auto-run: %s", e)
                return None
        from my_bot.core.my_model import ask
        metrics = ask(query, user_id=actor, room_id=room_id)
        return (metrics or {}).get("content", "") or ""
    except Exception as e:  # the agentic path should self-recover; guard anyway
        logger.error("[ambient] investigation failed: %s", e, exc_info=True)
        return None
    finally:
        if armed:
            try:
                from my_bot.auth.pokedex_rbac import set_autorun_readonly
                set_autorun_readonly(False)
            except Exception:
                pass


# --- Orchestration -----------------------------------------------------------


def _get_webex_api():
    from webexpythonsdk import WebexAPI
    from my_config import get_config
    token = getattr(get_config(), "webex_bot_access_token_pokedex", "") or ""
    if not token:
        raise RuntimeError("no pokedex bot token configured")
    return WebexAPI(access_token=token)


def _post_as_oauth() -> bool:
    """Post ambient messages with the OAuth service-account identity, not the bot.

    A Webex *bot* can't create a threaded reply under a group message it can't read,
    so bot posts are always standalone (top-level). The OAuth service account ("Pokedex")
    IS a room member and can read the parent, so it CAN thread — the senior-analyst,
    reply-in-thread look the room expects. Requires the OAuth integration to also carry
    ``spark:messages_write`` (the read path only needs ``spark:messages_read``).

    Default OFF: until the Pokedex service account + a write-capable token exist, ambient
    keeps posting standalone as the bot. Flip POKEDEX_AMBIENT_POST_AS_OAUTH=true to enable
    threaded posting once the account is provisioned and the token re-granted with write."""
    if not _env_flag("POKEDEX_AMBIENT_POST_AS_OAUTH", default=False):
        return False
    try:
        from services.webex_ambient_oauth import is_configured
        return is_configured()
    except Exception:
        return False


def _get_post_api():
    """WebexAPI used to POST ambient messages (cards + auto-run answers).

    Default: the Pokedex *bot* token — but a bot can't thread group messages, so
    those posts are standalone. When POKEDEX_AMBIENT_POST_AS_OAUTH is set and OAuth
    is configured, post with the service-account OAuth token instead (same token the
    read path uses; the integration must grant messages_write too), which CAN thread.
    Falls back to the bot if the OAuth token can't be minted."""
    from webexpythonsdk import WebexAPI
    if _post_as_oauth():
        token = _read_token()  # same OAuth integration; must be granted messages_write
        if token:
            return WebexAPI(access_token=token)
        logger.warning("[ambient] POST_AS_OAUTH set but no OAuth token available; posting as bot")
    return _get_webex_api()


def _read_token(force_refresh: bool = False) -> str:
    """Token used for READING room traffic.

    A Webex *bot* account cannot list group-room messages (403 'Failed to get
    activity') — proven 2026-06-24. So the read path needs a *service-account*
    OAuth token with ``spark:messages_read``. Resolution order:

      1. ``POKEDEX_AMBIENT_READ_TOKEN`` env — an explicit static token. This is
         the dev path (paste a 12h personal token to tune); it also wins as a
         manual override in any environment.
      2. The OAuth refresher (:mod:`services.webex_ambient_oauth`) — the PROD
         path. Auto-mints/rotates a real access token from a stored refresh
         token, so it never silently expires the way a personal token does.
      3. ``webex_ambient_read_token`` config — a legacy static secret, if set.

    There is deliberately no fallback to the bot token: without a real read
    token ambient cannot function, and a bot token would just 403 every tick.
    """
    tok = os.getenv("POKEDEX_AMBIENT_READ_TOKEN", "").strip()
    if tok:
        return tok
    try:
        from services.webex_ambient_oauth import get_access_token, is_configured
        if is_configured():
            return get_access_token(force=force_refresh)
    except Exception as e:
        logger.warning(f"[ambient] OAuth read-token path failed: {e}")
    try:
        from my_config import get_config
        return getattr(get_config(), "webex_ambient_read_token", "") or ""
    except Exception:
        return ""


def _get_read_api():
    """WebexAPI client for the read path (service-account token)."""
    from webexpythonsdk import WebexAPI
    token = _read_token()
    if not token:
        raise RuntimeError(
            "no ambient read token (POKEDEX_AMBIENT_READ_TOKEN / "
            "webex_ambient_read_token) — a bot token cannot read group messages"
        )
    return WebexAPI(access_token=token)


def _bot_email() -> str:
    try:
        from my_config import get_config
        return getattr(get_config(), "webex_bot_email_pokedex", "") or ""
    except Exception:
        return ""


def _is_unauthorized(exc: Exception) -> bool:
    """True if an exception looks like an HTTP 401 (expired/invalid read token)."""
    if getattr(exc, "status_code", None) == 401:
        return True
    return "401" in str(exc)


def scan_room(
    room_id: str,
    read_api=None,
    post_api=None,
    llm=None,
    threshold: Optional[float] = None,
) -> dict:
    """Poll one room, classify new human messages, post suggestions over the bar.

    ``read_api`` lists messages (service-account token); ``post_api`` posts the
    suggestion card (bot token). They are deliberately different identities — a
    bot can post but cannot read group traffic. Returns a small stats dict. Safe
    to call repeatedly — the cursor + processed ledger make it idempotent.
    """
    read_api = read_api or _get_read_api()
    # Two post identities, deliberately:
    #  * post_api (BOT) — posts destructive "Run it" cards. Adaptive-card buttons only
    #    route their Action.Submit back to the BOT's webhook, so a card MUST be bot-posted
    #    or the click is dead. A bot also can't thread group messages, so cards are standalone.
    #  * answer_api — posts auto-run answers (plain markdown, no buttons). When threading is
    #    on this is the OAuth service account ("Pokedex"), which CAN reply in-thread; otherwise
    #    it's the same bot (standalone).
    post_api = post_api or _get_webex_api()
    answer_api = _get_post_api()
    thread_posts = _post_as_oauth()
    threshold = _threshold() if threshold is None else threshold
    bot_email = _bot_email()
    stats = {"room": room_id, "seen": 0, "classified": 0, "suggested": 0,
             "answered": 0, "skipped": 0}

    # NB: webexpythonsdk's .list() AUTO-PAGINATES — ``max`` is the page size,
    # not a total cap. Without islice this iterates the ENTIRE room history every
    # tick (proven 2026-06-24: pulled 7528 msgs on the dev-test space). The cursor
    # only filters AFTER the fetch, so we must bound the fetch itself. islice
    # stops pagination after the first (newest) page.
    def _fetch(api):
        lookback = _lookback()
        return list(islice(api.messages.list(roomId=room_id, max=lookback), lookback))

    try:
        messages = _fetch(read_api)
    except Exception as e:
        # An expired/invalid OAuth access token surfaces here as a 401. Force a
        # token refresh, rebuild the client, and retry once before giving up —
        # this is what keeps the prod refresh-token path self-healing.
        if _is_unauthorized(e):
            logger.info(f"[ambient] read token 401 on {room_id} — forcing refresh + retry")
            try:
                fresh = _read_token(force_refresh=True)
                if not fresh:
                    raise e
                from webexpythonsdk import WebexAPI
                read_api = WebexAPI(access_token=fresh)
                messages = _fetch(read_api)
            except Exception as e2:
                logger.warning(f"[ambient] list failed for {room_id} after refresh: {e2}")
                return stats
        else:
            logger.warning(f"[ambient] could not list messages for {room_id}: {e}")
            return stats

    # messages.list returns newest-first; process oldest-first so the cursor
    # advances monotonically.
    messages = list(reversed(messages))

    conn = _connect()
    try:
        cursor = _get_cursor(conn, room_id)
        newest_created = cursor
        # Pass 1: filter to the human messages worth classifying this tick.
        # Cursor/ledger and bot-directed skips happen here; classification is
        # deferred so it runs as ONE batched call (rate-limit friendly) below.
        candidates = []  # (msg, msg_id, created, text)
        for msg in messages:
            created = getattr(msg, "created", None)
            created = str(created) if created is not None else ""
            msg_id = getattr(msg, "id", "") or ""
            text = getattr(msg, "text", "") or ""
            sender = getattr(msg, "personEmail", "") or ""
            stats["seen"] += 1

            # Skip anything at/before the cursor or already handled.
            if cursor and created and created <= cursor:
                continue
            if not msg_id or _already_processed(conn, msg_id):
                continue
            if created and (newest_created is None or created > newest_created):
                newest_created = created

            # Skip the bot's own messages and other bot accounts.
            if sender == bot_email or sender.endswith("@webex.bot"):
                stats["skipped"] += 1
                continue
            # mentionedPeople are person IDs, not emails; bot-name text match is
            # the reliable signal here, so pass emails empty and lean on text.
            if _is_bot_directed(text, [], bot_email):
                stats["skipped"] += 1
                continue

            candidates.append((msg, msg_id, created, text))

        # One batched relevance call for the whole tick.
        suggestions = classify_messages_batch([c[3] for c in candidates], llm=llm)

        # Pass 2: apply the bar. Over-bar READ-only suggestions auto-run and post the
        # answer; DESTRUCTIVE-intent ones post a human-in-the-loop card. Auto-runs are
        # capped per tick (each is a full investigation); overflow falls back to a card.
        autorun_enabled = _autorun_enabled()
        autorun_cap = _autorun_cap()
        autoruns_done = 0
        for (msg, msg_id, created, _text), suggestion in zip(candidates, suggestions):
            stats["classified"] += 1
            suggestion.source_text = _text  # let _run_query prefer the real question
            over_bar = suggestion.relevant and suggestion.score >= threshold
            posted = False
            if over_bar:
                logger.info(
                    f"[ambient] {room_id} HIT score={suggestion.score:.2f} "
                    f"cat={suggestion.category} entity={suggestion.entity!r} "
                    f"approval={suggestion.requires_approval} "
                    f"action={suggestion.suggested_action!r}"
                )
                # Cards are ALWAYS bot-posted + standalone (buttons must route to the bot,
                # which can't thread). Auto-run ANSWERS thread under the asker's message when
                # posting via the OAuth identity (parent = msg_id); on the bot path they stay
                # standalone and self-contained (names the asker, quotes the ask).
                answer_parent = msg_id if thread_posts else None
                if not _post_enabled():
                    logger.info("[ambient] POST disabled (dry-run) — not acting")
                elif suggestion.requires_approval or not autorun_enabled:
                    # Destructive intent (or auto-run off) → human-in-the-loop card (bot, standalone).
                    posted = _post_suggestion(post_api, room_id, None, suggestion)
                    if posted:
                        stats["suggested"] += 1
                elif autoruns_done >= autorun_cap:
                    # Over the per-tick budget — defer to a card rather than drop it.
                    logger.info("[ambient] auto-run cap %d reached — deferring read to a card", autorun_cap)
                    posted = _post_suggestion(post_api, room_id, None, suggestion)
                    if posted:
                        stats["suggested"] += 1
                else:
                    # Read-only → auto-run as the asker, hard read-only, post the answer.
                    asker = getattr(msg, "personEmail", "") or ""
                    query = _run_query(suggestion)
                    logger.info("[ambient] AUTO-RUN (read-only) for %s — query=%r", asker, query)
                    answer = _invoke_agent(query, asker, room_id, read_only=True)
                    autoruns_done += 1
                    if answer:
                        # Resolve the display name via the POST identity, not read_api:
                        # the OAuth read scope is spark:messages_read only, so a
                        # people.get on it 403s and we fall back to the email
                        # local-part (e.g. "Jdoe"). The bot / write identity can.
                        asker_name = _resolve_first_name(post_api, msg)
                        posted = _post_autorun_answer(
                            answer_api, room_id, asker_name,
                            _question_ref(suggestion), _format_for_webex(answer),
                            parent_id=answer_parent)
                        if posted:
                            stats["answered"] = stats.get("answered", 0) + 1
            _record(conn, msg_id, room_id, created, suggestion, posted)

        if newest_created and newest_created != cursor:
            _set_cursor(conn, room_id, newest_created)
        conn.commit()
    finally:
        conn.close()

    return stats


def scan_ambient_rooms() -> None:
    """Scheduler entry point. Inert unless POKEDEX_AMBIENT_ENABLED is set."""
    if not _ambient_enabled():
        logger.debug("[ambient] disabled (POKEDEX_AMBIENT_ENABLED not set) — skipping")
        return
    rooms = _ambient_rooms()
    if not rooms:
        logger.warning("[ambient] enabled but no rooms configured — nothing to scan")
        return
    try:
        read_api = _get_read_api()   # service-account token (reads traffic)
        post_api = _get_webex_api()  # bot token (posts cards; answers pick their own identity)
    except Exception as e:
        logger.warning(f"[ambient] cannot init Webex API: {e}")
        return
    llm = None
    try:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm(temperature=0.0)
    except Exception as e:
        logger.warning(f"[ambient] cannot init LLM: {e}")
        return

    totals = {"classified": 0, "suggested": 0, "answered": 0}
    for room_id in rooms:
        stats = scan_room(room_id, read_api=read_api, post_api=post_api, llm=llm)
        totals["classified"] += stats["classified"]
        totals["suggested"] += stats["suggested"]
        totals["answered"] += stats.get("answered", 0)
        logger.info(f"[ambient] scan {room_id}: {stats}")
    logger.info(
        f"[ambient] tick done: {totals['classified']} classified, "
        f"{totals['answered']} auto-answered, {totals['suggested']} cards posted "
        f"across {len(rooms)} room(s)"
    )
