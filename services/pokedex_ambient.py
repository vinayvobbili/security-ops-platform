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
  * Light + off-m1. One toolless ``create_llm`` (GPT-4.1) relevance call
    per new message, never the full agentic loop. Running the gate on the LLM —
    not the local router — keeps ambient from competing with the tool-calling
    investigation path for scarce m1 capacity, and is ~2-3s vs ~15s on a
    saturated m1. The LLM self-falls-back to m1 if the gateway is down.
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
# the LLM gateway's rate limit (429s in the ThreatCon dry-pass 2026-06-24).
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


# v2 gist prompt: read the conversation as a whole and surface the actual
# security need(s) it's raising, consolidating an artifact + its follow-up
# question that a per-message gate would score separately and miss.
_GIST_SYSTEM_PROMPT = """You are a senior SOC analyst silently reading a security \
operations chat room. You are given the recent conversation as a NUMBERED, \
time-ordered list of messages (oldest first). Messages tagged [NEW] arrived since \
you last looked.

Decide whether the CONVERSATION — taken as a whole, not message by message — is \
raising a concrete security need a SOC assistant can act on. A need is often spread \
across messages: an indicator mentioned in one, the actual question asked two \
messages later. Consolidate them into a single need.

The assistant is good at: triaging IOCs (IPs, domains, file hashes, URLs), looking \
up hosts/endpoints, checking CVEs against the fleet, investigating user accounts, \
and analyzing suspected phishing/malware.

Rules:
- Only raise a need if the [NEW] messages are part of it. Do NOT resurface a topic \
that was discussed earlier and isn't being actively pursued now.
- Consolidate: if several messages concern the same indicator/host/incident, return \
ONE need, not several.
- Most conversations need nothing. An empty list is the common, correct answer. Do \
NOT invent a need from chit-chat, status updates, opinions, or scheduling.
- "query" is the single natural-language instruction the assistant should run to \
address the need, phrased as a clear analyst request (e.g. "Assess IP \
185.220.101.5 for malicious activity and any sightings in our environment").
- "requires_approval" is true ONLY when the conversation asks the assistant to TAKE \
a changing/enforcement action — block, isolate/contain a host, quarantine or delete \
a file, close a case, run a command, launch a simulation. Reads, enrichment, and \
STATUS checks are false. When unsure, false.
- "latest_index" is the index of the most recent message that is part of this need \
(the reply threads under it).

Respond with ONLY a JSON array (it may be empty: []), no prose, no code fences:
[{"score": <0.0-1.0>, "category": "<ioc|host|cve|account|phishing|malware|other>", "entity": "<the specific artifact or subject>", "query": "<the instruction to run>", "suggested_action": "<short imperative, <=12 words>", "reason": "<one short clause: what the room is asking>", "requires_approval": <true|false>, "latest_index": <int>}]"""


@dataclass
class GistNeed:
    """A single security need synthesized from the whole conversation (v2)."""

    score: float
    category: str
    entity: str
    # The natural-language instruction to run / put on the card's Run button.
    query: str
    suggested_action: str
    reason: str
    requires_approval: bool
    # Index (into the gist window) of the latest message in this need — the reply
    # threads under it so it lands where the conversation is.
    latest_index: int


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


def _gist_enabled() -> bool:
    """v2 — respond to the conversation GIST, not each message in isolation.

    When on, a tick assembles a rolling window of the recent conversation and asks
    one LLM to identify the actual security need(s) the *discussion* is raising —
    consolidating an indicator dropped in one message with the question asked two
    messages later — instead of scoring every message independently. Off (default)
    keeps the v1 per-message relevance gate. Everything downstream (auto-run reads,
    HITL cards for destructive intent, threading, RBAC guard) is shared."""
    return _env_flag("POKEDEX_AMBIENT_GIST", default=False)


def _gist_window() -> int:
    """How many recent messages to feed the gist synthesis as context. The window
    carries older (already-seen) messages for context but only acts when at least
    one message in it is NEW since the cursor."""
    try:
        return max(2, int(os.getenv("POKEDEX_AMBIENT_GIST_WINDOW", "15")))
    except (TypeError, ValueError):
        return 15


def _gist_dedup_seconds() -> int:
    """Cooldown before the same conversational need (category:entity) may be
    answered again. Default 6h — long enough that an ongoing discussion of one
    indicator isn't re-answered every tick, short enough that a genuinely fresh
    ask about it later still gets a response."""
    try:
        return max(0, int(os.getenv("POKEDEX_AMBIENT_GIST_DEDUP_SECONDS", "21600")))
    except (TypeError, ValueError):
        return 21600


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
    """Page size for the message fetch — NOT a total cap. The fetch pages until it
    crosses the cursor (see ``scan_room._fetch``), so this only tunes how many
    messages come back per round-trip."""
    try:
        return int(os.getenv("POKEDEX_AMBIENT_LOOKBACK", str(_DEFAULT_LOOKBACK)))
    except (TypeError, ValueError):
        return _DEFAULT_LOOKBACK


def _max_catchup() -> int:
    """Hard ceiling on messages pulled in one tick. Steady-state the fetch stops as
    soon as it crosses the cursor (usually a handful), so this never binds normal
    traffic — even a fast burst of dozens of messages in one tick is caught in full.
    It only bounds a cold start or a long downtime so a first tick can't walk the
    entire room history (7528 msgs were pulled once before the fetch was bounded)."""
    try:
        return max(_DEFAULT_LOOKBACK, int(os.getenv("POKEDEX_AMBIENT_MAX_CATCHUP", "200")))
    except (TypeError, ValueError):
        return 200


def _vision_enabled() -> bool:
    """Read screenshots attached to messages and fold their content into the scan.

    When on (default), each tick runs the local vision model over the image
    attachment(s) on this tick's NEW messages and merges the transcription + IOCs
    into the text the relevance gate / gist synthesis reads — so a pasted alert
    console or phishing screenshot is treated like typed text. Self-disables when
    no vision endpoint is configured (``create_vision_llm`` raises), so a deploy
    without the VLM tunnel is simply inert here, never an error. Kill switch for
    isolating a vision problem without touching the rest of ambient."""
    return _env_flag("POKEDEX_AMBIENT_VISION", default=True)


def _vision_max() -> int:
    """Max screenshots to analyze per room per tick — bounds a tick's vision cost
    (each image is a VLM call) so a burst of image-heavy messages can't fan out
    unbounded. Over the cap, later images this tick are skipped (logged)."""
    try:
        return max(1, int(os.getenv("POKEDEX_AMBIENT_VISION_MAX", "4")))
    except (TypeError, ValueError):
        return 4


def _screenshot_bridge_enabled() -> bool:
    """Reactive bridge: ANSWER an @Pokedex message that carries a screenshot.

    A Webex *bot* account receives NO websocket event for a file-bearing message in
    a group space (proven 2026-06-28), so the reactive @-mention screenshot path
    can't fire on the bot side at all. This bridge closes that gap from the READ
    side: the ambient poller (OAuth service account) DOES see the file, so when a
    NEW message both @-mentions Pokedex AND carries an image we read this tick, we
    run the agentic investigation (read-only) on the analyst's ask + the transcribed
    screenshot, as the asker, and post the answer back as Pokedex — the reply the
    bot itself couldn't give.

    Deliberately INDEPENDENT of the proactive dry-run gate (``POKEDEX_AMBIENT_POST``):
    a direct @-mention is an explicit request, not a proactive suggestion, so it
    answers even while proactive suggestions are still being tuned in dry-run. It
    still requires ambient itself enabled and vision on (the bridge has nothing to
    act on without a transcribed screenshot). Default ON; flip off to isolate a
    problem without touching the rest of ambient."""
    return _vision_enabled() and _env_flag("POKEDEX_VISION_REACTIVE_BRIDGE", default=True)


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
    # v2 (gist mode): one row per conversational NEED we've already addressed, keyed
    # by (room, category:entity). A live conversation keeps mentioning the same
    # indicator across many ticks; without this we'd re-answer the same need every
    # tick. The cooldown (POKEDEX_AMBIENT_GIST_DEDUP_SECONDS) lets a genuinely new
    # ask about the same entity through later.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ambient_gist_answered ("
        " room_id TEXT NOT NULL,"
        " need_key TEXT NOT NULL,"
        " answered_at TEXT NOT NULL,"
        " PRIMARY KEY (room_id, need_key))"
    )
    # One row per auto-run answer we posted, with the reasoning trace that
    # produced it. Keyed on the answer's own message id; thread_root_id is the
    # message the answer hangs under (the asker's original question on the OAuth
    # threaded path, else the answer itself). A later "why?/how?" reply in that
    # thread is matched back to this row to explain the answer from the record —
    # the ambient twin of the reactive bot's pokedex_reasoning store.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ambient_answers ("
        " answer_message_id TEXT PRIMARY KEY,"
        " thread_root_id TEXT,"
        " room_id TEXT NOT NULL,"
        " asker TEXT,"
        " question TEXT,"
        " answer TEXT,"
        " trace_json TEXT,"
        " route TEXT,"
        " posted_at TEXT)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ambient_answers_thread "
        "ON ambient_answers(thread_root_id)"
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
        # Toolless classification → the LLM (fast, ~2-3s) instead of the
        # local router. This keeps ambient's per-message load OFF m1, which is
        # reserved for the tool-calling investigation path. The LLM self-falls-back
        # to m1 if the LLM gateway is unreachable, so this never hard-fails.
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
    request per message and trip the LLM gateway's rate limit (429s observed in
    the ThreatCon dry-pass). Batching makes a tick cost a single request.

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


# --- Conversation gist synthesis (v2) ----------------------------------------


def _parse_gist(content: str, window_len: int) -> list[GistNeed]:
    """Parse the gist model's JSON array of needs, defensively.

    An empty array (the common, correct answer for ordinary chatter) and any parse
    failure both yield ``[]`` — fail closed, never invent a need from garbage.
    ``latest_index`` is clamped into the window so a bad index can't index-error.
    """
    if not content:
        return []
    match = re.search(r"\[.*\]", content.strip(), re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    needs: list[GistNeed] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            score = float(item.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        score = max(0.0, min(1.0, score))
        try:
            li = int(item.get("latest_index", window_len - 1))
        except (TypeError, ValueError):
            li = window_len - 1
        li = max(0, min(window_len - 1, li)) if window_len > 0 else 0
        needs.append(
            GistNeed(
                score=score,
                category=str(item.get("category", "other") or "other"),
                entity=str(item.get("entity", "") or ""),
                query=str(item.get("query", "") or ""),
                suggested_action=str(item.get("suggested_action", "") or ""),
                reason=str(item.get("reason", "") or ""),
                requires_approval=bool(item.get("requires_approval", False)),
                latest_index=li,
            )
        )
    return needs


def synthesize_conversation(window: list[dict], llm=None) -> list[GistNeed]:
    """Read a conversational window and return the security need(s) it raises.

    ``window`` is a list of ``{"index", "sender", "text", "is_new"}`` dicts, oldest
    first. Returns ``[]`` when nothing in the room warrants action (the usual case)
    or when no message is NEW — a window with only stale context must never re-raise
    a need it already handled. ``llm`` is injectable for tests; defaults to the same
    toolless the LLM the v1 gate uses, to keep load off m1.
    """
    if not window or not any(w.get("is_new") for w in window):
        return []
    if llm is None:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm(temperature=0.0)
    from langchain_core.messages import HumanMessage, SystemMessage

    lines = []
    for w in window:
        tag = " [NEW]" if w.get("is_new") else ""
        sender = (w.get("sender") or "").split("@")[0]
        lines.append(f"[{w.get('index')}]{tag} {sender}: {(w.get('text') or '')[:500]}")
    convo = "\n".join(lines)
    try:
        resp = llm.invoke(
            [
                SystemMessage(content=_GIST_SYSTEM_PROMPT),
                HumanMessage(content=convo[:8000]),
            ]
        )
        content = getattr(resp, "content", "") or ""
    except Exception as e:
        logger.warning(f"[ambient] gist synthesis failed: {e}")
        return []
    return _parse_gist(content, len(window))


def _need_key(category: str, entity: str) -> str:
    """Dedup key for an answered gist need: normalized category:entity."""
    cat = (category or "other").strip().lower()
    ent = re.sub(r"\s+", " ", (entity or "").strip().lower())
    return f"{cat}:{ent}"


def _recently_answered(conn, room_id: str, need_key: str, within_seconds: int) -> bool:
    """True if this need was answered in ``room_id`` within the cooldown window."""
    if within_seconds <= 0:
        return False
    row = conn.execute(
        "SELECT answered_at FROM ambient_gist_answered WHERE room_id = ? AND need_key = ?",
        (room_id, need_key),
    ).fetchone()
    if not row or not row[0]:
        return False
    from datetime import datetime, timezone
    try:
        ts = datetime.fromisoformat(row[0])
    except (ValueError, TypeError):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() < within_seconds


def _mark_answered(conn, room_id: str, need_key: str) -> None:
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO ambient_gist_answered (room_id, need_key, answered_at) "
        "VALUES (?, ?, ?) ON CONFLICT(room_id, need_key) "
        "DO UPDATE SET answered_at = excluded.answered_at",
        (room_id, need_key, datetime.now(timezone.utc).isoformat()),
    )


_CORRECTION_SYSTEM_PROMPT = (
    "You watch a SOC analyst chat and capture CORRECTIONS to ticket dispositions, "
    "so the AI can learn from the room on its own. Return an entry ONLY for a "
    "message that BOTH names a specific ticket (a number like #12345) AND states "
    "what that ticket really is. Ignore questions, speculation, and general "
    "chatter. For each, return an object: "
    '{"index": <int from the [n] tag>, "ticket_id": "<digits only>", '
    '"disposition": one of ["malicious","contained","benign","false_positive"]}. '
    "'contained' = malicious but blocked/prevented. Reply with a JSON array only "
    "(empty array if none). No prose."
)


def _capture_corrections(room_id: str, messages: list, conn: sqlite3.Connection,
                         llm, bot_email: str) -> int:
    """Self-learning: detect analyst corrections in this tick's new chatter and
    record them as ground truth (source='chatter').

    One toolless LLM pass over the new human messages (same the LLM the gist
    uses). Best-effort: any failure is swallowed so it never breaks the scan.
    Dedup is by message_id in the coaching store, so re-scans are idempotent.
    """
    try:
        cursor = _get_cursor(conn, room_id)
        new_human: list[dict] = []
        for msg in messages:
            created = str(getattr(msg, "created", "") or "")
            msg_id = getattr(msg, "id", "") or ""
            text = getattr(msg, "text", "") or ""
            sender = getattr(msg, "personEmail", "") or ""
            if not msg_id or not text:
                continue
            if sender == bot_email or sender.endswith("@webex.bot"):
                continue
            if cursor and created and created <= cursor:  # only this tick's new msgs
                continue
            new_human.append({"msg_id": msg_id, "sender": sender, "text": text})
        if not new_human:
            return 0
        new_human = new_human[-30:]

        if llm is None:
            from my_bot.utils.llm_factory import create_llm
            llm = create_llm(temperature=0.0)
        from langchain_core.messages import HumanMessage, SystemMessage

        lines = [f"[{i}] {d['sender'].split('@')[0]}: {d['text'][:400]}"
                 for i, d in enumerate(new_human)]
        try:
            resp = llm.invoke([
                SystemMessage(content=_CORRECTION_SYSTEM_PROMPT),
                HumanMessage(content="\n".join(lines)[:8000]),
            ])
            content = getattr(resp, "content", "") or ""
        except Exception as e:
            logger.warning("[ambient] correction capture LLM failed: %s", e)
            return 0

        m = re.search(r"\[.*\]", content, re.DOTALL)
        if not m:
            return 0
        try:
            items = json.loads(m.group(0))
        except (json.JSONDecodeError, TypeError):
            return 0

        from src.components.soc_in_box import coaching
        count = 0
        for item in items if isinstance(items, list) else []:
            try:
                idx = int(item.get("index"))
            except (TypeError, ValueError):
                continue
            if not (0 <= idx < len(new_human)):
                continue
            tid = re.sub(r"\D", "", str(item.get("ticket_id") or ""))
            if not tid:
                continue
            verdict = coaching.normalize_disposition(str(item.get("disposition") or ""))
            if not verdict:
                continue
            d = new_human[idx]
            res = coaching.record_correction(
                ticket_id=tid, verdict=verdict, source="chatter",
                note=d["text"][:500], author=d["sender"], room_id=room_id,
                message_id=d["msg_id"],
            )
            if res.get("recorded"):
                count += 1
        if count:
            logger.info("[ambient] %s captured %d analyst correction(s) from chatter",
                        room_id, count)
        return count
    except Exception as e:
        logger.warning("[ambient] correction capture failed: %s", e)
        return 0


_KNOWLEDGE_SYSTEM_PROMPT = (
    "You watch a SOC analyst chat and capture DURABLE, REUSABLE security "
    "knowledge so the AI SOC can recall it later. Return an entry ONLY for a "
    "message that states a fact or piece of tradecraft worth remembering beyond "
    "today — how a threat works, an exploitation technique, a detection/hunting "
    "tip, a known-bad or known-good pattern, a tool/playbook step. "
    "DO NOT capture: questions, speculation, opinions, status updates, greetings, "
    "or a ticket's disposition (those are handled separately). For each keeper, "
    "return an object: "
    '{"index": <int from the [n] tag>, '
    '"fact": "<the durable knowledge in one clear sentence>", '
    '"topic": "<2-5 word subject, e.g. \'Citrix CVE exploitation\'>", '
    '"tags": "<space-separated keywords for later lookup>", '
    '"ttl_days": <number, or null if it is evergreen>}. '
    "Set ttl_days only when the fact is time-bound (an active campaign ~14, a "
    "this-week advisory ~7); leave it null for lasting knowledge. "
    "Reply with a JSON array only (empty array if nothing is worth keeping). "
    "No prose."
)


def _capture_knowledge(room_id: str, messages: list, conn: sqlite3.Connection,
                       llm, bot_email: str) -> int:
    """Self-learning: extract durable security facts/tradecraft from this tick's
    new chatter and persist them as recallable knowledge (source='chatter').

    Sibling of ``_capture_corrections`` — one toolless LLM pass over the new
    human messages, best-effort (any failure is swallowed), idempotent by
    message_id in the knowledge store. Where corrections capture a ticket's
    disposition, this captures reusable knowledge the SOC should recall later.
    """
    try:
        cursor = _get_cursor(conn, room_id)
        new_human: list[dict] = []
        for msg in messages:
            created = str(getattr(msg, "created", "") or "")
            msg_id = getattr(msg, "id", "") or ""
            text = getattr(msg, "text", "") or ""
            sender = getattr(msg, "personEmail", "") or ""
            if not msg_id or not text:
                continue
            if sender == bot_email or sender.endswith("@webex.bot"):
                continue
            if cursor and created and created <= cursor:  # only this tick's new msgs
                continue
            new_human.append({"msg_id": msg_id, "sender": sender, "text": text})
        if not new_human:
            return 0
        new_human = new_human[-30:]

        if llm is None:
            from my_bot.utils.llm_factory import create_llm
            llm = create_llm(temperature=0.0)
        from langchain_core.messages import HumanMessage, SystemMessage

        lines = [f"[{i}] {d['sender'].split('@')[0]}: {d['text'][:400]}"
                 for i, d in enumerate(new_human)]
        try:
            resp = llm.invoke([
                SystemMessage(content=_KNOWLEDGE_SYSTEM_PROMPT),
                HumanMessage(content="\n".join(lines)[:8000]),
            ])
            content = getattr(resp, "content", "") or ""
        except Exception as e:
            logger.warning("[ambient] knowledge capture LLM failed: %s", e)
            return 0

        m = re.search(r"\[.*\]", content, re.DOTALL)
        if not m:
            return 0
        try:
            items = json.loads(m.group(0))
        except (json.JSONDecodeError, TypeError):
            return 0

        from src.components.soc_in_box import knowledge
        count = 0
        for item in items if isinstance(items, list) else []:
            try:
                idx = int(item.get("index"))
            except (TypeError, ValueError):
                continue
            if not (0 <= idx < len(new_human)):
                continue
            fact = str(item.get("fact") or "").strip()
            if len(fact) < 8:  # too short to be a real fact
                continue
            ttl = item.get("ttl_days")
            try:
                ttl = float(ttl) if ttl is not None else None
            except (TypeError, ValueError):
                ttl = None
            d = new_human[idx]
            res = knowledge.record_fact(
                fact=fact,
                topic=str(item.get("topic") or "").strip(),
                tags=str(item.get("tags") or "").strip(),
                source="chatter", author=d["sender"], room_id=room_id,
                message_id=d["msg_id"], ttl_days=ttl,
            )
            if res.get("recorded"):
                count += 1
        if count:
            logger.info("[ambient] %s captured %d knowledge fact(s) from chatter",
                        room_id, count)
        return count
    except Exception as e:
        logger.warning("[ambient] knowledge capture failed: %s", e)
        return 0


def _collect_screenshots(messages: list, conn: sqlite3.Connection, room_id: str,
                         bot_email: str, token: str) -> dict:
    """Run the local vision model over the image attachment(s) on this tick's NEW
    messages and return ``{message_id: grounding_block}``.

    The grounding block is a transcription + extracted IOCs + one-line summary
    (see :mod:`services.screenshot_analysis`). Callers fold it into the text the
    relevance gate / gist synthesis reads, so a pasted screenshot flows into the
    same paths as typed text. Only NEW, non-bot messages that actually carry an
    image are analyzed (vision is the expensive step — never re-run on stale
    context), and the whole tick is capped at ``_vision_max`` images.

    Entirely best-effort: a missing vision endpoint, a download failure, or a
    non-image attachment yields no entry for that message — never an exception, so
    a screenshot can't break the scan. Returns ``{}`` when vision is disabled, no
    token is available, or nothing could be read.
    """
    if not _vision_enabled() or not token:
        return {}
    cursor = _get_cursor(conn, room_id)
    # Find new, non-bot messages carrying at least one attachment.
    pending: list[tuple[str, str, list]] = []  # (msg_id, text, file_urls)
    for msg in messages:
        msg_id = getattr(msg, "id", "") or ""
        if not msg_id:
            continue
        created = str(getattr(msg, "created", "") or "")
        sender = getattr(msg, "personEmail", "") or ""
        if sender == bot_email or sender.endswith("@webex.bot"):
            continue
        if cursor and created and created <= cursor:
            continue  # stale context — already seen, don't re-pay for vision
        if _already_processed(conn, msg_id):
            continue
        files = list(getattr(msg, "files", None) or [])
        if not files:
            continue
        pending.append((msg_id, getattr(msg, "text", "") or "", files))
    if not pending:
        return {}

    # One vision client for the whole tick; if it can't be built (no VLM
    # configured/reachable), vision is simply unavailable this tick.
    try:
        from my_bot.utils.llm_factory import create_vision_llm
        vision_llm = create_vision_llm(max_tokens=900)
    except Exception as e:
        logger.debug("[ambient] vision unavailable (no VLM): %s", e)
        return {}

    from services.screenshot_analysis import analyze_attachments
    out: dict = {}
    budget = _vision_max()
    for msg_id, text, files in pending:
        if budget <= 0:
            logger.info("[ambient] %s vision cap reached — skipping remaining screenshots", room_id)
            break
        block = analyze_attachments(
            files, token, context=text, llm=vision_llm, max_images=budget)
        if block:
            out[msg_id] = block
            # Charge the cap by images actually read (one block line per image).
            budget -= max(1, block.count("[screenshot:"))
    if out:
        logger.info("[ambient] %s read %d screenshot message(s) via vision", room_id, len(out))
    return out


def _with_screenshot(text: str, msg_id: str, vision_by_id: Optional[dict]) -> str:
    """Append a message's screenshot grounding block (if any) to its text, so a
    pasted image is read as part of the message. No-op when there's no screenshot."""
    if not vision_by_id:
        return text
    block = vision_by_id.get(msg_id)
    if not block:
        return text
    return f"{text}\n\n{block}" if text else block


def _need_as_suggestion(need: GistNeed) -> "Suggestion":
    """Adapt a GistNeed to a Suggestion so it can reuse the card builder/poster.

    ``source_text`` is set to the synthesized query so ``_run_query`` puts that exact
    instruction on the card's Run button (it reads like a request, so it's used
    verbatim rather than re-synthesized from the category)."""
    return Suggestion(
        relevant=True,
        score=need.score,
        category=need.category,
        entity=need.entity,
        reason=need.reason,
        suggested_action=need.suggested_action or "take a look",
        requires_approval=need.requires_approval,
        source_text=need.query,
    )


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
    # (a flast-style address capitalizes to "Labuser", which reads worse
    # than just showing the address). Per user: first name OR <personEmail>.
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
                         parent_id: Optional[str] = None) -> Optional[str]:
    """Post an auto-run answer into the room, addressed to the asker by name.

    Returns the posted message's id on success (so the caller can link the
    reasoning trace to it for later "why?" follow-ups), or None on failure.

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
        sent = post_api.messages.create(**kwargs)
        return getattr(sent, "id", "") or ""
    except Exception as e:
        logger.warning(f"[ambient] failed to post auto-run answer: {e}")
        return None


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


def _invoke_agent_full(query: str, actor: str, room_id: str,
                       read_only: bool) -> Optional[dict]:
    """Run a query through the agent as ``actor``; return the full metrics dict.

    The metrics carry the answer text (``content``) plus the per-turn
    ``reasoning_trace`` (tool/args/result preview), which the auto-run path
    persists so a later "why?" can explain the answer from the record.

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
        return ask(query, user_id=actor, room_id=room_id) or {}
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


def _invoke_agent(query: str, actor: str, room_id: str, read_only: bool) -> Optional[str]:
    """Text-only wrapper over :func:`_invoke_agent_full` (the human-click path)."""
    metrics = _invoke_agent_full(query, actor, room_id, read_only)
    return None if metrics is None else (metrics.get("content", "") or "")


def _store_ambient_answer(conn, answer_message_id: str, thread_root_id: str,
                          room_id: str, asker: str, question: str,
                          answer: str, metrics: dict) -> None:
    """Persist one posted auto-run answer + its reasoning trace (best-effort)."""
    if not answer_message_id:
        return
    try:
        import json as _json
        from datetime import datetime, timezone
        trace = (metrics or {}).get("reasoning_trace") or []
        route = str((metrics or {}).get("route")
                    or (metrics or {}).get("tools_used") or "")
        conn.execute(
            "INSERT OR REPLACE INTO ambient_answers "
            "(answer_message_id, thread_root_id, room_id, asker, question, "
            " answer, trace_json, route, posted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (answer_message_id, thread_root_id or answer_message_id, room_id,
             asker or "", (question or "")[:2000], (answer or "")[:4000],
             _json.dumps(trace, default=str)[:12000], route,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except Exception as e:
        logger.warning("[ambient] could not store answer reasoning: %s", e)


def _get_ambient_answer(conn, parent_id: str) -> Optional[dict]:
    """Find the auto-run answer a threaded reply hangs under.

    Matches the reply's parentId against either the answer's own message id or
    its thread root (Webex collapses a thread to its root message), newest first.
    """
    pid = (parent_id or "").strip()
    if not pid:
        return None
    try:
        row = conn.execute(
            "SELECT answer_message_id, thread_root_id, room_id, asker, question, "
            "       answer, trace_json, route, posted_at "
            "FROM ambient_answers "
            "WHERE answer_message_id = ? OR thread_root_id = ? "
            "ORDER BY posted_at DESC LIMIT 1",
            (pid, pid),
        ).fetchone()
    except Exception as e:
        logger.warning("[ambient] ambient_answers lookup failed: %s", e)
        return None
    if not row:
        return None
    cols = ["answer_message_id", "thread_root_id", "room_id", "asker",
            "question", "answer", "trace_json", "route", "posted_at"]
    return dict(zip(cols, row))


_FOLLOWUP_INTENT_PROMPT = (
    "You judge ONE chat reply that a person sent in a thread under an answer the "
    "assistant had posted. Decide if the reply is asking the assistant to JUSTIFY "
    "or EXPLAIN how it reached that answer — e.g. 'why?', 'why did you say that?', "
    "'how did you get that?', 'what did you base that on?', 'where's that from?', "
    "'show your work', 'explain your reasoning'. Acknowledgements ('thanks', 'ok', "
    "'got it'), brand-new questions, or unrelated chatter are NOT this.\n"
    "Reply with exactly one word: EXPLAIN if it asks the assistant to justify the "
    "prior answer, otherwise OTHER."
)


def _classify_followup_intent(text: str, llm=None) -> str:
    """Return 'explain' if a threaded reply asks the assistant to justify its
    prior answer, else 'other'. Semantic (LLM) judgement, not a keyword match —
    fails closed to 'other' so a hiccup never spams the room."""
    t = (text or "").strip()
    if not t:
        return "other"
    try:
        if llm is None:
            from my_bot.utils.llm_factory import create_llm
            llm = create_llm(temperature=0.0)
        from langchain_core.messages import HumanMessage, SystemMessage
        resp = llm.invoke([
            SystemMessage(content=_FOLLOWUP_INTENT_PROMPT),
            HumanMessage(content=t[:600]),
        ])
        verdict = (getattr(resp, "content", "") or "").strip().upper()
        return "explain" if "EXPLAIN" in verdict else "other"
    except Exception as e:
        logger.warning("[ambient] follow-up intent classify failed: %s", e)
        return "other"


def _render_ambient_reasoning(rec: dict, llm=None) -> str:
    """Compose a short, friendly explanation of how the stored answer was reached.

    Uses the recorded trace as the only source. Phrases it via the LLM for a
    natural reply; falls back to a deterministic bullet list if that fails."""
    import json as _json
    try:
        steps = _json.loads(rec.get("trace_json") or "[]")
    except Exception:
        steps = []

    # Deterministic facts block (also the fallback body).
    fact_lines = []
    for i, st in enumerate(steps, 1):
        tool = (st.get("tool") or "?").replace("_", " ")
        preview = (st.get("result_preview") or "").strip().replace("\n", " ")
        fact_lines.append(f"{i}. checked {tool} → {preview[:200] or 'no result'}")
    if fact_lines:
        facts = "I looked at:\n" + "\n".join(fact_lines)
    else:
        facts = ("I answered from what was already known / from the conversation — "
                 "I didn't run a live lookup for that one.")

    try:
        if llm is None:
            from my_bot.utils.llm_factory import create_llm
            llm = create_llm(temperature=0.0)
        from langchain_core.messages import HumanMessage, SystemMessage
        sys = (
            "You are Pokedex explaining, in a friendly threaded chat reply, HOW you "
            "reached an answer you already gave. Use ONLY the record provided — do "
            "not re-investigate or invent steps. Keep it to 2-4 short sentences, "
            "plain text (no tables, no code blocks). A couple of emojis are fine."
        )
        human = (
            f"The question was: {rec.get('question') or '(unknown)'}\n"
            f"Your answer was: {(rec.get('answer') or '')[:1200]}\n\n"
            f"Record of what you did:\n{facts}\n\n"
            "Explain how you got there."
        )
        resp = llm.invoke([SystemMessage(content=sys), HumanMessage(content=human[:6000])])
        out = (getattr(resp, "content", "") or "").strip()
        if out:
            return out
    except Exception as e:
        logger.warning("[ambient] reasoning render LLM failed, using fallback: %s", e)
    # Deterministic fallback.
    return f"Here's how I got that 👇\n\n{facts}"


def _handle_followups(room_id, messages, conn, post_api, answer_api,
                      thread_posts, llm, bot_email) -> int:
    """Answer threaded 'why?/how?' replies to our prior auto-run answers.

    For each NEW human message that is a reply in the thread of a stored auto-run
    answer AND asks us to justify it, post a short explanation built from the
    recorded reasoning trace. Other replies fall through to the normal classify
    path. Returns the count explained."""
    explained = 0
    for msg in messages:
        try:
            parent_id = (getattr(msg, "parentId", "") or "").strip()
            if not parent_id:
                continue  # only threaded replies can be follow-ups
            msg_id = getattr(msg, "id", "") or ""
            if not msg_id or _already_processed(conn, msg_id):
                continue
            sender = getattr(msg, "personEmail", "") or ""
            if sender == bot_email or sender.endswith("@webex.bot"):
                continue  # never react to our own / other bots' posts
            rec = _get_ambient_answer(conn, parent_id)
            if not rec:
                continue  # not a reply to one of our answers
            text = getattr(msg, "text", "") or ""
            if _classify_followup_intent(text, llm) != "explain":
                continue  # leave non-"why" replies to the normal path
            explanation = _render_ambient_reasoning(rec, llm)
            asker_name = _resolve_first_name(post_api, msg)
            posted_id = _post_autorun_answer(
                answer_api, room_id, asker_name, "how I got that",
                _format_for_webex(explanation),
                parent_id=(parent_id if thread_posts else None))
            if posted_id:
                explained += 1
                created = str(getattr(msg, "created", "") or "")
                # Record the reply (so we don't re-handle it) and our explanation
                # (so it isn't re-classified next tick).
                _record(conn, msg_id, room_id, created,
                        Suggestion.irrelevant("followup-why"), True)
                _record(conn, posted_id, room_id, created,
                        Suggestion.irrelevant("followup-explanation"), True)
                conn.commit()
                logger.info("[ambient] %s explained prior answer for reply %s",
                            room_id, msg_id)
        except Exception as e:
            logger.warning("[ambient] follow-up handling error: %s", e)
            continue
    return explained


# --- Reactive screenshot bridge (@Pokedex + image) ---------------------------


# Resolved once: Pokedex's own personId, so we can detect an @-mention precisely
# (mentionedPeople carries person IDs, not emails). Cached at module scope.
_POKEDEX_PERSON_ID: Optional[str] = None


def _pokedex_person_id(bot_api) -> str:
    """The Pokedex bot's own personId (for mention detection), resolved once.

    ``mentionedPeople`` on a listed message is a list of person IDs, so matching an
    @-mention needs the bot's id, not its email. ``people.me()`` on the bot token
    returns it. Cached; a lookup failure caches "" so we fall back to the text-name
    backstop rather than retry every tick."""
    global _POKEDEX_PERSON_ID
    if _POKEDEX_PERSON_ID is None:
        try:
            _POKEDEX_PERSON_ID = (getattr(bot_api.people.me(), "id", "") or "")
        except Exception as e:
            logger.debug("[ambient] could not resolve Pokedex personId: %s", e)
            _POKEDEX_PERSON_ID = ""
    return _POKEDEX_PERSON_ID


def _strip_bot_mention(text: str, bot_email: str) -> str:
    """Drop a leading bot-name token so an @-mention's plain text reads as the ask.

    Webex renders an @-mention into the message's plain text as the mentionee's
    display name, so '@Pokedex triage this' arrives as 'Pokedex triage this'. A dumb
    non-semantic leading-token strip (NOT a classifier) leaves just the analyst's
    request for the query."""
    t = (text or "").strip()
    for frag in _BOT_NAME_FRAGMENTS:
        if t.lower().startswith(frag):
            return t[len(frag):].lstrip(" :,-—")
    return t


def _handle_screenshot_mentions(room_id, messages, conn, post_api, answer_api,
                                thread_posts, vision_by_id, bot_email) -> int:
    """Answer @Pokedex messages that carry a screenshot — the reply the bot can't give.

    For each NEW, non-bot message that BOTH @-mentions Pokedex AND has a screenshot
    we transcribed this tick (``vision_by_id``), run the agentic investigation
    (read-only, as the asker) on the analyst's ask + the screenshot grounding, and
    post the answer back as Pokedex. Marks the asker's message + our answer as
    processed so the gist/v1 path never re-touches them. Returns the count answered.

    This is the ONLY ambient path that acts on a bot-directed message — every other
    path skips them as the reactive bot's job, but the bot never sees a file message,
    so this fills exactly that hole. Read-only is hard-armed (an auto-triggered reply
    must never block/isolate/quarantine); the analyst still drives any containment.
    Bounded by ``_vision_max`` upstream (only transcribed screenshots qualify)."""
    if not _screenshot_bridge_enabled() or not vision_by_id:
        return 0
    cursor = _get_cursor(conn, room_id)
    bot_pid = _pokedex_person_id(post_api)
    answered = 0
    for msg in messages:
        try:
            msg_id = getattr(msg, "id", "") or ""
            if not msg_id or msg_id not in vision_by_id:
                continue  # only messages we actually read a screenshot from
            if _already_processed(conn, msg_id):
                continue
            created = str(getattr(msg, "created", "") or "")
            if cursor and created and created <= cursor:
                continue
            sender = getattr(msg, "personEmail", "") or ""
            if sender == bot_email or sender.endswith("@webex.bot"):
                continue
            text = getattr(msg, "text", "") or ""
            mentioned = list(getattr(msg, "mentionedPeople", None) or [])
            directed = (bot_pid and bot_pid in mentioned) or _is_bot_directed(
                text, [], bot_email)
            if not directed:
                continue  # a screenshot NOT aimed at Pokedex → the gist path's job

            block = vision_by_id.get(msg_id) or ""
            ask = _strip_bot_mention(text, bot_email)
            if ask.strip():
                query = f"{ask}\n\n{block}".strip()
            else:
                query = (
                    "Triage this screenshot — transcribe what it shows, extract any "
                    "IOCs (IPs, domains, hashes, URLs, CVEs), and assess how bad it "
                    f"is.\n\n{block}")
            logger.info("[ambient] SCREENSHOT @mention by %s in %s — answering", sender, room_id)
            metrics = _invoke_agent_full(query, sender, room_id, read_only=True)
            answer = (metrics or {}).get("content", "") or "" if metrics else ""
            if not answer:
                # Even a failed investigation shouldn't leave the analyst hanging on a
                # direct @-mention; mark processed so we don't loop on it next tick.
                _record(conn, msg_id, room_id, created,
                        Suggestion.irrelevant("screenshot-mention-noanswer"), False)
                conn.commit()
                continue
            parent = getattr(msg, "parentId", None) or msg_id
            answer_parent = parent if thread_posts else None
            asker_name = _resolve_first_name(post_api, msg)
            posted_id = _post_autorun_answer(
                answer_api, room_id, asker_name, "your screenshot",
                _format_for_webex(answer), parent_id=answer_parent)
            if posted_id:
                answered += 1
                _store_ambient_answer(
                    conn, answer_message_id=posted_id,
                    thread_root_id=(answer_parent or posted_id),
                    room_id=room_id, asker=sender, question=query,
                    answer=answer, metrics=metrics or {})
                _record(conn, msg_id, room_id, created,
                        Suggestion.irrelevant("screenshot-mention"), True)
                _record(conn, posted_id, room_id, created,
                        Suggestion.irrelevant("screenshot-answer"), True)
                conn.commit()
                logger.info("[ambient] %s answered screenshot @mention %s", room_id, msg_id)
        except Exception as e:
            logger.warning("[ambient] screenshot mention handling error: %s", e)
            continue
    return answered


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


def _run_gist(
    room_id: str,
    messages: list,
    conn: sqlite3.Connection,
    post_api,
    answer_api,
    thread_posts: bool,
    threshold: float,
    llm,
    bot_email: str,
    stats: dict,
    vision_by_id: Optional[dict] = None,
) -> dict:
    """v2 tick: synthesize the conversation's need(s) and act on them.

    Replaces the v1 per-message Pass 2. Builds a rolling window of recent human,
    non-bot-directed messages (context + this tick's NEW ones), asks one LLM to
    consolidate the discussion into actionable need(s), then routes each over-bar
    need through the SAME machinery v1 uses: read-only needs auto-run as the latest
    contributor (with the hard read-only guard armed) and post a threaded answer;
    destructive-intent needs post a human-in-the-loop "Run it" card. A per-need
    cooldown stops a long-running discussion of one indicator from being re-answered
    every tick. ``messages`` is oldest-first.
    """
    cursor = _get_cursor(conn, room_id)
    newest_created = cursor
    window: list[dict] = []
    new_msgs: list[tuple[str, str, str]] = []  # (msg_id, room_id, created) to record
    for msg in messages:
        created = getattr(msg, "created", None)
        created = str(created) if created is not None else ""
        msg_id = getattr(msg, "id", "") or ""
        text = getattr(msg, "text", "") or ""
        sender = getattr(msg, "personEmail", "") or ""
        stats["seen"] += 1
        if not msg_id:
            continue
        # Fold any screenshot transcription into this message's text so the gist
        # synthesis reads a pasted alert console / phishing email as part of it.
        text = _with_screenshot(text, msg_id, vision_by_id)
        # Bot's own + other bots + bot-directed messages never enter the gist —
        # they're the reactive path's job and would skew "what's the room asking".
        if sender == bot_email or sender.endswith("@webex.bot"):
            stats["skipped"] += 1
            continue
        if _is_bot_directed(text, [], bot_email):
            stats["skipped"] += 1
            continue
        is_new = (
            bool(created)
            and (not cursor or created > cursor)
            and not _already_processed(conn, msg_id)
        )
        if is_new:
            if created and (newest_created is None or created > newest_created):
                newest_created = created
            new_msgs.append((msg_id, room_id, created))
        window.append(
            {"msg": msg, "msg_id": msg_id, "created": created,
             "text": text, "sender": sender, "is_new": is_new}
        )

    # Keep only the most recent N for the synthesis (context + new); positions in
    # this trimmed list are the indices the model sees and returns as latest_index.
    window = window[-_gist_window():]
    for pos, w in enumerate(window):
        w["index"] = pos
    stats["window"] = len(window)
    stats["new"] = sum(1 for w in window if w["is_new"])

    needs: list[GistNeed] = []
    if stats["new"] > 0:
        needs = synthesize_conversation(
            [{"index": w["index"], "sender": w["sender"],
              "text": w["text"], "is_new": w["is_new"]} for w in window],
            llm=llm,
        )

    autorun_enabled = _autorun_enabled()
    autorun_cap = _autorun_cap()
    dedup_seconds = _gist_dedup_seconds()
    autoruns_done = 0
    for need in needs:
        stats["classified"] = stats.get("classified", 0) + 1
        if not (need.query.strip() or need.entity.strip()):
            continue
        if need.score < threshold:
            logger.info(
                "[ambient] %s gist need below bar score=%.2f cat=%s entity=%r",
                room_id, need.score, need.category, need.entity,
            )
            continue
        key = _need_key(need.category, need.entity)
        if _recently_answered(conn, room_id, key, dedup_seconds):
            logger.info("[ambient] %s gist need recently answered, skipping: %s", room_id, key)
            continue

        anchor = window[need.latest_index] if 0 <= need.latest_index < len(window) else (window[-1] if window else None)
        anchor_msg = anchor["msg"] if anchor else None
        anchor_id = anchor["msg_id"] if anchor else None
        parent = ((getattr(anchor_msg, "parentId", None) or anchor_id) if anchor_msg else None)
        answer_parent = parent if thread_posts else None

        logger.info(
            "[ambient] %s GIST NEED score=%.2f cat=%s entity=%r approval=%s query=%r",
            room_id, need.score, need.category, need.entity,
            need.requires_approval, need.query,
        )
        posted = False
        if not _post_enabled():
            logger.info("[ambient] POST disabled (dry-run) — not acting on gist need")
        elif need.requires_approval or not autorun_enabled:
            # Destructive intent (or auto-run off) → human-in-the-loop card (bot, standalone).
            if _post_suggestion(post_api, room_id, None, _need_as_suggestion(need)):
                stats["suggested"] += 1
                _mark_answered(conn, room_id, key)
        elif autoruns_done >= autorun_cap:
            logger.info("[ambient] auto-run cap %d reached — deferring gist need to a card", autorun_cap)
            if _post_suggestion(post_api, room_id, None, _need_as_suggestion(need)):
                stats["suggested"] += 1
                _mark_answered(conn, room_id, key)
        else:
            # Read-only → auto-run as the latest contributor, hard read-only, post the answer.
            asker = (getattr(anchor_msg, "personEmail", "") or "") if anchor_msg else ""
            logger.info("[ambient] GIST AUTO-RUN (read-only) for %s — query=%r", asker, need.query)
            metrics = _invoke_agent_full(need.query, asker, room_id, read_only=True)
            answer = (metrics or {}).get("content", "") or "" if metrics else ""
            autoruns_done += 1
            if answer:
                asker_name = _resolve_first_name(post_api, anchor_msg) if anchor_msg else "there"
                posted_id = _post_autorun_answer(
                    answer_api, room_id, asker_name,
                    (need.reason or need.entity), _format_for_webex(answer),
                    parent_id=answer_parent,
                )
                posted = bool(posted_id)
                if posted:
                    stats["answered"] = stats.get("answered", 0) + 1
                    _mark_answered(conn, room_id, key)
                    # Persist the reasoning so a threaded "why?" can explain it.
                    _store_ambient_answer(
                        conn, answer_message_id=posted_id,
                        thread_root_id=(answer_parent or posted_id),
                        room_id=room_id, asker=asker, question=need.query,
                        answer=answer, metrics=metrics or {})

    # Record this tick's NEW messages as seen and advance the cursor so next tick
    # they're context-only ([NEW]=false) — dedup, not the ledger, prevents re-answers.
    for mid, rid, cr in new_msgs:
        _record(conn, mid, rid, cr, Suggestion.irrelevant("gist-context"), False)
    if newest_created and newest_created != cursor:
        _set_cursor(conn, room_id, newest_created)
    conn.commit()
    return stats


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

    # Cursor-aware fetch. webexpythonsdk's .list() AUTO-PAGINATES — ``max`` is the
    # PAGE SIZE, not a total cap; left unbounded it walks the ENTIRE room history
    # every tick (7528 msgs on the dev-test space, 2026-06-24). We page newest→older
    # and STOP as soon as we cross the cursor — so steady-state a tick pulls about one
    # page, but a fast burst (the team firing dozens of messages in one five-minute
    # tick during an incident) keeps paging until it has the whole gap, never silently
    # dropping the oldest ones the way a fixed head-of-list cap did. _max_catchup
    # bounds a cold start / long downtime so a first tick can't walk the full history.
    conn = _connect()
    try:
        cursor = _get_cursor(conn, room_id)

        def _fetch(api):
            ceiling = _max_catchup()
            out = []
            for m in api.messages.list(roomId=room_id, max=_lookback()):
                out.append(m)
                created = str(getattr(m, "created", "") or "")
                # Newest-first: once we're at/before the cursor, every older message
                # is already processed — stop paging.
                if cursor and created and created <= cursor:
                    break
                if len(out) >= ceiling:
                    logger.warning(
                        "[ambient] %s hit catch-up ceiling %d — older messages in this "
                        "burst are skipped this tick", room_id, ceiling)
                    break
            return out

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

        # Vision: read any screenshots attached to this tick's NEW messages once,
        # so their transcribed text + IOCs can flow into the relevance gate / gist
        # synthesis like typed text. Best-effort; {} when no images or no VLM.
        vision_by_id = _collect_screenshots(
            messages, conn, room_id, bot_email, _read_token())

        # Self-learning: capture any analyst disposition-corrections in this tick's
        # chatter as ground truth (independent of the suggest/answer path; runs in
        # both gist and v1 modes). Best-effort — never blocks the scan.
        stats["corrections"] = _capture_corrections(room_id, messages, conn, llm, bot_email)

        # Self-learning: capture durable security facts/tradecraft from this tick's
        # chatter into the recallable knowledge store (source='chatter'). Sibling
        # of the corrections pass; best-effort, never blocks the scan.
        stats["knowledge"] = _capture_knowledge(room_id, messages, conn, llm, bot_email)

        # Threaded "why?/how?" replies to our prior auto-run answers — explain from
        # the recorded reasoning trace. Runs in both modes, before classification,
        # so an explain reply is consumed here rather than re-answered downstream.
        if _post_enabled():
            stats["explained"] = _handle_followups(
                room_id, messages, conn, post_api, answer_api,
                thread_posts, llm, bot_email)

        # Reactive screenshot bridge: answer @Pokedex messages that carry a
        # screenshot — the reply the bot can't give (no websocket event for file
        # messages in group spaces). Runs in BOTH modes and is gated independently
        # of the proactive dry-run switch (a direct @-mention is an explicit ask),
        # before classification so the asker's message is consumed here, not
        # skipped downstream as bot-directed.
        stats["screenshot_answered"] = _handle_screenshot_mentions(
            room_id, messages, conn, post_api, answer_api,
            thread_posts, vision_by_id, bot_email)

        if _gist_enabled():
            # v2: respond to the conversation gist, not each message in isolation.
            return _run_gist(
                room_id, messages, conn, post_api, answer_api,
                thread_posts, threshold, llm, bot_email, stats, vision_by_id,
            )
        newest_created = cursor
        # Pass 1: filter to the human messages worth classifying this tick.
        # Cursor/ledger and bot-directed skips happen here; classification is
        # deferred so it runs as ONE batched call (rate-limit friendly) below.
        candidates = []  # (msg, msg_id, created, raw_text, classify_text)
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

            # Classify on the screenshot-augmented text (so a pasted indicator is
            # seen), but keep the raw typed text as source_text below — a
            # screenshot-only message then gets a clean category directive from
            # _run_query rather than the whole transcription as its query.
            classify_text = _with_screenshot(text, msg_id, vision_by_id)
            candidates.append((msg, msg_id, created, text, classify_text))

        # One batched relevance call for the whole tick.
        suggestions = classify_messages_batch([c[4] for c in candidates], llm=llm)

        # Pass 2: apply the bar. Over-bar READ-only suggestions auto-run and post the
        # answer; DESTRUCTIVE-intent ones post a human-in-the-loop card. Auto-runs are
        # capped per tick (each is a full investigation); overflow falls back to a card.
        autorun_enabled = _autorun_enabled()
        autorun_cap = _autorun_cap()
        autoruns_done = 0
        for (msg, msg_id, created, _text, _ctext), suggestion in zip(candidates, suggestions):
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
                    metrics = _invoke_agent_full(query, asker, room_id, read_only=True)
                    answer = (metrics or {}).get("content", "") or "" if metrics else ""
                    autoruns_done += 1
                    if answer:
                        # Resolve the display name via the POST identity, not read_api:
                        # the OAuth read scope is spark:messages_read only, so a
                        # people.get on it 403s and we fall back to the email
                        # local-part ("Labuser"). The bot / write identity can.
                        asker_name = _resolve_first_name(post_api, msg)
                        posted_id = _post_autorun_answer(
                            answer_api, room_id, asker_name,
                            _question_ref(suggestion), _format_for_webex(answer),
                            parent_id=answer_parent)
                        posted = bool(posted_id)
                        if posted:
                            stats["answered"] = stats.get("answered", 0) + 1
                            # Persist reasoning for a threaded "why?" follow-up.
                            _store_ambient_answer(
                                conn, answer_message_id=posted_id,
                                thread_root_id=(answer_parent or posted_id),
                                room_id=room_id, asker=asker, question=query,
                                answer=answer, metrics=metrics or {})
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
        logger.warning(f"[ambient] cannot init the LLM: {e}")
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
