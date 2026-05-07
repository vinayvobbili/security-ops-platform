"""Meeting Recap Handler.

Orchestrates the meeting recap pipeline:
    audio upload  ->  remote transcription (M1)  ->  LLM summary (M1)  ->  SQLite

The transcription itself runs on the inference Mac via services/transcription.py.
The LLM summarization reuses the same M1 LLM endpoint that meeting_qa_handler.py
uses, via the raw OpenAI SDK with assistant prefix-filling to skip GLM's
reasoning phase.
"""

import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from openai import OpenAI

from services.transcription import transcribe_audio
from my_config import get_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage layout
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
RECAPS_DIR = _PROJECT_ROOT / "data" / "recaps"
AUDIO_DIR = RECAPS_DIR / "audio"
DB_PATH = RECAPS_DIR / "recaps.db"

_db_init_lock = threading.Lock()
_db_initialized = False

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS recaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meeting_type TEXT NOT NULL,
    title TEXT,
    meeting_date TEXT,
    attendees TEXT,
    audio_filename TEXT,
    audio_path TEXT,
    transcript_json TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    speaker_names_json TEXT,
    summary_language TEXT DEFAULT 'en',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audio_deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recaps_created ON recaps(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recaps_type ON recaps(meeting_type);
"""


def _init_db() -> None:
    """Create the recaps table on first use. Idempotent and thread-safe."""
    global _db_initialized
    if _db_initialized:
        return
    with _db_init_lock:
        if _db_initialized:
            return
        RECAPS_DIR.mkdir(parents=True, exist_ok=True)
        AUDIO_DIR.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript(SCHEMA_SQL)
            # Additive migration for DBs created before summary_language existed.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(recaps)").fetchall()}
            if "summary_language" not in cols:
                conn.execute("ALTER TABLE recaps ADD COLUMN summary_language TEXT DEFAULT 'en'")
            conn.commit()
        logger.info(f"Recap DB initialized at {DB_PATH}")
        _db_initialized = True


def _connect() -> sqlite3.Connection:
    """Open a fresh SQLite connection. Caller is responsible for closing."""
    _init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# LLM client (mirrors meeting_qa_handler.py pattern)
# ---------------------------------------------------------------------------

_client: Optional[OpenAI] = None
_model_id: Optional[str] = None


def _get_client() -> OpenAI:
    global _client
    if _client is not None:
        return _client
    # m1 analysis (GLM-4.7-Flash)
    base_url = os.environ.get("POKEDEX_LLM_BASE_URL") or os.environ.get("LLM_BASE_URL", "http://localhost:8015/v1")
    logger.info(f"Recap LLM base URL: {base_url}")
    _client = OpenAI(base_url=base_url, api_key="not-needed")
    return _client


def _get_model_id() -> str:
    global _model_id
    if _model_id is not None:
        return _model_id
    try:
        models = _get_client().models.list()
        if models.data:
            _model_id = models.data[0].id
            logger.info(f"Recap using model: {_model_id}")
            return _model_id
    except Exception as e:
        logger.warning(f"Could not discover model ID: {e}")
    return "default"


# ---------------------------------------------------------------------------
# Supported summary languages
# ---------------------------------------------------------------------------
# ISO 639-1 code -> display name used in prompts and UI. The local LLM
# (GLM-4.7-Flash) is multilingual; these are the languages we've tested are
# handled well for both fresh summarization and post-hoc translation.
SUPPORTED_LANGUAGES: dict[str, str] = {
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "it": "Italian",
    "pt": "Portuguese",
    "nl": "Dutch",
    "ru": "Russian",
    "ja": "Japanese",
    "ko": "Korean",
    "zh": "Chinese (Simplified)",
    "hi": "Hindi",
    "ar": "Arabic",
}

DEFAULT_LANGUAGE = "en"


def _language_instruction(language: str) -> str:
    """Return an extra system-prompt clause that pins output language.

    Empty string for English (the prompts are already English-native, no
    need to add noise). For any other language, instruct the model to write
    all string values in that language while preserving JSON keys and the
    SPEAKER_NN labels verbatim.
    """
    if language == "en" or language not in SUPPORTED_LANGUAGES:
        return ""
    name = SUPPORTED_LANGUAGES[language]
    return (
        f" Write all human-readable string values in the output JSON in {name}. "
        f"Do NOT translate JSON keys, speaker labels like SPEAKER_00/SPEAKER_01, "
        f"ISO dates/timestamps, or priority tokens like 'must-have' / 'should-have' / "
        f"'nice-to-have' — keep those exactly as-is. If a due value is unknown, still "
        f"write it as the literal string 'unspecified'."
    )


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_INCIDENT_SYSTEM_PROMPT = (
    "You are a SOC incident analyst summarizing a recorded incident bridge call. "
    "Output ONLY valid JSON — no markdown, no preamble, no explanation. "
    "Be concise and fact-only. Distinguish decisions made, actions assigned, and the timeline of events. "
    "Use the speaker labels from the transcript verbatim when assigning action items."
)

_INCIDENT_USER_PROMPT = """\
Below is a diarized transcript of an incident bridge call. Produce a JSON object with EXACTLY these fields:

{{
  "title": "short descriptive title (max 80 chars), e.g. 'Phishing campaign — Acme tenant — 2026-04-09'",
  "summary": "3-5 sentence executive summary of what happened and current status",
  "timeline": [
    {{"time": "HH:MM:SS or relative", "speaker": "SPEAKER_NN", "event": "what happened"}}
  ],
  "decisions": [
    {{"decision": "what was decided", "decided_by": "SPEAKER_NN", "rationale": "why"}}
  ],
  "action_items": [
    {{"action": "what needs to be done", "owner": "SPEAKER_NN", "due": "deadline or 'unspecified'"}}
  ],
  "open_questions": [
    "unresolved item raised but not answered"
  ]
}}

If a field has no items, return an empty list. Do not invent details that are not in the transcript.

TRANSCRIPT:
{transcript}
"""

_TEAM_SYSTEM_PROMPT = (
    "You are an executive assistant summarizing a recorded team meeting. "
    "Output ONLY valid JSON — no markdown, no preamble, no explanation. "
    "Capture agenda topics discussed, decisions reached, and action items with clear owners. "
    "Use the speaker labels from the transcript verbatim when assigning action items."
)

_TEAM_USER_PROMPT = """\
Below is a diarized transcript of a team meeting. Produce a JSON object with EXACTLY these fields:

{{
  "title": "short descriptive title (max 80 chars), e.g. 'Weekly SOC sync — 2026-04-09'",
  "summary": "3-5 sentence overview of what the team discussed",
  "topics": [
    {{"topic": "agenda item or theme", "key_points": ["point 1", "point 2"]}}
  ],
  "decisions": [
    {{"decision": "what was decided", "rationale": "why"}}
  ],
  "action_items": [
    {{"action": "what needs to be done", "owner": "SPEAKER_NN", "due": "deadline or 'unspecified'"}}
  ]
}}

If a field has no items, return an empty list. Do not invent details that are not in the transcript.

TRANSCRIPT:
{transcript}
"""

_CUSTOMER_REQ_SYSTEM_PROMPT = (
    "You are a Senior Solutions Architect listening to a recorded customer discovery or requirements call. "
    "Your job is to extract the customer's stated requirements, pain points, and success criteria from the "
    "conversation so an engineering team can act on them. "
    "Output ONLY valid JSON — no markdown, no preamble, no explanation. "
    "Be precise and evidence-based — only capture what was explicitly stated or clearly implied; do not invent features the customer did not ask for. "
    "Use the speaker labels from the transcript verbatim when attributing requirements, concerns, or action items."
)

_CUSTOMER_REQ_USER_PROMPT = """\
Below is a diarized transcript of a customer meeting (discovery / requirements / solution review). Produce a JSON object with EXACTLY these fields:

{{
  "title": "short descriptive title (max 80 chars), e.g. 'Acme Corp — SIEM migration discovery — 2026-04-14'",
  "summary": "3-5 sentence executive summary of the customer's situation, what they're asking for, and the overall shape of the opportunity",
  "requirements": [
    {{"requirement": "the specific capability or outcome the customer needs", "priority": "must-have | should-have | nice-to-have", "raised_by": "SPEAKER_NN", "rationale": "why they want it — the business or technical driver"}}
  ],
  "pain_points": [
    {{"pain": "what is currently not working for them", "impact": "the business or operational consequence"}}
  ],
  "success_criteria": [
    "how the customer will judge the solution a success (measurable where possible)"
  ],
  "stakeholders": [
    {{"speaker": "SPEAKER_NN", "role": "their role or title if stated (e.g. CISO, SOC lead, platform owner)", "concerns": "what they personally care about in this engagement"}}
  ],
  "action_items": [
    {{"action": "what needs to be done next", "owner": "SPEAKER_NN", "due": "deadline or 'unspecified'"}}
  ],
  "open_questions": [
    "unresolved item raised but not answered — things we still need to go back and clarify"
  ]
}}

If a field has no items, return an empty list. Do not invent details that are not in the transcript.

TRANSCRIPT:
{transcript}
"""

_PROMPTS = {
    "incident_bridge": (_INCIDENT_SYSTEM_PROMPT, _INCIDENT_USER_PROMPT),
    "team_meeting": (_TEAM_SYSTEM_PROMPT, _TEAM_USER_PROMPT),
    "customer_requirements": (_CUSTOMER_REQ_SYSTEM_PROMPT, _CUSTOMER_REQ_USER_PROMPT),
}


def _format_transcript_for_llm(segments: list[dict]) -> str:
    """Format the diarized segments into a readable transcript for the LLM."""
    lines = []
    for seg in segments:
        ts = _format_timestamp(seg.get("start", 0))
        lines.append(f"[{ts}] {seg.get('speaker', 'SPEAKER_??')}: {seg.get('text', '').strip()}")
    return "\n".join(lines)


def _format_timestamp(seconds: float) -> str:
    """Format float seconds as HH:MM:SS."""
    s = int(seconds)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _strip_thinking(raw: str) -> str:
    """Strip GLM thinking tags if present."""
    if "</think>" in raw:
        raw = raw.split("</think>")[-1].strip()
    elif "<think>" in raw:
        raw = raw.split("<think>")[0].strip()
    return raw.strip()


def summarize(
    transcript_segments: list[dict],
    meeting_type: str,
    language: str = DEFAULT_LANGUAGE,
) -> dict[str, Any]:
    """Summarize a diarized transcript with the appropriate prompt for the meeting type.

    Args:
        transcript_segments: List of {speaker, start, end, text} from the transcription server.
        meeting_type: 'incident_bridge', 'team_meeting', or 'customer_requirements'.
        language: ISO 639-1 code of the desired output language. Defaults to English.
            Unknown codes silently fall back to English.

    Returns:
        Parsed JSON dict with summary, action_items, decisions, etc. Includes a 'title' field.

    Raises:
        ValueError: if meeting_type is unknown
        RuntimeError: if the LLM call fails or returns unparseable output
    """
    if meeting_type not in _PROMPTS:
        raise ValueError(f"Unknown meeting_type: {meeting_type}")

    base_system, user_template = _PROMPTS[meeting_type]
    system_prompt = base_system + _language_instruction(language)
    transcript_text = _format_transcript_for_llm(transcript_segments)
    user_prompt = user_template.format(transcript=transcript_text)

    # Assistant prefix-fill: start with `{` so GLM emits JSON immediately
    # instead of spending a minute on reasoning text.
    ASSISTANT_PREFIX = "{"

    try:
        resp = _get_client().chat.completions.create(
            model=_get_model_id(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": ASSISTANT_PREFIX},
            ],
            temperature=0,
            max_tokens=4096,
            timeout=300,
        )
        raw = resp.choices[0].message.content or ""
        # The model continues from the prefix, so prepend it back
        full_json = ASSISTANT_PREFIX + raw if not raw.startswith("{") else raw
        full_json = _strip_thinking(full_json)

        # Trim any trailing prose after the JSON object
        full_json = _extract_first_json_object(full_json)

        parsed = json.loads(full_json)
        return parsed

    except json.JSONDecodeError as e:
        logger.error(f"Recap LLM returned unparseable JSON: {e}\nRaw: {raw[:500]}")
        raise RuntimeError(f"LLM returned unparseable JSON: {e}")
    except Exception as e:
        logger.exception(f"Recap summarization failed: {e}")
        raise RuntimeError(f"LLM summarization failed: {e}")


def translate_summary(summary: dict, target_language: str) -> dict:
    """Translate a recap summary dict into `target_language` via the local LLM.

    The source language is inferred by the model from the content itself, which
    is reliable for well-structured JSON. JSON keys, SPEAKER_NN labels, ISO
    dates, and priority tokens ('must-have'/'should-have'/'nice-to-have') are
    preserved verbatim; only human-readable string values are translated.

    Raises:
        ValueError: unsupported target_language
        RuntimeError: LLM call failed or returned unparseable output
    """
    if target_language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported target language: {target_language}")

    target_name = SUPPORTED_LANGUAGES[target_language]
    system_prompt = (
        f"You are a precise translator. You receive a JSON object and return the same "
        f"JSON object with all human-readable string values translated into {target_name}. "
        f"Output ONLY the translated JSON — no markdown fences, no commentary.\n"
        f"STRICT RULES:\n"
        f"  1. Do NOT translate JSON keys — leave them exactly as they are in the input.\n"
        f"  2. Do NOT translate speaker labels of the form SPEAKER_00, SPEAKER_01, etc.\n"
        f"     When they appear inside a string value, keep them as-is.\n"
        f"  3. Do NOT translate ISO dates, timestamps, or times like '14:30' or '00:01:23'.\n"
        f"  4. Do NOT translate priority tokens: keep 'must-have', 'should-have', and "
        f"     'nice-to-have' exactly as written.\n"
        f"  5. Keep the literal token 'unspecified' in English if it appears as a 'due' value.\n"
        f"  6. Preserve the exact JSON structure: every array, object, and key present in "
        f"     the input must be present in the output.\n"
        f"  7. If the input value is already in {target_name}, return it unchanged."
    )
    user_prompt = (
        f"Translate all human-readable string values in the following JSON into "
        f"{target_name}. Return JSON only.\n\n"
        f"{json.dumps(summary, ensure_ascii=False)}"
    )

    ASSISTANT_PREFIX = "{"
    try:
        resp = _get_client().chat.completions.create(
            model=_get_model_id(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": ASSISTANT_PREFIX},
            ],
            temperature=0,
            max_tokens=16384,
            timeout=300,
        )
        raw = resp.choices[0].message.content or ""
        finish_reason = resp.choices[0].finish_reason if resp.choices else None
        if finish_reason == "length":
            logger.error(f"Translation hit max_tokens (finish_reason=length). Raw tail: {raw[-200:]}")
            raise RuntimeError("Translation output was truncated — summary is too long for a single pass")
        full_json = ASSISTANT_PREFIX + raw if not raw.startswith("{") else raw
        full_json = _strip_thinking(full_json)
        full_json = _extract_first_json_object(full_json)
        try:
            return json.loads(full_json)
        except json.JSONDecodeError:
            from json_repair import repair_json
            repaired = repair_json(full_json, return_objects=True)
            if isinstance(repaired, dict) and repaired:
                logger.warning(f"Translation JSON was malformed, repaired via json_repair ({len(full_json)} chars)")
                return repaired
            raise
    except json.JSONDecodeError as e:
        logger.error(f"Translation returned unparseable JSON (repair also failed): {e}\nRaw tail: {raw[-400:]}")
        raise RuntimeError(f"Translation returned unparseable JSON: {e}")
    except Exception as e:
        logger.exception(f"Recap translation failed: {e}")
        raise RuntimeError(f"Translation failed: {e}")


def translate_recap(recap_id: int, target_language: str) -> Optional[dict]:
    """Translate an existing recap's summary in place. Returns the updated recap.

    If the recap is already in target_language this is a no-op and the current
    recap is returned unchanged. Returns None if the recap does not exist.
    """
    if target_language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported target language: {target_language}")

    recap = get_recap(recap_id)
    if not recap:
        return None

    current_lang = recap.get("summary_language") or DEFAULT_LANGUAGE
    if current_lang == target_language:
        return recap

    summary = recap.get("summary") or {}
    translated = translate_summary(summary, target_language)
    new_title = translated.get("title") or recap.get("title")

    with _connect() as conn:
        conn.execute(
            "UPDATE recaps SET summary_json = ?, title = ?, summary_language = ? WHERE id = ?",
            (json.dumps(translated, ensure_ascii=False), new_title, target_language, recap_id),
        )
        conn.commit()
    logger.info(f"Recap #{recap_id} translated {current_lang} -> {target_language}")
    return get_recap(recap_id)


def _extract_first_json_object(text: str) -> str:
    """Extract the first balanced JSON object from text. Tolerates trailing prose."""
    text = text.strip()
    if not text.startswith("{"):
        # Find first {
        idx = text.find("{")
        if idx < 0:
            return text
        text = text[idx:]
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[: i + 1]
    return text


# ---------------------------------------------------------------------------
# Webex notification
# ---------------------------------------------------------------------------

# Webex caps messages at 7439 chars; leave headroom for the part-marker prefix.
_WEBEX_CHUNK_LIMIT = 6800


def _format_incident_summary(title: str, summary: dict) -> str:
    lines = [f"### 🚨 {title}", "", "**Type:** Incident Bridge", ""]
    lines += ["#### Summary", summary.get("summary", "_No summary._"), ""]

    timeline = summary.get("timeline") or []
    if timeline:
        lines.append("#### ⏱️ Timeline")
        for t in timeline:
            lines.append(f"- `{t.get('time','?')}` **{t.get('speaker','?')}** — {t.get('event','')}")
        lines.append("")

    decisions = summary.get("decisions") or []
    if decisions:
        lines.append("#### ✅ Decisions")
        for d in decisions:
            lines.append(
                f"- **{d.get('decision','')}** "
                f"_(by {d.get('decided_by','?')})_ — {d.get('rationale','')}"
            )
        lines.append("")

    actions = summary.get("action_items") or []
    if actions:
        lines.append("#### 🎯 Next Steps")
        for a in actions:
            lines.append(
                f"- **{a.get('action','')}** — owner: {a.get('owner','?')}, "
                f"due: {a.get('due','unspecified')}"
            )
        lines.append("")

    opens = summary.get("open_questions") or []
    if opens:
        lines.append("#### ❓ Open Questions")
        for q in opens:
            lines.append(f"- {q}")
        lines.append("")

    return "\n".join(lines).strip()


def _format_team_summary(title: str, summary: dict) -> str:
    lines = [f"### 👥 {title}", "", "**Type:** Team Meeting", ""]
    lines += ["#### Summary", summary.get("summary", "_No summary._"), ""]

    topics = summary.get("topics") or []
    if topics:
        lines.append("#### 📋 Topics")
        for t in topics:
            lines.append(f"- **{t.get('topic','')}**")
            for kp in (t.get("key_points") or []):
                lines.append(f"    - {kp}")
        lines.append("")

    decisions = summary.get("decisions") or []
    if decisions:
        lines.append("#### ✅ Decisions")
        for d in decisions:
            lines.append(f"- **{d.get('decision','')}** — {d.get('rationale','')}")
        lines.append("")

    actions = summary.get("action_items") or []
    if actions:
        lines.append("#### 🎯 Next Steps")
        for a in actions:
            lines.append(
                f"- **{a.get('action','')}** — owner: {a.get('owner','?')}, "
                f"due: {a.get('due','unspecified')}"
            )
        lines.append("")

    return "\n".join(lines).strip()


def _format_customer_requirements_summary(title: str, summary: dict) -> str:
    lines = [f"### 🧭 {title}", "", "**Type:** Customer Requirements", ""]
    lines += ["#### Summary", summary.get("summary", "_No summary._"), ""]

    reqs = summary.get("requirements") or []
    if reqs:
        lines.append("#### 📐 Requirements")
        for r in reqs:
            prio = r.get("priority", "?")
            by = r.get("raised_by", "?")
            lines.append(
                f"- **[{prio}]** {r.get('requirement','')} "
                f"_(raised by {by})_"
                + (f" — {r['rationale']}" if r.get("rationale") else "")
            )
        lines.append("")

    pains = summary.get("pain_points") or []
    if pains:
        lines.append("#### ⚠️ Pain Points")
        for p in pains:
            lines.append(
                f"- **{p.get('pain','')}**"
                + (f" — impact: {p['impact']}" if p.get("impact") else "")
            )
        lines.append("")

    success = summary.get("success_criteria") or []
    if success:
        lines.append("#### 🎯 Success Criteria")
        for s in success:
            lines.append(f"- {s}")
        lines.append("")

    stakeholders = summary.get("stakeholders") or []
    if stakeholders:
        lines.append("#### 👤 Stakeholders")
        for s in stakeholders:
            role = s.get("role", "?")
            lines.append(
                f"- **{s.get('speaker','?')}** _{role}_"
                + (f" — {s['concerns']}" if s.get("concerns") else "")
            )
        lines.append("")

    actions = summary.get("action_items") or []
    if actions:
        lines.append("#### ➡️ Next Steps")
        for a in actions:
            lines.append(
                f"- **{a.get('action','')}** — owner: {a.get('owner','?')}, "
                f"due: {a.get('due','unspecified')}"
            )
        lines.append("")

    opens = summary.get("open_questions") or []
    if opens:
        lines.append("#### ❓ Open Questions")
        for q in opens:
            lines.append(f"- {q}")
        lines.append("")

    return "\n".join(lines).strip()


def _chunk_markdown(text: str, limit: int = _WEBEX_CHUNK_LIMIT) -> list[str]:
    """Split a long markdown body on line boundaries so no chunk exceeds limit."""
    if len(text) <= limit:
        return [text]
    out: list[str] = []
    buf: list[str] = []
    size = 0
    for line in text.split("\n"):
        ln = len(line) + 1
        if size + ln > limit and buf:
            out.append("\n".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += ln
    if buf:
        out.append("\n".join(buf))
    return out


def _notify_webex(title: str, recap_id: int, meeting_type: str, summary: dict) -> None:
    """Post the full recap summary to the dev test Webex space, chunked under the 7k limit."""
    try:
        config = get_config()
        token = config.webex_bot_access_token_toodles
        room_id = config.webex_room_id_dev_test_space
        if not token or not room_id:
            logger.warning("Webex notification skipped — missing token or room ID")
            return

        if meeting_type == "incident_bridge":
            body = _format_incident_summary(title, summary)
        elif meeting_type == "customer_requirements":
            body = _format_customer_requirements_summary(title, summary)
        else:
            body = _format_team_summary(title, summary)

        chunks = _chunk_markdown(body)

        from webexteamssdk import WebexTeamsAPI
        api = WebexTeamsAPI(access_token=token)
        total = len(chunks)
        for i, chunk in enumerate(chunks, 1):
            prefix = f"_(part {i}/{total})_\n\n" if total > 1 else ""
            api.messages.create(roomId=room_id, markdown=prefix + chunk)

        footer = f"\n\n_Recap #{recap_id} · [view full recap](https://gdnr.the-company.com/recap)_"
        api.messages.create(roomId=room_id, markdown=footer)
        logger.info(f"Webex summary sent for recap #{recap_id} ({total} chunk(s))")
    except Exception as e:
        logger.warning(f"Webex notification failed (non-fatal): {e}")


# ---------------------------------------------------------------------------
# End-to-end pipeline (called by the job manager worker)
# ---------------------------------------------------------------------------

def run_recap_pipeline(
    audio_path: str,
    meeting_type: str,
    meeting_date: Optional[str] = None,
    attendees: Optional[str] = None,
    language: str = DEFAULT_LANGUAGE,
    generate_video: bool = False,
    progress_callback: Optional[Any] = None,
) -> int:
    """Transcribe -> summarize -> store. Returns the new recap_id.

    Args:
        audio_path: Absolute path to the saved upload (already in data/recaps/audio/).
        meeting_type: 'incident_bridge', 'team_meeting', or 'customer_requirements'.
        meeting_date, attendees: Optional metadata from the upload form.
        language: ISO 639-1 code for the summary output language.
        progress_callback: Optional callable(stage: str) for status updates.

    Returns:
        The id of the inserted recap row.
    """
    def _progress(stage: str):
        logger.info(f"Recap pipeline: {stage}")
        if progress_callback:
            try:
                progress_callback(stage)
            except Exception:
                pass

    if language not in SUPPORTED_LANGUAGES:
        language = DEFAULT_LANGUAGE

    _progress("transcribing")
    transcription = transcribe_audio(audio_path)
    segments = transcription.get("segments", [])
    if not segments:
        raise RuntimeError("Transcription returned no segments")

    _progress("summarizing")
    summary = summarize(segments, meeting_type, language=language)

    _progress("storing")
    recap_id = _insert_recap(
        meeting_type=meeting_type,
        title=summary.get("title", "Untitled meeting"),
        meeting_date=meeting_date,
        attendees=attendees,
        audio_filename=os.path.basename(audio_path),
        audio_path=audio_path,
        transcript_segments=segments,
        summary=summary,
        summary_language=language,
    )
    _notify_webex(summary.get("title", "Untitled meeting"), recap_id, meeting_type, summary)

    if generate_video:
        _progress("generating_video")
        try:
            _build_recap_video(recap_id)
        except Exception as e:
            logger.warning(f"Recap video generation failed for recap {recap_id}: {e}")

    _progress("complete")
    return recap_id


def _build_recap_video(recap_id: int) -> None:
    """Render the narrated slide-deck MP4 for this recap.

    Shells out to demos/videos/recap_from_json/build.py so the video deps
    (Pillow, Kokoro tunnel, ffmpeg) stay out of the web app's hot path.
    Raises on failure — caller decides whether to propagate.
    """
    project_root = Path(__file__).resolve().parents[3]
    build_script = project_root / "demos" / "videos" / "recap_from_json" / "build.py"
    result = subprocess.run(
        [sys.executable, str(build_script), "--recap-id", str(recap_id)],
        cwd=str(build_script.parent),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout)[-800:]
        raise RuntimeError(f"recap video build exited {result.returncode}: {tail}")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _insert_recap(
    meeting_type: str,
    title: str,
    meeting_date: Optional[str],
    attendees: Optional[str],
    audio_filename: str,
    audio_path: str,
    transcript_segments: list[dict],
    summary: dict,
    summary_language: str = DEFAULT_LANGUAGE,
) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO recaps
                (meeting_type, title, meeting_date, attendees, audio_filename,
                 audio_path, transcript_json, summary_json, summary_language)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meeting_type,
                title,
                meeting_date,
                attendees,
                audio_filename,
                audio_path,
                json.dumps(transcript_segments),
                json.dumps(summary, ensure_ascii=False),
                summary_language,
            ),
        )
        conn.commit()
        return cur.lastrowid


def get_recap(recap_id: int) -> Optional[dict]:
    """Fetch a single recap with parsed transcript/summary/speaker_names."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM recaps WHERE id = ?", (recap_id,)).fetchone()
        if not row:
            return None
        return _row_to_dict(row)


def list_recaps(limit: int = 50) -> list[dict]:
    """Return recent recaps (no transcript bodies — list view)."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, meeting_type, title, meeting_date, attendees,
                   audio_filename, created_at, audio_deleted_at
            FROM recaps
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_speaker_names(recap_id: int, mapping: dict[str, str]) -> bool:
    """Save the speaker rename mapping for a recap.

    The mapping is stored as a separate JSON column rather than rewriting the
    transcript so the original SPEAKER_NN labels remain available if the user
    wants to start over.
    """
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE recaps SET speaker_names_json = ? WHERE id = ?",
            (json.dumps(mapping), recap_id),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_recap(recap_id: int) -> bool:
    """Delete a recap and its audio file (if still on disk)."""
    recap = get_recap(recap_id)
    if not recap:
        return False
    audio_path = recap.get("audio_path")
    if audio_path and os.path.exists(audio_path):
        try:
            os.unlink(audio_path)
        except OSError as e:
            logger.warning(f"Could not delete audio file {audio_path}: {e}")
    with _connect() as conn:
        conn.execute("DELETE FROM recaps WHERE id = ?", (recap_id,))
        conn.commit()
    return True


def cleanup_old_audio(retention_days: int = 30) -> dict[str, int]:
    """Delete recap audio files older than retention_days and mark in SQLite.

    Transcripts and summaries are kept forever — only the source audio is removed.
    Called from src/ir_scheduler.py on a daily schedule.

    Returns:
        {"deleted": <count>, "errors": <count>}
    """
    import time as _time
    if not AUDIO_DIR.exists():
        return {"deleted": 0, "errors": 0}

    cutoff = _time.time() - (retention_days * 86400)
    deleted = 0
    errors = 0
    deleted_paths: list[str] = []

    for entry in AUDIO_DIR.iterdir():
        if not entry.is_file():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
                deleted += 1
                deleted_paths.append(str(entry))
        except OSError as e:
            logger.warning(f"Could not delete old recap audio {entry}: {e}")
            errors += 1

    # Mark deleted in SQLite so the UI can show "audio expired"
    if deleted_paths:
        try:
            with _connect() as conn:
                conn.executemany(
                    "UPDATE recaps SET audio_deleted_at = CURRENT_TIMESTAMP WHERE audio_path = ?",
                    [(p,) for p in deleted_paths],
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to mark deleted audio in DB: {e}")
            errors += 1

    logger.info(f"Recap audio cleanup: deleted={deleted}, errors={errors}, retention_days={retention_days}")
    return {"deleted": deleted, "errors": errors}


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a dict, parsing JSON columns."""
    d = dict(row)
    for col in ("transcript_json", "summary_json", "speaker_names_json"):
        if col in d and d[col]:
            try:
                d[col.replace("_json", "")] = json.loads(d[col])
            except json.JSONDecodeError:
                d[col.replace("_json", "")] = None
        else:
            d[col.replace("_json", "")] = None
        d.pop(col, None)
    d["has_video"] = get_recap_video_path(d["id"]).exists()
    return d


def get_recap_video_path(recap_id: int) -> Path:
    """Where the narrated recap MP4 lives on disk. May or may not exist."""
    return (
        Path(__file__).resolve().parents[3]
        / "demos" / "videos" / "recap_from_json" / "output"
        / f"recap_{recap_id}" / f"recap_{recap_id}.mp4"
    )
