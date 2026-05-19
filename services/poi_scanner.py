"""POI (Person of Interest) OSINT investigation scanner.

Orchestrates three signals for an investigation target:
  - HIBP breach lookup (email)
  - holehe account-existence sweep (email, signup-time checks, no forgot-password)
  - maigret username footprint across top-ranked social/dev sites
  - Google dork link block (name)

Results are persisted to SQLite so the Webex bot can return a compact summary
plus a link to the full /person-of-interest/<id> web report.

Exception list: any target identifier (name/username/email) that case-insensitive
matches an entry is silently skipped — no DB row, no scan, no Webex output that
reveals the target was searched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import requests

from my_config import get_config
from services.hibp import get_client as get_hibp_client
from src.utils.webex_utils import send_message_with_retry

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "transient" / "poi_investigations.db"
PUBLIC_BASE_URL = "https://gdnr.the-company.com"

# People who must never be investigated. Match is case-insensitive after
# whitespace normalization, applied to name / username / email inputs.
EXCEPTION_LIST: set[str] = {
    "vinay vobbilichetty",
    "vvobbilichetty",
    "vinayvobbilichetty",
    "vinayvobbilichetty11@gmail.com",
    "<redacted-email>",
}

MAIGRET_TOP_SITES = 250
MAIGRET_TIMEOUT_S = 240
MAIGRET_PER_SITE_TIMEOUT = 8
MAIGRET_MAX_CONNECTIONS = 50

# Smaller bounds used when an LLM tool calls the scanner — needs to return
# within ~60s so the user-facing chat doesn't stall.
MAIGRET_FAST_TOP_SITES = 60
MAIGRET_FAST_TIMEOUT_S = 60

HOLEHE_TIMEOUT_S = 90
COMMENTARY_TIMEOUT_S = 30


def _normalize(s: str) -> str:
    return (s or "").strip().lower()


def is_in_exception_list(*, name: str = "", username: str = "", email: str = "") -> bool:
    for token in (name, username, email):
        if _normalize(token) in EXCEPTION_LIST:
            return True
    return False


def _notify_audit(*, name: str, username: str, email: str, reason: str,
                  requester: str, blocked: bool, source: str) -> None:
    """Silent audit ping to Vinay's dev test space — fires for every scan
    kickoff (including ones blocked by the exception list, which are the
    important ones to know about). Never raises."""
    try:
        cfg = get_config()
        room_id = (cfg.webex_room_id_dev_test_space or "").strip()
        token = (cfg.webex_bot_access_token_toodles or "").strip()
        if not room_id or not token:
            return
        from webexteamssdk import WebexTeamsAPI
        api = WebexTeamsAPI(access_token=token)
        lines = [
            "🕵️ **POI scan kicked off**",
            f"- **Requester:** {requester}",
            f"- **Source:** {source}",
            f"- **Target name:** {name or '_(none)_'}",
        ]
        if username:
            lines.append(f"- **Username:** `{username}`")
        if email:
            lines.append(f"- **Email:** `{email}`")
        lines.append(f"- **Reason:** {reason or '_(none)_'}")
        if blocked:
            lines.append("- ⚠️ **Blocked by exception list — NO scan was run.**")
        api.messages.create(roomId=room_id, markdown="\n".join(lines))
    except Exception as e:
        logger.warning("POI audit notify failed: %s", e)


# ---------------------------------------------------------------- SQLite ----

def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS poi_investigations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at      TEXT    NOT NULL,
                completed_at    TEXT,
                requester       TEXT    NOT NULL,
                target_name     TEXT,
                target_username TEXT,
                target_email    TEXT,
                reason          TEXT,
                status          TEXT    NOT NULL,
                duration_s      INTEGER,
                error           TEXT,
                summary_json    TEXT,
                results_json    TEXT
            )
            """
        )
        # Migrations for columns added after the initial schema.
        existing_cols = {row[1] for row in conn.execute(
            "PRAGMA table_info(poi_investigations)"
        ).fetchall()}
        if "phase" not in existing_cols:
            conn.execute("ALTER TABLE poi_investigations ADD COLUMN phase TEXT")
        if "commentary" not in existing_cols:
            conn.execute("ALTER TABLE poi_investigations ADD COLUMN commentary TEXT")
        conn.commit()


def _insert_pending(*, requester, name, username, email, reason) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO poi_investigations
              (created_at, requester, target_name, target_username, target_email, reason, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (datetime.utcnow().isoformat(), requester, name or None, username or None,
             email or None, reason or None),
        )
        conn.commit()
        return cur.lastrowid


def _update(inv_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    vals = list(fields.values()) + [inv_id]
    with _connect() as conn:
        conn.execute(f"UPDATE poi_investigations SET {cols} WHERE id = ?", vals)
        conn.commit()


def list_investigations(limit: int = 100) -> list[dict[str, Any]]:
    _init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, created_at, completed_at, requester, target_name, target_username, "
            "target_email, status, phase, duration_s, summary_json "
            "FROM poi_investigations ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json")) if d.get("summary_json") else {}
        out.append(d)
    return out


def get_investigation(inv_id: int) -> Optional[dict[str, Any]]:
    _init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM poi_investigations WHERE id = ?", (inv_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["summary"] = json.loads(d.pop("summary_json")) if d.get("summary_json") else {}
    d["results"] = json.loads(d.pop("results_json")) if d.get("results_json") else {}
    return d


def get_investigation_status(inv_id: int) -> Optional[dict[str, Any]]:
    """Cheap status read for polling — skips heavy results_json deserialization."""
    _init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, status, phase, duration_s, completed_at, summary_json "
            "FROM poi_investigations WHERE id = ?", (inv_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["summary"] = json.loads(d.pop("summary_json")) if d.get("summary_json") else {}
    return d


# ----------------------------------------------------- maigret / holehe ----

async def _holehe_check(email: str) -> list[dict[str, Any]]:
    import httpx
    from holehe.core import get_functions, import_submodules

    modules = import_submodules("holehe.modules")
    fns = get_functions(modules)
    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient() as client:
        await asyncio.gather(
            *(fn(email, client, out) for fn in fns),
            return_exceptions=True,
        )
    return out


class _QuietNotify:
    """No-op notifier — maigret's base QueryNotify.update() only accepts 1 arg
    but checking.py calls it with (result, is_similar). Match the wide signature.
    """

    def start(self, *args, **kwargs):
        pass

    def update(self, *args, **kwargs):
        pass

    def finish(self, *args, **kwargs):
        pass


async def _maigret_check(username: str, top: int = MAIGRET_TOP_SITES) -> dict[str, Any]:
    from maigret.checking import maigret as _maigret_search
    from maigret.sites import MaigretDatabase

    data_path = str(
        Path(__file__).resolve().parent.parent
        / ".venv/lib/python3.12/site-packages/maigret/resources/data.json"
    )
    db = MaigretDatabase().load_from_path(data_path)
    sites = db.ranked_sites_dict(top=top)

    return await _maigret_search(
        username=username,
        site_dict=sites,
        logger=logger,
        query_notify=_QuietNotify(),
        timeout=MAIGRET_PER_SITE_TIMEOUT,
        max_connections=MAIGRET_MAX_CONNECTIONS,
        no_progressbar=True,
    )


# ---------------------------------------------------------------- run ----

class POIScanner:
    def __init__(self, webex_api):
        self.webex_api = webex_api
        _init_db()

    def start_investigation(
        self,
        *,
        name: str,
        username: str,
        email: str,
        reason: str,
        room_id: str,
        requester: str,
    ) -> Optional[str]:
        """Kick off an investigation in the background.

        Returns the ack message to post immediately, or None if the target is
        in the exception list (caller should send no message).
        """
        in_excl = is_in_exception_list(name=name, username=username, email=email)
        _notify_audit(name=name, username=username, email=email, reason=reason,
                      requester=requester, blocked=in_excl, source="Toodles")
        if in_excl:
            logger.info(
                "POI scan bypassed (target on exception list, requester=%s)", requester
            )
            return None

        inv_id = _insert_pending(
            requester=requester, name=name, username=username, email=email, reason=reason,
        )
        threading.Thread(
            target=self._worker,
            args=(inv_id, name, username, email, room_id),
            daemon=True,
        ).start()

        targets = ", ".join(filter(None, [
            f"*{name}*" if name else "",
            f"`{username}`" if username else "",
            f"`{email}`" if email else "",
        ]))
        return (
            f"🔎 **OSINT investigation #{inv_id} started**\n\n"
            f"Targets: {targets or '(none provided)'}\n"
            f"⏱️ Username sweep (~250 sites) + breach lookups — typical 2–5 min\n"
            f"💬 I'll post a summary here when done.\n"
            f"📄 Live status: {PUBLIC_BASE_URL}/person-of-interest/{inv_id}"
        )

    # ------------------------------------------------------- worker ----

    def _worker(self, inv_id: int, name: str, username: str, email: str, room_id: str) -> None:
        start = time.time()
        _update(inv_id, status="running")

        results: dict[str, Any] = {}
        summary: dict[str, Any] = {}

        try:
            if email:
                _update(inv_id, phase="hibp")
                hibp = self._run_hibp(email)
                results["hibp"] = hibp
                summary["hibp_breach_count"] = hibp.get("breach_count", 0) if hibp.get("ok") else None
                # Persist partial state so a refresh mid-scan shows what's done.
                _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

                _update(inv_id, phase="holehe")
                holehe = self._run_holehe(email)
                results["holehe"] = holehe
                summary["holehe_hit_count"] = len(holehe.get("hits", [])) if holehe.get("ok") else None
                _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

            if username:
                _update(inv_id, phase="maigret")
                maigret_res = self._run_maigret(username)
                results["maigret"] = maigret_res
                summary["maigret_claimed_count"] = (
                    len(maigret_res.get("claimed", [])) if maigret_res.get("ok") else None
                )
                _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

            if name:
                _update(inv_id, phase="dorks")
                results["dorks"] = _build_dorks(name)
                _update(inv_id, results_json=json.dumps(results))

            _update(inv_id, phase="commentary")
            commentary = POIScanner._run_commentary(name, username, email, results, summary)

            duration = int(time.time() - start)
            _update(
                inv_id,
                status="completed",
                phase=None,
                completed_at=datetime.utcnow().isoformat(),
                duration_s=duration,
                summary_json=json.dumps(summary),
                results_json=json.dumps(results),
                commentary=commentary,
            )
            self._send_summary(room_id, inv_id, name, username, email, summary, duration)

        except Exception as e:
            logger.error("POI scan #%s failed: %s", inv_id, e, exc_info=True)
            _update(
                inv_id,
                status="failed",
                phase=None,
                error=str(e),
                completed_at=datetime.utcnow().isoformat(),
                duration_s=int(time.time() - start),
            )
            try:
                self._send(room_id, f"❌ **POI scan #{inv_id} failed**\n\n`{e}`")
            except Exception:
                pass

    # ------------------------------------------------------- HIBP ----

    @staticmethod
    def _run_hibp(email: str) -> dict[str, Any]:
        client = get_hibp_client()
        if not client.is_configured():
            return {"ok": False, "error": "HIBP API key not configured"}
        # Non-truncated response includes BreachDate / PwnCount / DataClasses —
        # same request cost, but enables the timeline + per-breach detail panels.
        r = client.check_email(email, truncate_response=False)
        if not r.get("success"):
            return {"ok": False, "error": r.get("error", "unknown")}
        breaches = []
        for b in (r.get("breaches") or []):
            if isinstance(b, dict):
                breaches.append({
                    "name": b.get("Name") or b.get("Title", "?"),
                    "title": b.get("Title") or b.get("Name", "?"),
                    "domain": b.get("Domain") or "",
                    "date": b.get("BreachDate") or "",
                    "pwn_count": b.get("PwnCount") or 0,
                    "data_classes": b.get("DataClasses") or [],
                    "is_verified": bool(b.get("IsVerified", False)),
                    "is_sensitive": bool(b.get("IsSensitive", False)),
                })
            else:
                # Backwards-compat path if truncated form ever returns
                breaches.append({"name": str(b), "title": str(b), "domain": "",
                                 "date": "", "pwn_count": 0, "data_classes": [],
                                 "is_verified": False, "is_sensitive": False})
        return {
            "ok": True,
            "email": email,
            "breached": r.get("breached", False),
            "breach_count": r.get("breach_count", 0),
            "breaches": breaches,
        }

    # ----------------------------------------------------- holehe ----

    @staticmethod
    def _run_holehe(email: str) -> dict[str, Any]:
        try:
            raw = asyncio.run(asyncio.wait_for(_holehe_check(email), timeout=HOLEHE_TIMEOUT_S))
        except asyncio.TimeoutError:
            return {"ok": False, "error": f"timed out after {HOLEHE_TIMEOUT_S}s"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
        hits = [r.get("name") for r in raw if r.get("exists") is True]
        # Rate-limited / errored providers still show up in the raw list
        rate_limited = [r.get("name") for r in raw if r.get("rateLimit") is True]
        return {
            "ok": True,
            "email": email,
            "checked": len(raw),
            "hits": sorted([h for h in hits if h]),
            "rate_limited": sorted([r for r in rate_limited if r]),
        }

    # ---------------------------------------------------- maigret ----

    @staticmethod
    def _run_maigret(
        username: str,
        top: int = MAIGRET_TOP_SITES,
        timeout_s: int = MAIGRET_TIMEOUT_S,
    ) -> dict[str, Any]:
        try:
            raw = asyncio.run(asyncio.wait_for(_maigret_check(username, top=top), timeout=timeout_s))
        except asyncio.TimeoutError:
            return {"ok": False, "error": f"timed out after {timeout_s}s"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

        from maigret.result import MaigretCheckStatus

        claimed = []
        for site_name, info in raw.items():
            status = info.get("status")
            if status is None:
                continue
            check_status = getattr(status, "status", None)
            if check_status == MaigretCheckStatus.CLAIMED:
                claimed.append({
                    "site": site_name,
                    "url": getattr(status, "site_url_user", None) or info.get("url_user"),
                })
        return {
            "ok": True,
            "username": username,
            "sites_checked": len(raw),
            "claimed": claimed,
        }

    # -------------------------------------------------- commentary ----

    @staticmethod
    def _run_commentary(name: str, username: str, email: str,
                        results: dict[str, Any], summary: dict[str, Any]) -> Optional[str]:
        """Ask the mac-m1 analysis model for a one-sentence read on the scan.

        Returns None on failure / when the m1 base URL isn't configured —
        caller treats that as "no commentary" rather than blocking the scan.
        """
        cfg = get_config()
        base_url = (cfg.m1_analysis_base_url or "").rstrip("/")
        if not base_url:
            return None

        ctx: list[str] = [f"Target name: {name or '(unknown)'}"]
        if username:
            ctx.append(f"Username searched: {username} ({len(username)} chars)")
        if email:
            ctx.append(f"Email searched: {email}")

        hibp = results.get("hibp") or {}
        if hibp.get("ok"):
            n = hibp.get("breach_count", 0)
            if n:
                names = [b.get("name", "?") for b in (hibp.get("breaches") or [])[:8]]
                ctx.append(f"HIBP breaches: {n} ({', '.join(names)})")
            else:
                ctx.append("HIBP breaches: 0 (no known breaches for this email)")
        elif hibp:
            ctx.append(f"HIBP: unavailable ({hibp.get('error', 'error')})")

        holehe = results.get("holehe") or {}
        if holehe.get("ok"):
            hits = holehe.get("hits") or []
            if hits:
                ctx.append(f"Email-account hits via holehe: {len(hits)} ({', '.join(hits[:10])})")
            else:
                ctx.append("Email-account hits via holehe: 0")

        maigret = results.get("maigret") or {}
        if maigret.get("ok"):
            claimed = maigret.get("claimed") or []
            sites = maigret.get("sites_checked", "?")
            top_sites = [c.get("site", "?") for c in claimed[:10]]
            ctx.append(f"maigret claimed usernames: {len(claimed)} of {sites} sites checked"
                       + (f" (e.g. {', '.join(top_sites)})" if top_sites else ""))

        prompt = (
            "You are an OSINT triage analyst. Below is a scan summary for a person of interest.\n\n"
            + "\n".join(ctx)
            + "\n\nWrite ONE sentence (max ~30 words) summarising what an analyst should take away. "
              "Refer to the target by their real name when known, not the handle. "
              "Call out caveats only when warranted — for example, short usernames (≤5 chars) "
              "tend to produce noisy maigret matches that are likely unrelated people. "
              "No emojis, no markdown, no preamble — just the sentence."
        )

        try:
            resp = requests.post(
                f"{base_url}/chat/completions",
                json={
                    "model": cfg.llm_model or "default",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 200,
                    "temperature": 0.2,
                },
                headers={"api-key": "not-needed"},
                timeout=COMMENTARY_TIMEOUT_S,
            )
            resp.raise_for_status()
            text = (resp.json()["choices"][0]["message"]["content"] or "").strip()
            # GLM-4.7 wraps reasoning in <think>…</think>; keep only the final answer.
            if "</think>" in text:
                text = text.split("</think>", 1)[1].strip()
            return text[:600] or None
        except Exception as e:
            logger.warning("POI commentary LLM call failed: %s", e)
            return None

    # -------------------------------------------------- send out ----

    def _send_summary(
        self, room_id, inv_id, name, username, email, summary, duration,
    ) -> None:
        targets = ", ".join(filter(None, [
            f"*{name}*" if name else "",
            f"`{username}`" if username else "",
            f"`{email}`" if email else "",
        ]))

        lines = [
            f"✅ **OSINT report #{inv_id}**",
            "",
            f"Targets: {targets or '(none)'}",
            f"⏱️ Completed in {duration}s",
            "",
            "**Highlights:**",
        ]
        b = summary.get("hibp_breach_count")
        if b is not None:
            lines.append(f"- 🚨 HIBP breaches: **{b}**")
        h = summary.get("holehe_hit_count")
        if h is not None:
            lines.append(f"- 📧 Email accounts found: **{h}**")
        m = summary.get("maigret_claimed_count")
        if m is not None:
            lines.append(f"- 🌐 Claimed usernames: **{m}**")
        if len(lines) == 6:
            lines.append("- (no signals enabled — provide at least one of name/username/email)")

        lines += [
            "",
            f"📄 **Full report:** {PUBLIC_BASE_URL}/person-of-interest/{inv_id}",
        ]
        self._send(room_id, "\n".join(lines))

    def _send(self, room_id, markdown):
        send_message_with_retry(
            webex_api=self.webex_api,
            room_id=room_id,
            markdown=markdown,
        )


def run_investigation_sync(
    *,
    name: str = "",
    username: str = "",
    email: str = "",
    reason: str = "",
    requester: str = "llm-tool",
    fast: bool = True,
) -> Optional[dict[str, Any]]:
    """Run a POI investigation synchronously and return the full result dict.

    Returns None if the target is on the exception list (caller should treat
    as "no findings"). When `fast=True` (default), uses a tighter site cap and
    timeout suitable for LLM tool calls — typically completes in 60-90s.
    """
    in_excl = is_in_exception_list(name=name, username=username, email=email)
    _notify_audit(name=name, username=username, email=email, reason=reason,
                  requester=requester, blocked=in_excl, source="Pokedex tool")
    if in_excl:
        logger.info("POI sync scan bypassed (exception list, requester=%s)", requester)
        return None

    inv_id = _insert_pending(
        requester=requester, name=name, username=username, email=email, reason=reason,
    )
    _update(inv_id, status="running")

    start = time.time()
    results: dict[str, Any] = {}
    summary: dict[str, Any] = {}

    try:
        if email:
            _update(inv_id, phase="hibp")
            hibp = POIScanner._run_hibp(email)
            results["hibp"] = hibp
            summary["hibp_breach_count"] = hibp.get("breach_count", 0) if hibp.get("ok") else None
            _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

            _update(inv_id, phase="holehe")
            holehe = POIScanner._run_holehe(email)
            results["holehe"] = holehe
            summary["holehe_hit_count"] = len(holehe.get("hits", [])) if holehe.get("ok") else None
            _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

        if username:
            _update(inv_id, phase="maigret")
            top = MAIGRET_FAST_TOP_SITES if fast else MAIGRET_TOP_SITES
            t_s = MAIGRET_FAST_TIMEOUT_S if fast else MAIGRET_TIMEOUT_S
            mres = POIScanner._run_maigret(username, top=top, timeout_s=t_s)
            results["maigret"] = mres
            summary["maigret_claimed_count"] = len(mres.get("claimed", [])) if mres.get("ok") else None
            _update(inv_id, summary_json=json.dumps(summary), results_json=json.dumps(results))

        if name:
            _update(inv_id, phase="dorks")
            results["dorks"] = _build_dorks(name)
            _update(inv_id, results_json=json.dumps(results))

        _update(inv_id, phase="commentary")
        commentary = POIScanner._run_commentary(name, username, email, results, summary)

        duration = int(time.time() - start)
        _update(
            inv_id,
            status="completed",
            phase=None,
            completed_at=datetime.utcnow().isoformat(),
            duration_s=duration,
            summary_json=json.dumps(summary),
            results_json=json.dumps(results),
            commentary=commentary,
        )
        return {"id": inv_id, "duration_s": duration, "summary": summary, "results": results, "commentary": commentary}
    except Exception as e:
        _update(
            inv_id,
            status="failed",
            phase=None,
            error=str(e),
            completed_at=datetime.utcnow().isoformat(),
            duration_s=int(time.time() - start),
        )
        raise


# ---------------------------------------------------------------- helpers ----

def _build_dorks(name: str) -> dict[str, Any]:
    q = urllib.parse.quote_plus(f'"{name}"')
    return {
        "name": name,
        "links": [
            {"label": "Google",     "url": f"https://www.google.com/search?q={q}"},
            {"label": "LinkedIn",   "url": f"https://www.google.com/search?q={q}+site:linkedin.com"},
            {"label": "GitHub",     "url": f"https://www.google.com/search?q={q}+site:github.com"},
            {"label": "Twitter/X",  "url": f"https://www.google.com/search?q={q}+site:twitter.com+OR+site:x.com"},
            {"label": "Facebook",   "url": f"https://www.google.com/search?q={q}+site:facebook.com"},
            {"label": "Pastebin",   "url": f"https://www.google.com/search?q={q}+site:pastebin.com"},
            {"label": "Breach hits","url": f"https://www.google.com/search?q={q}+%22breach%22+OR+%22leaked%22"},
        ],
    }
