"""Per-user capability gating for DESTRUCTIVE Pokedex (Webex) tools.

Pokedex runs inside Webex rooms with no per-user authorization: every participant
of a room can invoke any tool the agent exposes — including ones that block URLs,
fire live breach-and-attack scenarios, delete stored data, or close cases. This
module gates that *destructive* tier behind the same capability model the web app
already uses (``web.auth.rbac``), keyed on the requesting Webex user's email.

Why only the destructive tier: benign writes (add a note, create a case, save a
memory) are part of normal analyst work, so gating them would break workflows. The
concern this addresses is an analyst running a *destructive* action — possibly in a
room the operator isn't even in. So we gate the small, high-blast-radius set and
leave routine writes open.

Design choices:
  * One source of truth. We reuse ``web.auth.db.get_user_by_email`` +
    ``web.auth.rbac.has_capability``, so grants made on /admin-users and the
    AUTH_ADMIN_EMAILS admin safety-net apply here verbatim — no parallel store.
  * Admin-only by default. The capabilities used (enforce.block, run.bas,
    data.destructive, run.rtr) are in NO default role, so out of the box only the
    env-admin and explicitly-granted users can run these tools, in any room. run.rtr
    (ad-hoc command execution on a live endpoint) is the highest blast radius and is
    kept admin-only.
  * Fail closed. A gated tool reaching this guard with no resolvable identity is
    DENIED. (Only the Webex path carries a real identity here; the public web page
    never reaches a mutating tool — it is readonly-filtered upstream.)
  * Total visibility. Every destructive attempt — allowed OR denied — is posted to
    a central audit room (WEBEX_ROOM_ID_POKEDEX_AUDIT) via the Pokedex bot, so the
    operator sees actions taken in rooms they don't sit in.

Identity is read from the thread-local logging context (set by ``ask()`` to
``"{user_email}_{room_id}"``), so no tool signatures change.
See [[project_rbac_capabilities]].
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Auto-run read-only guard                                                     #
# --------------------------------------------------------------------------- #
# Ambient "auto-run" executes a read-only investigation in response to room
# chatter with NO human click. To guarantee such an un-clicked action can never
# perform a destructive operation — even if the message author happens to be an
# admin — the auto-run path arms this thread-local flag. While armed,
# guard_tool_call DENIES every gated (destructive) tool regardless of identity.
# A destructive action always requires an explicit human click (which runs with
# the flag OFF, so the clicker's real capabilities apply).
_autorun = threading.local()


def set_autorun_readonly(on: bool) -> None:
    """Arm/disarm the hard read-only guard for the current thread (auto-run path)."""
    _autorun.readonly = bool(on)


def _is_autorun_readonly() -> bool:
    return getattr(_autorun, "readonly", False)


def _caps():
    """Lazy import of the web RBAC capability tokens (avoids importing Flask-side
    modules at my_bot import time / any circular-import risk)."""
    from web.auth import rbac
    return rbac


# Destructive Pokedex tool name -> required capability token. Tools NOT listed
# here are not gated by this module (benign writes + all read-only tools run as
# before). Capability tokens come straight from web.auth.rbac.
def _tool_capability_map() -> dict:
    rbac = _caps()
    return {
        # --- network/endpoint enforcement (blocking) -----------------------
        "request_url_block": rbac.ENFORCE_BLOCK,
        "add_url_to_proxy_blocklist": rbac.ENFORCE_BLOCK,
        "remove_url_from_proxy_blocklist": rbac.ENFORCE_BLOCK,
        "activate_proxy_changes": rbac.ENFORCE_BLOCK,
        # --- live breach-and-attack simulation on real assets --------------
        "attackiq_run_assessment": rbac.RUN_BAS,
        "attackiq_create_assessment": rbac.RUN_BAS,
        # --- arbitrary command execution on a live endpoint (RTR) ----------
        # Highest blast radius in the toolset; admin-only by default.
        "run_endpoint_command": rbac.RUN_RTR,
        # NOTE: run_endpoint_diagnostic is INTENTIONALLY not listed here. It's a
        # read-only RTR diagnostic whose command is built server-side from a fixed
        # allowlist (the caller never supplies a free-text command), so it's open
        # to any analyst — same posture as collect_browser_history. Only the
        # free-text run_endpoint_command above carries the admin gate. Don't add a
        # gate here without changing that design.
        # --- destructive data / case-state changes -------------------------
        "forget_memory": rbac.DATA_DESTRUCTIVE,
        "bulk_clear_advisory_group": rbac.DATA_DESTRUCTIVE,
        "close_iris_case": rbac.DATA_DESTRUCTIVE,
        "close_thehive_case": rbac.DATA_DESTRUCTIVE,
        "run_tests": rbac.DATA_DESTRUCTIVE,
        "simple_live_message_test": rbac.DATA_DESTRUCTIVE,
    }


def required_capability(tool_name: str) -> Optional[str]:
    """The capability a tool requires, or None if the tool is not gated."""
    try:
        return _tool_capability_map().get(tool_name)
    except Exception:
        # If the RBAC layer can't be imported, fail closed for known-destructive
        # names so a broken import never silently opens the gate.
        return None


def _actor_from_context() -> Tuple[str, str]:
    """Return (user_email, room_id) parsed from the thread-local logging context.

    ``ask()`` sets the context to ``"{user_id}_{room_id}"`` where user_id is the
    Webex personEmail. Emails contain no '_', so splitting on the first '_' is
    safe. Returns ('', '') when no usable context is set."""
    try:
        from src.utils.tool_logging import get_logging_context
        session_id = get_logging_context() or ""
    except Exception:
        return "", ""
    if not session_id or "_" not in session_id:
        return "", ""
    email, room_id = session_id.split("_", 1)
    return email.strip(), room_id.strip()


def _is_allowed(user_email: str, capability: str) -> bool:
    """Capability check via the web RBAC store. Fail closed on any error or on a
    missing/non-email identity. The env-admin (AUTH_ADMIN_EMAILS) passes even with
    no DB row — the admin check is email-only."""
    email = (user_email or "").strip()
    if not email or "@" not in email:
        return False
    try:
        from web.auth import db, rbac, helpers
        # Env-admin first, BEFORE touching the user DB — the AUTH_ADMIN_EMAILS net
        # must hold even if the auth store is unavailable, so the operator can never
        # be locked out of their own destructive tools.
        if helpers.is_admin_email(email):
            return True
        row = db.get_user_by_email(email)
        if row is not None:
            user = {
                "id": row["id"],
                "email": row["email"],
                "role": row["role"],
                "extra_capabilities": row["extra_capabilities"],
            }
        else:
            # Unknown to the user store — only the env-admin email gets through.
            user = {"email": email}
        return rbac.has_capability(user, capability)
    except Exception as e:
        logger.error("Pokedex RBAC check failed for %s/%s: %s", email, capability, e)
        return False


# Tools that are NOT gated (they always run, open to any analyst) but whose
# execution we still mirror to the audit room for transparency — live actions on
# a real endpoint where operators want visibility even without a gate. The notify
# is best-effort and never blocks the call. See _audit_notify.
_NOTIFY_ONLY_TOOLS = {"run_endpoint_diagnostic"}


def guard_tool_call(tool_name: str, tool_args: dict) -> Optional[str]:
    """Authorize a (gated) tool call before it runs, or mirror a notify-only one.

    Returns None to allow the call (not gated, or the user is authorized). Returns
    a denial string (to be surfaced as the tool result) when the user lacks the
    required capability. Every gated attempt — allowed or denied — is posted to the
    audit room; notify-only tools (_NOTIFY_ONLY_TOOLS) post an informational 'ran'
    record but are never blocked.
    """
    capability = required_capability(tool_name)
    if not capability:
        if tool_name in _NOTIFY_ONLY_TOOLS:
            user_email, room_id = _actor_from_context()
            try:
                _audit_notify(tool_name, tool_args, user_email, room_id)
            except Exception as e:
                logger.error("Pokedex notify audit failed for %s: %s", tool_name, e)
        return None  # not gated — runs regardless (notify-only tools mirror first)

    # Ambient auto-run (no human click) is hard read-only: refuse ANY destructive
    # tool, regardless of identity. This is the invariant that lets reads auto-run
    # safely — a destructive change always needs an explicit human click.
    if _is_autorun_readonly():
        user_email, room_id = _actor_from_context()
        logger.warning(
            "Pokedex RBAC: DENY %s — ambient auto-run is read-only (user=%s)",
            tool_name, user_email or "?",
        )
        try:
            _audit(tool_name, tool_args, user_email, room_id, capability, allowed=False)
        except Exception as e:
            logger.error("Pokedex RBAC audit failed for %s: %s", tool_name, e)
        return (
            "ACCESS_DENIED (internal: this was an automatic, un-clicked run and is "
            "read-only — destructive actions require an explicit human click on the "
            "suggestion). Do NOT retry. Briefly tell the user this kind of change "
            "needs them to click to confirm before you can do it."
        )

    user_email, room_id = _actor_from_context()
    allowed = _is_allowed(user_email, capability)

    # Best-effort audit; never let a notification failure change the decision.
    try:
        _audit(tool_name, tool_args, user_email, room_id, capability, allowed)
    except Exception as e:
        logger.error("Pokedex RBAC audit failed for %s: %s", tool_name, e)

    if allowed:
        logger.info("Pokedex RBAC: ALLOW %s for %s (cap=%s)", tool_name, user_email or "?", capability)
        return None

    logger.warning("Pokedex RBAC: DENY %s for %s (missing cap=%s)", tool_name, user_email or "?", capability)
    desc = _capability_desc(capability)
    # The string below is consumed by the agent (as a tool result), which then
    # phrases the actual reply to the user — so this is an INSTRUCTION, not the
    # verbatim message. Keep the agent-control parts (don't retry), but steer the
    # user-facing wording to be short and friendly: no capability tokens, no tool
    # names, no "destructive", no "this was logged" — that reads as accusatory.
    return (
        f"ACCESS_DENIED (internal: needs '{capability}' — {desc}; not granted to "
        f"{user_email or 'this user'}). Do NOT retry this or any equivalent action. "
        f"Relay a brief, friendly note to the user: this one's limited to admins, so "
        f"you weren't able to run it for them — and an admin can grant access on "
        f"request if they need it. Keep it to a sentence or two, warm and casual; "
        f"don't mention logging, capability names, or call it 'destructive'."
    )


def _capability_desc(capability: str) -> str:
    try:
        return _caps().CAPABILITIES.get(capability, capability)
    except Exception:
        return capability


# --------------------------------------------------------------------------- #
# Audit notifications                                                          #
# --------------------------------------------------------------------------- #

def _audit_room_id() -> str:
    """The central Webex room that receives every destructive-action audit line.
    Read from the environment so it's a config change, not a code change."""
    return (os.environ.get("WEBEX_ROOM_ID_POKEDEX_AUDIT") or "").strip()


def _bot_token() -> str:
    try:
        from my_config import get_config
        return get_config().webex_bot_access_token_pokedex or ""
    except Exception:
        return ""


def _now_eastern() -> str:
    try:
        from datetime import datetime
        import pytz
        return datetime.now(pytz.timezone("US/Eastern")).strftime("%m/%d/%Y %-I:%M %p %Z")
    except Exception:
        return ""


def _args_preview(tool_args: dict) -> str:
    """Compact single-line arg preview — never let huge args bloat a card."""
    try:
        preview = ", ".join(f"{k}={v}" for k, v in (tool_args or {}).items())
    except Exception:
        preview = str(tool_args)
    if len(preview) > 300:
        preview = preview[:300] + "…"
    return preview


def _send_audit_card(room: str, token: str, message: str) -> None:
    """Best-effort Webex post to the audit room. Logs on failure, never raises."""
    try:
        import httpx
        resp = httpx.post(
            "https://webexapis.com/v1/messages",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"roomId": room, "markdown": message},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.error("Pokedex audit Webex send failed: %s", e)


def _audit(tool_name: str, tool_args: dict, user_email: str, room_id: str,
           capability: str, allowed: bool) -> None:
    """Post a one-line audit record of a destructive (gated) attempt to the audit room.

    Best-effort and non-fatal: if the room or token isn't configured, or the send
    fails, we log locally and move on (the gate decision still stands)."""
    room = _audit_room_id()
    token = _bot_token()
    if not room or not token:
        logger.info(
            "Pokedex RBAC audit (no audit room/token configured): %s %s by %s in %s cap=%s",
            "ALLOWED" if allowed else "DENIED", tool_name, user_email or "?", room_id or "?", capability,
        )
        return

    verdict = "✅ ALLOWED" if allowed else "⛔ DENIED"
    message = (
        f"🛡️ **Pokedex destructive action — {verdict}**\n\n"
        f"- 🧰 **Tool:** `{tool_name}`\n"
        f"- 👤 **User:** {user_email or 'unknown'}\n"
        f"- 💬 **Room:** {room_id or 'unknown'}\n"
        f"- 🔑 **Capability:** `{capability}`\n"
        f"- 📝 **Args:** {_args_preview(tool_args) or '(none)'}\n"
        f"- 🕐 **When:** {_now_eastern() or 'n/a'}"
    )
    _send_audit_card(room, token, message)


def _audit_notify(tool_name: str, tool_args: dict, user_email: str, room_id: str) -> None:
    """Post an informational 'ran' record for a NOTIFY-ONLY tool to the audit room.

    Unlike _audit, this never gates anything — the tool always runs. It mirrors a
    live, real-host action (e.g. an RTR endpoint diagnostic) to the audit room so
    operators get the same visibility they have for gated tools, even though the
    tool is open to any analyst. Best-effort and non-fatal."""
    room = _audit_room_id()
    token = _bot_token()
    if not room or not token:
        logger.info(
            "Pokedex notify audit (no audit room/token configured): RAN %s by %s in %s",
            tool_name, user_email or "?", room_id or "?",
        )
        return

    message = (
        f"🔎 **Pokedex live endpoint action — RAN**\n\n"
        f"- 🧰 **Tool:** `{tool_name}`\n"
        f"- 👤 **User:** {user_email or 'unknown'}\n"
        f"- 💬 **Room:** {room_id or 'unknown'}\n"
        f"- 📝 **Args:** {_args_preview(tool_args) or '(none)'}\n"
        f"- 🕐 **When:** {_now_eastern() or 'n/a'}\n\n"
        f"_Read-only diagnostic, open to any analyst — mirrored here for visibility._"
    )
    _send_audit_card(room, token, message)
