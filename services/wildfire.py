"""WildFire detonation via XSOAR Prod (XP).

Thin wrapper over the ``WildFire-v2`` integration configured in XP
(``WildFire-v2_instance_1`` — verified live 2026-06-05). Two modes:

  * ``get_verdict(hash)`` — read-only hash-reputation lookup. Instant, submits
    nothing. Used inline on the phishing page for every attachment.
  * ``detonate(bytes, name)`` — uploads the file to a scratch incident, runs
    ``!wildfire-upload``, then polls ``!wildfire-get-verdict`` until the sandbox
    returns a verdict. This DOES submit the sample to the WildFire cloud, so it
    is gated behind an explicit analyst action, never auto-run.

Commands execute in the dedicated mail-robot utility incident (the API-key user
has no playground), the same context ``xsoar_teams`` uses — so we never touch a
live investigation. All calls go through XP only.
"""

from __future__ import annotations

import ast
import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from my_config import get_config
from services.xsoar._client import get_prod_client
from services.xsoar._files import upload_file_to_war_room

logger = logging.getLogger(__name__)

# Scratch execution context — the mail-robot utility incident xsoar_teams uses.
_SCRATCH_INV = "1056832"

# WildFire verdict codes → human label.
VERDICT_LABELS = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    5: "c2",
    -100: "pending",
    -101: "error",
    -102: "not_found",
    -103: "invalid_hash",
}


def _execute(command: str, args: Dict[str, str]) -> List[Dict[str, Any]]:
    """Run an XSOAR command in the scratch incident, return war-room entries.

    demisto-py hands the body back as a Python-repr string (single quotes), so
    we parse with ``ast.literal_eval`` (see reference_xsoar_xp_xd).
    """
    body = {
        "investigationId": _SCRATCH_INV,
        "data": command,
        "args": {k: {"simple": v} for k, v in args.items()},
    }
    data, _status, _ = get_prod_client().generic_request("/entry/execute/sync", "POST", body=body)
    obj = ast.literal_eval(data) if isinstance(data, str) else data
    return obj if isinstance(obj, list) else [obj]


def _entry_ok(entry: Dict[str, Any]) -> bool:
    """type 4 == error entry."""
    return entry.get("type") != 4 and not entry.get("errorSource")


def _parse_verdict_entry(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pull the verdict code out of a wildfire-get-verdict result.

    The integration returns a markdown table; the structured verdict also rides
    in the entry's ``reputations``/context, but parsing the markdown is the most
    robust across versions. Falls back to scanning the text for 'Verdict'.
    """
    for e in entries:
        if not isinstance(e, dict) or not _entry_ok(e):
            continue
        contents = str(e.get("contents") or "")
        # markdown table row: | md5 | sha256 | <code> | <label> |
        for line in contents.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 4 and cells[2].lstrip("-").isdigit():
                code = int(cells[2])
                return {
                    "ok": True,
                    "verdict_code": code,
                    "verdict": VERDICT_LABELS.get(code, str(code)),
                    "md5": cells[0] if cells[0].lower() != "md5" else "",
                    "sha256": cells[1] if cells[1].lower() != "sha256" else "",
                    "raw": contents[:600],
                }
    # No parseable verdict — surface the first error/content for diagnosis.
    msg = ""
    for e in entries:
        if isinstance(e, dict) and e.get("contents"):
            msg = str(e["contents"])[:300]
            break
    return {"ok": False, "verdict_code": None, "verdict": "unknown", "error": msg}


def get_verdict(file_hash: str) -> Dict[str, Any]:
    """Read-only WildFire verdict lookup for an MD5/SHA256. Submits nothing."""
    file_hash = (file_hash or "").strip()
    if not file_hash:
        return {"ok": False, "verdict": "unknown", "error": "empty hash"}
    try:
        entries = _execute("!wildfire-get-verdict", {"hash": file_hash})
        return _parse_verdict_entry(entries)
    except Exception as e:
        logger.warning("WildFire get_verdict failed: %s: %s", type(e).__name__, str(e)[:200])
        return {"ok": False, "verdict": "unknown", "error": f"{type(e).__name__}: {str(e)[:200]}"}


def _upload_entry_id(file_bytes: bytes, filename: str, actor: str = "") -> Optional[str]:
    """Upload bytes to the scratch incident's war room, return the entry ID.

    ``actor`` (the human analyst) is stamped into the comment so the war-room
    entry carries the real identity — the API call itself authenticates as the
    XSOAR service account, so this is the only place the human shows up XSOAR-side.
    """
    cfg = get_config()
    tmp_path = None
    try:
        suffix = os.path.splitext(filename)[1] or ".bin"
        fd, tmp_path = tempfile.mkstemp(prefix="wf_", suffix=suffix)
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)
        comment = f"phishing-tool detonation: {filename}"
        if actor:
            comment += f" (requested by {actor})"
        resp = upload_file_to_war_room(
            base_url=cfg.xsoar_prod_api_base_url,
            auth_key=cfg.xsoar_prod_auth_key,
            auth_id=cfg.xsoar_prod_auth_id,
            incident_id=_SCRATCH_INV,
            file_path=tmp_path,
            comment=comment,
            tags="phishing-attachment",
        )
        # Response shape varies; the file entry id is what wildfire-upload needs.
        if isinstance(resp, dict):
            for k in ("id", "ID", "entryID"):
                if resp.get(k):
                    return str(resp[k])
        if isinstance(resp, list) and resp and isinstance(resp[0], dict):
            return str(resp[0].get("id") or resp[0].get("ID") or "")
        logger.warning("Upload returned unrecognized shape: %s", str(resp)[:300])
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def detonate(file_bytes: bytes, filename: str, poll_seconds: int = 180,
             interval: int = 15, actor: str = "") -> Dict[str, Any]:
    """Submit a file to WildFire and poll for a verdict.

    EXPLICIT action only — this uploads the sample to the WildFire cloud. Returns
    the resolved verdict, or a 'pending' status if the sandbox is still running
    when the poll window expires (the verdict can be fetched later by hash).

    ``actor`` is the human analyst, recorded in the XSOAR war-room comment.
    """
    import hashlib
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    try:
        entry_id = _upload_entry_id(file_bytes, filename, actor=actor)
        if not entry_id:
            return {"ok": False, "status": "error", "error": "Could not upload sample to XSOAR."}

        # Trigger detonation. We poll on our locally-computed SHA256 rather than
        # parsing it back out of the submission response (more robust).
        _execute("!wildfire-upload", {"upload": entry_id})

        deadline = poll_seconds
        waited = 0
        while waited <= deadline:
            v = get_verdict(sha256)
            code = v.get("verdict_code")
            if v.get("ok") and code is not None and code not in (-100,):  # not pending
                v["status"] = "complete"
                v["sha256"] = v.get("sha256") or sha256
                return v
            time.sleep(interval)
            waited += interval
        return {"ok": True, "status": "pending", "sha256": sha256,
                "verdict": "pending",
                "note": "Still detonating — re-check verdict by hash shortly."}
    except Exception as e:
        logger.warning("WildFire detonate failed: %s: %s", type(e).__name__, str(e)[:200])
        return {"ok": False, "status": "error", "error": f"{type(e).__name__}: {str(e)[:200]}"}
