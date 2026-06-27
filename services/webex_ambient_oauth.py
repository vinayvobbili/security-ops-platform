"""Webex OAuth token refresher for the Pokedex ambient READ identity.

Ambient reads group-room traffic with a *service-account* OAuth token
(``spark:messages_read``) — a bot token 403s on group reads (proven 2026-06-24).
OAuth access tokens live ~14 days and refresh tokens ~90 days, and the 90-day
refresh-token clock RESETS on every refresh. So as long as we refresh at least
once per 90 days — the scheduler ticks every 5 minutes — the chain never lapses.
This module mints, caches, and rotates that access token from a stored refresh
token with zero manual intervention after a one-time browser grant.

Bootstrap (one-time, by a human):
  1. Create a Webex Integration at developer.webex.com/my-apps with scopes
     ``spark:messages_read`` + ``spark:rooms_read`` and a capturable redirect URI.
  2. Authorize once in a browser AS the service account → capture the ``?code=``.
  3. Exchange the code for the first refresh token via :func:`exchange_code`.
  4. Put client_id / client_secret / refresh_token in config (env or secrets):
     WEBEX_AMBIENT_OAUTH_CLIENT_ID / _CLIENT_SECRET / _REFRESH_TOKEN.
Thereafter :func:`get_access_token` keeps a live token on its own.

The access token + the rotated refresh token are cached in
``data/transient/webex_ambient_token.json`` (gitignored, chmod 600). The seed
refresh token in config is the fallback if the cached one ever goes stale.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_TOKEN_URL = "https://webexapis.com/v1/access_token"
_CACHE_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "transient" / "webex_ambient_token.json"
)
# Refresh this many seconds BEFORE the access token actually expires so a tick
# never races the expiry boundary.
_EXPIRY_MARGIN = 6 * 3600  # 6h


def _creds() -> tuple[str, str, str]:
    """(client_id, client_secret, refresh_token) from env first, then config."""
    cid = os.getenv("WEBEX_AMBIENT_OAUTH_CLIENT_ID", "").strip()
    secret = os.getenv("WEBEX_AMBIENT_OAUTH_CLIENT_SECRET", "").strip()
    refresh = os.getenv("WEBEX_AMBIENT_OAUTH_REFRESH_TOKEN", "").strip()
    if cid and secret and refresh:
        return cid, secret, refresh
    try:
        from my_config import get_config
        c = get_config()
        cid = cid or (getattr(c, "webex_ambient_oauth_client_id", "") or "")
        secret = secret or (getattr(c, "webex_ambient_oauth_client_secret", "") or "")
        refresh = refresh or (getattr(c, "webex_ambient_oauth_refresh_token", "") or "")
    except Exception:
        pass
    return cid, secret, refresh


def is_configured() -> bool:
    """True only if client id/secret AND a seed refresh token are all present."""
    cid, secret, refresh = _creds()
    return bool(cid and secret and refresh)


def _load_cache() -> dict:
    try:
        return json.loads(_CACHE_PATH.read_text())
    except Exception:
        return {}


def _save_cache(data: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(_CACHE_PATH)
        try:
            _CACHE_PATH.chmod(0o600)
        except OSError:
            pass
    except Exception as e:
        logger.warning(f"[ambient-oauth] could not persist token cache: {e}")


def _post_token(payload: dict) -> Optional[dict]:
    """POST the token endpoint and normalize the response into a cache dict."""
    try:
        resp = requests.post(_TOKEN_URL, data=payload, timeout=30)
    except requests.RequestException as e:
        logger.warning(f"[ambient-oauth] token request failed: {e}")
        return None
    if resp.status_code != 200:
        logger.warning(f"[ambient-oauth] token HTTP {resp.status_code}: {resp.text[:200]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        logger.warning("[ambient-oauth] token response was not JSON")
        return None
    now = time.time()
    return {
        "access_token": body.get("access_token", ""),
        "access_expires_at": now + int(body.get("expires_in", 0) or 0),
        # Webex returns a refresh token here too; persist it (its clock resets).
        "refresh_token": body.get("refresh_token") or payload.get("refresh_token", ""),
        "refresh_expires_at": now + int(body.get("refresh_token_expires_in", 0) or 0),
        "obtained_at": now,
    }


def _refresh(client_id: str, client_secret: str, refresh_token: str) -> Optional[dict]:
    cache = _post_token(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        }
    )
    if cache and cache.get("access_token"):
        _save_cache(cache)
        hrs = int((cache["access_expires_at"] - time.time()) // 3600)
        logger.info(f"[ambient-oauth] minted fresh access token (valid ~{hrs}h)")
        return cache
    return None


def get_access_token(force: bool = False) -> str:
    """Return a valid access token, refreshing if stale. '' if unconfigured.

    Uses the cached token while it's comfortably unexpired; otherwise refreshes,
    preferring the rotated refresh token in the cache and falling back to the
    seed refresh token from config if the cached one is rejected.
    """
    cid, secret, seed_refresh = _creds()
    if not (cid and secret and seed_refresh):
        return ""
    cache = _load_cache()
    tok = cache.get("access_token", "")
    exp = float(cache.get("access_expires_at", 0) or 0)
    if not force and tok and (exp - _EXPIRY_MARGIN) > time.time():
        return tok
    refresh_token = cache.get("refresh_token") or seed_refresh
    refreshed = _refresh(cid, secret, refresh_token)
    if refreshed is None and refresh_token != seed_refresh:
        # Cached refresh token may be stale — retry once with the config seed.
        logger.info("[ambient-oauth] cached refresh token failed; retrying with seed")
        refreshed = _refresh(cid, secret, seed_refresh)
    return refreshed.get("access_token", "") if refreshed else ""


def exchange_code(code: str, redirect_uri: str) -> Optional[dict]:
    """One-time bootstrap: exchange an authorization code for the first token pair.

    Persists the cache and returns it so the ``refresh_token`` can be copied into
    config. Not used by the runtime path — only when standing up the integration.
    """
    cid, secret, _ = _creds()
    if not (cid and secret):
        logger.warning("[ambient-oauth] client id/secret not configured")
        return None
    cache = _post_token(
        {
            "grant_type": "authorization_code",
            "client_id": cid,
            "client_secret": secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
    )
    if cache and cache.get("access_token"):
        _save_cache(cache)
        return cache
    return None
