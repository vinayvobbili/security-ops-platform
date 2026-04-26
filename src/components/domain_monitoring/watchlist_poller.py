"""Lightweight domain watchlist poller for near-real-time monitoring.

Runs every 5 minutes (via scheduler) and checks DNS, HTTP reachability, and SSL
fingerprints for high-priority suspicious domains. Alerts on changes via Webex
adaptive card. Much lighter than the daily full monitoring pipeline (no dnstwist,
VT, Shodan, HIBP, etc.).

Usage:
    from src.components.domain_monitoring.watchlist_poller import poll_watchlist
    poll_watchlist()  # first run seeds baseline silently
"""

import hashlib
import json
import logging
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests

from .config import (
    ENABLE_REALTIME_WATCHLIST,
    EASTERN_TZ,
    CONFIG_FILE,
    RESULTS_DIR,
    get_webex_api,
    get_active_room_id,
)
from .card_helpers import get_container_style, send_adaptive_card
from src.utils.webex_utils import send_card_with_retry

from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, ColumnSet, Column, Container, options,
    HorizontalAlignment,
)

logger = logging.getLogger(__name__)

STATE_FILE = RESULTS_DIR / "watchlist_state.json"


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def _resolve_dns(domain: str) -> dict:
    """Resolve A, AAAA, MX, and NS records via dig.

    Filters out dig diagnostic/error lines (starting with ';;') so that
    transient DNS resolver failures don't get stored as fake records and
    trigger false-positive change alerts.  When dig fails entirely, the
    record type is set to None (unknown) rather than [] (confirmed empty)
    so the differ can distinguish 'no records' from 'lookup failed'.
    """
    result = {}
    for rtype in ("A", "AAAA", "MX", "NS"):
        try:
            proc = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=10,
            )
            lines = sorted(
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip() and not line.strip().startswith(";;")
            )
            # Non-zero exit or stderr with no valid lines → treat as failed lookup
            if proc.returncode != 0 or (not lines and proc.stderr.strip()):
                logger.debug(f"dig {rtype} for {domain} failed: {proc.stderr.strip()}")
                result[rtype] = None  # unknown — don't diff against this
            else:
                result[rtype] = lines
        except (subprocess.TimeoutExpired, FileNotFoundError):
            result[rtype] = None  # unknown
    return result


# ---------------------------------------------------------------------------
# HTTP reachability
# ---------------------------------------------------------------------------

def _check_http(domain: str) -> dict:
    """HEAD request — try HTTPS first, fall back to HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.head(url, timeout=8, allow_redirects=True, verify=False)
            return {
                "reachable": True,
                "scheme": scheme,
                "status_code": resp.status_code,
                "redirect_url": resp.url if resp.url != url else None,
            }
        except requests.RequestException:
            continue
    return {"reachable": False, "scheme": None, "status_code": None, "redirect_url": None}


# ---------------------------------------------------------------------------
# SSL fingerprint
# ---------------------------------------------------------------------------

def _get_ssl_fingerprint(domain: str) -> str | None:
    """Connect to port 443 and return SHA-256 fingerprint of the leaf cert."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    return hashlib.sha256(der).hexdigest()
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Combined per-domain check
# ---------------------------------------------------------------------------

def _check_domain(domain: str) -> dict:
    """Run all lightweight checks for a single domain."""
    dns = _resolve_dns(domain)
    http = _check_http(domain)
    ssl_fp = _get_ssl_fingerprint(domain)
    return {
        "domain": domain,
        "dns": dns,
        "http": http,
        "ssl_fingerprint": ssl_fp,
        "checked_at": datetime.now(EASTERN_TZ).isoformat(),
    }


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    """Load the previous baseline from disk."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load watchlist state: {e}")
    return {}


def _save_state(state: dict) -> None:
    """Persist the current baseline to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------

def _diff_domain(domain: str, current: dict, previous: dict) -> list[dict]:
    """Compare current snapshot to previous and return a list of changes."""
    changes = []

    # DNS record changes — skip when either side is None (lookup failed)
    for rtype in ("A", "AAAA", "MX", "NS"):
        cur_raw = current.get("dns", {}).get(rtype)
        prev_raw = previous.get("dns", {}).get(rtype)
        if cur_raw is None or prev_raw is None:
            continue  # can't compare — one side had a DNS resolution error
        cur_records = set(cur_raw)
        prev_records = set(prev_raw)
        if cur_records != prev_records:
            added = cur_records - prev_records
            removed = prev_records - cur_records
            changes.append({
                "type": f"dns_{rtype.lower()}",
                "label": f"DNS {rtype} changed",
                "previous": sorted(prev_records),
                "current": sorted(cur_records),
                "added": sorted(added),
                "removed": sorted(removed),
            })

    # HTTP reachability
    prev_reachable = previous.get("http", {}).get("reachable", False)
    cur_reachable = current.get("http", {}).get("reachable", False)
    if cur_reachable and not prev_reachable:
        changes.append({
            "type": "http_now_live",
            "label": "Domain is now LIVE",
            "previous": "unreachable",
            "current": f"{current['http']['scheme']}://{domain} → {current['http']['status_code']}",
        })
    elif not cur_reachable and prev_reachable:
        changes.append({
            "type": "http_now_down",
            "label": "Domain is now DOWN",
            "previous": f"{previous['http'].get('scheme')}://{domain}",
            "current": "unreachable",
        })

    # HTTP status code change (while still reachable)
    if cur_reachable and prev_reachable:
        prev_status = previous.get("http", {}).get("status_code")
        cur_status = current.get("http", {}).get("status_code")
        if prev_status != cur_status:
            changes.append({
                "type": "http_status_change",
                "label": "HTTP status changed",
                "previous": str(prev_status),
                "current": str(cur_status),
            })

        # Redirect URL change
        prev_redir = previous.get("http", {}).get("redirect_url")
        cur_redir = current.get("http", {}).get("redirect_url")
        if prev_redir != cur_redir and (prev_redir or cur_redir):
            changes.append({
                "type": "http_redirect_change",
                "label": "Redirect target changed",
                "previous": prev_redir or "(none)",
                "current": cur_redir or "(none)",
            })

    # SSL certificate fingerprint
    prev_ssl = previous.get("ssl_fingerprint")
    cur_ssl = current.get("ssl_fingerprint")
    if prev_ssl and cur_ssl and prev_ssl != cur_ssl:
        changes.append({
            "type": "ssl_cert_change",
            "label": "SSL certificate changed",
            "previous": prev_ssl[:16] + "...",
            "current": cur_ssl[:16] + "...",
        })
    elif cur_ssl and not prev_ssl:
        changes.append({
            "type": "ssl_cert_new",
            "label": "SSL certificate appeared",
            "previous": "(none)",
            "current": cur_ssl[:16] + "...",
        })

    return changes


# ---------------------------------------------------------------------------
# Webex alert card
# ---------------------------------------------------------------------------

def _send_changes_card(all_changes: dict[str, list[dict]]) -> None:
    """Send a Webex adaptive card summarizing detected changes."""
    timestamp = datetime.now(EASTERN_TZ).strftime("%Y-%m-%d %I:%M %p %Z")
    total = sum(len(c) for c in all_changes.values())

    body = [
        TextBlock(
            text="⚡ Watchlist Domain Change Detected",
            size=options.FontSize.LARGE,
            weight=options.FontWeight.BOLDER,
            color=options.Colors.ATTENTION,
        ),
        TextBlock(
            text=f"{total} change(s) across {len(all_changes)} domain(s) — {timestamp}",
            size=options.FontSize.SMALL,
            isSubtle=True,
        ),
    ]

    for domain, changes in all_changes.items():
        body.append(Container(items=[
            TextBlock(
                text=domain,
                weight=options.FontWeight.BOLDER,
                size=options.FontSize.MEDIUM,
            ),
        ]))
        for change in changes:
            body.append(ColumnSet(columns=[
                Column(width="1", items=[
                    TextBlock(text=change["label"], weight=options.FontWeight.BOLDER,
                              size=options.FontSize.SMALL),
                ]),
                Column(width="2", items=[
                    TextBlock(
                        text=f"{change.get('previous', '')}  →  {change.get('current', '')}",
                        size=options.FontSize.SMALL,
                        wrap=True,
                    ),
                ]),
            ]))

    card = AdaptiveCard(body=body)

    fallback_lines = [f"⚡ Watchlist Domain Change Detected — {timestamp}"]
    for domain, changes in all_changes.items():
        for change in changes:
            fallback_lines.append(
                f"- **{domain}**: {change['label']} — {change.get('previous', '')} → {change.get('current', '')}"
            )
    fallback_text = "\n".join(fallback_lines)

    try:
        webex_api = get_webex_api()
        send_adaptive_card(webex_api, card, fallback_text)
    except Exception as e:
        logger.error(f"Failed to send watchlist change card: {e}")


# ---------------------------------------------------------------------------
# Watchlist management (called by bot command handler)
# ---------------------------------------------------------------------------

def remove_watchlist_domain(domain: str) -> str:
    """Remove a domain from the realtime watchlist and its persisted state.

    Returns a user-facing status message.
    """
    if not CONFIG_FILE.exists():
        return f"Config file not found — cannot remove **{domain}**."

    try:
        config = json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, IOError) as e:
        return f"Failed to read config: {e}"

    watchlist = config.get("realtime_watchlist", [])
    if domain not in watchlist:
        return f"**{domain}** is not in the watchlist."

    watchlist.remove(domain)
    config["realtime_watchlist"] = watchlist
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

    # Clean up persisted baseline state for this domain
    state = _load_state()
    if domain in state:
        del state[domain]
        _save_state(state)

    logger.info(f"Removed {domain} from realtime watchlist")
    defanged = domain.replace(".", "[.]")
    return f"✅ **{defanged}** removed from watchlist monitoring."


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _load_realtime_watchlist() -> list[str]:
    """Read the realtime_watchlist list from config.json."""
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            return config.get("realtime_watchlist", [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading realtime watchlist config: {e}")
    return []


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def poll_watchlist() -> None:
    """Check all realtime watchlist domains and alert on changes.

    First run seeds the baseline silently (no alert). Subsequent runs diff
    against the baseline and send a Webex card if anything changed.
    """
    if not ENABLE_REALTIME_WATCHLIST:
        return

    domains = _load_realtime_watchlist()
    if not domains:
        logger.debug("Realtime watchlist is empty — nothing to poll")
        return

    logger.debug(f"Polling {len(domains)} watchlist domain(s): {', '.join(domains)}")

    # Check all domains concurrently
    results = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_check_domain, d): d for d in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                logger.error(f"Error checking watchlist domain {domain}: {e}")

    # Load previous baseline
    state = _load_state()
    is_first_run = len(state) == 0

    # Diff and collect changes
    all_changes: dict[str, list[dict]] = {}
    if not is_first_run:
        for domain, snapshot in results.items():
            prev = state.get(domain)
            if prev is None:
                # New domain added to watchlist — treat as first run for this domain
                logger.info(f"New watchlist domain {domain} — seeding baseline")
                continue
            changes = _diff_domain(domain, snapshot, prev)
            if changes:
                all_changes[domain] = changes

    # Alert if there are changes
    if all_changes:
        logger.info(f"Watchlist changes detected: {all_changes}")
        _send_changes_card(all_changes)
    elif is_first_run:
        logger.info("First watchlist poll — baseline seeded, no alert sent")
    else:
        logger.debug("Watchlist poll complete — no changes")

    # Update baseline — preserve previous DNS values for record types where
    # the current lookup failed (None) so transient errors don't corrupt
    # the baseline and cause a false-positive on the next successful poll.
    for domain, snapshot in results.items():
        prev = state.get(domain)
        if prev is not None:
            for rtype in ("A", "AAAA", "MX", "NS"):
                if snapshot.get("dns", {}).get(rtype) is None:
                    snapshot.setdefault("dns", {})[rtype] = prev.get("dns", {}).get(rtype, [])
        state[domain] = snapshot
    _save_state(state)


def send_heartbeat() -> None:
    """Send a weekly heartbeat confirming the watchlist poller is healthy.

    Scheduled Monday mornings so the team knows the poller is alive
    without having to check server logs.
    """
    domains = _load_realtime_watchlist()
    state = _load_state()
    timestamp = datetime.now(EASTERN_TZ).strftime("%Y-%m-%d %I:%M %p %Z")

    # Build domain status rows
    domain_rows = []
    for d in domains:
        entry = state.get(d, {})
        reachable = entry.get("http", {}).get("reachable", False)
        has_ssl = entry.get("ssl_fingerprint") is not None
        mx_records = entry.get("dns", {}).get("MX", [])
        a_records = entry.get("dns", {}).get("A", [])

        status_icon = "🟢" if reachable else ("🟡" if mx_records else "⚫")
        flags = []
        if a_records:
            flags.append("DNS")
        if mx_records:
            flags.append("MX")
        if has_ssl:
            flags.append("SSL")
        flags_str = " · ".join(flags) if flags else "no records"

        # Build detail lines (A records, MX records)
        details = []
        if a_records:
            details.append(f"A: {', '.join(a_records)}")
        if mx_records:
            details.append(f"MX: {', '.join(mx_records)}")

        domain_rows.append((d, status_icon, flags_str, reachable, details, bool(mx_records)))

    body = [
        # Header
        Container(
            style=get_container_style("blue"),
            items=[
                TextBlock(
                    text="💓 Watchlist Poller — Heartbeat",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                ),
                TextBlock(
                    text=f"🕐 {timestamp}",
                    size=options.FontSize.SMALL,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                ),
            ],
        ),
        # Status summary
        TextBlock(
            text=f"🛡️ Monitoring **{len(domains)}** domain(s) every **5 minutes** — DNS · HTTP · SSL",
            size=options.FontSize.SMALL,
            wrap=True,
        ),
    ]

    # Domain detail rows
    if domain_rows:
        body.append(TextBlock(
            text="📋 **Watched Domains**",
            size=options.FontSize.SMALL,
            weight=options.FontWeight.BOLDER,
            spacing=options.Spacing.MEDIUM,
        ))
        for domain_name, icon, flags_str, reachable, details, has_mx in domain_rows:
            if reachable:
                status_label = "web active"
            elif has_mx:
                status_label = "email only"
            else:
                status_label = "no web"
            body.append(ColumnSet(columns=[
                Column(width="auto", items=[
                    TextBlock(text=icon, size=options.FontSize.MEDIUM),
                ]),
                Column(width="stretch", items=[
                    TextBlock(
                        text=f"**{domain_name}**",
                        size=options.FontSize.SMALL,
                    ),
                ]),
                Column(width="auto", items=[
                    TextBlock(
                        text=f"{status_label} — {flags_str}",
                        size=options.FontSize.SMALL,
                        isSubtle=True,
                    ),
                ]),
            ]))
            if details:
                for detail in details:
                    body.append(TextBlock(
                        text=f"  ↳ {detail}",
                        size=options.FontSize.SMALL,
                        isSubtle=True,
                        spacing=options.Spacing.NONE,
                    ))
    else:
        body.append(TextBlock(
            text="⚠️ _No domains configured in realtime watchlist_",
            size=options.FontSize.SMALL,
            isSubtle=True,
        ))

    # Footer
    body.append(TextBlock(
        text="✅ No news is good news — alerts fire only on changes",
        size=options.FontSize.SMALL,
        isSubtle=True,
        spacing=options.Spacing.MEDIUM,
        horizontalAlignment=HorizontalAlignment.CENTER,
    ))

    card = AdaptiveCard(body=body)
    fallback = (
        f"💓 Watchlist Poller Heartbeat — {len(domains)} domains monitored, "
        f"all healthy — {timestamp}"
    )

    # Convert to dict and inject per-domain trash buttons
    card_dict = card.to_dict()
    if domains:
        # Walk the body and append a 🗑️ column to each domain ColumnSet
        row_idx = 0
        for item in card_dict["body"]:
            if item.get("type") != "ColumnSet" or row_idx >= len(domain_rows):
                continue
            domain_name = domain_rows[row_idx][0]
            item["columns"].append({
                "type": "Column",
                "width": "auto",
                "verticalContentAlignment": "Center",
                "items": [{
                    "type": "ActionSet",
                    "actions": [{
                        "type": "Action.Submit",
                        "title": "🗑️",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "watchlist_remove",
                            "domain_to_remove": domain_name,
                        },
                    }],
                }],
            })
            row_idx += 1

    try:
        webex_api = get_webex_api()
        room_id = get_active_room_id()
        send_card_with_retry(
            webex_api, room_id,
            text=fallback,
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card_dict,
            }],
        )
        logger.info("Sent watchlist poller heartbeat")
    except Exception as e:
        logger.error(f"Failed to send watchlist heartbeat: {e}")
