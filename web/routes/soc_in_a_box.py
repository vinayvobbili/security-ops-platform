"""SOC-in-a-Box landing page — single dashboard for the demo + on-call.

Surfaces:

- **Service health** for the 3 long-running agents + 3 timer-driven agents,
  with last-run / next-run for timers.
- **Recent bus activity** (last N events from soc.audit), one row per event.
- **Pending HITL count** with a deep link to /soc-hitl/audit.
- **Quick-link tiles** to /soc-timeline, /soc-hitl/audit, /soc-hitl/decide?…

Auth: login_required (any logged-in user can view; the audit / decide pages
already gate sensitive actions).
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from flask import Blueprint, redirect, render_template, request, url_for

from src.utils.logging_utils import log_web_activity
from web.auth.helpers import login_required

logger = logging.getLogger(__name__)

soc_in_a_box_bp = Blueprint("soc_in_a_box", __name__)


EASTERN = ZoneInfo("America/New_York")


# Service inventory — the 6 agent services + Sentinel + web HITL.
# Each entry: (key, display_name, role, systemd_unit, unit_kind, emoji, description)
SOC_SERVICES = [
    ("sentinel",      "Sentinel (Tier 1)",  "Tier 1 — alert triage",
     "ir-scheduler.service",          "service", "🛰️",
     "Triages XSOAR alerts; publishes AlertTriaged to the bus. Lives in the IR scheduler."),
    ("tier2",         "Tier 2 Analyst",     "Tier 2 — deeper investigation",
     "ir-soc-tier2.service",          "service", "🔍",
     "Long-running consumer on soc.triage. Filters TP-malicious / pri≥7 + escalates."),
    ("ir_lead",       "IR Lead",            "IR — response plan",
     "ir-soc-ir-lead.service",        "service", "🚨",
     "Long-running consumer on soc.cases. Drafts SEV/containment plan + HITL handoff."),
    ("threat_intel",  "Threat Intel",       "TI — actor + IOC attribution",
     "ir-soc-threat-intel.service",   "service", "🌐",
     "Long-running consumer on soc.cases. Enriches confirmed incidents with actor / MITRE."),
    ("soc_manager",   "SOC Manager",        "Manager — shift summaries",
     "ir-soc-manager.timer",          "timer", "🛰️",
     "Fires at every shift handoff (06:00 / 14:00 / 22:00 EST). 8h window summary."),
    ("threat_hunter", "Threat Hunter",      "Hunter — proactive sweeps",
     "ir-soc-threat-hunter.timer",    "timer", "🔭",
     "Fires twice daily (06:00 / 18:00 EST). 12h window pattern detection."),
    ("detection_eng", "Detection Engineer", "DetEng — rule tuning",
     "ir-soc-detection-eng.timer",    "timer", "🔧",
     "Fires 09:00 EST Mon-Fri. 24h window FP/benign-TP rule tuning recommendations."),
    ("hitl_web",      "HITL Approval Pages","HITL — human handoff",
     "ir-web-app.service",            "service", "🤝",
     "/soc-hitl/decide + /soc-hitl/audit Flask endpoints. Approve/Reject IR Lead containment."),
]


# Event-type → display label + bucket for the recent-activity stream
EVENT_LABELS = {
    "alert.triaged":        ("Sentinel triage",     "Tier 1"),
    "tier2.analysis":       ("Tier 2 analysis",     "Tier 2"),
    "case.escalated":       ("Escalation",          "Handoff"),
    "ir.plan":              ("IR Lead plan",        "IR"),
    "threat_intel.report":  ("Threat Intel report", "TI"),
    "detection.tuning_report": ("Detection tuning",  "DetEng"),
    "hunting.report":       ("Hunting sweep",       "Hunter"),
    "shift.summary":        ("Shift summary",       "Manager"),
    "action.proposed":      ("HITL proposed",       "HITL"),
    "action.decision":      ("HITL decision",       "HITL"),
}


def _systemd_show(unit: str, props: list[str]) -> dict[str, str]:
    """Run `systemctl --user show` for the named properties; return dict."""
    try:
        result = subprocess.run(
            ["systemctl", "--user", "show", unit] + [f"--property={p}" for p in props],
            capture_output=True, text=True, timeout=5,
        )
        out: dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                out[k] = v
        return out
    except Exception as exc:
        logger.warning("soc_in_a_box: systemctl show %s failed: %s", unit, exc)
        return {}


def _fmt_eastern(raw: str) -> str:
    """systemd timestamps look like 'Sat 2026-05-23 22:01:08 EDT'. Pass through
    unchanged when present; return '—' when empty or 'n/a'."""
    if not raw or raw in ("0", "n/a"):
        return "—"
    return raw


def _service_status(svc: dict[str, Any]) -> dict[str, Any]:
    """Probe one service entry, return a flat dict for the template."""
    unit = svc["unit"]
    kind = svc["kind"]
    if kind == "timer":
        props = _systemd_show(unit, [
            "ActiveState", "SubState", "NextElapseUSecRealtime",
            "LastTriggerUSec", "Description",
        ])
        active = (props.get("ActiveState") == "active")
        # Timer shows the LAST trigger time + NEXT trigger time. systemd
        # gives these as raw timestamps; pass through for now.
        last = props.get("LastTriggerUSec") or ""
        nxt  = props.get("NextElapseUSecRealtime") or ""
        return {
            **svc,
            "status": "scheduled" if active else "disabled",
            "status_color": "good" if active else "muted",
            "last_run": _fmt_eastern(last),
            "next_run": _fmt_eastern(nxt),
            "is_timer": True,
        }
    else:
        props = _systemd_show(unit, [
            "ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp",
        ])
        active = (props.get("ActiveState") == "active"
                  and props.get("SubState") in ("running", "exited"))
        return {
            **svc,
            "status": "running" if active else "stopped",
            "status_color": "good" if active else "bad",
            "main_pid": props.get("MainPID") or "—",
            "active_since": _fmt_eastern(props.get("ActiveEnterTimestamp") or ""),
            "is_timer": False,
        }


def _recent_events(limit: int = 25) -> list[dict[str, Any]]:
    """Last N events from soc.audit, newest first, with display labels."""
    try:
        from src.components.soc_in_box import bus
        client = bus.get_redis_client()
        # XREVRANGE pulls newest-first
        raw = client.xrevrange(bus.STREAM_AUDIT, count=limit)
    except Exception as exc:
        logger.warning("soc_in_a_box: bus read failed: %s", exc)
        return []
    out = []
    for mid, fields in raw:
        try:
            e = json.loads(fields.get("payload", "{}"))
        except Exception:
            continue
        et = e.get("event_type") or ""
        label, bucket = EVENT_LABELS.get(et, (et or "event", "—"))
        ts = e.get("timestamp") or ""
        # Try to localize
        ts_display = ts
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            ts_display = dt.astimezone(EASTERN).strftime("%m/%d %I:%M:%S %p")
        except Exception:
            pass
        out.append({
            "msg_id": mid, "event_type": et,
            "label": label, "bucket": bucket,
            "ticket_id": e.get("ticket_id") or e.get("correlation_id") or "—",
            "produced_by": e.get("produced_by") or "—",
            "verdict": e.get("verdict") or e.get("severity") or e.get("refined_verdict") or "",
            "timestamp_eastern": ts_display,
        })
    return out


def _parse_iso(raw: Any) -> Optional[datetime]:
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _avg(nums: list[float]) -> Optional[float]:
    nums = [n for n in nums if n is not None]
    return round(sum(nums) / len(nums), 1) if nums else None


def _pct(part: int, total: int) -> Optional[float]:
    return round(100.0 * part / total, 1) if total else None


def _compute_stats(window_hours: int) -> dict[str, Any]:
    """Replay soc.audit and compute per-role telemetry for the last N hours.

    All counts derived deterministically — no extra DB. The bus IS the
    source of truth for activity. Demo-day numbers: "this week we
    processed X, escalated Y, the human approved Z."
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    try:
        from src.components.soc_in_box import bus
        client = bus.get_redis_client()
        events = bus.replay(client, bus.STREAM_AUDIT, start="-", end="+", count=None)
    except Exception as exc:
        logger.warning("soc_in_a_box: stats replay failed: %s", exc)
        return {"window_hours": window_hours, "events_examined": 0, "error": str(exc)}

    # Keep only events inside the window
    in_window: list[dict[str, Any]] = []
    for e in events:
        ts = _parse_iso(e.get("timestamp"))
        if ts is not None and ts >= cutoff:
            in_window.append(e)

    # Bucket by event_type
    by_type: dict[str, list[dict[str, Any]]] = {}
    for e in in_window:
        by_type.setdefault(e.get("event_type") or "", []).append(e)

    # ---- per-role rollups ----
    roles: list[dict[str, Any]] = []

    # Format helpers — emit safe HTML for the template's |safe rendering.
    def _b(s: Any) -> str:
        return f"<strong>{s}</strong>"

    def _code(s: Any) -> str:
        return f"<code>{s}</code>"

    def _mix(counter: Counter, k: int = 5) -> str:
        return "  ·  ".join(f"{_code(v)} {_b(n)}" for v, n in counter.most_common(k)) \
            if counter else "—"

    # Sentinel (Tier 1)
    triaged = by_type.get("alert.triaged", [])
    verdict_dist = Counter(e.get("verdict") or "unknown" for e in triaged)
    roles.append({
        "key": "sentinel", "name": "Sentinel (Tier 1)", "emoji": "🛰️",
        "events": len(triaged),
        "avg_wall_ms": None,  # Sentinel doesn't denormalize wall time onto AlertTriaged
        "avg_tools": None,
        "extras": [
            ("Verdict mix", _mix(verdict_dist, 5)),
        ],
    })

    # Tier 2
    t2 = by_type.get("tier2.analysis", [])
    t2_decisions = Counter(e.get("escalation_decision") or "unknown" for e in t2)
    escalations = t2_decisions.get("escalate_to_ir_lead", 0)
    roles.append({
        "key": "tier2", "name": "Tier 2 Analyst", "emoji": "🔍",
        "events": len(t2),
        "avg_wall_ms": _avg([e.get("wall_time_ms") for e in t2]),
        "avg_tools": _avg([e.get("tool_calls_made") for e in t2]),
        "extras": [
            ("Decisions", _mix(t2_decisions, 3)),
            ("Escalated → IR Lead",
             f"{_b(escalations)} of {len(t2)} "
             f"({_b(str(_pct(escalations, len(t2)) or 0) + '%')})"),
        ],
    })

    # IR Lead
    plans = by_type.get("ir.plan", [])
    sev_dist = Counter(e.get("severity") or "?" for e in plans)
    bridge_count = sum(1 for e in plans if e.get("bridge_required"))
    roles.append({
        "key": "ir_lead", "name": "IR Lead", "emoji": "🚨",
        "events": len(plans),
        "avg_wall_ms": _avg([e.get("wall_time_ms") for e in plans]),
        "avg_tools": _avg([e.get("tool_calls_made") for e in plans]),
        "extras": [
            ("Severity mix", _mix(sev_dist, 4)),
            ("Bridge required",
             f"{_b(bridge_count)} of {len(plans)} "
             f"({_b(str(_pct(bridge_count, len(plans)) or 0) + '%')})"),
        ],
    })

    # Threat Intel
    ti = by_type.get("threat_intel.report", [])
    with_actor = sum(1 for e in ti if (e.get("likely_actor") or "").strip())
    sev_adj = Counter(e.get("severity_adjustment") or "none" for e in ti)
    sev_adj_no_none = Counter({k: v for k, v in sev_adj.items() if k != "none"})
    roles.append({
        "key": "threat_intel", "name": "Threat Intel", "emoji": "🌐",
        "events": len(ti),
        "avg_wall_ms": _avg([e.get("wall_time_ms") for e in ti]),
        "avg_tools": _avg([e.get("tool_calls_made") for e in ti]),
        "extras": [
            ("Named actor",
             f"{_b(with_actor)} of {len(ti)} "
             f"({_b(str(_pct(with_actor, len(ti)) or 0) + '%')})"),
            ("SEV adjustments",
             _mix(sev_adj_no_none) if sev_adj_no_none else "<em>none recommended</em>"),
        ],
    })

    # SOC Manager (timer)
    sm = by_type.get("shift.summary", [])
    roles.append({
        "key": "soc_manager", "name": "SOC Manager", "emoji": "🛰️",
        "events": len(sm), "avg_wall_ms": None, "avg_tools": None,
        "extras": [
            ("Avg alerts/shift", _b(_avg([e.get("total_alerts") for e in sm]) or 0)),
        ],
    })

    # Detection Engineer (timer)
    de = by_type.get("detection.tuning_report", [])
    proposal_total = sum(len(e.get("proposals") or []) for e in de)
    roles.append({
        "key": "detection_eng", "name": "Detection Engineer", "emoji": "🔧",
        "events": len(de), "avg_wall_ms": None, "avg_tools": None,
        "extras": [
            ("Proposals/run",
             f"{_b(round(proposal_total / len(de), 1) if de else 0)} "
             f"(total {_b(proposal_total)})"),
        ],
    })

    # Threat Hunter (timer)
    hunts = by_type.get("hunting.report", [])
    finding_total = sum(len(e.get("findings") or []) for e in hunts)
    roles.append({
        "key": "threat_hunter", "name": "Threat Hunter", "emoji": "🔭",
        "events": len(hunts), "avg_wall_ms": None, "avg_tools": None,
        "extras": [
            ("Findings/sweep",
             f"{_b(round(finding_total / len(hunts), 1) if hunts else 0)} "
             f"(total {_b(finding_total)})"),
        ],
    })

    # HITL (action.proposed + action.decision)
    proposed = by_type.get("action.proposed", [])
    decisions = by_type.get("action.decision", [])
    approved = sum(1 for e in decisions if e.get("decision") == "approved")
    rejected = sum(1 for e in decisions if e.get("decision") == "rejected")
    pending = max(0, len(proposed) - len(decisions))
    roles.append({
        "key": "hitl", "name": "HITL (human handoff)", "emoji": "🤝",
        "events": len(proposed), "avg_wall_ms": None, "avg_tools": None,
        "extras": [
            ("Decisions",
             f"approved {_b(approved)}  •  rejected {_b(rejected)}  •  "
             f"pending {_b(pending)}"),
            ("Approval rate",
             f"{_b(str(_pct(approved, approved + rejected) or 0) + '%')} "
             f"(of {approved + rejected} decided)"),
        ],
    })

    return {
        "window_hours": window_hours,
        "events_examined": len(in_window),
        "total_events_on_bus": len(events),
        "roles": roles,
    }


BACKTEST_SUMMARY_PATH = "data/soc_in_box/backtest_summary.json"


def _load_backtest_summary() -> Optional[dict[str, Any]]:
    """Read the latest backtest summary, if any. Returns None when the file
    is missing or malformed — the panel then renders a "no run yet" hint.
    """
    try:
        from pathlib import Path
        p = Path(BACKTEST_SUMMARY_PATH)
        if not p.exists():
            return None
        with open(p) as f:
            data = json.load(f)
        # Pretty-format generated_at for Eastern display
        gen = _parse_iso(data.get("generated_at"))
        if gen is not None:
            data["generated_at_display"] = gen.astimezone(EASTERN).strftime(
                "%m/%d/%Y %I:%M %p %Z")
        return data
    except Exception as exc:
        logger.warning("soc_in_a_box: backtest summary load failed: %s", exc)
        return None


def _pending_hitl_count() -> int:
    try:
        from src.components.soc_in_box import hitl_store
        # list_recent returns actions + latest decision; pending = decision is None
        rows = hitl_store.list_recent(limit=100)
        return sum(1 for r in rows if not r.get("latest_decision"))
    except Exception as exc:
        logger.warning("soc_in_a_box: HITL count failed: %s", exc)
        return 0


@soc_in_a_box_bp.route("/soc-in-a-box")
@login_required
@log_web_activity
def display_landing():
    services = []
    for key, name, role, unit, kind, emoji, desc in SOC_SERVICES:
        svc = {
            "key": key, "name": name, "role": role,
            "unit": unit, "kind": kind, "emoji": emoji, "description": desc,
        }
        services.append(_service_status(svc))

    running = sum(1 for s in services if s["status"] in ("running", "scheduled"))
    events = _recent_events(limit=25)
    pending = _pending_hitl_count()

    # Window selector for the stats panel: 24h / 7d / 30d
    try:
        stats_window_hours = int(request.args.get("stats_window") or "168")
    except ValueError:
        stats_window_hours = 168
    if stats_window_hours not in (24, 168, 720):
        stats_window_hours = 168
    stats = _compute_stats(stats_window_hours)

    # Optional banner from a redirect after Fire / Cleanup actions
    banner = None
    if request.args.get("fired"):
        banner = {
            "kind": "good",
            "title": "Demo cascade fired",
            "body": (f"Synthetic ticket #{request.args.get('fired')} injected onto soc.triage. "
                     f"Watch the Webex room — Tier 2 → IR Lead → Threat Intel cards will land "
                     f"over the next ~60s. Refresh this page to see the bus activity."),
        }
    elif request.args.get("cleaned"):
        banner = {
            "kind": "muted",
            "title": "Demo artifacts cleaned",
            "body": request.args.get("cleaned"),
        }
    elif request.args.get("error"):
        banner = {
            "kind": "bad",
            "title": "Action failed",
            "body": request.args.get("error"),
        }

    backtest = _load_backtest_summary()

    return render_template(
        "soc_in_a_box.html",
        services=services,
        services_total=len(services),
        services_running=running,
        events=events,
        pending_hitl=pending,
        banner=banner,
        scenarios=["cobalt_strike", "ransomware_precursor"],
        stats=stats,
        stats_window_hours=stats_window_hours,
        backtest=backtest,
    )


@soc_in_a_box_bp.route("/soc-in-a-box/fire", methods=["POST"])
@login_required
@log_web_activity
def fire_demo():
    """Inject one demo Sentinel triage event. pause_sec=0 — the dashboard
    is the narration surface, not a terminal.
    """
    scenario = (request.form.get("scenario") or "cobalt_strike").strip()
    try:
        from src.components.soc_in_box.demo import fire, SCENARIOS
        if scenario not in SCENARIOS:
            return redirect(url_for("soc_in_a_box.display_landing",
                                    error=f"Unknown scenario: {scenario!r}"))
        result = fire(scenario=scenario, pause_sec=0)
        return redirect(url_for("soc_in_a_box.display_landing",
                                fired=result["ticket_id"]))
    except Exception as exc:
        logger.exception("fire_demo failed: %s", exc)
        return redirect(url_for("soc_in_a_box.display_landing",
                                error=f"Fire failed: {exc}"))


@soc_in_a_box_bp.route("/soc-in-a-box/cleanup", methods=["POST"])
@login_required
@log_web_activity
def cleanup_demo():
    """Wipe every demo bus event + HITL row (ticket prefix 999)."""
    try:
        from src.components.soc_in_box.demo import cleanup
        deleted = cleanup()
        summary = (f"Removed {deleted.get('soc.triage', 0)} triage / "
                   f"{deleted.get('soc.cases', 0)} cases / "
                   f"{deleted.get('soc.audit', 0)} audit events; "
                   f"{deleted.get('hitl_actions', 0)} HITL actions + "
                   f"{deleted.get('hitl_decisions', 0)} decisions; "
                   f"{deleted.get('verdicts', 0)} verdict rows.")
        return redirect(url_for("soc_in_a_box.display_landing", cleaned=summary))
    except Exception as exc:
        logger.exception("cleanup_demo failed: %s", exc)
        return redirect(url_for("soc_in_a_box.display_landing",
                                error=f"Cleanup failed: {exc}"))


# Sample inputs offered on the analyze page — one click to populate the form.
SANDBOX_SAMPLES = {
    "phishing": (
        "From: \"DocuSign\" <no-reply@docu-sign-secure.com>\n"
        "To: <redacted-email>\n"
        "Subject: You have a document awaiting your signature\n"
        "Date: Thu, 29 May 2026 09:14:22 -0400\n"
        "Reply-To: <redacted-email>\n\n"
        "Dana,\n\nA confidential document has been shared with you and requires "
        "your signature today. Review and sign here:\n\n"
        "https://docu-sign-secure.com/auth/login?id=8821&redirect=hxxp://198.51.100.77/collect\n\n"
        "This link expires in 24 hours. Do not share this email.\n\n"
        "DocuSign Electronic Signature Service"
    ),
    "endpoint": (
        "CrowdStrike detection on host FIN-WKS-2291 (user: m.alvarez):\n"
        "Process tree: outlook.exe -> winword.exe -> powershell.exe\n"
        "Command line: powershell -nop -w hidden -enc "
        "JABzAD0ATgBlAHcaLQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==\n"
        "PowerShell made an outbound TLS connection to 203.0.113.45:443.\n"
        "File written: C:\\Users\\m.alvarez\\AppData\\Roaming\\update.dll\n"
        "SHA256: 9f2c4b1e7a8d3c0f5e6b2a9d4c7e1f8b0a3d6c9e2f5b8a1d4c7e0f3b6a9d2c5e\n"
        "Pattern disposition: detection only — NOT blocked."
    ),
}


@soc_in_a_box_bp.route("/soc-in-a-box/analyze", methods=["GET"])
@login_required
@log_web_activity
def analyze_form():
    """Render the sandbox 'paste a log or email to analyze' form."""
    return render_template(
        "soc_analyze.html",
        samples=SANDBOX_SAMPLES,
        error=request.args.get("error", ""),
    )


@soc_in_a_box_bp.route("/soc-in-a-box/analyze", methods=["POST"])
@login_required
@log_web_activity
def analyze_submit():
    """Kick off a sandbox triage run and redirect to the timeline for it.

    Runs the *real* Sentinel triage pipeline on a synthetic 999-namespace
    ticket (background thread), then sends the user to /soc-timeline filtered
    to that ticket so they watch the agents cascade in near-real-time.
    """
    text = (request.form.get("text") or "").strip()
    kind = (request.form.get("kind") or "auto").strip()
    hostname = (request.form.get("hostname") or "").strip()
    username = (request.form.get("username") or "").strip()
    if not text:
        return redirect(url_for("soc_in_a_box.analyze_form",
                                error="Paste a log line or an email to analyze."))
    try:
        from src.components.soc_in_box import sandbox
        ticket_id = sandbox.start_async(text, kind=kind,
                                        hostname=hostname, username=username)
        # url_for to the timeline blueprint with the ticket filter.
        return redirect(url_for("soc_timeline.display_soc_timeline",
                                ticket=ticket_id))
    except Exception as exc:
        logger.exception("analyze_submit failed: %s", exc)
        return redirect(url_for("soc_in_a_box.analyze_form",
                                error=f"Analyze failed: {exc}"))
