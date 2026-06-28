"""Admin view of analyst training progress: /admin-lessons.

Gated by the app-wide auth's admin role (web.auth.helpers.admin_required).

The page is organized BY LESSON: pick a lesson from the dropdown to see its
high-level metrics (who's attempted, pass rate, distinctions, average best
score, total attempts), a week-over-week trend, and a per-analyst breakdown
(name, attempts, best score, status, last attempt). The same per-lesson
breakdown is downloadable as CSV.
"""

import json
import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import yaml
from flask import Blueprint, render_template, request, send_file
from quizforge import assess_speed

from services import training_db
from src.utils.excel_formatting import apply_professional_formatting
from web.auth.helpers import admin_required

logger = logging.getLogger(__name__)

admin_lessons_bp = Blueprint('admin_lessons', __name__)

TOPICS_DIR = Path(__file__).parent.parent.parent / "data" / "training" / "topics"
_EASTERN = ZoneInfo('America/New_York')
TREND_WEEKS = 10  # weeks of history shown in the per-lesson sparklines


def _fmt_et(ts: str | None) -> str:
    """Render a stored UTC ISO timestamp as Eastern Time for display."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(_EASTERN).strftime("%m/%d/%Y %-I:%M %p %Z")
    except (ValueError, TypeError):
        return ts


def _fmt_duration(seconds: int) -> str:
    """Human-friendly elapsed time (e.g. 95 -> '1m 35s'); '—' when unrecorded."""
    seconds = int(seconds or 0)
    if seconds <= 0:
        return "—"
    m, s = divmod(seconds, 60)
    return f"{m}m {s}s" if m else f"{s}s"


def _display_name(email: str) -> str:
    """Friendly label from an email local-part (e.g. jane.doe -> Jane Doe)."""
    local = (email or "").split("@", 1)[0]
    parts = [p for p in local.replace("_", ".").replace("-", ".").split(".") if p]
    return " ".join(p.capitalize() for p in parts) or email


def _list_topics() -> list[dict]:
    out = []
    if TOPICS_DIR.is_dir():
        for path in sorted(TOPICS_DIR.glob("*.yaml")):
            if path.name.startswith("_"):
                continue  # scaffolding (_template.yaml) — not a real lesson
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                out.append({
                    "id": data["id"],
                    "title": data["title"],
                    "icon": data.get("icon") or "🎓",
                })
            except Exception as exc:
                logger.warning("Failed to load topic %s: %s", path, exc)
    return out


def _qtype_maps() -> dict[str, dict[str, str]]:
    """Per-topic {question_id -> format} index, for reconstructing an attempt's
    question mix from its stored ``sampled_q_ids`` (the anti-cheat timing check
    needs to know how many open vs. multiple-choice questions were on the test).
    """
    maps: dict[str, dict[str, str]] = {}
    if not TOPICS_DIR.is_dir():
        return maps
    for path in sorted(TOPICS_DIR.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            maps[data["id"]] = {q["id"]: q.get("type", "mc") for q in data.get("questions", [])}
        except Exception as exc:
            logger.warning("Failed to index question types for %s: %s", path, exc)
    return maps


def _attempt_flag(row: dict, qtype_map: dict[str, str]):
    """Run the quizforge timing check on one attempt row.

    ``row`` carries ``elapsed_seconds``, ``passed`` and JSON ``sampled_q_ids``;
    we map those ids back to their formats (missing ids default to 'mc' — the
    lowest floor, so it never invents suspicion).
    """
    try:
        ids = json.loads(row.get("sampled_q_ids") or "[]")
    except (json.JSONDecodeError, TypeError):
        ids = []
    types = [qtype_map.get(qid, "mc") for qid in ids]
    return assess_speed(
        elapsed_seconds=int(row.get("elapsed_seconds") or 0),
        question_types=types,
        passed=bool(row.get("passed")),
    )


def _integrity_index(qtype_maps: dict[str, dict[str, str]]) -> dict[tuple[str, str], dict]:
    """Aggregate fast-pass flags per (analyst, lesson) across every attempt."""
    index: dict[tuple[str, str], dict] = {}
    for row in training_db.get_all_attempts():
        flag = _attempt_flag(row, qtype_maps.get(row["topic"], {}))
        if not flag.suspicious:
            continue
        key = (row["user_email"], row["topic"])
        agg = index.setdefault(key, {"fast_passes": 0, "severity": "low", "min_ratio": 1.0})
        agg["fast_passes"] += 1
        if flag.severity == "high":
            agg["severity"] = "high"
        agg["min_ratio"] = min(agg["min_ratio"], flag.speed_ratio)
    return index


def _collect_lessons() -> tuple[list[dict], dict]:
    """Per-lesson analyst breakdowns + metrics, plus overall KPIs.

    Shared by the dashboard and the CSV export so both report identically.
    """
    training_db.init_db()
    rows = training_db.get_all_progress()
    topics = _list_topics()
    dist = training_db.DISTINCTION_THRESHOLD
    integrity = _integrity_index(_qtype_maps())

    per_topic: dict[str, list[dict]] = {t["id"]: [] for t in topics}
    all_users: set[str] = set()
    for row in rows:
        all_users.add(row["user_email"])
        if row["topic"] not in per_topic:
            continue  # an attempt for a lesson whose YAML is gone — skip
        best = row["best_ratio"] or 0.0
        flag = integrity.get((row["user_email"], row["topic"]))
        per_topic[row["topic"]].append({
            "email": row["user_email"],
            "name": _display_name(row["user_email"]),
            "attempts": row["attempts"],
            "best_pct": round(best * 100),
            "passed": bool(row["ever_passed"]),
            "distinction": best >= dist,
            "last_ts": _fmt_et(row["last_ts"]),
            "fast_passes": flag["fast_passes"] if flag else 0,
            "flag_severity": flag["severity"] if flag else "",
        })

    lessons = []
    overall_attempts = overall_passed = overall_attempted = overall_flagged = 0
    for t in topics:
        analysts = sorted(
            per_topic[t["id"]],
            key=lambda a: (not a["passed"], -a["best_pct"], a["name"]),
        )
        attempted = len(analysts)
        passed = sum(1 for a in analysts if a["passed"])
        distinctions = sum(1 for a in analysts if a["distinction"])
        total_attempts = sum(a["attempts"] for a in analysts)
        avg_best = round(sum(a["best_pct"] for a in analysts) / attempted) if attempted else 0
        pass_rate = round(passed / attempted * 100) if attempted else 0
        flagged = sum(1 for a in analysts if a["fast_passes"])

        overall_attempts += total_attempts
        overall_passed += passed
        overall_attempted += attempted
        overall_flagged += flagged

        lessons.append({
            "id": t["id"],
            "title": t["title"],
            "icon": t["icon"],
            "analysts": analysts,
            "metrics": {
                "attempted": attempted,
                "passed": passed,
                "pass_rate": pass_rate,
                "distinctions": distinctions,
                "avg_best": avg_best,
                "total_attempts": total_attempts,
                "flagged": flagged,
            },
        })

    overall = {
        "analysts": len(all_users),
        "lessons": len(topics),
        "attempts": overall_attempts,
        "pass_rate": round(overall_passed / overall_attempted * 100) if overall_attempted else 0,
        "flagged": overall_flagged,
    }
    return lessons, overall


def _spark(values: list[float], width: int = 240, height: int = 46,
           pad: int = 5, ymax: float | None = None) -> dict:
    """Precompute SVG polyline/area geometry for a sparkline (no JS chart lib)."""
    n = len(values)
    if n == 0:
        return {"line": "", "area": "", "last_x": 0, "last_y": 0, "ymax": 1}
    top = ymax if ymax is not None else (max(values) or 1)
    top = top or 1
    step = (width - 2 * pad) / (n - 1) if n > 1 else 0
    pts = []
    for i, v in enumerate(values):
        x = pad + i * step
        y = (height - pad) - (v / top) * (height - 2 * pad)
        pts.append((round(x, 1), round(y, 1)))
    line = " ".join(f"{x},{y}" for x, y in pts)
    last_x = round(pad + (n - 1) * step, 1)
    area = f"{pad},{height - pad} {line} {last_x},{height - pad}"
    return {"line": line, "area": area, "last_x": pts[-1][0], "last_y": pts[-1][1], "ymax": top}


def _build_trend(rows: list[dict], weeks: int = TREND_WEEKS) -> dict:
    """Bucket a lesson's attempts into the last `weeks` ET calendar weeks."""
    today = datetime.now(_EASTERN).date()
    this_monday = today - timedelta(days=today.weekday())
    buckets = [this_monday - timedelta(weeks=(weeks - 1 - i)) for i in range(weeks)]
    idx = {wk: i for i, wk in enumerate(buckets)}
    attempts = [0] * weeks
    passes = [0] * weeks
    for r in rows:
        try:
            dt = datetime.fromisoformat(r["ts"].replace("Z", "+00:00")).astimezone(_EASTERN)
        except (ValueError, TypeError, AttributeError):
            continue
        wk = dt.date() - timedelta(days=dt.date().weekday())
        i = idx.get(wk)
        if i is None:
            continue  # older than the window
        attempts[i] += 1
        if r["passed"]:
            passes[i] += 1
    pass_rate = [round(passes[i] / attempts[i] * 100) if attempts[i] else 0 for i in range(weeks)]
    cur, prev = attempts[-1], attempts[-2] if weeks > 1 else 0
    return {
        "labels": [wk.strftime("%-m/%-d") for wk in buckets],
        "attempts": attempts,
        "pass_rate": pass_rate,
        "has_data": any(attempts),
        "total_recent": sum(attempts),
        "this_week": cur,
        "delta": cur - prev,
        "spark_att": _spark(attempts),
        "spark_pr": _spark(pass_rate, ymax=100),
    }


@admin_lessons_bp.route('/admin-lessons')
@admin_required
def index():
    lessons, overall = _collect_lessons()

    # Attach week-over-week trend per lesson from the raw attempt log.
    raw = training_db.get_all_attempts()
    by_topic: dict[str, list[dict]] = {}
    for r in raw:
        by_topic.setdefault(r["topic"], []).append(r)
    for l in lessons:
        l["trend"] = _build_trend(by_topic.get(l["id"], []))

    return render_template(
        "admin_lessons/index.html",
        lessons=lessons,
        overall=overall,
        trend_weeks=TREND_WEEKS,
        pass_pct=int(training_db.PASS_THRESHOLD * 100),
        dist_pct=int(training_db.DISTINCTION_THRESHOLD * 100),
    )


@admin_lessons_bp.route('/admin-lessons/export.xlsx')
@admin_required
def export_xlsx():
    """Download the per-lesson analyst breakdown as a professionally
    formatted Excel workbook.

    All lessons by default; ?lesson=<id> restricts to one.
    """
    lessons, _ = _collect_lessons()
    only = request.args.get("lesson")
    if only:
        lessons = [l for l in lessons if l["id"] == only]

    records = []
    for l in lessons:
        for a in l["analysts"]:
            if a["distinction"]:
                status = "🏆 Distinction"
            elif a["passed"]:
                status = "Passed"
            else:
                status = "In progress"
            if a["fast_passes"]:
                sev = "High" if a["flag_severity"] == "high" else "Review"
                integrity = f"⚠️ {sev} — {a['fast_passes']} fast pass(es)"
            else:
                integrity = "OK"
            records.append({
                "Lesson": l["title"],
                "Analyst": a["name"],
                "Email": a["email"],
                "Attempts": a["attempts"],
                "Best Score (%)": a["best_pct"],
                "Status": status,
                "Integrity": integrity,
                "Last Attempt (ET)": a["last_ts"],
            })

    columns = ["Lesson", "Analyst", "Email", "Attempts",
               "Best Score (%)", "Status", "Integrity", "Last Attempt (ET)"]
    df = pd.DataFrame(records, columns=columns)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    tmp_path = tmp.name
    tmp.close()
    df.to_excel(tmp_path, index=False, sheet_name="Lesson Progress", engine="openpyxl")
    apply_professional_formatting(
        tmp_path,
        column_widths={
            "lesson": 32,
            "analyst": 24,
            "email": 34,
            "attempts": 12,
            "best score (%)": 16,
            "status": 16,
            "integrity": 30,
            "last attempt (et)": 28,
        },
        wrap_columns={"lesson", "integrity"},
    )

    stamp = datetime.now(_EASTERN).strftime("%Y-%m-%d")
    slug = (only or "all").replace("/", "_")
    fname = f"lessons_progress_{slug}_{stamp}.xlsx"
    return send_file(
        tmp_path,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=fname,
    )


@admin_lessons_bp.route('/admin-lessons/<path:user_email>')
@admin_required
def user_detail(user_email: str):
    training_db.init_db()
    attempts = training_db.get_user_attempts(user_email)
    progress = training_db.get_user_progress(user_email)
    topics = {t["id"]: t for t in _list_topics()}
    qtype_maps = _qtype_maps()

    for a in attempts:
        a["ts_et"] = _fmt_et(a.get("ts"))
        a["topic_title"] = topics.get(a["topic"], {}).get("title", a["topic"])
        a["topic_icon"] = topics.get(a["topic"], {}).get("icon", "🎓")
        flag = _attempt_flag(a, qtype_maps.get(a["topic"], {}))
        a["flagged"] = flag.suspicious
        a["flag_severity"] = flag.severity
        a["elapsed_label"] = _fmt_duration(a.get("elapsed_seconds") or 0)

    prog_rows = []
    for tid, p in progress.items():
        prog_rows.append({
            "topic": tid,
            "title": topics.get(tid, {}).get("title", tid),
            "icon": topics.get(tid, {}).get("icon", "🎓"),
            "passed": p["passed"],
            "best_pct": round((p["best_ratio"] or 0.0) * 100),
            "distinction": (p["best_ratio"] or 0.0) >= training_db.DISTINCTION_THRESHOLD,
            "attempts": p["attempts"],
            "last_ts": _fmt_et(p["last_ts"]),
        })
    prog_rows.sort(key=lambda r: r["title"])

    return render_template(
        "admin_lessons/user_detail.html",
        user_email=user_email,
        display_name=_display_name(user_email),
        attempts=attempts,
        progress=prog_rows,
        pass_pct=int(training_db.PASS_THRESHOLD * 100),
        dist_pct=int(training_db.DISTINCTION_THRESHOLD * 100),
    )
