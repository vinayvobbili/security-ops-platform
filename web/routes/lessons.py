"""Analyst-facing training routes: /lessons.

Identity comes from the app-wide auth in web.auth.helpers (signed-in user's
email keys per-user progress). Per-user quiz progress is persisted via
services.training_db; the admin view lives in /admin-lessons.
"""

import logging
import random
from collections import defaultdict
from pathlib import Path

import yaml
from flask import Blueprint, Response, redirect, render_template, request
from quizforge import DEFAULT_TIME_LIMIT_SECONDS, sample_test

from services import lesson_certificate, quiz_grading, training_db
from web.auth.helpers import current_user, login_required

logger = logging.getLogger(__name__)

lessons_bp = Blueprint('lessons', __name__)

TOPICS_DIR = Path(__file__).parent.parent.parent / "data" / "training" / "topics"

# Each attempt draws a fresh, mixed-format test from the topic's question bank.
# The blueprint is the *target* composition; quizforge.sample_test degrades
# gracefully when a bank doesn't yet hold enough of a given type. Deterministic
# formats (mc / fill_blank / match) carry the volume; the AI-graded open formats
# (short / freetext) are capped so each submit fires only a few LLM calls.
TEST_BLUEPRINT = {
    "mc": 8,
    "fill_blank": 4,
    "match": 2,
    "short": 4,
    "freetext": 2,
}
QUESTIONS_PER_ATTEMPT = sum(TEST_BLUEPRINT.values())  # 20

# Wall-clock budget per attempt — the quiz page counts down from this and
# auto-submits at zero. Sourced from quizforge so the limit policy lives with
# the rest of the timing logic (anti-cheat fast-pass detection).
QUIZ_TIME_LIMIT_SECONDS = DEFAULT_TIME_LIMIT_SECONDS  # 30 minutes


def _load_topic(topic_id: str) -> dict | None:
    safe = "".join(c for c in topic_id if c.isalnum() or c in "-_").lower()
    # Leading underscore is reserved for scaffolding files (e.g. _template.yaml)
    # that live alongside topics but are not real lessons.
    if not safe or safe != topic_id.lower() or safe.startswith("_"):
        return None
    path = TOPICS_DIR / f"{safe}.yaml"
    if not path.is_file():
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def _list_topics() -> list[dict]:
    topics = []
    if TOPICS_DIR.is_dir():
        for path in sorted(TOPICS_DIR.glob("*.yaml")):
            if path.name.startswith("_"):
                continue  # scaffolding (e.g. _template.yaml), not a real lesson
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                topics.append({
                    "id": data["id"],
                    "title": data["title"],
                    "tier": data.get("tier", ""),
                    "icon": data.get("icon", "🎓"),
                    "summary": data.get("summary", ""),
                })
            except Exception as exc:
                logger.warning("Failed to load topic %s: %s", path, exc)
    return topics


# ---------------------------------------------------------------------------
# Catalog + topic page
# ---------------------------------------------------------------------------

@lessons_bp.route('/lessons')
@login_required
def index():
    training_db.init_db()
    email = current_user()["email"]
    progress = training_db.get_user_progress(email)
    topics = _list_topics()
    for t in topics:
        p = progress.get(t["id"], {})
        t["passed"] = p.get("passed", False)
        t["attempts"] = p.get("attempts", 0)
        t["best_ratio"] = p.get("best_ratio", 0.0)

    total = len(topics)
    passed_n = sum(1 for t in topics if t["passed"])
    inprog_n = sum(1 for t in topics if t["attempts"] > 0 and not t["passed"])
    attempted_n = sum(1 for t in topics if t["attempts"] > 0)
    stats = {
        "total": total,
        "passed": passed_n,
        "in_progress": inprog_n,
        "not_started": total - passed_n - inprog_n,
        "overall_pct": round(100 * passed_n / total) if total else 0,
        # Pass/fail only — no scores stored; pass rate = passed / topics attempted.
        "pass_rate": round(100 * passed_n / attempted_n) if attempted_n else 0,
    }
    # Friendly handle from the email local part — no raw work address on the page.
    handle = email.split("@")[0]
    display_name = handle.replace(".", " ").replace("_", " ").title()
    return render_template(
        "lessons/index.html",
        topics=topics,
        user_email=email,
        display_name=display_name,
        user_initial=(display_name[:1] or "?").upper(),
        stats=stats,
    )


@lessons_bp.route('/lessons/<topic_id>')
@login_required
def topic_page(topic_id: str):
    topic = _load_topic(topic_id)
    if topic is None:
        return render_template("lessons/not_found.html", topic_id=topic_id), 404
    training_db.init_db()
    email = current_user()["email"]
    passed = training_db.has_passed(email, topic["id"])
    video_filename = f"{topic['id']}.mp4"
    video_path = Path(__file__).parent.parent / "static" / "videos" / video_filename
    has_video = video_path.is_file()
    # Honest count for the CTA: the blueprint capped by what the bank actually holds.
    avail: dict[str, int] = defaultdict(int)
    for q in topic.get("questions", []):
        avail[q.get("type", "mc")] += 1
    quiz_len = sum(min(want, avail.get(qtype, 0)) for qtype, want in TEST_BLUEPRINT.items())
    return render_template(
        "lessons/topic.html",
        topic=topic,
        passed=passed,
        has_video=has_video,
        video_filename=video_filename,
        quiz_len=quiz_len,
        chat_context=_lesson_chat_context(topic),
    )


def _lesson_chat_context(topic: dict) -> str:
    """Plain-text lesson material handed to the in-page chat widget as context.

    Lets the standard page-chat assistant teach from this exact lesson rather
    than linking analysts out to a separate chat tool.
    """
    lines = [f"# Lesson: {topic.get('title', '')}", ""]
    if topic.get("summary"):
        lines += [topic["summary"], ""]
    if topic.get("why_risky"):
        lines += ["## Why it's risky", topic["why_risky"].strip(), ""]
    if topic.get("key_concepts"):
        lines.append("## Key concepts")
        for c in topic["key_concepts"]:
            lines.append(f"- {c.get('title', '')}: {c.get('body', '')}".strip())
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------

@lessons_bp.route('/lessons/<topic_id>/quiz')
@login_required
def quiz_page(topic_id: str):
    topic = _load_topic(topic_id)
    if topic is None:
        return render_template("lessons/not_found.html", topic_id=topic_id), 404

    email = current_user()["email"]
    seen = training_db.get_seen_question_ids(email, topic["id"])
    sampled = sample_test(topic.get("questions", []), blueprint=TEST_BLUEPRINT, seen_ids=seen)

    rendered = []
    for q in sampled:
        qtype = q.get("type", "mc")
        item = {"id": q["id"], "prompt": q["prompt"], "type": qtype,
                "difficulty": q.get("difficulty", "medium")}
        if qtype == "mc":
            perm = list(range(len(q["choices"])))
            random.shuffle(perm)
            item["choices_in_order"] = [q["choices"][i] for i in perm]
            item["perm"] = ",".join(str(i) for i in perm)
        elif qtype == "fill_blank":
            # Single text box; graded deterministically against accepted_answers.
            pass
        elif qtype == "match":
            # Left labels in order; a shuffled pool of right labels for the dropdowns.
            pairs = q.get("pairs", [])
            item["lefts"] = [p.get("left", "") for p in pairs]
            options = [p.get("right", "") for p in pairs]
            random.shuffle(options)
            item["options"] = options
        else:
            # Open question (short / freetext) — analyst types a response; the LLM grades it.
            item["rows"] = 6 if qtype == "freetext" else 3
        rendered.append(item)
    return render_template(
        "lessons/quiz.html",
        topic=topic,
        questions=rendered,
        time_limit_seconds=QUIZ_TIME_LIMIT_SECONDS,
    )


@lessons_bp.route('/lessons/<topic_id>/quiz/submit', methods=['POST'])
@login_required
def quiz_submit(topic_id: str):
    topic = _load_topic(topic_id)
    if topic is None:
        return render_template("lessons/not_found.html", topic_id=topic_id), 404

    by_id = {q["id"]: q for q in topic.get("questions", [])}
    n = int(request.form.get("n", "0"))
    score = 0.0       # fractional credit earned
    max_score = 0.0   # questions that counted (open Qs drop out if grading is down)
    sampled_ids: list[str] = []
    results = []

    for i in range(n):
        q_id = request.form.get(f"q_id_{i}", "")
        if not q_id or q_id not in by_id:
            continue
        q = by_id[q_id]
        sampled_ids.append(q_id)
        qtype = q.get("type", "mc")

        if qtype == "mc":
            perm_str = request.form.get(f"q_perm_{i}", "")
            answer_str = request.form.get(f"answer_{i}", "")
            max_score += 1
            try:
                perm = [int(x) for x in perm_str.split(",")]
                selected_original = perm[int(answer_str)]
            except (ValueError, IndexError):
                results.append({"q": q, "type": "mc", "correct": False, "selected_original": None})
                continue
            correct = (selected_original == q["answer_idx"])
            if correct:
                score += 1
            results.append({"q": q, "type": "mc", "correct": correct, "selected_original": selected_original})
        elif qtype == "fill_blank":
            user_answer = request.form.get(f"answer_text_{i}", "")
            graded = quiz_grading.grade_fill_blank(q, user_answer)
            max_score += 1
            score += graded["score"]
            results.append({"q": q, "type": "fill_blank", "answer_text": user_answer, "graded": graded})
        elif qtype == "match":
            # Collect the per-row dropdown picks: answer_match_{i}_{row}.
            selections = {}
            for row in range(len(q.get("pairs", []))):
                selections[str(row)] = request.form.get(f"answer_match_{i}_{row}", "")
            graded = quiz_grading.grade_match(q, selections)
            max_score += 1
            score += graded["score"]
            results.append({"q": q, "type": "match", "graded": graded})
        else:
            # Open-ended (short / freetext) — the LLM scores it 0..1 with feedback.
            user_answer = request.form.get(f"answer_text_{i}", "")
            grade = quiz_grading.grade_open_answer(q, user_answer)
            if grade is None:
                # Grading unavailable — don't penalize the learner; just don't count it.
                results.append({"q": q, "type": qtype, "answer_text": user_answer, "grade": None})
                continue
            max_score += 1
            score += grade.score
            results.append({"q": q, "type": qtype, "answer_text": user_answer, "grade": grade})

    try:
        elapsed_seconds = max(0, int(request.form.get("elapsed_seconds", "0")))
    except ValueError:
        elapsed_seconds = 0

    email = current_user()["email"]
    passed = training_db.record_attempt(email, topic["id"], sampled_ids, score, max_score,
                                        elapsed_seconds=elapsed_seconds)
    # Distinction is a display-only tier (not persisted) — 80%+ earns extra fanfare.
    distinction = max_score > 0 and (score / max_score) >= training_db.DISTINCTION_THRESHOLD
    return render_template(
        "lessons/result.html",
        topic=topic,
        score=score,
        total=max_score,
        questions_shown=len(sampled_ids),
        passed=passed,
        distinction=distinction,
        pass_pct=int(training_db.PASS_THRESHOLD * 100),
        distinction_pct=int(training_db.DISTINCTION_THRESHOLD * 100),
        results=results,
        elapsed_seconds=elapsed_seconds,
    )


# ---------------------------------------------------------------------------
# Completion certificate
# ---------------------------------------------------------------------------

def _display_name(email: str) -> str:
    """Friendly name from an email local part — no raw work address on the page."""
    return email.split("@")[0].replace(".", " ").replace("_", " ").title()


@lessons_bp.route('/lessons/<topic_id>/certificate')
@login_required
def certificate_page(topic_id: str):
    topic = _load_topic(topic_id)
    if topic is None:
        return render_template("lessons/not_found.html", topic_id=topic_id), 404
    email = current_user()["email"]
    cert = lesson_certificate.build_certificate(
        email, _display_name(email), topic["id"], topic["title"])
    if cert is None:
        # Not earned yet — send them to the lesson to take (or retake) the quiz.
        return redirect(f"/lessons/{topic['id']}")
    return render_template("lessons/certificate.html", topic=topic, cert=cert)


@lessons_bp.route('/lessons/<topic_id>/certificate.pdf')
@login_required
def certificate_pdf(topic_id: str):
    topic = _load_topic(topic_id)
    if topic is None:
        return render_template("lessons/not_found.html", topic_id=topic_id), 404
    email = current_user()["email"]
    cert = lesson_certificate.build_certificate(
        email, _display_name(email), topic["id"], topic["title"])
    if cert is None:
        return redirect(f"/lessons/{topic['id']}")
    pdf = lesson_certificate.render_pdf(cert)
    safe_name = _display_name(email).replace(" ", "_")
    fname = f"{topic['id']}_certificate_{safe_name}.pdf"
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
