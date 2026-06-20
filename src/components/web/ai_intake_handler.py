"""AI Project Intake Form Handler for Web Dashboard."""

import html
import logging
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover — Python <3.9
    ZoneInfo = None  # type: ignore

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.azdo import create_wit
from data.data_maps import azdo_orgs, azdo_projects
from src.utils.webex_messaging import safe_send_message

logger = logging.getLogger(__name__)
CONFIG = get_config()

# Database & uploads
DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "ai_intake"
DB_PATH = DATA_DIR / "ai_intake.db"
UPLOADS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "transient" / "ai_intake_uploads"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.pptx',
    '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif', '.svg',
}


@contextmanager
def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the submissions table if it doesn't exist."""
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_name TEXT NOT NULL,
                email TEXT NOT NULL,
                team TEXT NOT NULL,
                project_name TEXT NOT NULL,
                use_case TEXT NOT NULL,
                problem_statement TEXT NOT NULL,
                expected_outcome TEXT NOT NULL,
                priority TEXT NOT NULL,
                data_sources TEXT,
                timeline TEXT NOT NULL,
                additional_notes TEXT,
                documents TEXT,
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Add documents column if upgrading from earlier schema
        cols = [row[1] for row in conn.execute("PRAGMA table_info(submissions)").fetchall()]
        if 'documents' not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN documents TEXT")

        # Comments / discussion thread per submission.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id INTEGER NOT NULL,
                author_name TEXT NOT NULL,
                author_email TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_comments_submission ON comments(submission_id)")
    logger.info(f"AI intake database initialized at {DB_PATH}")


# Auto-init on import
init_db()


def _save_uploads(files: List[FileStorage], project_name: str) -> List[str]:
    """Save uploaded files to a project-named directory. Returns list of saved filenames."""
    if not files:
        return []

    folder_name = secure_filename(project_name) or "unnamed_project"
    sub_dir = UPLOADS_DIR / folder_name
    sub_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    for f in files:
        if not f or not f.filename:
            continue
        name = secure_filename(f.filename)
        if not name:
            continue
        ext = Path(name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            logger.warning(f"Skipped disallowed file type: {name}")
            continue
        # Read content and check size
        content = f.read()
        if len(content) > MAX_FILE_SIZE:
            logger.warning(f"Skipped oversized file: {name} ({len(content)} bytes)")
            continue
        dest = sub_dir / name
        dest.write_bytes(content)
        saved.append(name)
        logger.info(f"Saved upload: {dest}")

    return saved


def get_all_submissions() -> List[Dict[str, Any]]:
    """Return all submissions ordered by most recent first."""
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM submissions ORDER BY submitted_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_submission(submission_id: int) -> Optional[Dict[str, Any]]:
    """Return a single submission by ID, or None if not found."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        return dict(row) if row else None


def delete_submission(submission_id: int) -> bool:
    """Delete a submission by ID. Returns True if a row was deleted."""
    with _get_connection() as conn:
        # Cascade requires foreign_keys pragma; do the cleanup explicitly to be safe.
        conn.execute("DELETE FROM comments WHERE submission_id = ?", (submission_id,))
        cursor = conn.execute("DELETE FROM submissions WHERE id = ?", (submission_id,))
        return cursor.rowcount > 0


_URL_RE = re.compile(r'(https?://[^\s<>"\'`]+)')
_TRAILING_PUNCT = ".,;:!?)]}"


def _linkify(text: str) -> str:
    """HTML-escape ``text`` and turn bare http(s) URLs into anchor tags."""
    if not text:
        return ""
    out: List[str] = []
    last = 0
    for match in _URL_RE.finditer(text):
        out.append(html.escape(text[last:match.start()]))
        url = match.group(1)
        trail = ""
        while url and url[-1] in _TRAILING_PUNCT:
            trail = url[-1] + trail
            url = url[:-1]
        if url:
            href = html.escape(url, quote=True)
            label = html.escape(url)
            out.append(f'<a href="{href}" target="_blank" rel="noopener noreferrer">{label}</a>')
        out.append(html.escape(trail))
        last = match.end()
    out.append(html.escape(text[last:]))
    return "".join(out)


def _format_comment_timestamp(ts: Optional[str]) -> str:
    """Render a SQLite UTC timestamp as ``MM/DD/YYYY HH:MM AM/PM EDT|EST``."""
    if not ts:
        return ""
    raw = ts.split(".")[0] if "." in ts else ts
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return ts
    dt = dt.replace(tzinfo=timezone.utc)
    if ZoneInfo is not None:
        dt_local = dt.astimezone(ZoneInfo("America/New_York"))
        tz_label = dt_local.strftime("%Z") or "ET"
    else:
        dt_local = dt
        tz_label = "UTC"
    return f"{dt_local.strftime('%m/%d/%Y')} {dt_local.strftime('%I:%M %p')} {tz_label}"


def _enrich_comment(row: Dict[str, Any]) -> Dict[str, Any]:
    """Attach display-friendly fields (linkified body, formatted timestamp)."""
    row["body_html"] = _linkify(row.get("body") or "")
    row["created_at_display"] = _format_comment_timestamp(row.get("created_at"))
    return row


def get_comments(submission_id: int) -> List[Dict[str, Any]]:
    """Return all comments for a submission, oldest first."""
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM comments WHERE submission_id = ? ORDER BY created_at ASC, id ASC",
            (submission_id,),
        ).fetchall()
        return [_enrich_comment(dict(row)) for row in rows]


def add_comment(
    submission_id: int,
    author_name: str,
    author_email: str,
    body: str,
) -> Dict[str, Any]:
    """Append a comment to a submission and notify the AI intake Webex room.

    Returns a status dict with the saved comment (or an error message).
    """
    author_name = (author_name or "").strip()
    author_email = (author_email or "").strip()
    body = (body or "").strip()
    if not author_name or not body:
        return {"status": "error", "message": "Name and comment body are required."}
    # Email is optional. If a bare local-part was provided (no @), assume corp domain.
    if author_email and "@" not in author_email:
        author_email = f"{author_email}@the-company.com"

    submission = get_submission(submission_id)
    if not submission:
        return {"status": "error", "message": "Submission not found."}

    with _get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO comments (submission_id, author_name, author_email, body) VALUES (?, ?, ?, ?)",
            (submission_id, author_name, author_email, body),
        )
        comment_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()

    saved = _enrich_comment(dict(row)) if row else None
    logger.info(
        f"AI intake submission {submission_id} new comment #{comment_id} by {author_name} ({author_email})"
    )

    # Webex audit notification — same channel as the intake submission lifecycle.
    base_url = CONFIG.web_server_url
    view_url = f"{base_url}/ai-intake-submissions/{submission_id}#comments"
    access_token = CONFIG.webex_bot_access_token_aide
    room_id = CONFIG.webex_room_id_gs_ai
    if access_token and room_id:
        try:
            webex_api = WebexAPI(access_token=access_token, disable_ssl_verify=True)
            preview = body if len(body) <= 400 else body[:400].rstrip() + "…"
            md = (
                f"💬 **New comment on AI Intake #{submission_id}** — *{submission.get('project_name')}*  \n"
                f"👤 {author_name} ({author_email})  \n\n"
                f"> {preview}  \n\n"
                f"🔗 [Open discussion]({view_url})"
            )
            safe_send_message(
                webex_api,
                room_id,
                markdown=md,
                fallback_text=f"New comment on AI Intake #{submission_id} by {author_name}: {view_url}",
            )
        except Exception as exc:
            logger.warning(f"Could not send AI intake comment Webex notification: {exc}")

    return {"status": "success", "comment": saved}


def get_document_path(submission_id: int, filename: str) -> Optional[Path]:
    """Return the on-disk path of an uploaded document, or None if it
    doesn't belong to the submission or doesn't exist on disk."""
    submission = get_submission(submission_id)
    if not submission:
        return None
    documents = (submission.get('documents') or '').split(',')
    allowed = {d.strip() for d in documents if d.strip()}
    safe_name = secure_filename(filename)
    if not safe_name or safe_name not in allowed:
        return None
    folder = secure_filename(submission.get('project_name') or '') or "unnamed_project"
    fpath = UPLOADS_DIR / folder / safe_name
    return fpath if fpath.is_file() else None


def update_submission(
    submission_id: int,
    form_data: Dict[str, Any],
    files: Optional[List[FileStorage]] = None,
) -> Dict[str, Any]:
    """Update an existing submission. All text fields replaceable; documents append-only."""
    existing = get_submission(submission_id)
    if not existing:
        return {'status': 'error', 'message': 'Submission not found'}

    requester_name = form_data.get('requesterName', '').strip()
    email = form_data.get('email', '').strip()
    team = form_data.get('team', '').strip()
    project_name = form_data.get('projectName', '').strip()
    use_case = form_data.get('useCase', '')
    problem_statement = form_data.get('problemStatement', '').strip()
    expected_outcome = form_data.get('expectedOutcome', '').strip()
    priority = form_data.get('priority', '')
    data_sources = form_data.get('dataSources', '').strip()
    timeline = form_data.get('timeline', '')
    additional_notes = form_data.get('additionalNotes', '').strip()

    required = {
        'Requester Name': requester_name,
        'Email': email,
        'Team / Department': team,
        'Project Name': project_name,
        'Use Case Category': use_case,
        'Problem Statement': problem_statement,
        'Expected Outcome': expected_outcome,
        'Priority': priority,
        'Target Timeline': timeline,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        return {'status': 'error', 'message': f"Missing required fields: {', '.join(missing)}"}

    # Append new uploads to the existing project folder; existing docs are never removed
    saved_files = _save_uploads(files or [], project_name)
    existing_docs = [d.strip() for d in (existing.get('documents') or '').split(',') if d.strip()]
    combined = existing_docs[:]
    for name in saved_files:
        if name not in combined:
            combined.append(name)
    documents_str = ", ".join(combined) if combined else None

    with _get_connection() as conn:
        conn.execute(
            """UPDATE submissions SET
                 requester_name=?, email=?, team=?, project_name=?, use_case=?,
                 problem_statement=?, expected_outcome=?, priority=?, data_sources=?,
                 timeline=?, additional_notes=?, documents=?
               WHERE id=?""",
            (requester_name, email, team, project_name, use_case,
             problem_statement, expected_outcome, priority, data_sources or None,
             timeline, additional_notes or None, documents_str, submission_id),
        )

    # Webex audit notification
    base_url = CONFIG.web_server_url
    view_url = f"{base_url}/ai-intake-submissions/{submission_id}"
    new_docs_str = ", ".join(saved_files) if saved_files else "(no new files)"
    access_token = CONFIG.webex_bot_access_token_aide
    room_id = CONFIG.webex_room_id_gs_ai
    if access_token and room_id:
        try:
            webex_api = WebexAPI(access_token=access_token, disable_ssl_verify=True)
            md = (
                f"✏️ **AI Intake submission #{submission_id} edited** by {requester_name} ({team})  \n"
                f"📋 **{project_name}**  \n"
                f"📎 New attachments: {new_docs_str}  \n"
                f"🔗 [View submission]({view_url})"
            )
            safe_send_message(
                webex_api,
                room_id,
                markdown=md,
                fallback_text=f"AI Intake submission #{submission_id} edited by {requester_name}: {view_url}",
            )
        except Exception as exc:
            logger.warning(f"Could not send AI intake edit Webex notification: {exc}")

    logger.info(f"AI intake submission {submission_id} edited by {requester_name} (added {len(saved_files)} files)")

    return {
        'status': 'success',
        'message': 'Your submission has been updated.',
        'added_files': saved_files,
    }


def handle_ai_intake_submission(
    form_data: Dict[str, Any],
    files: Optional[List[FileStorage]] = None,
) -> Dict[str, Any]:
    """Handles AI project intake form submissions.

    Saves to SQLite, stores uploaded files, and sends a Webex notification.

    Args:
        form_data: Form data from request
        files: List of uploaded FileStorage objects

    Returns:
        Dictionary with status and message
    """
    requester_name = form_data.get('requesterName', '').strip()
    email = form_data.get('email', '').strip()
    team = form_data.get('team', '').strip()
    project_name = form_data.get('projectName', '').strip()
    use_case = form_data.get('useCase', '')
    problem_statement = form_data.get('problemStatement', '').strip()
    expected_outcome = form_data.get('expectedOutcome', '').strip()
    priority = form_data.get('priority', '')
    data_sources = form_data.get('dataSources', '').strip()
    timeline = form_data.get('timeline', '')
    additional_notes = form_data.get('additionalNotes', '').strip()

    # Validate required fields
    required = {
        'Requester Name': requester_name,
        'Email': email,
        'Team / Department': team,
        'Project Name': project_name,
        'Use Case Category': use_case,
        'Problem Statement': problem_statement,
        'Expected Outcome': expected_outcome,
        'Priority': priority,
        'Target Timeline': timeline,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        return {'status': 'error', 'message': f"Missing required fields: {', '.join(missing)}"}

    # Save to database (without documents first to get the ID)
    with _get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO submissions
               (requester_name, email, team, project_name, use_case,
                problem_statement, expected_outcome, priority, data_sources,
                timeline, additional_notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (requester_name, email, team, project_name, use_case,
             problem_statement, expected_outcome, priority, data_sources or None,
             timeline, additional_notes or None)
        )
        submission_id = cursor.lastrowid

    # Save uploaded files
    saved_files = _save_uploads(files or [], project_name)
    if saved_files:
        with _get_connection() as conn:
            conn.execute(
                "UPDATE submissions SET documents = ? WHERE id = ?",
                (", ".join(saved_files), submission_id)
            )

    # Create Azure DevOps work item under REA project
    azdo_url = None
    try:
        wit_description = (
            f"<h3>AI Project Intake Request</h3>"
            f"<b>Requester:</b> {requester_name} ({email})<br>"
            f"<b>Team:</b> {team}<br>"
            f"<b>Category:</b> {use_case}<br>"
            f"<b>Priority:</b> {priority}<br>"
            f"<b>Timeline:</b> {timeline}<br><br>"
            f"<h4>Problem Statement</h4>{problem_statement}<br><br>"
            f"<h4>Expected Outcome</h4>{expected_outcome}"
        )
        if data_sources:
            wit_description += f"<br><br><b>Data Sources:</b> {data_sources}"
        if additional_notes:
            wit_description += f"<br><br><b>Additional Notes:</b> {additional_notes}"
        if saved_files:
            wit_description += f"<br><br><b>Attached Documents:</b> {', '.join(saved_files)}"

        wit_id = create_wit(
            title=f"[AI Intake] {project_name}",
            item_type="User Story",
            description=wit_description,
            project="rea",
            submitter=f"{requester_name} ({email})",
            parent_url=CONFIG.azdo_rea_parent_url,
            iteration=CONFIG.azdo_rea_iteration,
            tags="AI Intake",
        )
        if wit_id:
            from urllib.parse import quote
            org = azdo_orgs.get("rea")
            proj = azdo_projects.get("rea")
            azdo_url = f"https://dev.azure.com/{org}/{quote(proj)}/_workitems/edit/{wit_id}"
            logger.info(f"Created AzDO work item {wit_id} for AI intake: {project_name}")
    except Exception as exc:
        logger.warning(f"Could not create AzDO work item for AI intake: {exc}")

    # Build adaptive card for Webex
    priority_emoji = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴'}.get(priority, '⚪')
    priority_color = {'Low': 'Good', 'Medium': 'Warning', 'High': 'Attention'}.get(priority, 'Default')
    category_emoji = {
        'Automation': '⚙️', 'Data Analysis': '📊', 'Chat/Assistant': '💬',
        'Content Generation': '✍️', 'Threat Detection': '🔍', 'Other': '🧩',
    }.get(use_case, '🧩')
    base_url = CONFIG.web_server_url
    view_url = f"{base_url}/ai-intake-submissions/{submission_id}"

    card_body = [
        # Header
        {
            "type": "TextBlock",
            "text": "🤖 New AI Project Intake Request",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent",
            "horizontalAlignment": "Center",
        },
        {
            "type": "TextBlock",
            "text": "✨ Global Security ✨",
            "size": "Small",
            "isSubtle": True,
            "horizontalAlignment": "Center",
            "spacing": "None",
        },
        # Project name highlight
        {
            "type": "Container",
            "style": "accent",
            "spacing": "Medium",
            "items": [{
                "type": "TextBlock",
                "text": f"📋 {project_name}",
                "weight": "Bolder",
                "size": "Medium",
                "horizontalAlignment": "Center",
                "wrap": True,
            }],
        },
        # Details in columns
        {
            "type": "ColumnSet",
            "spacing": "Medium",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "👤 Requester", "weight": "Bolder", "color": "Accent", "size": "Small"},
                        {"type": "TextBlock", "text": requester_name, "spacing": "None", "wrap": True},
                        {"type": "TextBlock", "text": f"📧 {email}", "size": "Small", "isSubtle": True, "spacing": "None"},
                    ],
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "🏢 Team", "weight": "Bolder", "color": "Accent", "size": "Small"},
                        {"type": "TextBlock", "text": team, "spacing": "None", "wrap": True},
                    ],
                },
            ],
        },
        # Category, Priority, Timeline row
        {
            "type": "ColumnSet",
            "spacing": "Medium",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": f"{category_emoji} Category", "weight": "Bolder", "color": "Accent", "size": "Small"},
                        {"type": "TextBlock", "text": use_case, "spacing": "None"},
                    ],
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "🚦 Priority", "weight": "Bolder", "color": "Accent", "size": "Small"},
                        {"type": "TextBlock", "text": f"{priority_emoji} {priority}", "spacing": "None", "color": priority_color, "weight": "Bolder"},
                    ],
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "📅 Timeline", "weight": "Bolder", "color": "Accent", "size": "Small"},
                        {"type": "TextBlock", "text": timeline, "spacing": "None"},
                    ],
                },
            ],
        },
        # Problem statement
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {"type": "TextBlock", "text": "🎯 Problem Statement", "weight": "Bolder", "color": "Good", "size": "Small"},
                {"type": "TextBlock", "text": problem_statement, "wrap": True, "size": "Small", "spacing": "Small"},
            ],
        },
    ]

    if saved_files:
        card_body.append({
            "type": "TextBlock",
            "text": f"📎 Attachments: {', '.join(saved_files)}",
            "size": "Small",
            "isSubtle": True,
            "spacing": "Medium",
        })

    if azdo_url:
        card_body.append({
            "type": "TextBlock",
            "text": f"📋 [AzDO Work Item]({azdo_url})",
            "size": "Small",
            "color": "Accent",
            "spacing": "Small",
        })

    adaptive_card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": card_body,
        "actions": [
            {"type": "Action.OpenUrl", "title": "🔗 View Submission", "url": view_url, "style": "positive"},
            *([{"type": "Action.OpenUrl", "title": "📋 AzDO Work Item", "url": azdo_url}] if azdo_url else []),
        ],
    }

    attachments = [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": adaptive_card,
    }]

    # Send to GS AI Enablement Webex space via Aide
    access_token = CONFIG.webex_bot_access_token_aide
    room_id = CONFIG.webex_room_id_gs_ai

    if access_token and room_id:
        try:
            webex_api = WebexAPI(access_token=access_token, disable_ssl_verify=True)
            success = safe_send_message(
                webex_api,
                room_id,
                text=f"New AI Project Intake: {project_name} from {requester_name} ({team})",
                attachments=attachments,
            )
            if not success:
                logger.warning("Webex message send returned False for AI intake submission")
        except Exception as exc:
            logger.warning(f"Could not send AI intake Webex notification: {exc}")
    else:
        logger.warning("Webex credentials not configured — AI intake notification skipped")

    logger.info(f"AI intake submission received: '{project_name}' from {requester_name} ({team})")

    result = {
        'status': 'success',
        'message': 'Your AI project request has been submitted. The team has been notified and will follow up.',
        'submission_url': view_url,
        'submission_id': submission_id,
    }
    if azdo_url:
        result['azdo_url'] = azdo_url
    return result
