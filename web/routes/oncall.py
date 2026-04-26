"""On-Call Schedule Management routes - page + CRUD API."""

import logging
import threading
from datetime import date, timedelta

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity, get_client_ip

logger = logging.getLogger(__name__)

oncall_bp = Blueprint("oncall", __name__)

# Analyst color palette (consistent assignment by index)
ANALYST_COLORS = [
    "#3b82f6",  # blue
    "#10b981",  # emerald
    "#f59e0b",  # amber
    "#ef4444",  # red
    "#8b5cf6",  # violet
    "#06b6d4",  # cyan
    "#f97316",  # orange
    "#ec4899",  # pink
    "#14b8a6",  # teal
    "#6366f1",  # indigo
]


def _notify_oncall_change(message: str):
    """Send on-call change notification to Webex rooms in a background thread."""
    def _send():
        try:
            from my_config import get_config
            from webexpythonsdk import WebexAPI

            config = get_config()
            webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
            for room_id in [config.webex_room_id_response_engineering, config.webex_room_id_dev_test_space]:
                if not room_id:
                    continue
                try:
                    webex_api.messages.create(roomId=room_id, markdown=message)
                except Exception as e:
                    logger.error(f"Failed to send on-call notification to {room_id}: {e}")
        except Exception as e:
            logger.error(f"On-call notification error: {e}", exc_info=True)

    threading.Thread(target=_send, daemon=True).start()


def _build_rotation_display(rotation, analysts):
    """Build rotation entries with display dates and status flags."""
    today = date.today()
    current_monday = today - timedelta(days=today.weekday())
    # Show from 4 weeks ago
    cutoff = current_monday - timedelta(weeks=4)

    # Build analyst color map
    analyst_names = [a["name"] for a in analysts]
    color_map = {name: ANALYST_COLORS[i % len(ANALYST_COLORS)] for i, name in enumerate(analyst_names)}

    entries = []
    for entry in rotation:
        try:
            monday = date.fromisoformat(entry["Monday_date"])
        except (ValueError, KeyError):
            continue
        if monday < cutoff:
            continue

        sunday = monday + timedelta(days=6)
        if monday.month == sunday.month:
            display_date = f"{monday.strftime('%b %d')} - {sunday.day}"
        else:
            display_date = f"{monday.strftime('%b %d')} - {sunday.strftime('%b %d')}"

        if monday < current_monday:
            status = "past"
        elif monday == current_monday:
            status = "current"
        else:
            status = "future"

        name = entry.get("analyst_name", "Unassigned")
        entries.append({
            "monday_date": entry["Monday_date"],
            "analyst_name": name,
            "display_date": display_date,
            "display_monday": monday.strftime("%b %d"),
            "display_sunday": sunday.strftime("%b %d"),
            "month_label": monday.strftime("%B %Y"),
            "status": status,
            "color": color_map.get(name, "#94a3b8"),
        })

    return entries, color_map


@oncall_bp.route("/oncall")
@log_web_activity
def oncall_page():
    from src.components import oncall as oc

    data = oc.get_all_data()
    current = oc.get_on_call_person()
    analysts = data.get("analysts", [])
    rotation = data.get("rotation", [])

    entries, color_map = _build_rotation_display(rotation, analysts)

    # Group entries by month for calendar display
    months = {}
    for entry in entries:
        label = entry["month_label"]
        months.setdefault(label, []).append(entry)

    return render_template(
        "oncall.html",
        current=current,
        analysts=analysts,
        months=months,
        color_map=color_map,
    )


# --- API endpoints ---

@oncall_bp.route("/api/oncall", methods=["GET"])
@log_web_activity
def api_get_oncall():
    from src.components import oncall as oc
    data = oc.get_all_data()
    current = oc.get_on_call_person()
    return jsonify({"success": True, "data": data, "current": current})


@oncall_bp.route("/api/oncall/analysts", methods=["POST"])
@log_web_activity
def api_add_analyst():
    try:
        from src.components import oncall as oc
        body = request.get_json()
        if not body:
            return jsonify({"success": False, "error": "No data provided"}), 400

        name = (body.get("name") or "").strip()
        email = (body.get("email_address") or "").strip()
        phone = (body.get("phone_number") or "").strip()

        if not name:
            return jsonify({"success": False, "error": "Name is required"}), 400
        if oc.add_analyst(name, email, phone):
            _notify_oncall_change(f"**On-Call Update:** {name} added to the on-call roster ({get_client_ip()})")
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Analyst already exists"}), 409
    except Exception as e:
        logger.error(f"Error adding analyst: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error"}), 500


@oncall_bp.route("/api/oncall/analysts", methods=["PUT"])
@log_web_activity
def api_update_analyst():
    try:
        from src.components import oncall as oc
        body = request.get_json()
        if not body:
            return jsonify({"success": False, "error": "No data provided"}), 400

        original_name = (body.get("original_name") or "").strip()
        name = (body.get("name") or "").strip()
        email = (body.get("email_address") or "").strip()
        phone = (body.get("phone_number") or "").strip()

        if not original_name or not name:
            return jsonify({"success": False, "error": "Name is required"}), 400
        if oc.update_analyst(original_name, name, email, phone):
            _notify_oncall_change(f"**On-Call Update:** {original_name}'s details updated ({get_client_ip()})")
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Analyst not found"}), 404
    except Exception as e:
        logger.error(f"Error updating analyst: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error"}), 500


@oncall_bp.route("/api/oncall/analysts", methods=["DELETE"])
@log_web_activity
def api_delete_analyst():
    try:
        from src.components import oncall as oc
        body = request.get_json()
        if not body:
            return jsonify({"success": False, "error": "No data provided"}), 400

        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Name is required"}), 400
        if oc.remove_analyst(name):
            _notify_oncall_change(f"**On-Call Update:** {name} removed from the on-call roster ({get_client_ip()})")
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Analyst not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting analyst: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error"}), 500


@oncall_bp.route("/api/oncall/rotation", methods=["PUT"])
@log_web_activity
def api_update_rotation():
    try:
        from src.components import oncall as oc
        body = request.get_json()
        if not body:
            return jsonify({"success": False, "error": "No data provided"}), 400

        monday_date = (body.get("monday_date") or "").strip()
        analyst_name = (body.get("analyst_name") or "").strip()

        if not monday_date or not analyst_name:
            return jsonify({"success": False, "error": "Date and analyst are required"}), 400
        if oc.assign_week(monday_date, analyst_name):
            _notify_oncall_change(f"**On-Call Update:** Week of {monday_date} assigned to **{analyst_name}** ({get_client_ip()})")
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Failed to update"}), 500
    except Exception as e:
        logger.error(f"Error updating rotation: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error"}), 500


@oncall_bp.route("/api/oncall/swap", methods=["POST"])
@log_web_activity
def api_swap_weeks():
    try:
        from src.components import oncall as oc
        body = request.get_json()
        if not body:
            return jsonify({"success": False, "error": "No data provided"}), 400

        d1 = (body.get("monday_date_1") or "").strip()
        d2 = (body.get("monday_date_2") or "").strip()

        if not d1 or not d2:
            return jsonify({"success": False, "error": "Both dates required"}), 400
        if oc.swap_weeks(d1, d2):
            _notify_oncall_change(f"**On-Call Update:** Weeks {d1} and {d2} swapped ({get_client_ip()})")
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Weeks not found"}), 404
    except Exception as e:
        logger.error(f"Error swapping weeks: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error"}), 500
