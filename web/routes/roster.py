"""SecOps Daily Roster routes - page + CRUD API."""

import logging
import threading
from datetime import datetime

import pytz
from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity, get_client_ip

logger = logging.getLogger(__name__)

roster_bp = Blueprint("roster", __name__)

SHIFT_META = {
    "shift1": {"label": "Shift 1", "icon": "&#127769;", "time_et": "7:30 PM - 4:30 AM ET", "time_ist": "6:00 AM - 3:00 PM IST", "css": "shift1"},
    "shift2": {"label": "Shift 2", "icon": "&#9728;&#65039;", "time_et": "3:30 AM - 12:30 PM ET", "time_ist": "2:00 PM - 11:00 PM IST", "css": "shift2"},
    "shift3": {"label": "Shift 3", "icon": "&#127780;&#65039;", "time_et": "6:30 AM - 3:30 PM ET", "time_ist": "5:00 PM - 2:00 AM IST", "css": "shift3"},
    "shift4": {"label": "Shift 4", "icon": "&#127747;", "time_et": "11:30 AM - 8:30 PM ET", "time_ist": "10:00 PM - 7:00 AM IST", "css": "shift4"},
}


def _notify_roster_change(message: str):
    """Send roster change notification to Webex rooms in a background thread."""
    def _send():
        try:
            from my_config import get_config
            from webexpythonsdk import WebexAPI

            config = get_config()
            webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
            for room_id in [config.webex_room_id_dev_test_space]:
                if not room_id:
                    continue
                try:
                    webex_api.messages.create(roomId=room_id, markdown=message)
                except Exception as e:
                    logger.error(f"Failed to send roster notification to {room_id}: {e}")
        except Exception as e:
            logger.error(f"Roster notification error: {e}", exc_info=True)

    threading.Thread(target=_send, daemon=True).start()


def _notify_new_schedule(message: str):
    """Send new schedule notification to ThreatCon collab room."""
    def _send():
        try:
            from my_config import get_config
            from webexpythonsdk import WebexAPI

            config = get_config()
            room_id = config.webex_room_id_threatcon_collab
            if not room_id:
                return
            webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
            webex_api.messages.create(roomId=room_id, markdown=message)
        except Exception as e:
            logger.error(f"ThreatCon roster notification error: {e}", exc_info=True)

    threading.Thread(target=_send, daemon=True).start()


# --- Page ---

@roster_bp.route("/roster")
@log_web_activity
def roster_page():
    from src.components import roster
    from src.secops.shift_utils import get_current_shift

    data = roster.load_data()
    current_period_id = roster.get_current_period_id()
    requested_period = request.args.get("period", current_period_id)

    eastern = pytz.timezone('US/Eastern')
    now = datetime.now(eastern)
    current_day = now.strftime('%A')
    legacy_shift = get_current_shift()
    current_shift = roster.LEGACY_TO_ROSTER.get(legacy_shift, legacy_shift)

    # Ensure current period always exists
    roster.ensure_period(data, current_period_id)

    # Check if requested period exists
    period_exists = requested_period in data.get("periods", {})
    schedule = data["periods"][requested_period]["schedule"] if period_exists else None

    # Current staffing for banner
    current_staffing = roster.get_staffing_for_day(current_day, current_shift)
    seniors = current_staffing.get('senior_analysts', [])
    current_lead = seniors[0] if seniors else None

    # Period navigation
    prev_period = roster.get_adjacent_period_id(requested_period, -1)
    next_period = roster.get_adjacent_period_id(requested_period, +1)

    # Rotate shifts so the active one is first, rest follow chronologically
    shifts_ordered = list(roster.SHIFTS)
    if requested_period == current_period_id and current_shift in shifts_ordered:
        idx = shifts_ordered.index(current_shift)
        shifts_ordered = shifts_ordered[idx:] + shifts_ordered[:idx]

    # Group members by their primary role from the schedule
    members_by_role = roster.get_members_by_role(schedule, data)
    all_members = roster.get_team_members(data)
    assigned = set()
    for names in members_by_role.values():
        assigned.update(names)
    unassigned = sorted(n for n in all_members if n not in assigned)

    member_details = roster.get_team_member_details(data)

    return render_template(
        "roster.html",
        schedule=schedule,
        period_exists=period_exists,
        periods=roster.get_all_periods(data),
        requested_period=requested_period,
        current_period_id=current_period_id,
        period_label=roster.period_label(requested_period),
        prev_period=prev_period,
        next_period=next_period,
        current_day=current_day,
        current_shift=current_shift,
        current_lead=current_lead,
        team_members=all_members,
        member_details=member_details,
        members_by_role=members_by_role,
        unassigned_members=unassigned,
        shift_meta=SHIFT_META,
        days=roster.DAYS_OF_WEEK,
        shifts=shifts_ordered,
        teams=roster.TEAMS,
        slots_per_team=roster.SLOTS_PER_TEAM,
    )


# --- API ---

@roster_bp.route("/api/roster/period/<period_id>")
@log_web_activity
def api_get_period(period_id):
    from src.components import roster
    data = roster.load_data()
    period = data.get("periods", {}).get(period_id)
    if not period:
        return jsonify({"success": False, "error": "Period not found"}), 404
    return jsonify({"success": True, "period": period, "label": roster.period_label(period_id)})


@roster_bp.route("/api/roster/period", methods=["POST"])
@log_web_activity
def api_create_period():
    from src.components import roster
    body = request.get_json()
    if not body:
        return jsonify({"success": False, "error": "No data"}), 400
    period_id = (body.get("period_id") or "").strip()
    if not period_id:
        return jsonify({"success": False, "error": "Period ID required"}), 400

    data = roster.load_data()
    if period_id in data.get("periods", {}):
        return jsonify({"success": False, "error": "Period already exists"}), 409

    roster.ensure_period(data, period_id)
    label = roster.period_label(period_id)
    _notify_roster_change(f"**Roster Update:** New schedule created for **{label}** ({get_client_ip()})")
    _notify_new_schedule(f"**New SecOps Schedule:** A new daily roster has been created for **{label}**. "
                         f"View and fill it out at [/roster](/roster?period={period_id}).")
    return jsonify({"success": True})


@roster_bp.route("/api/roster/slot", methods=["PUT"])
@log_web_activity
def api_update_slot():
    from src.components import roster
    body = request.get_json()
    if not body:
        return jsonify({"success": False, "error": "No data"}), 400

    period_id = (body.get("period_id") or "").strip()
    day = (body.get("day") or "").strip()
    shift = (body.get("shift") or "").strip()
    team = (body.get("team") or "").strip()
    slot = body.get("slot")
    name = (body.get("name") or "").strip()

    if not all([period_id, day, shift, team]) or slot is None:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    if roster.update_slot(period_id, day, shift, team, int(slot), name):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid parameters"}), 400


@roster_bp.route("/api/roster/team-members", methods=["POST"])
@log_web_activity
def api_add_team_member():
    from src.components import roster
    body = request.get_json()
    name = (body.get("name") or "").strip() if body else ""
    email = (body.get("email") or "").strip() if body else ""
    role = (body.get("role") or "").strip() if body else ""
    if not name:
        return jsonify({"success": False, "error": "Name required"}), 400
    if roster.add_team_member(name, email=email, role=role):
        _notify_roster_change(f"**Roster Update:** {name} added to team roster ({get_client_ip()})")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Already exists"}), 409


@roster_bp.route("/api/roster/team-members", methods=["PUT"])
@log_web_activity
def api_update_team_member():
    from src.components import roster
    body = request.get_json()
    if not body:
        return jsonify({"success": False, "error": "No data"}), 400
    old_name = (body.get("old_name") or "").strip()
    first_name = (body.get("first_name") or "").strip()
    last_name = (body.get("last_name") or "").strip()
    email = (body.get("email") or "").strip()
    if not old_name or not (first_name or last_name):
        return jsonify({"success": False, "error": "Name required"}), 400
    result = roster.update_team_member(old_name, first_name, last_name, email)
    if result["success"]:
        new_name = result["new_name"]
        if new_name != old_name:
            _notify_roster_change(f"**Roster Update:** {old_name} renamed to {new_name} ({get_client_ip()})")
        return jsonify({"success": True, "new_name": new_name})
    return jsonify({"success": False, "error": result["error"]}), 400


@roster_bp.route("/api/roster/team-members", methods=["DELETE"])
@log_web_activity
def api_remove_team_member():
    from src.components import roster
    body = request.get_json()
    name = (body.get("name") or "").strip() if body else ""
    if not name:
        return jsonify({"success": False, "error": "Name required"}), 400
    if roster.remove_team_member(name):
        _notify_roster_change(f"**Roster Update:** {name} removed from team roster ({get_client_ip()})")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Not found"}), 404
