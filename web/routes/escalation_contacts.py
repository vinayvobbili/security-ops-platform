"""Escalation Contacts routes — page + CRUD API."""

import logging
import threading

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from src.components.web.edit_auth import notify_edit_async
from web.auth import helpers

logger = logging.getLogger(__name__)

escalation_contacts_bp = Blueprint("escalation_contacts", __name__)

_rebuild_status: dict = {"running": False}


def _upsert_embedding_async(contact_id: int):
    """Upsert a single contact's embedding in a background thread."""
    _rebuild_status["running"] = True
    try:
        from src.components.contacts_lookup import get_contacts_store
        get_contacts_store().upsert_contact(contact_id)
    except Exception as e:
        logger.error("Upsert embedding failed for contact %s: %s", contact_id, e, exc_info=True)
    finally:
        _rebuild_status["running"] = False


def _remove_embedding_async(contact_id: int):
    """Remove a single contact's embedding in a background thread."""
    _rebuild_status["running"] = True
    try:
        from src.components.contacts_lookup import get_contacts_store
        get_contacts_store().remove_contact(contact_id)
    except Exception as e:
        logger.error("Remove embedding failed for contact %s: %s", contact_id, e, exc_info=True)
    finally:
        _rebuild_status["running"] = False


@escalation_contacts_bp.route("/escalation-contacts")
@log_web_activity
def escalation_contacts_page():
    from src.components.web import escalation_contacts_handler as h

    contacts = h.get_all_contacts()
    regions = list(contacts.keys()) if contacts else []
    region_order = ["Global", "APAC", "LATAM", "EMEA", "JAPAN"]
    ordered_regions = [r for r in region_order if r in regions]
    ordered_regions += [r for r in regions if r not in ordered_regions]

    sheet_tabs = h.get_all_sheet_tabs()

    return render_template(
        "escalation_contacts.html",
        contacts=contacts,
        regions=ordered_regions,
        sheet_tabs=sheet_tabs,
    )


@escalation_contacts_bp.route("/api/escalation-contacts", methods=["POST"])
@log_web_activity
def create_contact():
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    try:
        from src.components.web import escalation_contacts_handler as h

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        region = (data.get("region") or "").strip()
        team = (data.get("team") or "").strip()
        name = (data.get("name") or "").strip()

        if not region or not team or not name:
            return jsonify({"success": False, "error": "Region, team, and name are required"}), 400

        contact_id = h.create_contact(
            region=region,
            team=team,
            name=name,
            title=(data.get("title") or "").strip(),
            email=(data.get("email") or "").strip(),
            phone=(data.get("phone") or "").strip(),
            comments=(data.get("comments") or "").strip(),
        )
        contact = h.get_contact(contact_id)
        threading.Thread(target=_upsert_embedding_async, args=(contact_id,), daemon=True).start()
        notify_edit_async("Contacts", f"Added contact **{name}** ({team}, {region})")
        return jsonify({"success": True, "contact": contact})
    except Exception as e:
        logger.error("Error creating contact: %s", e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@escalation_contacts_bp.route("/api/escalation-contacts/<int:contact_id>", methods=["PUT"])
@log_web_activity
def update_contact(contact_id):
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    try:
        from src.components.web import escalation_contacts_handler as h

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        updated = h.update_contact(contact_id, **data)
        if not updated:
            return jsonify({"success": False, "error": "Contact not found or no changes"}), 404

        contact = h.get_contact(contact_id)
        threading.Thread(target=_upsert_embedding_async, args=(contact_id,), daemon=True).start()
        notify_edit_async("Contacts", f"Updated contact ID {contact_id} — **{contact.get('name', '')}**")
        return jsonify({"success": True, "contact": contact})
    except Exception as e:
        logger.error("Error updating contact %s: %s", contact_id, e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@escalation_contacts_bp.route("/api/escalation-contacts/<int:contact_id>", methods=["DELETE"])
@log_web_activity
def delete_contact(contact_id):
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    try:
        from src.components.web import escalation_contacts_handler as h

        deleted = h.delete_contact(contact_id)
        if not deleted:
            return jsonify({"success": False, "error": "Contact not found"}), 404
        threading.Thread(target=_remove_embedding_async, args=(contact_id,), daemon=True).start()
        notify_edit_async("Contacts", f"Deleted contact ID {contact_id}")
        return jsonify({"success": True, "message": "Contact deleted"})
    except Exception as e:
        logger.error("Error deleting contact %s: %s", contact_id, e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@escalation_contacts_bp.route("/api/escalation-contacts/status", methods=["GET"])
@log_web_activity
def rebuild_status():
    return jsonify({"running": _rebuild_status["running"]})
