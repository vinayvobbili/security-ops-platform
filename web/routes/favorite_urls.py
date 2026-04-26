"""Favorite URLs routes — page + CRUD API."""

import logging

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from src.components.web.edit_auth import check_edit_password, notify_edit_async

logger = logging.getLogger(__name__)

favorite_urls_bp = Blueprint("favorite_urls", __name__)


@favorite_urls_bp.route("/favorite-urls")
@log_web_activity
def favorite_urls_page():
    from src.components.web import favorite_urls_handler as h

    urls = h.get_all_urls()
    categories = list(urls.keys()) if urls else []
    return render_template(
        "favorite_urls.html",
        urls=urls,
        categories=categories,
    )


@favorite_urls_bp.route("/api/favorite-urls", methods=["POST"])
@log_web_activity
def create_url():
    if not check_edit_password(request, "favorites"):
        return jsonify({"success": False, "error": "Invalid password"}), 403
    try:
        from src.components.web import favorite_urls_handler as h

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Name is required"}), 400

        url_val = (data.get("url") or "").strip()
        phone = (data.get("phone_number") or "").strip()
        if not url_val and not phone:
            return jsonify({"success": False, "error": "URL or phone number is required"}), 400

        category = (data.get("category") or "General").strip()

        item = h.create_url(
            name=name,
            url=url_val,
            phone_number=phone,
            category=category,
        )
        notify_edit_async("Favorite URLs", f"Added **{name}** to {category}")
        return jsonify({"success": True, "item": item})
    except Exception as e:
        logger.error("Error creating favorite URL: %s", e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@favorite_urls_bp.route("/api/favorite-urls/<int:url_id>", methods=["PUT"])
@log_web_activity
def update_url(url_id):
    if not check_edit_password(request, "favorites"):
        return jsonify({"success": False, "error": "Invalid password"}), 403
    try:
        from src.components.web import favorite_urls_handler as h

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        item = h.update_url(url_id, **data)
        if not item:
            return jsonify({"success": False, "error": "Item not found or no changes"}), 404

        notify_edit_async("Favorite URLs", f"Updated item ID {url_id} — **{item.get('name', '')}**")
        return jsonify({"success": True, "item": item})
    except Exception as e:
        logger.error("Error updating favorite URL %s: %s", url_id, e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@favorite_urls_bp.route("/api/favorite-urls/<int:url_id>", methods=["DELETE"])
@log_web_activity
def delete_url(url_id):
    if not check_edit_password(request, "favorites"):
        return jsonify({"success": False, "error": "Invalid password"}), 403
    try:
        from src.components.web import favorite_urls_handler as h

        deleted = h.delete_url(url_id)
        if not deleted:
            return jsonify({"success": False, "error": "Item not found"}), 404
        notify_edit_async("Favorite URLs", f"Deleted item ID {url_id}")
        return jsonify({"success": True, "message": "URL deleted"})
    except Exception as e:
        logger.error("Error deleting favorite URL %s: %s", url_id, e, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500
