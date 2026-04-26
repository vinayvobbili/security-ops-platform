"""Cyber Tool Inventory page — searchable list of CISO-org tools."""

from flask import Blueprint, jsonify, render_template

from src.components.web import cyber_tool_inventory_handler
from src.utils.logging_utils import log_web_activity

cyber_tool_inventory_bp = Blueprint("cyber_tool_inventory", __name__)


@cyber_tool_inventory_bp.route("/cyber-tool-inventory")
@log_web_activity
def display_cyber_tool_inventory():
    """Render the inventory page."""
    rows = cyber_tool_inventory_handler.get_inventory()
    return render_template("cyber_tool_inventory.html", tool_count=len(rows))


@cyber_tool_inventory_bp.route("/api/cyber-tool-inventory/list")
@log_web_activity
def api_cyber_tool_inventory_list():
    """Return the full inventory as JSON."""
    rows = cyber_tool_inventory_handler.get_inventory()
    return jsonify({"count": len(rows), "rows": rows})
