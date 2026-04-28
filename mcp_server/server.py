"""
IR Unified MCP Server

Single FastMCP 2.0 server exposing tools from all IR service integrations.
Run: python -m mcp_server.server
"""

import logging
import sys
from pathlib import Path

from fastmcp import FastMCP

# Ensure project root is on sys.path so `services.*` imports work
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# --- Logging ---
_log_dir = Path(_project_root) / "logs"
_log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(_log_dir / "mcp_server.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("mcp_server")

# --- FastMCP App ---
mcp = FastMCP("ir-security-ops")

# --- Register tool modules ---
# Each module imports `mcp` and decorates functions with @mcp.tool()
from mcp_server.tools import (  # noqa: E402, F401
    # --- Existing integrations ---
    crowdstrike,
    tanium,
    service_now,
    qradar,
    xsiam,
    virustotal,
    recorded_future,
    xsoar,
    dfir_iris,
    thehive,
    abnormal,
    vectra,
    attackiq,
    oe_detection,
    # --- Threat intelligence ---
    abuseipdb,
    abusech,
    shodan,
    urlscan,
    intelx,
    hibp,
    # --- Identity & infrastructure ---
    active_directory,
    varonis,
    # --- SOC operations ---
    contacts,
    staffing,
    memory,
    wiki,
    # --- Utilities ---
    web_search,
    weather,
    block_url,
    diagrams,
)

logger.info("All tool modules registered")


# Entry point: python -m mcp_server  (uses __main__.py)
# Do NOT run this file directly — causes double-import of the mcp instance.
