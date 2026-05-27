#!/usr/bin/python3

import sys
from pathlib import Path

ROOT_DIRECTORY = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIRECTORY))

# Setup logging FIRST before any imports that might use it
import logging

from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='barnacles',
    log_level=logging.INFO,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager'],
    rotate_on_startup=False  # Keep logs continuous, rely on RotatingFileHandler for size-based rotation
)

# Note: Noisy library logs are suppressed by ResilientBot framework

logger = logging.getLogger(__name__)

# Suppress noisy messages from webex libraries
logging.getLogger('webex_bot').setLevel(logging.ERROR)  # Suppress bot-to-bot and self-message warnings
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)

# ALWAYS configure SSL for proxy environments (auto-detects the corporate proxy/proxies)
from src.utils.ssl_config import configure_ssl_if_needed
configure_ssl_if_needed(verbose=True)

# ALWAYS apply enhanced WebSocket patches for connection resilience
# This is critical to prevent the bot from going to sleep
from src.utils.enhanced_websocket_client import patch_websocket_client
patch_websocket_client()

# Import datetime for startup marker
from datetime import datetime as dt_for_marker

# Log clear startup marker for visual separation in logs
logger.warning("=" * 100)
logger.warning(f"🚀 BARNACLES BOT STARTED - {dt_for_marker.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

import json
import re
import random
import signal
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import threading
import time

import anthropic
import requests as _requests
from my_bot.core.mcp_client import MCPClient
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    Column, AdaptiveCard, ColumnSet, Image,
    HorizontalAlignment, ActionSet, ImageStyle, ActionStyle, Choice, FactSet, Fact
)
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from src.charts import threatcon_level
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_pool_config import configure_webex_api_session

config = get_config()
bot_token = config.webex_bot_access_token_barnacles
# Configure WebexTeamsAPI with larger connection pool to prevent timeout issues
webex_api = configure_webex_api_session(
    WebexTeamsAPI(
        access_token=bot_token,
        single_request_timeout=120
    ),
    pool_connections=50,
    pool_maxsize=50,
    max_retries=3
)

# Global variables
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

NOTES_FILE = ROOT_DIRECTORY / "data" / "transient" / "secOps" / "management_notes.json"
THREAT_CON_FILE = ROOT_DIRECTORY / "data" / "transient" / "secOps" / "threatcon.json"
COMPANY_LOGO_BASE64 = ROOT_DIRECTORY / "web" / "static" / "icons" / "company_logo.txt"

with open(COMPANY_LOGO_BASE64, "r") as file:
    company_logo = file.read()

ICONS_BY_COLOR = {
    'green': '🟢',
    'yellow': '🟡',
    'orange': '🟠',
    'red': '🔴'
}

# Fun ThreatCon related messages
THREATCON_MESSAGES = {
    "green": ["🌿 All clear! Smooth sailing ahead!", "🍃 Peaceful waters, captain!", "☘️ Green means go!"],
    "yellow": ["⚠️ Caution advised, stay alert!", "🟡 Moderate threat detected!", "🚧 Proceed with awareness!"],
    "orange": ["🚨 Elevated threat level!", "🔥 High alert status!", "⚡ Heightened security mode!"],
    "red": ["🚩 MAXIMUM ALERT! All hands on deck!", "🔴 CRITICAL THREAT LEVEL!", "⭐ Emergency protocols active!"]
}

BARNACLES_QUOTES = [
    "⚓ Anchors aweigh!",
    "🌊 Steady as she goes!",
    "🧭 Charting the course ahead!",
    "⛵ Full speed ahead!",
    "🏴‍☠️ Yo ho ho and a bottle of... data!"
]


class BotStatusCommand(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="🔍 Check bot health and status",
            delete_previous_message=True,
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        current_time = datetime.now(EASTERN_TZ)

        # Simple status using the resilience framework
        health_status = "🟢 Healthy"
        health_detail = "Running with resilience framework"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        # Create status card with enhanced details
        status_card = AdaptiveCard(
            body=[
                TextBlock(
                    text="⚓ the alert triage service Bot 🤖 Status",
                    color=Colors.GOOD,
                    size=FontSize.LARGE,
                    weight=FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Status Information**", weight=FontWeight.BOLDER),
                                TextBlock(text=f"Status: {health_status}"),
                                TextBlock(text=f"Details: {health_detail}"),
                                TextBlock(text=f"Framework: BotResilient (auto-reconnect, health monitoring)"),
                                TextBlock(text=f"Current Time: {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
                            ]
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text="Bot Status Information",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}]
        )


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


# Command to save notes
class SaveManagementNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_notes",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(NOTES_FILE, "w") as file:
                file.write(json.dumps({
                    "note": attachment_actions.inputs['management_notes'],
                    "keep_until": attachment_actions.inputs['keep_until']
                }, indent=4))

            card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="Notes Updated Successfully",
                        weight=FontWeight.BOLDER,
                        color=Colors.ACCENT,
                        size=FontSize.DEFAULT,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                    FactSet(
                        facts=[
                            Fact(title="Note", value=attachment_actions.inputs['management_notes']),
                            Fact(title="Keep Until", value=attachment_actions.inputs['keep_until'])
                        ]
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Notes Saved Successfully',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"Management notes saved successfully by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to save notes: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


# Command to view/edit notes
class ManagementNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="notes",
            help_message="Management Notes",
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(NOTES_FILE, "r") as file:
                management_notes = file.read()
                management_notes = json.loads(management_notes)
                note = management_notes['note']
                keep_until = management_notes['keep_until']

            today = datetime.now().strftime("%Y-%m-%d")
            next_week = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
            tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

            card = AdaptiveCard(
                body=[
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    Image(
                                        url=company_logo,
                                        height="30px",
                                        style=ImageStyle.PERSON
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    TextBlock(
                                        text="Management Notes",
                                        wrap=True,
                                        size=FontSize.MEDIUM,
                                        weight=FontWeight.BOLDER,
                                        color=Colors.ACCENT,
                                        horizontalAlignment=HorizontalAlignment.CENTER,
                                    )
                                ],
                                width="stretch",
                            )
                        ]
                    ),
                    INPUTS.Text(
                        id="management_notes",
                        isMultiline=True,
                        value=note,
                        placeholder="Enter notes here",
                        isRequired=True,
                    ),
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    TextBlock(
                                        text="Keep Until",
                                        horizontalAlignment=HorizontalAlignment.LEFT,
                                        color=OPTIONS.Colors.DARK,
                                        height=OPTIONS.BlockElementHeight.STRETCH
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    INPUTS.Date(
                                        id='keep_until',
                                        max=next_week,
                                        min=today,
                                        value=keep_until or tomorrow,
                                        isRequired=True,
                                        height=OPTIONS.BlockElementHeight.AUTO
                                    )
                                ],
                                width="175px",
                            )
                        ]
                    ),
                    ActionSet(
                        actions=[
                            Submit(
                                title="Update",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "save_notes"},
                            ),
                        ],
                        spacing=OPTIONS.Spacing.NONE,
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Management Notes',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"Management notes viewed by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to load notes: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


# Command to update threatcon level
class SaveThreatcon(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_threatcon",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            level = attachment_actions.inputs['threatcon_level']
            reason = attachment_actions.inputs['reason']

            threatcon_details = {
                "level": level,
                "reason": reason
            }

            with open(THREAT_CON_FILE, "w") as file:
                json.dump(threatcon_details, file, indent=4)

            # Generate the chart so the user can preview before announcing
            threatcon_level.make_chart()
            today_date = datetime.now().strftime('%m-%d-%Y')
            chart_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Threatcon Level.png"

            # Send chart preview
            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text=f"ThreatCon Level Updated to {ICONS_BY_COLOR.get(level, '🟢')} {level.capitalize()}",
                files=[str(chart_path)]
            )

            # Send announce action card
            card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="ThreatCon Level Updated Successfully",
                        weight=FontWeight.BOLDER,
                        color=Colors.ACCENT,
                        horizontalAlignment=HorizontalAlignment.CENTER
                    ),
                    TextBlock(
                        text=f"ThreatCon Level: {ICONS_BY_COLOR.get(level, '🟢') + ' ' + level.capitalize()}",
                    ),
                    TextBlock(
                        text=f"Reason: \n {reason}",
                        wrap=True
                    ),
                    ActionSet(
                        actions=[
                            Submit(
                                title="Announce in ThreatCon Chat",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "announce_threatcon"}
                            )
                        ]
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='ThreatCon Level Updated Successfully',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"ThreatCon level updated to {level} by {activity['actor']['displayName']}")

            # Send a fun ThreatCon-related message
            fun_message = get_threatcon_message(level)
            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text=fun_message
            )

        except Exception as e:
            error_msg = f"❌ Failed to save ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threatcon",
            help_message="ThreatCon Level",
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(THREAT_CON_FILE, "r") as file:
                threatcon_details = json.load(file)

            level = threatcon_details.get('level', 'green')
            reason = threatcon_details.get('reason', 'No current threats!')

            card = AdaptiveCard(
                body=[
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    Image(
                                        url=company_logo,
                                        height="30px",
                                        style=ImageStyle.PERSON
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    TextBlock(
                                        text="ThreatCon",
                                        wrap=True,
                                        size=FontSize.LARGE,
                                        weight=FontWeight.BOLDER,
                                        color=Colors.ACCENT,
                                        horizontalAlignment=HorizontalAlignment.CENTER
                                    )
                                ],
                                width="stretch"
                            )
                        ]
                    ),
                    INPUTS.ChoiceSet(
                        id="threatcon_level",
                        value=level,
                        label="Level",
                        choices=[
                            Choice(title="🟢 Green", value="green"),
                            Choice(title="🟡 Yellow", value="yellow"),
                            Choice(title="🟠 Orange", value="orange"),
                            Choice(title="🔴 Red", value="red"),
                        ],
                        style=OPTIONS.ChoiceInputStyle.EXPANDED
                    ),
                    INPUTS.Text(
                        id="reason",
                        label="Reason",
                        isMultiline=True,
                        value=reason,
                        placeholder="Enter reason here",
                        isRequired=True
                    ),
                    ActionSet(
                        spacing=OPTIONS.Spacing.NONE,
                        actions=[
                            Submit(
                                title="Update",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "save_threatcon"}
                            )
                        ],
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Threatcon Level',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"ThreatCon level viewed by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to load ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class AnnounceThreatcon(Command):
    def __init__(self):
        super().__init__(
            command_keyword="announce_threatcon",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            threatcon_level.make_chart()

            today_date = datetime.now().strftime('%m-%d-%Y')
            file_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Threatcon Level.png"

            WebexTeamsAPI(access_token=config.webex_bot_access_token_toodles).messages.create(
                roomId=config.webex_room_id_threatcon_collab,
                text=f"🚨 **NEW THREATCON LEVEL ANNOUNCEMENT!** 🚨",
                files=[str(file_path)]
            )

            # Confirm to user
            confirmation_card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="ThreatCon Announcement Sent",
                        weight=FontWeight.BOLDER,
                        color=Colors.GOOD,
                        horizontalAlignment=HorizontalAlignment.CENTER
                    ),
                    TextBlock(
                        text=f"The ThreatCon Level change has been announced.",
                        wrap=True
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='ThreatCon Announcement Sent',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": confirmation_card.to_dict()}]
            )
            logger.info(f"ThreatCon announcement sent by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to announce ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


def get_random_barnacles_quote():
    """Get a random nautical quote."""
    return random.choice(BARNACLES_QUOTES)


def get_threatcon_message(level):
    """Get a themed message for ThreatCon levels."""
    return random.choice(THREATCON_MESSAGES.get(level, THREATCON_MESSAGES["green"]))


class AlertTriageBot(WebexBot):
    """the alert triage service Bot — Claude API + MCP server for all tool calls.

    Free-form messages go to Claude with the full MCP toolset.
    Keyword commands (notes, threatcon, bot_status) fall through to the
    existing card-based handlers unchanged.
    """

    # Commands handled by card-based keyword handlers — bypass Claude for these
    _KEYWORD_COMMANDS = frozenset(['notes', 'threatcon', 'bot_status'])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = get_config()

        # Claude API client — uses barnacles_claude_api_key (BARNACLES_CLAUDE_API_KEY)
        # so that Pokédex never picks up this key and stays on the local LLM.
        self._claude = anthropic.Anthropic(api_key=cfg.barnacles_claude_api_key) if cfg.barnacles_claude_api_key else None
        self._model = cfg.claude_model or "claude-sonnet-4-6"

        # MCP client — all tool calls go through the Lab VM MCP server
        self._mcp = MCPClient(cfg.mcp_server_url or "http://127.0.0.1:8200/mcp")

        # Claude API format tools, with cache_control on last entry
        self._tools: list = []

        # In-memory session history per user (last 20 messages ≈ 10 turns)
        self._sessions: dict[str, list] = {}

        # Monthly cost tracker (persisted to disk)
        self._cost_file = ROOT_DIRECTORY / "data" / "transient" / "barnacles_cost.json"
        self._monthly_cost = self._load_monthly_cost()

        self._init_tools()

    def _load_monthly_cost(self) -> float:
        """Load current month's accumulated cost from disk."""
        month_key = datetime.now(EASTERN_TZ).strftime('%Y-%m')
        try:
            with open(self._cost_file) as f:
                data = json.load(f)
            return data.get(month_key, 0.0)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0.0

    def _save_monthly_cost(self, cost: float) -> None:
        """Add cost to current month's total and persist."""
        month_key = datetime.now(EASTERN_TZ).strftime('%Y-%m')
        try:
            with open(self._cost_file) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        self._monthly_cost = data.get(month_key, 0.0) + cost
        data[month_key] = self._monthly_cost
        with open(self._cost_file, 'w') as f:
            json.dump(data, f)

    def _init_tools(self) -> None:
        """Discover tools from MCP server and prepare cached list for Claude."""
        mcp_tools = self._mcp.list_tools()
        if not mcp_tools:
            logger.warning("the alert triage service: no tools from MCP server — Claude will run without tools")
            return

        # MCP format: {name, description, inputSchema}
        # Claude format: {name, description, input_schema}
        claude_tools = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("inputSchema", {"type": "object", "properties": {}}),
            }
            for t in mcp_tools
        ]

        # cache_control on the last tool caches system prompt + all tool definitions
        last = dict(claude_tools[-1])
        last["cache_control"] = {"type": "ephemeral"}
        claude_tools[-1] = last

        self._tools = claude_tools
        logger.info(f"the alert triage service: {len(claude_tools)} tools loaded from MCP server, prompt caching enabled")

    def _system_prompt(self, room_id: str = "", parent_id: str = "", user_email: str = "") -> str:
        today = datetime.now(EASTERN_TZ).strftime('%A, %B %d, %Y')
        prompt = (
            "You are the alert triage service, the personal AI assistant for the head of Cyber Security "
            "Detection and Response. Your user is fully trusted — help with anything asked, "
            "whether it's security operations, general research, writing, analysis, brainstorming, "
            "or just a quick question. Don't restrict topics or second-guess the requests.\n\n"
            "You have the full security operations toolset available: threat intelligence, "
            "endpoint data, SIEM, ticketing, case management, identity lookups, and more. "
            "Use tools proactively when they'd give a better answer than guessing.\n\n"
            "Scope: the team works only on XSOAR tickets where type starts with 'CIRT' "
            "(e.g. CIRT, CIRT_*). When querying XSOAR for ticket volume, trends, backlog, "
            "MTTD/MTTR, coverage, or anything about 'our tickets' / 'the team's tickets', "
            "always filter to type=CIRT* unless the user explicitly asks about another team's work. "
            "Other ticket types (e.g. phishing-only queues, vendor-run queues) belong to different "
            "teams and should be excluded by default.\n\n"
            "Tone: match the user's energy. Be direct and substantive, skip the filler phrases. "
            "If they're asking a quick question, give a quick answer. "
            "If they want depth, go deep. No need to be stiff or overly formal.\n\n"
            "Default lens: executive. The user leads Detection and Response, "
            "so lead with leadership-level framing — risk posture, coverage gaps, trends, "
            "MTTD/MTTR, alert volume, program-level impact. Surface the 'so what' before the details. "
            "Drop to tactical depth (queries, rule logic, raw events, tool internals) when he asks for it "
            "or when the question is clearly hands-on.\n\n"
            "FORMATTING: You are responding in Webex, which does NOT render markdown tables. "
            "Never use markdown table syntax (pipes/dashes). Instead use bullet lists, "
            "bold labels, or numbered lists to present structured data. "
            f"When referencing XSOAR ticket IDs, make them clickable links using this format: "
            f"[#TICKET_ID]({config.xsoar_prod_ui_base_url}/Custom/caseinfoid/TICKET_ID)\n\n"
            f"Today is {today}."
        )
        if room_id:
            prompt += (
                f"\n\nCurrent Webex conversation context:"
                f"\n  room_id: {room_id}"
                f"\n  parent_id: {parent_id or ''}"
                f"\nWhen calling tools that post to Webex (e.g. render_diagram), "
                f"always pass room_id={room_id!r} and parent_id={parent_id!r}."
            )
        if user_email:
            prompt += f"\n\nThe current user's email is {user_email}."
        return prompt

    def _ask_claude(self, user_id: str, text: str,
                    room_id: str = "", parent_id: str = "",
                    user_email: str = "") -> tuple[str, dict]:
        """Agentic loop: Claude decides, MCP executes. Returns (reply, stats)."""
        empty_stats = {}
        if not self._claude:
            return "❌ AI not available — BARNACLES_CLAUDE_API_KEY not configured.", empty_stats

        session = self._sessions.setdefault(user_id, [])
        session.append({"role": "user", "content": text})
        if len(session) > 20:
            session[:] = session[-20:]

        # Guard against token overflow — estimate size and trim if needed
        session_str = str(session)
        while len(session_str) > 800_000 and len(session) > 2:
            session.pop(0)
            session_str = str(session)

        max_tool_chars = 8000
        max_per_tool_calls = 2
        tool_call_counts: dict[str, int] = {}

        # Stats tracking
        total_in = 0
        total_out = 0
        total_cache_read = 0
        total_cache_create = 0
        tools_used: list[str] = []
        t_start = time.time()
        t_first_token = None

        try:
            for iteration in range(1, 6):
                call_kwargs = {
                    "model": self._model,
                    "max_tokens": 2048,
                    "system": [{
                        "type": "text",
                        "text": self._system_prompt(room_id=room_id, parent_id=parent_id, user_email=user_email),
                        "cache_control": {"type": "ephemeral"},
                    }],
                    "messages": session,
                }
                if self._tools:
                    call_kwargs["tools"] = self._tools

                resp = self._claude.messages.create(**call_kwargs)

                if t_first_token is None:
                    t_first_token = time.time()

                cache_read = getattr(resp.usage, 'cache_read_input_tokens', 0) or 0
                cache_create = getattr(resp.usage, 'cache_creation_input_tokens', 0) or 0
                total_in += resp.usage.input_tokens
                total_out += resp.usage.output_tokens
                total_cache_read += cache_read
                total_cache_create += cache_create
                logger.info(
                    f"the alert triage service Claude iter {iteration}: {resp.usage.input_tokens} in / "
                    f"{resp.usage.output_tokens} out | cache_read={cache_read} | stop={resp.stop_reason}"
                )

                if resp.stop_reason != "tool_use":
                    reply = "".join(b.text for b in resp.content if b.type == "text")
                    session.append({"role": "assistant", "content": reply})
                    elapsed = time.time() - t_start
                    ttft = (t_first_token - t_start) if t_first_token else elapsed
                    tps = total_out / elapsed if elapsed > 0 else 0
                    # Sonnet 4 pricing: $3/MTok in, $15/MTok out, $0.30/MTok cache read, $3.75/MTok cache write
                    cost = (total_in * 3.0 + total_out * 15.0 + total_cache_read * 0.30 + total_cache_create * 3.75) / 1_000_000
                    stats = {
                        "input_tokens": total_in,
                        "output_tokens": total_out,
                        "cache_read": total_cache_read,
                        "cache_write": total_cache_create,
                        "iterations": iteration,
                        "tools_used": tools_used,
                        "elapsed": elapsed,
                        "ttft": ttft,
                        "tps": tps,
                        "cost": cost,
                        "model": self._model,
                    }
                    self._save_monthly_cost(cost)
                    stats["monthly_cost"] = self._monthly_cost
                    return reply, stats

                # Tool calls — add assistant turn then execute via MCP in parallel
                session.append({"role": "assistant", "content": resp.content})
                tool_use_blocks = [b for b in resp.content if b.type == "tool_use"]

                tool_results = []
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {}
                    for b in tool_use_blocks:
                        tool_call_counts[b.name] = tool_call_counts.get(b.name, 0) + 1
                        tools_used.append(b.name)
                        if tool_call_counts[b.name] > max_per_tool_calls:
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": b.id,
                                "content": f"Tool {b.name} already called {max_per_tool_calls} times — limit reached.",
                            })
                        else:
                            futures[executor.submit(self._mcp.call_tool, b.name, b.input)] = b

                    for future in as_completed(futures):
                        block = futures[future]
                        try:
                            result = str(future.result())
                        except Exception as e:
                            result = f"Tool error: {e}"
                        if len(result) > max_tool_chars:
                            result = result[:max_tool_chars] + f"\n\n[Truncated — {len(result):,} chars total]"
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

                session.append({"role": "user", "content": tool_results})

            return "I reached my reasoning limit. Please try rephrasing.", empty_stats

        except anthropic.APIError as e:
            logger.error(f"Claude API error for {user_id}: {e}")
            return "❌ AI service error. Please try again.", empty_stats
        except Exception as e:
            logger.error(f"Unexpected error in _ask_claude for {user_id}: {e}", exc_info=True)
            return "❌ An unexpected error occurred. Please try again.", empty_stats

    def process_incoming_message(self, teams_message, activity):
        """Route to existing card commands or Claude + MCP."""
        if activity.get('actor', {}).get('type') != 'PERSON':
            return
        if activity.get('verb') != 'post':
            return

        if not self.check_user_approved(user_email=teams_message.personEmail, approved_rooms=self.approved_rooms):
            return

        text = (teams_message.text or "").strip()
        if not text:
            return

        # Strip bot name prefix if present (covers "the alert triage service" and "DnR_the alert triage service")
        text = re.sub(r'(?i)^(dnr[_\s]*)?barnacles[,\s]*', '', text).strip()
        if not text:
            # Bare @mention in a group space — show the help card
            self.process_raw_command("help", teams_message, teams_message.personEmail, activity)
            return

        text_lower = text.lower().strip()

        # Hi short circuit — quick liveness check, no LLM call
        if text_lower in ('hi', 'hi!'):
            parent_id = getattr(teams_message, 'parentId', None) or teams_message.id
            webex_api.messages.create(
                roomId=teams_message.roomId,
                parentId=parent_id,
                markdown="Hi 👋🏾",
            )
            return

        # "adaptive card(s)" — show the home card with all command buttons
        if re.match(r'^adaptive\s*cards?$', text_lower):
            self.process_raw_command("help", teams_message, teams_message.personEmail, activity)
            return

        # Delegate card-based commands to the WebexBot command framework (still works for direct keyword use)
        first_word = text.split()[0].lower()
        if first_word in self._KEYWORD_COMMANDS:
            return super().process_incoming_message(teams_message, activity)

        # Clear session short circuit — no LLM call needed
        from my_bot.core.my_model import _is_clear_session_command
        if _is_clear_session_command(text):
            user_id = activity.get('actor', {}).get('id', getattr(teams_message, 'personEmail', 'unknown'))
            self._sessions.pop(user_id, None)
            parent_id = getattr(teams_message, 'parentId', None) or teams_message.id
            webex_api.messages.create(
                roomId=teams_message.roomId,
                parentId=parent_id,
                markdown="🧹 Session cleared. Starting fresh!",
            )
            return

        # Everything else → Claude + MCP
        user_id = activity.get('actor', {}).get('id', getattr(teams_message, 'personEmail', 'unknown'))
        actor_name = activity.get('actor', {}).get('displayName', 'unknown')
        parent_id = getattr(teams_message, 'parentId', None) or teams_message.id

        logger.info(f"the alert triage service Claude query from {actor_name}: {text[:80]}...")

        # Log free-text queries to activity DB
        try:
            from src.utils.bot_logs_db import log_activity as _db_log_activity
            from src.utils.logging_utils import get_room_name_cached
            _db_log_activity(
                bot="barnacles",
                actor=actor_name,
                command_keyword="claude_chat",
                room_name=get_room_name_cached(teams_message.roomId, bot_token),
                timestamp_eastern=datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %H:%M:%S'),
            )
        except Exception as e:
            logger.warning(f"Failed to log claude_chat activity: {e}")

        # Thinking indicator with rotating messages every 15 seconds
        thinking_msg = None
        thinking_active = threading.Event()
        try:
            thinking_msg = webex_api.messages.create(
                roomId=teams_message.roomId,
                parentId=parent_id,
                text=random.choice(BARNACLES_QUOTES),
            )

            thinking_active.set()

            def update_thinking_message():
                counter = 1
                max_edits = 9
                while thinking_active.is_set() and counter <= max_edits:
                    time.sleep(10)
                    if thinking_active.is_set():
                        try:
                            new_message = random.choice(BARNACLES_QUOTES)
                            resp = _requests.put(
                                f"https://webexapis.com/v1/messages/{thinking_msg.id}",
                                headers={
                                    "Authorization": f"Bearer {bot_token}",
                                    "Content-Type": "application/json",
                                },
                                json={
                                    "roomId": teams_message.roomId,
                                    "text": f"{new_message} ({counter * 10}s)",
                                },
                                timeout=10,
                            )
                            if resp.status_code == 200:
                                counter += 1
                            else:
                                logger.warning(f"Thinking edit failed: {resp.status_code}")
                                break
                        except Exception as e:
                            logger.warning(f"Failed to update thinking message: {e}")
                            break

            threading.Thread(target=update_thinking_message, daemon=True).start()
        except Exception:
            pass

        response, stats = self._ask_claude(
            user_id, text,
            room_id=teams_message.roomId,
            parent_id=parent_id,
            user_email=getattr(teams_message, 'personEmail', ''),
        )
        thinking_active.clear()

        # Append LLM stats footer
        if stats:
            parts = []
            parts.append(f"⏱ {stats['elapsed']:.1f}s")
            parts.append(f"TTFT {stats['ttft']:.1f}s")
            parts.append(f"TPS {stats['tps']:.0f}")
            parts.append(f"🔢 {stats['input_tokens']:,}→{stats['output_tokens']:,}")
            if stats['cache_read']:
                parts.append(f"📦 {stats['cache_read']:,} cached")
            parts.append(f"Loops: {stats['iterations']}")
            if stats['tools_used']:
                route = ' → '.join(dict.fromkeys(stats['tools_used']))  # dedupe, preserve order
                parts.append(f"Route: {route}")
            parts.append(f"💰 ${stats['cost']:.4f} (MTD ${stats.get('monthly_cost', 0):.2f})")
            response += f"\n\n---\n*{' | '.join(parts)}*"

        # Log LLM usage + full conversation to DB
        try:
            from src.utils.bot_logs_db import log_llm_usage, log_conversation
            from src.utils.logging_utils import get_room_name_cached
            room_name = get_room_name_cached(teams_message.roomId, bot_token)
            now_eastern = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %H:%M:%S')
            if stats:
                log_llm_usage(
                    bot="barnacles", actor=actor_name, prompt_preview=text,
                    model=stats.get('model', ''), prompt_tokens=stats.get('input_tokens', 0),
                    completion_tokens=stats.get('output_tokens', 0),
                    cached_tokens=stats.get('cache_read', 0),
                    total_tokens=stats.get('input_tokens', 0) + stats.get('output_tokens', 0),
                    cost=stats.get('cost', 0), elapsed_s=stats.get('elapsed', 0),
                    room_name=room_name,
                    timestamp_eastern=now_eastern,
                )
            log_conversation(
                bot="barnacles",
                person=actor_name,
                user_prompt=text,
                bot_response=response,
                response_length=len(response or ''),
                response_time_s=float(stats.get('elapsed', 0)) if stats else 0.0,
                room_name=room_name,
                message_time=now_eastern,
            )
        except Exception as e:
            logger.warning(f"Failed to log barnacles conversation: {e}")

        if len(response) > 7000:
            response = response[:6900] + "\n\n*[Response truncated]*"

        if thinking_msg:
            try:
                edit_resp = _requests.put(
                    f"https://webexapis.com/v1/messages/{thinking_msg.id}",
                    headers={
                        "Authorization": f"Bearer {bot_token}",
                        "Content-Type": "application/json",
                    },
                    json={"roomId": teams_message.roomId, "markdown": response},
                    timeout=10,
                )
                edit_resp.raise_for_status()
                return
            except Exception as e:
                logger.error(f"Failed to edit thinking message: {e}")

        # Fallback if edit fails
        webex_api.messages.create(
            roomId=teams_message.roomId,
            parentId=parent_id,
            markdown=response,
        )


def barnacles_bot_factory():
    """Create the alert triage service bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        bot_token,
        bot_name="the alert triage service"
    )

    # Build approved users list: configured users + all bots for peer ping communication
    configured_users = config.barnacles_approved_users.split(',')
    bot_emails = [
        config.webex_bot_email_toodles,
        config.webex_bot_email_msoar,
        config.webex_bot_email_money_ball,
        config.webex_bot_email_jarvis,
        config.webex_bot_email_pokedex,
        config.webex_bot_email_pinger,  # Pinger bot for keepalive
    ]
    approved_users = configured_users + bot_emails

    return AlertTriageBot(
        bot_token,
        approved_users=approved_users,
        bot_name="the alert triage service - The Captain's Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Click a button to start!",
        allow_bot_to_bot=True
    )


def barnacles_initialization(bot_instance=None):
    """Initialize the alert triage service commands"""
    if bot_instance:
        # Add commands to the bot
        bot_instance.add_command(ManagementNotes())
        bot_instance.add_command(ThreatconLevel())
        bot_instance.add_command(SaveManagementNotes())
        bot_instance.add_command(SaveThreatcon())
        bot_instance.add_command(AnnounceThreatcon())
        bot_instance.add_command(BotStatusCommand())
        bot_instance.add_command(Hi())
        return True
    return False


def _shutdown_handler(signum=None, frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 BARNACLES BOT STOPPED - {dt_for_marker.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """the alert triage service main - simplified to use basic WebexBot (keepalive handled by peer_ping_keepalive.py)"""
    logger.info("Starting the alert triage service with basic WebexBot")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Create bot instance
    bot = barnacles_bot_factory()

    # Initialize commands
    barnacles_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 the alert triage service is up and running...")
    print("🚀 the alert triage service is up and running...", flush=True)
    bot.run()


if __name__ == "__main__":
    main()
