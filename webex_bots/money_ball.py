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
    bot_name='money_ball',
    log_level=logging.WARNING,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager']
)

logger = logging.getLogger(__name__)

# ALWAYS configure SSL for proxy environments (auto-detects ZScaler/proxies)
from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)

# ALWAYS apply enhanced WebSocket patches for connection resilience
# This is critical to prevent the bot from going to sleep
from src.utils.enhanced_websocket_client import patch_websocket_client

patch_websocket_client()

import os
import random
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

from tabulate import tabulate
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment
)
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from src.charts import aging_tickets
from src.components import reimaged_hosts
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_messaging import send_message_with_files, safe_send_message

# Load configuration
config = get_config()

# Initialize Webex API client with extended timeout for proxy environments
webex_api = WebexTeamsAPI(
    access_token=config.webex_bot_access_token_moneyball,
    single_request_timeout=120,  # Increased from default 60s to 120s for proxy/network stability
    wait_on_rate_limit=True
)

# Global variables
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

# Fun chart-related messages
CHART_MESSAGES = [
    "📊 Chart magic in progress...",
    "🎨 Creating visual masterpieces...",
    "📈 Turning data into art...",
    "🎯 Targeting chart perfection...",
    "🔥 Brewing some hot metrics...",
    "🧙‍♂️ Summoning the chart wizard...",
    "🚀 Launching your data to new heights...",
    "🕵️‍♂️ Investigating the secrets of your numbers...",
    "🧠 Crunching numbers with AI brainpower...",
    "☕ Brewing up a fresh pot of analytics...",
    "🧩 Piecing together the data puzzle...",
    "🛠️ Assembling your chart masterpiece...",
    "🌈 Adding color to your metrics...",
    "🦄 Searching for unicorn insights...",
    "🦉 Consulting the wise chart owl...",
    "🧊 Chilling with cool visualizations...",
    "🦖 Digging up data fossils...",
    "🧗‍♂️ Climbing the mountain of information...",
    "🛸 Beaming up your data to the cloud...",
    "🦋 Transforming raw data into beauty...",
    "🧹 Sweeping up data dust...",
    "🧲 Attracting the most relevant facts...",
    "🦜 Parroting back the best results...",
    "🦩 Flamingling with fancy metrics...",
    "🦦 Otterly focused on your chart...",
    "🦔 Prickling through the data haystack...",
    "🎩 Pulling insights out of a hat...",
    "🎢 Riding the rollercoaster of trends...",
    "🎬 Directing a blockbuster data story...",
    "🎻 Orchestrating a symphony of stats..."
]


# Define command classes
class DetectionEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="det_eng", help_message="")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "DE Stories", "de_stories.png")


class ResponseEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="resp_eng", help_message="")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "RE Stories", "RE Stories.png")


class MttrMttc(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""

    def __init__(self):
        super().__init__(command_keyword="mttr_mttc", help_message="MTTR-MTTC ⏱️")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "MTTR-MTTC", "MTTR MTTC.png")


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""

    def __init__(self):
        super().__init__(command_keyword="aging", help_message="Aging Tickets 📈")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Aging Tickets", "Aging Tickets.png")


class SlaBreaches(Command):
    """Webex Bot command to display a graph of SLA breaches."""

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches ⚠️")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "SLA Breaches", "SLA Breaches.png")


class Outflow(Command):

    def __init__(self):
        super().__init__(command_keyword="outflow", help_message="Outflow 📤")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Outflow Yesterday", "Outflow Yesterday.png")


class Inflow(Command):

    def __init__(self):
        super().__init__(command_keyword="inflow", help_message="Inflow 📥")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Inflow Yesterday", "Inflow Yesterday.png")


class HeatMap(Command):
    def __init__(self):
        super().__init__(command_keyword="heat_map", help_message="Heat Map 🔥")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Heat Map", "Heat Map.png")


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(command_keyword="threatcon_level", help_message="Threatcon Level 🚨")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Threatcon Level", "Threatcon Level.png")


class QRadarRuleEfficacy(Command):
    def __init__(self):
        super().__init__(command_keyword="efficacy", help_message="")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "QR Rule Efficacy", "QR Rule Efficacy.png")


class GetAgingTicketsByOwnerReport(Command):
    def __init__(self):
        super().__init__(command_keyword="aging_tickets_by_owner_report", help_message="", exact_command_keyword_match=True)

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        aging_tickets.send_report(room_id)


class ReimagedHostDetails(Command):
    def __init__(self):
        super().__init__(command_keyword="reimaged_hosts", help_message="", exact_command_keyword_match=False)

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        details = reimaged_hosts.get_details()
        tickets = details.get("tickets", [])
        mtuc = details.get("MTUC", "N/A")
        table_data = []
        for t in tickets:
            table_data.append([
                t.get('id', ''),
                t.get('hostname', ''),
                t.get('created', ''),
                t.get('TUC', ''),
                t.get('count', ''),
                t.get('name', ''),
            ])
        table_str = tabulate(table_data, headers=["ID", "Hostname", "Created", "TUC", "Count", "Name", ], tablefmt="github")
        return f"{activity['actor']['displayName']}, here are the details of the reimaged hosts YTD. MTUC: {mtuc}\n```\n{table_str}\n```"


class HelpCommand(Command):
    def __init__(self):
        super().__init__(command_keyword="help", help_message="List all commands and their help messages.", exact_command_keyword_match=False)

    def execute(self, message, attachment_actions, activity):
        keywords = ["aging", "mttr_mttc", "sla_breach", "outflow", "threatcon_level", "reimaged_hosts", "inflow", "help"]
        keywords.sort()
        return f"{activity['actor']['displayName']}, here are the available commands:\n" + "\n".join(keywords)


class GetBotHealth(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="Bot health 🏥",
            delete_previous_message=True,
        )

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
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
                    text="📊 MoneyBall Bot 🤖 Status",
                    color=options.Colors.GOOD,
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Status Information**", weight=options.FontWeight.BOLDER),
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

        # Send status card with retry logic
        try:
            from src.utils.webex_messaging import send_card
            send_card(
                webex_api,
                room_id,
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}],
                text="Bot Status Information"
            )
        except Exception as e:
            logger.error(f"Failed to send bot status card: {e}")
            # Fallback to simple message with retry
            safe_send_message(
                webex_api,
                room_id,
                markdown=f"📊 **MoneyBall Bot Status**\n\n{health_status}\n{health_detail}",
                fallback_text=f"MoneyBall Bot Status: {health_status}"
            )


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


def send_chart(room_id, display_name, chart_name, chart_filename):
    """Sends a chart image to a Webex room with enhanced error handling and automatic retry logic."""
    try:
        today_date = datetime.now().strftime('%m-%d-%Y')
        chart_path = os.path.join(os.path.dirname(__file__), f'../web/static/charts/{today_date}', chart_filename)

        if not os.path.exists(chart_path):
            error_msg = f"❌ Sorry {display_name}, the {chart_name} chart is not available."
            logger.warning(f"Chart not found: {chart_path}")
            safe_send_message(webex_api, room_id, markdown=error_msg)
            return

        # Add fun loading message
        loading_message = get_random_chart_message()

        # Build the success message
        success_msg = f"{loading_message}\n\n📊 **{display_name}, here's the latest {chart_name} chart!**"

        # Send message with chart file (includes automatic retry)
        send_message_with_files(
            webex_api,
            room_id,
            files=[chart_path],  # type: ignore[arg-type]
            markdown=success_msg
        )
        logger.info(f"Successfully sent chart {chart_name} to room {room_id}")

    except Exception as e:
        error_msg = f"❌ Failed to send {chart_name} chart: {str(e)}"
        logger.error(error_msg)
        # Use safe_send_message for error notification (won't throw exception)
        safe_send_message(
            webex_api,
            room_id,
            markdown=error_msg,
            fallback_text=f"Failed to send {chart_name} chart"
        )


def get_random_chart_message():
    """Get a random fun chart loading message."""
    return random.choice(CHART_MESSAGES)


def moneyball_bot_factory():
    """Create MoneyBall bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        config.webex_bot_access_token_moneyball,
        bot_name="MoneyBall"
    )

    logger.info("🌐 Creating WebexBot instance...")
    bot = WebexBot(
        config.webex_bot_access_token_moneyball,
        approved_domains=[config.my_web_domain],
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        bot_name="MoneyBall - The Metrics & Analytics Bot",
        threads=True,
        log_level="WARNING",  # Changed from ERROR to see more details
        bot_help_subtitle="Your friendly neighborhood metrics bot! Click a button to get charts and reports!"
    )
    logger.info("✅ WebexBot instance created successfully")

    return bot


def moneyball_initialization(bot_instance=None):
    """Initialize MoneyBall commands"""
    if bot_instance:
        # Add commands to the bot
        bot_instance.add_command(AgingTickets())
        bot_instance.add_command(MttrMttc())
        bot_instance.add_command(SlaBreaches())
        bot_instance.add_command(Inflow())
        bot_instance.add_command(Outflow())
        bot_instance.add_command(ThreatconLevel())
        # bot_instance.add_command(DetectionEngineeringStories())
        # bot_instance.add_command(ResponseEngineeringStories())
        bot_instance.add_command(HeatMap())
        # bot_instance.add_command(QRadarRuleEfficacy())
        bot_instance.add_command(ReimagedHostDetails())
        bot_instance.add_command(GetAgingTicketsByOwnerReport())
        bot_instance.add_command(GetBotHealth())
        bot_instance.add_command(HelpCommand())
        bot_instance.add_command(Hi())
        return True
    return False


def moneyball_initialization_with_tracking(bot_instance, resilient_runner):
    """Initialize MoneyBall with message activity tracking for idle detection"""
    from src.utils.bot_resilience import enable_message_tracking

    if not bot_instance:
        return False

    # Enable message tracking for idle timeout detection
    enable_message_tracking(bot_instance, resilient_runner)

    # Run original initialization
    return moneyball_initialization(bot_instance)


def main():
    """MoneyBall main - always uses resilience framework"""
    # Run tests (optional, can be disabled in production)
    if '--skip-tests' not in sys.argv:
        try:
            unittest.main(exit=False, argv=[''], verbosity=0)
        except Exception as e:
            logger.warning(f"Tests failed or skipped: {e}")

    from src.utils.bot_resilience import ResilientBot

    logger.info("Starting MoneyBall with standard resilience framework")

    resilient_runner = ResilientBot(
        bot_name="MoneyBall",
        bot_factory=moneyball_bot_factory,
        initialization_func=lambda bot: moneyball_initialization_with_tracking(bot, resilient_runner),
        max_retries=5,
        initial_retry_delay=30,
        max_retry_delay=300,
        keepalive_interval=105,  # Staggered to avoid synchronized API load (60s, 75s, 90s, 105s, 120s)
    )
    resilient_runner.run()


if __name__ == '__main__':
    main()
