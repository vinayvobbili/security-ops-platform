import logging.handlers
import os
import random
import signal
import sys
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from tabulate import tabulate
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment
)
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.charts import aging_tickets
from src.components import reimaged_hosts
from src.utils.logging_utils import log_activity

# Load configuration
config = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent

# Ensure logs directory exists
(ROOT_DIRECTORY / "logs").mkdir(exist_ok=True)

# Setup logging with rotation and better formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            ROOT_DIRECTORY / "logs" / "money_ball.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)

# Global variables for health monitoring
shutdown_requested = False
HEALTH_CHECK_INTERVAL = 300  # 5 minutes
last_health_check = time.time()
bot_start_time: datetime | None = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")


# Fun chart-related messages and achievements
CHART_MESSAGES = [
    "📊 Chart magic in progress...",
    "🎨 Creating visual masterpieces...",
    "📈 Turning data into art...",
    "🎯 Targeting chart perfection...",
    "🔥 Brewing some hot metrics..."
]

ACHIEVEMENT_MESSAGES = {
    "first_time": "🎉 **First Timer!** Welcome to the MoneyBall experience!",
    "chart_collector": "📊 **Chart Collector!** You've requested {count} charts today!",
    "data_explorer": "🕵️ **Data Explorer!** You're diving deep into the metrics!",
    "weekend_warrior": "⚔️ **Weekend Warrior!** Working hard even on weekends!",
    "early_bird": "🐦 **Early Bird!** Up bright and early for some data insights!",
    "night_owl": "🦉 **Night Owl!** Burning the midnight oil with metrics!"
}


# Define command classes
class DetectionEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="det_eng", help_message="DE Stories")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "DE Stories", "de_stories.png")


class ResponseEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="resp_eng", help_message="RE Stories")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "RE Stories", "RE Stories.png")


class MttrMttc(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""

    def __init__(self):
        super().__init__(command_keyword="mttr_mttc", help_message="MTTR-MTTC")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "MTTR-MTTC", "MTTR MTTC.png")


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""

    def __init__(self):
        super().__init__(command_keyword="aging", help_message="Aging Tickets")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Aging Tickets", "Aging Tickets.png")


class SlaBreaches(Command):
    """Webex Bot command to display a graph of SLA breaches."""

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "SLA Breaches", "SLA Breaches.png")


class Outflow(Command):

    def __init__(self):
        super().__init__(command_keyword="outflow", help_message="Outflow")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Outflow Yesterday", "Outflow.png")


class Inflow(Command):

    def __init__(self):
        super().__init__(command_keyword="inflow", help_message="Inflow")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Inflow Yesterday", "Inflow Yesterday.png")
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Inflow Past 60 Days", "Inflow Past 60 Days.png")


class HeatMap(Command):
    def __init__(self):
        super().__init__(command_keyword="heat_map", help_message="Heat Map")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Heat Map", "Heat Map.png")


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(command_keyword="threatcon_level", help_message="Threatcon Level")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Threatcon Level", "Threatcon Level.png")


class QRadarRuleEfficacy(Command):
    def __init__(self):
        super().__init__(command_keyword="efficacy", help_message="QR Rule Efficacy")

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "QR Rule Efficacy", "QR Rule Efficacy.png")


class GetAgingTicketsByOwnerReport(Command):
    def __init__(self):
        super().__init__(command_keyword="aging_tickets_by_owner_report", help_message="Aging Tickets by Owner Report", exact_command_keyword_match=True)

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


class BotStatusCommand(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="🔍 Check bot health and status",
            delete_previous_message=True,
        )

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        global bot_start_time, last_health_check

        room_id = attachment_actions.roomId
        current_time = datetime.now(EASTERN_TZ)

        # Calculate uptime
        if bot_start_time:
            uptime = current_time - bot_start_time
            uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds // 60) % 60}m"
        else:
            uptime_str = "Unknown"

        # Health check info with better explanations
        time_since_last_check = time.time() - last_health_check
        if time_since_last_check < HEALTH_CHECK_INTERVAL:
            health_status = "🟢 Healthy"
            health_detail = "Webex connection stable"
        else:
            health_status = "🟡 Warning"
            minutes_overdue = int((time_since_last_check - HEALTH_CHECK_INTERVAL) / 60)
            health_detail = f"Webex API connection issues detected ({minutes_overdue}min ago)"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        # Format last health check time
        last_check_time = datetime.fromtimestamp(last_health_check, EASTERN_TZ)
        last_check_str = last_check_time.strftime(f'%H:%M:%S {tz_name}')

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
                                TextBlock(text=f"Uptime: {uptime_str}"),
                                TextBlock(text=f"Last Health Check: {last_check_str}"),
                                TextBlock(text=f"Current Time: {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
                            ]
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            roomId=room_id,
            text="Bot Status Information",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}]
        )


class QuickActionsCommand(Command):
    """Quick actions dashboard for common MoneyBall operations."""

    def __init__(self):
        super().__init__(
            command_keyword="dashboard",
            help_message="📋 Quick Actions Dashboard",
            delete_previous_message=True,
        )

    @log_activity(config.webex_bot_access_token_moneyball, "moneyball_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        current_time = datetime.now(EASTERN_TZ)
        hour = current_time.hour

        # Time-based greeting
        if 5 <= hour < 12:
            greeting = f"🌅 Good morning, {activity['actor']['displayName']}!"
        elif 12 <= hour < 17:
            greeting = f"☀️ Good afternoon, {activity['actor']['displayName']}!"
        elif 17 <= hour < 21:
            greeting = f"🌆 Good evening, {activity['actor']['displayName']}!"
        else:
            greeting = f"🌙 Working late, {activity['actor']['displayName']}?"

        dashboard_card = AdaptiveCard(
            body=[
                TextBlock(
                    text="📊 MoneyBall Quick Actions",
                    color=options.Colors.ACCENT,
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=greeting,
                    wrap=True,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="🎯 **Most Popular Charts**", weight=options.FontWeight.BOLDER),
                                TextBlock(text="• Aging Tickets 📈"),
                                TextBlock(text="• MTTR/MTTC ⏱️"),
                                TextBlock(text="• SLA Breaches ⚠️"),
                                TextBlock(text="• Heat Map 🔥")
                            ]
                        ),
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Flow Analysis**", weight=options.FontWeight.BOLDER),
                                TextBlock(text="• Inflow Trends 📥"),
                                TextBlock(text="• Outflow Metrics 📤"),
                                TextBlock(text="• ThreatCon Level 🚨"),
                                TextBlock(text="• QRadar Efficacy 🛡️")
                            ]
                        )
                    ]
                ),
                TextBlock(
                    text=f"💡 **Pro Tip:** Use the buttons above to quickly access your most-used charts!",
                    wrap=True,
                    color=options.Colors.ACCENT
                )
            ]
        )

        webex_api.messages.create(
            roomId=attachment_actions.roomId,
            text="MoneyBall Dashboard",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": dashboard_card.to_dict()}]
        )


def keepalive_ping():
    """Keep the bot connection alive with periodic pings."""
    global last_health_check
    wait = 60  # Start with 1 minute
    max_wait = 1800  # Max wait: 30 minutes
    while not shutdown_requested:
        try:
            webex_api.people.me()
            last_health_check = time.time()  # Update on successful ping
            wait = 240  # Reset to normal interval (4 min) after success
        except Exception as e:
            logger.warning(f"Keepalive ping failed: {e}. Retrying in {wait} seconds.")
            # Don't update last_health_check on failure - this will trigger warning status
            time.sleep(wait)
            wait = min(wait * 2, max_wait)  # Exponential backoff, capped at max_wait
            continue
        time.sleep(wait)


def signal_handler(_sig, _frame):
    """Handle signals for graceful shutdown."""
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown requested. Cleaning up and exiting...")
    sys.exit(0)


def send_chart(room_id, display_name, chart_name, chart_filename):
    """Sends a chart image to a Webex room with enhanced error handling."""
    try:
        today_date = datetime.now().strftime('%m-%d-%Y')
        chart_path = os.path.join(os.path.dirname(__file__), f'../web/static/charts/{today_date}', chart_filename)

        if not os.path.exists(chart_path):
            error_msg = f"❌ Sorry {display_name}, the {chart_name} chart is not available."
            logger.warning(f"Chart not found: {chart_path}")
            webex_api.messages.create(
                roomId=room_id,
                markdown=error_msg
            )
            return

        success_msg = f"📊 **{display_name}, here's the latest {chart_name} chart!**"

        webex_api.messages.create(
            roomId=room_id,
            markdown=success_msg,
            files=[chart_path]
        )
        logger.info(f"Successfully sent chart {chart_name} to room {room_id}")

    except Exception as e:
        error_msg = f"❌ Failed to send {chart_name} chart: {str(e)}"
        logger.error(error_msg)
        try:
            webex_api.messages.create(
                roomId=room_id,
                markdown=error_msg
            )
        except Exception as msg_error:
            logger.error(f"Failed to send error message: {msg_error}")


def run_bot_with_reconnection():
    """Run the bot with automatic reconnection on failures."""
    global bot_start_time
    bot_start_time = datetime.now(EASTERN_TZ)  # Make bot_start_time timezone-aware

    max_retries = 5
    retry_delay = 30  # Start with 30 seconds
    max_delay = 300  # Max delay of 5 minutes

    for attempt in range(max_retries):
        try:
            logger.info(f"Starting MoneyBall bot (attempt {attempt + 1}/{max_retries})")

            bot = WebexBot(
                config.webex_bot_access_token_moneyball,
                approved_rooms=[config.webex_room_id_vinay_test_space, config.webex_room_id_metrics],
                bot_name="📊 MoneyBall 🤖\n The Metrics & Analytics Bot",
                threads=True,
                log_level="ERROR",
                bot_help_subtitle="📈 Your friendly neighborhood metrics bot! Click a button to get charts and reports!"
            )

            # Add commands to the bot
            bot.add_command(AgingTickets())
            bot.add_command(MttrMttc())
            bot.add_command(SlaBreaches())
            bot.add_command(Inflow())
            bot.add_command(Outflow())
            bot.add_command(ThreatconLevel())
            bot.add_command(DetectionEngineeringStories())
            bot.add_command(ResponseEngineeringStories())
            bot.add_command(HeatMap())
            bot.add_command(QRadarRuleEfficacy())
            bot.add_command(ReimagedHostDetails())
            bot.add_command(GetAgingTicketsByOwnerReport())
            bot.add_command(BotStatusCommand())
            bot.add_command(QuickActionsCommand())
            bot.add_command(HelpCommand())

            print("📊 MoneyBall is up and running with enhanced features...")
            logger.info(f"Bot started successfully at {bot_start_time}")

            # Start the bot
            bot.run()

            # If we reach here, the bot stopped normally
            logger.info("Bot stopped normally")
            break

        except KeyboardInterrupt:
            logger.info("Bot stopped by user")
            break
        except Exception as e:
            logger.error(f"Bot crashed with error: {e}")

            if attempt < max_retries - 1:
                logger.info(f"Restarting bot in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_delay)  # Exponential backoff
            else:
                logger.error("Max retries exceeded. Bot will not restart.")
                raise


def get_random_chart_message():
    """Get a random fun chart loading message."""
    return random.choice(CHART_MESSAGES)


def get_achievement_message(user_name, chart_count=1):
    """Generate achievement messages based on usage patterns."""
    current_time = datetime.now(EASTERN_TZ)
    hour = current_time.hour
    weekday = current_time.weekday()

    achievements = []

    # Time-based achievements
    if 5 <= hour <= 8:
        achievements.append(ACHIEVEMENT_MESSAGES["early_bird"])
    elif 22 <= hour or hour <= 2:
        achievements.append(ACHIEVEMENT_MESSAGES["night_owl"])

    # Weekend achievement
    if weekday >= 5:  # Saturday = 5, Sunday = 6
        achievements.append(ACHIEVEMENT_MESSAGES["weekend_warrior"])

    # Chart count achievements
    if chart_count >= 5:
        achievements.append(ACHIEVEMENT_MESSAGES["chart_collector"].format(count=chart_count))
    elif chart_count == 1:
        achievements.append(ACHIEVEMENT_MESSAGES["first_time"])

    return achievements


def main():
    """Initialize and run the Webex bot with enhanced features."""

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start keepalive thread
    threading.Thread(target=keepalive_ping, daemon=True).start()

    # Run tests (optional, can be disabled in production)
    if '--skip-tests' not in sys.argv:
        try:
            unittest.main(exit=False, argv=[''], verbosity=0)
        except Exception as e:
            logger.warning(f"Tests failed or skipped: {e}")

    # Run bot with automatic reconnection
    run_bot_with_reconnection()


if __name__ == '__main__':
    main()
