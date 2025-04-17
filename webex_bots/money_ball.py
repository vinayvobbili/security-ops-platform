import os
import unittest
from datetime import datetime
from unittest.mock import patch

from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.helper_methods import log_moneyball_activity

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)


# Define a common function to send chart images
def send_chart(room_id, display_name, chart_name, chart_filename):
    """Sends a chart image to a Webex room."""
    today_date = datetime.now().strftime('%m-%d-%Y')
    chart_path = os.path.join(os.path.dirname(__file__), f'../web/static/charts/{today_date}', chart_filename)

    if not os.path.exists(chart_path):
        webex_api.messages.create(
            roomId=room_id,
            text=f"Sorry {display_name}, the {chart_name} chart is not available."
        )
        return

    webex_api.messages.create(
        roomId=room_id,
        text=f"{display_name}, here's the latest {chart_name} chart!",
        files=[chart_path]
    )


# Define command classes
class DetectionEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="det_eng", help_message="DE Stories")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "DE Stories", "de_stories.png")


class ResponseEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="resp_eng", help_message="RE Stories")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data['roomId'], activity['actor']['displayName'], "RE Stories", "RE Stories.png")


class MttrMttc(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""

    def __init__(self):
        super().__init__(command_keyword="mttr_mttc", help_message="MTTR-MTTC")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "MTTR-MTTC", "MTTR MTTC.png")


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""

    def __init__(self):
        super().__init__(command_keyword="aging", help_message="Aging Tickets")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Aging Tickets", "Aging Tickets.png")


class SlaBreaches(Command):
    """Webex Bot command to display a graph of SLA breaches."""

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "SLA Breaches", "SLA Breaches.png")


class Outflow(Command):

    def __init__(self):
        super().__init__(command_keyword="outflow", help_message="Outflow")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Outflow Yesterday", "Outflow.png")


class Inflow(Command):

    def __init__(self):
        super().__init__(command_keyword="inflow", help_message="Inflow")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Inflow Yesterday", "Inflow Yesterday.png")
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Inflow Past 60 Days", "Inflow Past 60 Days.png")


class HeatMap(Command):
    def __init__(self):
        super().__init__(command_keyword="heat_map", help_message="Heat Map")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Heat Map", "Heat Map.png")


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(command_keyword="threatcon_level", help_message="Threatcon Level")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "Threatcon Level", "Threatcon Level.png")


class QRadarRuleEfficacy(Command):
    def __init__(self):
        super().__init__(command_keyword="efficacy", help_message="QR Rule Efficacy")

    @log_moneyball_activity(bot_access_token=config.webex_bot_access_token_moneyball)
    def execute(self, message, attachment_actions, activity):
        send_chart(attachment_actions.json_data["roomId"], activity['actor']['displayName'], "QR Rule Efficacy", "QR Rule Efficacy.png")


class TestSendThreatconLevelChart(unittest.TestCase):
    @patch('webex_bots.money_ball.webex_api.messages.create')
    def test_send_threatcon_level_chart(self, mock_create_message):
        # Mock the create message function
        mock_create_message.return_value = None  # Simulate successful send

        # Call the function directly instead of main()
        try:
            send_chart(
                config.webex_room_id_vinay_test_space,
                'Metricmeister',
                'Threatcon Level',
                'Threatcon Level.png'
            )
        except Exception as ex:
            webex_api.messages.create(
                roomId=config.webex_room_id_vinay_test_space,
                text=f"An error occurred: {ex}"
            )


def main():
    """Initialize and run the Webex bot."""

    # Run the test
    unittest.main(exit=False)

    bot = WebexBot(
        config.webex_bot_access_token_moneyball,
        approved_rooms=config.money_ball_approved_rooms.split(','),
        bot_name="Hello, Metricmeister!"
    )

    # Add commands to the bot
    bot.add_command(AgingTickets())
    bot.add_command(MttrMttc())
    bot.add_command(SlaBreaches())
    bot.add_command(Inflow())
    bot.add_command(Outflow())
    bot.add_command(ThreatconLevel())

    # Start the bot
    bot.run()


if __name__ == '__main__':
    main()
