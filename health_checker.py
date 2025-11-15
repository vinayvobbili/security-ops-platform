#!/usr/bin/env python3
"""
Health Checker for Webex Bots

Sends periodic test messages to all configured bots to validate their inbound
connectivity. This helps detect when firewalls drop inbound connection tracking
even while outbound keepalives continue to work.

Usage:
    python health_checker.py
"""

import logging
import os
import time
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import after logging setup
try:
    from webexpythonsdk import WebexTeamsAPI
    from dotenv import load_dotenv
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error("Install with: pip install webexpythonsdk python-dotenv")
    exit(1)


class BotHealthChecker:
    """Sends periodic health check messages to bots"""

    def __init__(self, check_interval_minutes=10):
        """
        Initialize the health checker

        Args:
            check_interval_minutes: How often to send health checks (default 10 minutes)
        """
        self.check_interval_minutes = check_interval_minutes

        # Load environment variables
        env_path = Path(__file__).parent / '.env'
        load_dotenv(env_path)

        # Get health checker bot token
        # Use a dedicated "health checker" bot account or one of the existing bots
        health_checker_token = os.getenv('HEALTH_CHECKER_TOKEN') or os.getenv('WEBEX_TEAMS_ACCESS_TOKEN')

        if not health_checker_token:
            raise ValueError("No health checker token found in environment")

        self.api = WebexTeamsAPI(access_token=health_checker_token)

        # Bot emails to check (configure these in .env or here)
        self.bot_emails = [
            os.getenv('TOODLES_BOT_EMAIL', 'XSOAR_On_Call_Bot@webex.bot'),
            os.getenv('BARNACLES_BOT_EMAIL', 'barnacles@webex.bot'),
            os.getenv('MONEY_BALL_BOT_EMAIL', 'money_ball@webex.bot'),
            os.getenv('MSOAR_BOT_EMAIL', 'msoar@webex.bot'),
        ]

        # Filter out None values
        self.bot_emails = [email for email in self.bot_emails if email and '@' in email]

        logger.info(f"🏥 Health Checker initialized")
        logger.info(f"📋 Monitoring {len(self.bot_emails)} bots: {', '.join(self.bot_emails)}")
        logger.info(f"⏰ Check interval: {check_interval_minutes} minutes")

    def send_health_check(self, bot_email):
        """Send a health check message to a bot"""
        try:
            message_text = f"🏥 Health check @ {datetime.now().strftime('%H:%M:%S')}"

            self.api.messages.create(
                toPersonEmail=bot_email,
                text=message_text
            )

            logger.info(f"✅ Sent health check to {bot_email}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to send health check to {bot_email}: {e}")
            return False

    def run(self):
        """Run the health checker loop"""
        logger.info(f"🚀 Starting health checker - will ping bots every {self.check_interval_minutes} minutes")

        while True:
            try:
                logger.info(f"🏥 Sending health checks to {len(self.bot_emails)} bots...")

                for bot_email in self.bot_emails:
                    self.send_health_check(bot_email)
                    time.sleep(2)  # Small delay between sends

                logger.info(f"✅ Health check round complete")
                logger.info(f"⏰ Next health check in {self.check_interval_minutes} minutes")

                # Sleep until next check
                time.sleep(self.check_interval_minutes * 60)

            except KeyboardInterrupt:
                logger.info("🛑 Health checker stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Error in health checker: {e}")
                logger.info("⏰ Retrying in 1 minute...")
                time.sleep(60)


def main():
    """Main entry point"""
    # Create and run health checker (10 minute interval)
    checker = BotHealthChecker(check_interval_minutes=10)
    checker.run()


if __name__ == "__main__":
    main()
