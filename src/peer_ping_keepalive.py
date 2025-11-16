#!/usr/bin/env python3
"""
Standalone peer ping script to keep bot NAT paths active.

This script sends periodic "hi" messages to all bots from a user account,
avoiding bot-to-bot complexity and message loops.

Run via cron or systemd timer every 5-10 minutes.
"""
import logging
from datetime import datetime

from webexteamssdk import WebexTeamsAPI

from my_config import get_config

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CONFIG = get_config()

# List of all bots to ping
# PingBot pings all production bots to keep NAT paths active
BOTS_TO_PING = [
    ("the notification service", CONFIG.webex_bot_email_toodles),
    ("the case orchestrator", CONFIG.webex_bot_email_msoar),
    ("MoneyBall", CONFIG.webex_bot_email_money_ball),
    ("the orchestration service", CONFIG.webex_bot_email_jarvis),
    ("Tars", CONFIG.webex_bot_email_tars),
    ("the alert triage service", CONFIG.webex_bot_email_barnacles),
]


def send_peer_pings(access_token: str):
    """Send ping messages to all bots to keep NAT paths active."""
    api = WebexTeamsAPI(access_token=access_token)
    timestamp = datetime.now().strftime('%H:%M:%S')

    logger.info(f"🔔 Starting peer ping cycle at {timestamp}")

    success_count = 0
    fail_count = 0

    for bot_name, bot_email in BOTS_TO_PING:
        try:
            api.messages.create(
                toPersonEmail=bot_email,
                text=f"Hi @ {timestamp}"  # Simple greeting that triggers bot response
            )
            logger.debug(f"  ✅ Pinged {bot_name} ({bot_email})")
            success_count += 1
        except Exception as e:
            logger.error(f"  ❌ Failed to ping {bot_name}: {e}")
            fail_count += 1

    logger.debug(f"✅ Peer ping cycle complete: {success_count} successful, {fail_count} failed")


def main():
    """Main entry point."""
    # Use Pinger bot token to send pings to all production bots
    access_token = CONFIG.webex_bot_access_token_pinger

    if not access_token:
        logger.error("❌ Missing Pinger bot Webex access token")
        return 1

    try:
        send_peer_pings(access_token)
        return 0
    except Exception as e:
        logger.error(f"❌ Peer ping failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
