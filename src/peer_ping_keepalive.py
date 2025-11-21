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
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Suppress verbose HTTP logs from libraries
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('webexteamssdk').setLevel(logging.WARNING)

CONFIG = get_config()

# List of all bots to ping
# PingBot pings all production bots to keep NAT paths active
BOTS_TO_PING = [
    ("Toodles", CONFIG.webex_bot_email_toodles),
    ("MSOAR", CONFIG.webex_bot_email_msoar),
    ("MoneyBall", CONFIG.webex_bot_email_money_ball),
    ("Jarvis", CONFIG.webex_bot_email_jarvis),
    ("Tars", CONFIG.webex_bot_email_tars),
    ("Barnacles", CONFIG.webex_bot_email_barnacles),
    # ("Pokedex", CONFIG.webex_bot_email_pokedex),
]


def send_peer_pings(access_token: str):
    """Send ping messages to all bots to keep NAT paths active."""
    api = WebexTeamsAPI(access_token=access_token)
    timestamp = datetime.now().strftime('%H:%M:%S')

    logger.debug(f"🔔 Starting peer ping cycle at {timestamp}")

    success_count = 0
    fail_count = 0
    successful_bots = []
    failed_bots = []

    for bot_name, bot_email in BOTS_TO_PING:
        try:
            logger.debug(f"Pinging {bot_name} ({bot_email})...")
            # Send the message
            api.messages.create(
                toPersonEmail=bot_email,
                text=f"Hi @ {timestamp}"  # Simple greeting that triggers bot response
            )
            logger.debug(f'Message sent to {bot_name}')

        #         # Wait for bot to respond
        #         time.sleep(5)  # Wait 5 seconds for bot to process and reply
        #
        #         # Fetch recent messages from the room to get bot's reply
        #         room_id = response.roomId
        #         messages = list(api.messages.list(roomId=room_id, max=10))
        #
        #         logger.debug(f"  Found {len(messages)} messages in room")
        #
        #         # Debug: print all messages
        #         # for idx, msg in enumerate(messages):
        #         #     logger.debug(f"    Msg {idx}: from={msg.personEmail}, created={msg.created}, text={msg.text[:50] if hasattr(msg, 'text') and msg.text else 'N/A'}")
        #
        #         # Find the bot's reply (not our own message)
        #         bot_reply = None
        #         for msg in messages:
        #             # Skip our own message
        #             if msg.id == response.id:
        #                 continue
        #             # Check if it's from the bot (newer than our message)
        #             if msg.personEmail == bot_email and msg.created > response.created:
        #                 bot_reply = msg
        #                 break
        #
        #         if bot_reply:
        #             logger.debug(f"  ✅ {bot_name} replied: {bot_reply.text}")
        #             success_count += 1
        #             successful_bots.append(bot_name)
        #         else:
        #             logger.debug(f"  ⚠️  No reply from {bot_name} yet")
        #             fail_count += 1
        #             failed_bots.append(bot_name)
        except Exception as e:
            logger.error(f"  ❌ Failed to ping {bot_name}: {e}")
            # fail_count += 1
            # failed_bots.append(bot_name)
    #
    # # Build summary message
    # summary = f"✅ Peer ping cycle complete: {success_count} successful, {fail_count} failed"
    # if successful_bots:
    #     summary += f"\n  Successful: {', '.join(successful_bots)}"
    # if failed_bots:
    #     summary += f"\n  Failed: {', '.join(failed_bots)}"
    # logger.info(summary)


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
