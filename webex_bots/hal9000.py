# HAL9000 SOC Bot - LLM Agent Architecture
"""
HIGH LEVEL REQUIREMENTS:
========================
1. SOC analyst sends message via Webex
2. LLM agent decides what's needed: documents, tools, or direct response
3. Agent searches documents and uses tools as appropriate
4. Agent provides answers with proper source attribution
5. Agent supplements with training data when local info insufficient
6. Keep responses under 30 seconds for operational needs
7. Prioritize reliability and intelligent decision-making

ARCHITECTURE APPROACH:
=====================
- LLM agent makes all decisions about tools and document search
- Agent has access to document search, CrowdStrike tools, weather tools
- Agent handles parameter extraction, tool selection, and response formatting
- Synchronous processing in WebX threads with agent-driven intelligence
- Source attribution handled by agent prompts and tool responses
"""
import csv
import logging.handlers
import os
import random
import sys
from datetime import datetime
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pytz import timezone
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from my_bot.core.my_model import ask, initialize_model_and_agent
from my_bot.core.session_manager import get_session_manager
from services.bot_rooms import get_room_name
from src.utils.bot_messages import THINKING_MESSAGES, DONE_MESSAGES

CONFIG = get_config()

# Configure logging with colors
ROOT_DIRECTORY = Path(__file__).parent.parent


class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to console output"""

    def format(self, record):
        # Get the original formatted message without colors first
        log_message = super().format(record)

        # Only colorize WARNING and ERROR levels, leave INFO as default
        if record.levelname == 'WARNING':
            return f"\033[33m{log_message}\033[0m"  # Yellow
        elif record.levelname == 'ERROR':
            return f"\033[31m{log_message}\033[0m"  # Red
        elif record.levelname == 'CRITICAL':
            return f"\033[35m{log_message}\033[0m"  # Magenta
        else:
            # INFO, DEBUG and others - no color (default terminal color)
            return log_message


# Create file handler (no colors for file)
file_handler = logging.handlers.RotatingFileHandler(
    ROOT_DIRECTORY / "logs" / "hal9000.log",
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

# Create console handler with colors
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

# Configure root logger with simple approach
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[file_handler, console_handler],
    force=True  # Override any existing logging config
)

logger = logging.getLogger(__name__)

# Configuration
WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_hal9000
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_hal9000

# Network logging configuration - set to False to improve performance
SHOULD_LOG_NETWORK_TRAFFIC = False  # Change to False to disable network logging

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_ACCESS_TOKEN environment variable is required")
    import sys

    sys.exit(1)

# Logging configuration
eastern = timezone('US/Eastern')
LOG_FILE_DIR = Path(__file__).parent.parent / 'data' / 'transient' / 'logs'


def log_conversation(user_name: str, user_prompt: str, bot_response: str, response_time: float, room_name: str):
    """Log complete conversation to CSV file for analytics"""
    try:
        log_file = LOG_FILE_DIR / "_conversations.csv"
        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')

        # Create header if file doesn't exist
        if not log_file.exists():
            os.makedirs(LOG_FILE_DIR, exist_ok=True)
            with open(log_file, "w", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerow([
                    "Person", "User Prompt", "Bot Response", "Response Length",
                    "Response Time (s)", "Webex Room", "Message Time"
                ])

        # Sanitize data for CSV
        sanitized_prompt = user_prompt.replace('\n', ' ').replace('\r', ' ')[:500]
        sanitized_response = bot_response.replace('\n', ' ').replace('\r', ' ')[:1000]
        response_length = len(bot_response)
        response_time_rounded = round(response_time, 2)

        # Append conversation
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([
                user_name, sanitized_prompt, sanitized_response, response_length,
                response_time_rounded, room_name, now_eastern
            ])

    except Exception as e:
        logger.error(f"Error logging conversation: {e}")


def initialize_bot():
    """Initialize the bot components using streamlined approach"""

    logger.info("🚀 Starting Streamlined Bot Initialization...")
    start_time = datetime.now()

    try:
        logger.info("Initializing streamlined SOC Q&A components...")

        if not initialize_model_and_agent():
            logger.error("Failed to initialize streamlined components")
            return False

        # Clean up old conversation sessions on startup
        session_manager = get_session_manager()
        cleaned_count = session_manager.cleanup_old_sessions()
        if cleaned_count > 0:
            logger.info(f"🧹 Cleaned up {cleaned_count} old conversation messages")

        # Set bot as ready immediately after core initialization
        total_time = (datetime.now() - start_time).total_seconds()

        # Get model information
        try:
            from my_bot.core.state_manager import get_state_manager
            state_manager = get_state_manager()
            model_name = state_manager.model_config.llm_model_name if state_manager and hasattr(state_manager, 'model_config') else "Unknown"
        except:
            model_name = "Unknown"

        startup_message = f"🚀 HAL9000 is up and running (startup in {total_time:.1f}s) using {model_name}..."
        logger.info(startup_message)
        print(startup_message)

        return True

    except Exception as e:
        logger.error(f"Streamlined bot initialization failed: {e}", exc_info=True)
        return False


class Bot(WebexBot):
    """LLM Agent-powered SOC bot for Webex"""

    def process_incoming_message(self, teams_message, activity):
        """Process incoming messages"""
        logger.info(f"Processing message: {getattr(teams_message, 'text', 'NO TEXT')[:50]}...")

        # Basic filtering - ignore bot messages and non-person actors
        bot_email = WEBEX_BOT_EMAIL  # Use the actual bot email from config
        if (hasattr(teams_message, 'personEmail') and
                teams_message.personEmail == bot_email):
            logger.info(f"Ignoring bot's own message from {bot_email}")
            return

        if activity.get('actor', {}).get('type') != 'PERSON':
            logger.info("Ignoring non-person actor")
            return

        try:
            # Clean message
            raw_message = teams_message.text or ""

            # Process message with LLM agent
            user_name = activity.get('actor', {}).get('displayName', 'Unknown')
            room_name = get_room_name(teams_message.roomId, self.access_token)
            start_time = datetime.now()

            # Inline message processing logic
            if not raw_message.strip():
                return

            logger.info(f"Processing message from {teams_message.personEmail}: {raw_message[:100]}...")

            # Initialize thinking message variables
            import threading
            thinking_msg = None
            thinking_active = threading.Event()

            # Note: Session management is handled inside the ask() function
            # The LLM agent automatically manages conversation context via SQLite

            # Send thinking indicator as a threaded reply for user engagement
            try:
                thinking_message = random.choice(THINKING_MESSAGES)
                # Use original parent ID if the incoming message is already a reply
                parent_id = teams_message.parentId if hasattr(teams_message, 'parentId') and teams_message.parentId else teams_message.id
                thinking_msg = self.teams.messages.create(
                    roomId=teams_message.roomId,
                    parentId=parent_id,  # Use original parent to avoid "reply to reply"
                    markdown=thinking_message
                )

                # Start background thread to update thinking message every 5 seconds
                import time
                thinking_active.set()

                def update_thinking_message():
                    counter = 1
                    while thinking_active.is_set():
                        time.sleep(10)
                        if thinking_active.is_set():  # Check again after sleep
                            try:
                                new_message = random.choice(THINKING_MESSAGES)
                                # Try editing with proper API call format
                                import requests
                                update_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                                update_headers = {
                                    'Authorization': f'Bearer {self.access_token}',
                                    'Content-Type': 'application/json'
                                }
                                payload = {
                                    'roomId': teams_message.roomId,
                                    'markdown': f"{new_message} ({counter * 10}s)"
                                }

                                response = requests.put(update_url, headers=update_headers, json=payload)

                                if response.status_code == 200:
                                    counter += 1
                                else:
                                    error_detail = response.text if response.text else f"Status {response.status_code}"
                                    logger.warning(f"Message edit failed (disabling updates): {error_detail}")
                                    # If editing fails, stop the updates to avoid clutter
                                    break

                            except Exception as update_error:
                                logger.warning(f"Failed to update thinking message: {update_error}")
                                break

                thinking_thread = threading.Thread(target=update_thinking_message, daemon=True)
                thinking_thread.start()

            except Exception as e:
                logger.warning(f"Failed to send thinking message: {e}")
                thinking_msg = None

            # Process query through LLM agent
            try:
                response_text = ask(
                    raw_message,
                    user_id=teams_message.personId,
                    room_id=teams_message.roomId
                )
            except Exception as e:
                logger.error(f"Error in LLM agent processing: {e}")
                response_text = "❌ I encountered an error processing your message. Please try again."

            # Format for Webex
            if len(response_text) > 7000:
                response_text = response_text[:6900] + "\n\n*[Response truncated for message limits]*"

            logger.info(f"Sending response to {teams_message.personEmail}: {len(response_text)} chars")

            # Done message logic - moved inside the else block where response_text is set
            if response_text:
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()

                # Stop thinking message updates and update to "Done!" message
                if thinking_active:
                    thinking_active.clear()

                # Update the final thinking message to show "Done!"
                if thinking_msg:
                    done_prefix = random.choice(DONE_MESSAGES)
                    done_message = f"{done_prefix} ⚡ Response time: **{response_time:.1f}s**"
                    try:
                        # Update the thinking message to show completion
                        import requests
                        edit_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                        headers = {'Authorization': f'Bearer {CONFIG.webex_bot_access_token_hal9000}', 'Content-Type': 'application/json'}
                        edit_data = {
                            'roomId': teams_message.roomId,
                            'markdown': done_message
                        }

                        edit_response = requests.put(edit_url, headers=headers, json=edit_data)
                        if edit_response.status_code == 200:
                            logger.info(f"Updated thinking message to completion: {done_message}")
                        else:
                            logger.warning(f"Failed to update thinking message to completion: {edit_response.status_code}")
                    except Exception as completion_error:
                        logger.warning(f"Could not update thinking message to completion: {completion_error}")

                # Handle threading - avoid "Cannot reply to a reply" error
                try:
                    # Use original parent ID if the incoming message is already a reply
                    parent_id = teams_message.parentId if hasattr(teams_message, 'parentId') and teams_message.parentId else teams_message.id

                    # Send LLM response directly as Webex message
                    self.teams.messages.create(
                        roomId=teams_message.roomId,
                        parentId=parent_id,
                        markdown=response_text
                    )

                    log_conversation(user_name, raw_message, response_text, response_time, room_name)

                except Exception as threading_error:
                    logger.error(f"Error in threading/response: {threading_error}")
                    # Send response without threading as fallback
                    self.teams.messages.create(
                        roomId=teams_message.roomId,
                        text=response_text if isinstance(response_text, str) and len(response_text) < 7000 else "Response too long for message limits"
                    )

        except Exception as e:
            logger.error(f"Error in message processing: {e}", exc_info=True)
            self.teams.messages.create(
                roomId=teams_message.roomId,
                text="❌ I encountered an error processing your message. Please try again."
            )


def main():
    """HAL9000 main with resilience framework"""
    from src.utils.bot_resilience import ResilientBot

    resilient_runner = ResilientBot(
        bot_factory=lambda: Bot(
            teams_bot_token=WEBEX_ACCESS_TOKEN,
            approved_domains=['company.com'],
            bot_name="HAL9000"
        ),
        initialization_func=initialize_bot
    )
    resilient_runner.run()


if __name__ == "__main__":
    main()
