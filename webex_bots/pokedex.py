# Pokedex SOC Bot - LLM Agent Architecture
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
import signal
import sys
from datetime import datetime
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pytz import timezone
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from pokedex_bot.core.my_model import ask, initialize_model_and_agent
from services.bot_rooms import get_room_name

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
    ROOT_DIRECTORY / "logs" / "pokedex.log",
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
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[file_handler, console_handler],
    force=True  # Override any existing logging config
)

logger = logging.getLogger(__name__)

# Configuration
WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_pokedex
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_pokedex

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_ACCESS_TOKEN environment variable is required")
    import sys

    sys.exit(1)

# Global state
bot_ready = False
bot_instance = None

# Logging configuration
eastern = timezone('US/Eastern')
LOG_FILE_DIR = Path(__file__).parent.parent / 'data' / 'transient' / 'logs'


def log_conversation(user_name: str, user_prompt: str, bot_response: str, response_time: float, room_name: str):
    """Log complete conversation to CSV file for analytics"""
    try:
        log_file = LOG_FILE_DIR / "pokedex_conversations.csv"
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


def generate_health_test_report(test_results, failed_critical):
    """Generate a formatted health test report"""
    total_tests = len(test_results)
    passed_tests = sum(1 for result in test_results.values() if result.get('status') == 'PASS')
    failed_tests = total_tests - passed_tests

    if failed_critical:
        status_emoji = "❌"
        status_text = "CRITICAL FAILURES DETECTED"
    elif failed_tests > 0:
        status_emoji = "⚠️"
        status_text = "SOME TESTS FAILED"
    else:
        status_emoji = "✅"
        status_text = "ALL TESTS PASSED"

    report = f"""🔬 **Pokedex Health Test Report**

{status_emoji} **Overall Status:** {status_text}
📊 **Summary:** {passed_tests}/{total_tests} tests passed

"""

    # Add individual test results
    for test_name, result in test_results.items():
        status = result.get('status', 'UNKNOWN')
        duration = result.get('duration', '0.00s')

        # Duration is already formatted as string (e.g., "2.30s" or "N/A")
        # Don't try to reformat it

        if status == 'PASS':
            emoji = "✅"
        elif status == 'FAIL':
            emoji = "❌"
        else:
            emoji = "⚠️"

        report += f"{emoji} **{test_name}:** {status} ({duration})\n"

        # Add error details for failed tests
        if status == 'FAIL' and 'error' in result:
            report += f"   └─ Error: {result['error']}\n"

    # Add critical test warnings
    if failed_critical:
        report += f"\n🚨 **Critical systems affected:** {', '.join(failed_critical)}"
        report += "\n⚠️ Bot functionality may be impaired. Please review system configuration."

    return report


def send_health_test_report(report):
    """Send health test report directly to user via Webex"""
    global bot_instance
    try:
        if bot_instance and hasattr(bot_instance, 'teams'):
            # Send direct message to user using configured email
            user_email = CONFIG.my_email_address
            bot_instance.teams.messages.create(toPersonEmail=user_email, markdown=report)
            logger.info(f"Health test report sent directly to {user_email}")
        else:
            logger.warning("Cannot send health test report - bot not fully initialized")
    except Exception as e:
        logger.error(f"Failed to send health test report to user: {e}")
        # Fallback to test room if direct message fails
        try:
            if bot_instance and hasattr(bot_instance, 'teams'):
                test_room_id = CONFIG.webex_room_id_vinay_test_space
                bot_instance.teams.messages.create(roomId=test_room_id, markdown=report)
                logger.info("Health test report sent to test room as fallback")
            else:
                logger.error("Bot instance not available for fallback message")
        except Exception as fallback_error:
            logger.error(f"Fallback to test room also failed: {fallback_error}")


def run_health_tests_background():
    """Run health tests in background thread after initialization"""
    try:
        logger.info("🔬 Running system health tests in background...")
        from pokedex_bot.tests.system_health_tests import run_health_tests
        test_results = run_health_tests()

        # Check if critical tests passed
        critical_tests = ['State Manager', 'Document Search', 'LLM Responses']
        failed_critical = []

        for test_name in critical_tests:
            if test_results.get(test_name, {}).get('status') == 'FAIL':
                failed_critical.append(test_name)

        # Generate test report
        report = generate_health_test_report(test_results, failed_critical)

        # Log results
        if failed_critical:
            logger.error(f"❌ Critical tests failed: {', '.join(failed_critical)}")
            logger.error("Bot may not function correctly. Please check system configuration.")
        else:
            logger.info("✅ All critical systems healthy - bot ready for use!")

        # Send WebX message with test results
        send_health_test_report(report)

    except Exception as e:
        logger.warning(f"⚠️  Health tests could not run: {e}")
        # Send error report
        error_report = f"🔬 **Health Test Report - ERROR**\n\n❌ Health tests could not run: {e}"
        send_health_test_report(error_report)


def initialize_bot():
    """Initialize the bot components using streamlined approach"""
    global bot_ready

    logger.info("🚀 Starting Streamlined Bot Initialization...")
    start_time = datetime.now()

    try:
        logger.info("Initializing streamlined SOC Q&A components...")

        if not initialize_model_and_agent():
            logger.error("Failed to initialize streamlined components")
            return False

        # Set bot as ready immediately after core initialization
        bot_ready = True
        total_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"✅ Streamlined bot initialization completed in {total_time:.1f}s")

        # Health tests disabled for faster startup - run manually when needed
        # To run health tests: python pokedex_bot/tests/system_health_tests.py
        # Or use pytest: python -m pytest tests/
        logger.info("🚀 Bot ready - health tests available on demand")

        return True

    except Exception as e:
        logger.error(f"Streamlined bot initialization failed: {e}", exc_info=True)
        bot_ready = False
        return False


class PokeDexBot(WebexBot):
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

        # Check user approval
        user_email = teams_message.personEmail
        if not self.check_user_approved(user_email=user_email, approved_rooms=self.approved_rooms):
            logger.info(f"User {user_email} not approved")
            return

        try:
            # Clean message
            raw_message = teams_message.text or ""
            is_one_on_one = 'ONE_ON_ONE' in activity.get('target', {}).get('tags', [])

            if not is_one_on_one:
                raw_message = raw_message.replace(self.bot_display_name, '').strip()

            # Process message with LLM agent
            user_name = activity.get('actor', {}).get('displayName', 'Unknown')
            room_name = get_room_name(teams_message.roomId, self.access_token)
            start_time = datetime.now()

            # Inline message processing logic
            if not raw_message.strip():
                return

            logger.info(f"Processing message from {teams_message.personEmail}: {raw_message[:100]}...")

            # Initialize thinking_msg as None
            thinking_msg = None

            # Check if bot is ready
            if not bot_ready:
                response_text = "🔄 I'm still starting up. Please try again in a moment."
            else:
                # Send thinking indicator as a threaded reply for user engagement
                try:
                    thinking_msg = self.teams.messages.create(
                        roomId=teams_message.roomId,
                        parentId=teams_message.id,  # Thread it as a reply to user's message
                        text="🤔 Thinking..."
                    )
                except Exception as e:
                    logger.warning(f"Failed to send thinking message: {e}")
                    thinking_msg = None

                # Process query through LLM agent
                agent_start_time = datetime.now()
                # Get response from LLM agent  
                try:
                    response_text = ask(
                        raw_message,
                        user_id=teams_message.personId,
                        room_id=teams_message.roomId
                    )
                    # Calculate response time for cards
                    agent_end_time = datetime.now()
                    response_time_seconds = (agent_end_time - agent_start_time).total_seconds()

                    # Replace placeholder with actual response time in Adaptive Cards
                    if "[X.X]s" in response_text:
                        response_text = response_text.replace("[X.X]s", f"{response_time_seconds:.1f}s")
                except Exception as e:
                    logger.error(f"Error in LLM agent processing: {e}")
                    response_text = "❌ I encountered an error processing your message. Please try again."

                # Format for Webex
                if len(response_text) > 7000:
                    response_text = response_text[:6900] + "\n\n*[Response truncated for message limits]*"

                logger.info(f"Sending response to {teams_message.personEmail}: {len(response_text)} chars")

            if response_text:
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()

                # Handle threading - avoid "Cannot reply to a reply" error
                try:
                    # If the incoming message has a parentId, use that instead to stay in same thread
                    parent_id = getattr(teams_message, 'parentId', None) or teams_message.id

                    # Check for Adaptive Card in LLM response
                    card_dict, clean_text = self._extract_adaptive_card(response_text)

                    # Also check if the entire response is just JSON (LLM mistake)
                    if not card_dict and response_text.strip().startswith('{') and '"type": "AdaptiveCard"' in response_text:
                        try:
                            import json
                            potential_card = json.loads(response_text.strip())
                            if potential_card.get("type") == "AdaptiveCard":
                                card_dict = potential_card
                                clean_text = "Enhanced staffing information"
                                logger.info("Detected raw JSON card response from LLM")
                        except:
                            pass

                    # First, update thinking message with "Done!" regardless of card presence
                    if thinking_msg:
                        # Skip the problematic update, just send completion as new message
                        # This is more reliable than trying to update thinking message
                        done_message = f"✅ **Done!** ⚡ Response time: {response_time:.1f}s"
                        try:
                            self.teams.messages.create(
                                roomId=teams_message.roomId,
                                parentId=parent_id,
                                markdown=done_message
                            )
                            logger.info(f"Sent completion status: {done_message}")
                        except Exception as completion_error:
                            logger.error(f"Could not send completion message: {completion_error}")

                    # Then send the actual response
                    if card_dict:
                        # Send Adaptive Card
                        logger.info("Sending response as Adaptive Card")
                        self.teams.messages.create(
                            roomId=teams_message.roomId,
                            parentId=parent_id,  # ✅ Threaded with original message
                            text=clean_text or " ",  # Minimal text for card
                            attachments=[{
                                "contentType": "application/vnd.microsoft.card.adaptive",
                                "content": card_dict
                            }]
                        )
                    else:
                        # Send regular response as new threaded message
                        self.teams.messages.create(
                            roomId=teams_message.roomId,
                            parentId=parent_id,  # Threaded with original message
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

    @staticmethod
    def _extract_adaptive_card(response_text):
        """
        Extract Adaptive Card JSON from LLM response if present
        
        Returns:
            tuple: (card_dict, clean_text) or (None, response_text)
        """
        import json
        import re

        try:
            # Look for Adaptive Card markers in the response
            if "ADAPTIVE_CARD_START" in response_text and "ADAPTIVE_CARD_END" in response_text:
                # Extract the JSON between markers
                pattern = r'ADAPTIVE_CARD_START\s*\n?(.*?)\n?ADAPTIVE_CARD_END'
                match = re.search(pattern, response_text, re.DOTALL)

                if match:
                    card_json = match.group(1).strip()
                    # Remove any Markdown code block markers
                    card_json = card_json.replace('```json', '').replace('```', '').strip()

                    try:
                        card_dict = json.loads(card_json)
                        # Remove the card from the original text for fallback
                        clean_text = re.sub(pattern, '', response_text, flags=re.DOTALL).strip()

                        logger.info("Successfully extracted Adaptive Card from LLM response")
                        return card_dict, clean_text

                    except json.JSONDecodeError as je:
                        logger.warning(f"Failed to parse Adaptive Card JSON: {je}")

        except Exception as e:
            logger.error(f"Error extracting Adaptive Card: {e}")

        # No card found or error occurred
        return None, response_text


def create_webex_bot():
    """Create and configure the WebexBot instance"""
    return PokeDexBot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_rooms=[CONFIG.webex_room_id_vinay_test_space],
        approved_domains=['company.com'],
        bot_name="Pokedex"
    )


def graceful_shutdown():
    """Perform graceful shutdown with proper websocket cleanup"""
    global bot_ready, bot_instance
    bot_ready = False

    logger.info("🛑 Performing graceful shutdown...")

    try:
        if bot_instance:
            # Try to properly close the websocket connection
            if hasattr(bot_instance, 'stop'):
                logger.info("Stopping bot instance...")
                bot_instance.stop()
            elif hasattr(bot_instance, 'websocket_client'):
                logger.info("Closing websocket client...")
                bot_instance.websocket_client.close()

            # Clear the instance
            bot_instance = None
            logger.info("Bot instance cleared")
    except Exception as e:
        logger.error(f"Error during graceful shutdown: {e}")
        bot_instance = None


def main():
    """Main application entry point"""
    global bot_instance

    start_time = datetime.now()
    logger.info("🤖 Starting Pokedex Webex Bot...")

    try:
        # Small delay to ensure any previous connections are cleaned up
        logger.info("⏳ Waiting for any previous connections to clean up...")
        import time
        time.sleep(2)

        # Create Webex bot first (before complex initialization)
        logger.info("🌐 Creating Webex bot connection...")
        bot_instance = create_webex_bot()
        logger.info("✅ Bot created successfully")
        logger.info(f"📧 Bot email: {WEBEX_BOT_EMAIL}")

        # Now initialize the LLM components (after Webex bot creation)
        logger.info("🧠 Initializing LLM components...")
        if not initialize_bot():
            logger.error("❌ Failed to initialize bot. Exiting.")
            return 1

        # Calculate total initialization time
        init_duration = (datetime.now() - start_time).total_seconds()

        from pokedex_bot.utils.enhanced_config import ModelConfig
        config = ModelConfig()

        print(f"🚀 Pokedex is up and running with {config.llm_model_name} (startup in {init_duration:.1f}s)...")
        logger.info(f"🚀 Pokedex is up and running with {config.llm_model_name} (startup in {init_duration:.1f}s)...")

        # Start the bot (this will block and run forever)
        bot_instance.run()

    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user (Ctrl+C)")
        graceful_shutdown()
    except Exception as e:
        logger.error(f"❌ Bot error: {e}", exc_info=True)
        graceful_shutdown()
        return 1


if __name__ == "__main__":
    import sys


    def signal_handler(sig, _):
        logger.info(f"🛑 Signal {sig} received, shutting down...")
        graceful_shutdown()
        sys.exit(0)


    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        exit_code = main()
        sys.exit(exit_code or 0)
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        graceful_shutdown()
        sys.exit(1)
