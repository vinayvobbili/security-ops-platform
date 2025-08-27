# webex_bot.py - Using webex_bot library with WebSockets
import csv
import logging
import os
import re
import signal
from datetime import datetime
from pathlib import Path
from typing import Union

from pytz import timezone

from webex_bot.models.command import Command
from webex_bot.models.response import Response
# Import the webex_bot library
from webex_bot.webex_bot import WebexBot

from my_config import get_config
# Import your enhanced RAG model
from bot.core.my_model import initialize_model_and_agent, ask, warmup, shutdown_handler
from services.bot_rooms import get_room_name

CONFIG = get_config()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_pokedex
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_pokedex

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_ACCESS_TOKEN environment variable is required")
    exit(1)

# Global variables for bot state
bot_ready = False
initialization_time: Union[datetime, None] = None
bot_instance = None  # Store bot instance for clean shutdown

# Logging configuration
eastern = timezone('US/Eastern')
LOG_FILE_DIR = Path(__file__).parent.parent / 'data' / 'transient' / 'logs'


def log_conversation(user_name: str, user_prompt: str, bot_response: str, response_time: float, room_name: str):
    """Log complete conversation (prompt + response) to CSV file for analytics"""
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
        
        # Sanitize data for CSV (remove problematic characters, limit length)
        sanitized_prompt = user_prompt.replace('\n', ' ').replace('\r', ' ')[:500]
        sanitized_response = bot_response.replace('\n', ' ').replace('\r', ' ')[:1000]  # Longer limit for responses
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


def log_user_prompt(user_name: str, user_prompt: str, room_name: str):
    """Log user prompts to CSV file for analytics (legacy function)"""
    try:
        log_file = LOG_FILE_DIR / "pokedex_user_prompts.csv"
        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        
        # Create header if file doesn't exist
        if not log_file.exists():
            os.makedirs(LOG_FILE_DIR, exist_ok=True)
            with open(log_file, "w", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["Person", "User Prompt", "Webex Room", "Message Time"])
        
        # Sanitize prompt for CSV (remove newlines, limit length)
        sanitized_prompt = user_prompt.replace('\n', ' ').replace('\r', ' ')[:500]
        
        # Append user prompt
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([user_name, sanitized_prompt, room_name, now_eastern])
            
    except Exception as e:
        logger.error(f"Error logging user prompt: {e}")


class RAGBotCommands:
    """Command handlers for the RAG bot"""

    def __init__(self):
        self.startup_time = datetime.now()

    @staticmethod
    def preprocess_message(message: str) -> str:
        """Clean up message text"""
        if not message:
            return ""

        # Remove HTML entities
        message = message.replace('&lt;', '<').replace('&gt;', '>')
        message = message.replace('&amp;', '&').replace('&nbsp;', ' ')

        # Remove extra whitespace
        message = ' '.join(message.split())

        return message.strip()

    @staticmethod
    def format_response_for_webex(response: str) -> str:
        """Format response for Webex Teams with proper markdown support"""
        # Webex message limit
        if len(response) > 7000:
            response = response[:6900] + "\n\n*[Response truncated for message limits]*"

        # The response is already formatted with proper Webex markdown from format_for_chat
        # Just ensure it's properly structured for Webex
        return response


# Initialize the command handler
commands = RAGBotCommands()


# --- Command Definitions ---

class AskCommand(Command):
    """Handle general questions and RAG queries"""

    def __init__(self):
        super().__init__(
            command_keyword="*",  # Use * as a wildcard catch-all
            help_message="Ask me anything! I can help with documents, weather, math, and API calls.",
            card=None
        )

    def pre_execute(self, message, teams_message, activity):
        """Check if bot should respond to this message"""
        # Add debugging to see if this method is being called
        logger.info(f"AskCommand.pre_execute called for message: {getattr(teams_message, 'text', 'NO TEXT')[:50]}...")

        # Don't respond to bot's own messages
        if hasattr(teams_message, 'personEmail') and teams_message.personEmail == WEBEX_BOT_EMAIL:
            logger.info("Ignoring bot's own message")
            return False

        # This is a catch-all command - respond to ALL other messages
        logger.info("AskCommand will handle this message")
        return True

    def execute(self, message, teams_message, activity):
        """Process the user's message and return response - this is the main method WebexBot calls"""
        global bot_ready

        try:
            # Clean the message text using our instance's helper methods
            user_message = commands.preprocess_message(teams_message.text or "")

            # Remove bot mentions
            user_message = re.sub(rf'<@personEmail:{re.escape(WEBEX_BOT_EMAIL)}>', '', user_message).strip()

            if not user_message:
                return Response()

            logger.info(f"Processing message from {teams_message.personEmail}: {user_message[:100]}...")

            # Check if bot is ready
            if not bot_ready:
                response = Response()
                response.text = "🔄 I'm still starting up. Please try again in a moment."
                return response

            # Access command info from self for logging
            logger.debug(f"Command keyword: {self.command_keyword}, Help: {self.help_message}")

            # Get response from RAG model
            response_text = ask(
                user_message,
                user_id=teams_message.personId,
                room_id=teams_message.roomId
            )

            # Format for Webex using our static helper
            formatted_response = commands.format_response_for_webex(response_text)

            logger.info(f"Sending response to {teams_message.personEmail}: {len(formatted_response)} chars")

            response = Response()
            response.markdown = formatted_response  # Use markdown instead of text
            return response

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            response = Response()
            response.text = "❌ I encountered an error processing your message. Please try again."
            return response

    def card_callback(self, message, teams_message, activity):
        """Card callback method - delegates to execute to avoid recursion"""
        # This should NOT call execute, instead it should BE the implementation
        # But since the WebexBot source shows it calls card_callback, this IS the main method
        return self.execute(message, teams_message, activity)


# --- Bot Initialization ---

def initialize_bot():
    """Initialize the RAG model and bot"""
    global bot_ready, initialization_time

    logger.info("🚀 Initializing RAG Bot...")

    try:
        # Initialize the RAG model
        logger.info("Initializing RAG model and agent...")
        success = initialize_model_and_agent()

        if not success:
            logger.error("Failed to initialize RAG model")
            return False

        initialization_time = datetime.now()
        logger.info("✅ RAG model initialized successfully")

        # Warm up the model
        logger.info("Warming up model...")
        if warmup():
            logger.info("✅ Model warmed up successfully")
        else:
            logger.warning("⚠️ Model warmup had issues, but continuing...")

        bot_ready = True
        logger.info("🎉 Bot initialization completed!")

        return True

    except Exception as e:
        logger.error(f"Bot initialization failed: {e}", exc_info=True)
        bot_ready = False
        return False


class CatchAllWebexBot(WebexBot):
    """Custom WebexBot that sends ALL messages to a single handler"""

    def process_incoming_message(self, teams_message, activity):
        """
        Override to send all messages to our AskCommand.
        This completely bypasses the default command matching logic.
        """
        logger.info(f"CatchAllWebexBot processing message: {getattr(teams_message, 'text', 'NO TEXT')[:50]}...")

        # Don't respond to bot's own messages (check against bot display name)
        if hasattr(teams_message, 'personEmail') and teams_message.personEmail == self.bot_display_name:
            logger.info("Ignoring bot's own message")
            return
        
        # Don't respond to lorem ipsum demo clearing messages 
        message_text = getattr(teams_message, 'text', '')
        if "lorem ipsum" in message_text.lower() and len(message_text) > 500:
            logger.info("Ignoring lorem ipsum demo clearing message")
            return

        # Also check the actor type to ensure it's from a person, not a bot
        if activity.get('actor', {}).get('type') != 'PERSON':
            logger.info("Ignoring message from non-person actor")
            return

        user_email = teams_message.personEmail
        if not self.check_user_approved(user_email=user_email, approved_rooms=self.approved_rooms):
            logger.info(f"User {user_email} not approved")
            return

        # Create an AskCommand instance and execute it directly
        ask_command = AskCommand()

        # Follow the exact same pattern as the base WebexBot
        try:
            # Get the raw message and clean it like WebexBot does
            raw_message = teams_message.text
            is_one_on_one_space = 'ONE_ON_ONE' in activity['target']['tags']

            # Remove the Bots display name from the message if this is not a 1-1 (like WebexBot does)
            if not is_one_on_one_space:
                raw_message = raw_message.replace(self.bot_display_name, '').strip()

            # Get message without command (WebexBot does this on line 368-369)
            message_without_command = WebexBot.get_message_passed_to_command(ask_command.command_keyword, raw_message)

            logger.info(f"Raw message: '{raw_message}', Cleaned: '{message_without_command}'")

            # Prepare for logging
            user_name = activity.get('actor', {}).get('displayName', 'Unknown')
            room_name = get_room_name(teams_message.roomId, self.access_token)
            start_time = datetime.now()

            # Call pre_execute with the exact same signature as WebexBot (line 386-388)
            pre_exec_result = ask_command.pre_execute(message_without_command, teams_message, activity)
            if pre_exec_result:
                logger.info("AskCommand pre_execute passed, executing command")

                # Call card_callback with exact same signature as WebexBot (line 396)
                response = ask_command.card_callback(message_without_command, teams_message, activity)

                # Calculate response time and log conversation
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                
                # Extract response text for logging
                bot_response_text = ""
                response_sent = False
                
                if response and (hasattr(response, 'markdown') and response.markdown) or (hasattr(response, 'text') and response.text):
                    if hasattr(response, 'markdown') and response.markdown:
                        bot_response_text = response.markdown
                        self.teams.messages.create(roomId=teams_message.roomId, markdown=response.markdown)
                        logger.info("Response sent successfully via catch-all handler using markdown")
                        response_sent = True
                    elif hasattr(response, 'text') and response.text:
                        bot_response_text = response.text
                        self.teams.messages.create(roomId=teams_message.roomId, text=response.text)
                        logger.info("Response sent successfully via catch-all handler using text")
                        response_sent = True
                    
                    # Log the complete conversation
                    log_conversation(user_name, message_without_command, bot_response_text, response_time, room_name)
                    log_user_prompt(user_name, message_without_command, room_name)  # Keep legacy log
                
                if not response_sent:
                    # Check if this was intentionally ignored (empty response for lorem ipsum)
                    if response and hasattr(response, 'text') and response.text == "":
                        logger.info("Bot intentionally ignored message (lorem ipsum or demo clearing)")
                    else:
                        logger.warning("AskCommand returned empty or invalid response")
            else:
                logger.info("AskCommand pre_execute returned False, not executing")

        except Exception as e:
            logger.error(f"Error in catch-all message processing: {e}", exc_info=True)
            # Send an error message back to the user
            self.teams.messages.create(
                roomId=teams_message.roomId,
                text="❌ I encountered an error processing your message. Please try again."
            )


def create_webex_bot():
    """Create and configure the WebexBot instance"""

    # Create custom bot instance that catches all messages
    bot = CatchAllWebexBot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_rooms=[CONFIG.webex_room_id_vinay_test_space],  # Empty list means all rooms
        approved_domains=['company.com'],
        bot_name="Pokedex"
    )

    # We don't need to add any commands since we're overriding the processing
    logger.info("Created custom catch-all bot")

    return bot


# --- Main Application ---

def graceful_shutdown():
    """Perform graceful shutdown of all bot components"""
    global bot_ready, bot_instance
    bot_ready = False
    
    try:
        # Try graceful shutdown first
        shutdown_handler()
        logger.info("✅ Graceful shutdown completed")
    except Exception as e:
        logger.error(f"Error during graceful shutdown: {e}")
    
    # Force exit after timeout
    import os, threading, time
    def force_exit():
        time.sleep(2)  # Wait 2 seconds for cleanup
        logger.info("🔥 Force exiting...")
        os._exit(0)
    
    # Start force exit timer
    force_exit_thread = threading.Thread(target=force_exit, daemon=True)
    force_exit_thread.start()
    
    # Try to stop WebEx bot connection if it exists
    if bot_instance:
        try:
            logger.info("Stopping WebEx bot connection...")
            # Force close any websocket connections
            if hasattr(bot_instance, 'websocket'):
                bot_instance.websocket.close()
        except Exception as e:
            logger.error(f"Error stopping bot: {e}")
    
    os._exit(0)


def main():
    """Main application entry point"""
    global bot_instance
    
    start_time = datetime.now()
    logger.info("🤖 Starting Webex RAG Bot with WebSocket connection...")

    # Initialize the RAG model first
    if not initialize_bot():
        logger.error("❌ Failed to initialize bot. Exiting.")
        return 1

    try:
        # Create and start the WebEx bot
        logger.info("🌐 Creating WebEx bot connection...")
        bot_instance = create_webex_bot()

        logger.info("✅ Bot created successfully")
        logger.info(f"📧 Bot email: {WEBEX_BOT_EMAIL}")
        logger.info("🔗 Connecting to Webex via WebSocket...")
        
        # Calculate initialization time
        end_time = datetime.now()
        init_duration = (end_time - start_time).total_seconds()
        
        print(f"🤖 Pokedex is up and running with llama3.1:70b (initialized in {init_duration:.1f}s)...")
        logger.info(f"🤖 Pokedex is up and running with llama3.1:70b (initialized in {init_duration:.1f}s)...")

        # Start the bot (this will block and run forever)
        bot_instance.run()

    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user (Ctrl+C)")
        graceful_shutdown()
        # Immediate exit for PyCharm restart
        import os
        os._exit(0)
    except Exception as e:
        logger.error(f"❌ Bot error: {e}", exc_info=True)
        graceful_shutdown()
        import os
        os._exit(1)
    finally:
        # Ensure cleanup happens regardless of how we exit
        if 'bot_instance' in globals() and bot_instance:
            graceful_shutdown()
        # Force exit in finally block too
        import os
        os._exit(0)


# --- Development/Testing Functions ---

def test_bot_locally():
    """Test bot functionality without WebSocket connection"""
    logger.info("🧪 Testing bot locally...")

    if not initialize_bot():
        logger.error("Failed to initialize bot for testing")
        return

    # Test queries
    test_queries = [
        "Hello!",
        "What's the weather in Tokyo?",
        "Calculate 15 * 23 + 7",
        "status",
        "help"
    ]

    print("\n" + "=" * 60)
    print("🧪 LOCAL BOT TESTING")
    print("=" * 60)

    for i, query in enumerate(test_queries, 1):
        print(f"\n{i}. User: {query}")
        print("-" * 40)

        try:
            # Test the ask function directly
            response = ask(query, user_id="test_user", room_id="test_room")
            print(f"Bot: {response}")
        except Exception as e:
            print(f"Error: {e}")

        print()


if __name__ == "__main__":
    import sys

    # Check for test mode
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_bot_locally()
    else:
        # Enhanced signal handler for clean shutdown
        def signal_handler(sig, frame):
            logger.info(f"Signal {sig} received, initiating graceful shutdown...")
            graceful_shutdown()
            logger.info("Shutdown complete, exiting...")
            # Use os._exit instead of sys.exit for PyCharm compatibility
            import os
            os._exit(0)


        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            exit_code = main()
            sys.exit(exit_code)
        except Exception as e:
            logger.error(f"Fatal error in main: {e}", exc_info=True)
            graceful_shutdown()
            sys.exit(1)
