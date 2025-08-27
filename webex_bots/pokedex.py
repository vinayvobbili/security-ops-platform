# Pokedx SOC Bot - Streamlined Q&A Architecture
"""
HIGH LEVEL REQUIREMENTS:
========================
1. SOC analyst sends message via Webex
2. Search local documents first for relevant information
3. If found, provide answer with proper source attribution
4. Use available tools (CrowdStrike, weather, etc.) as needed
5. Supplement with LLM training data with clear disclaimers
6. Keep responses under 30 seconds for operational needs
7. Prioritize reliability and speed over sophisticated reasoning

ARCHITECTURE APPROACH:
=====================
- Direct document search first (not agent-driven)
- Simple LLM calls for supplementation (not complex agents)  
- Synchronous processing in WebX threads
- Clear error boundaries and timeouts
- Source attribution for all document-based responses
"""
import csv
import logging
import os
import signal
from datetime import datetime
from pathlib import Path

from pytz import timezone
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from bot.core.my_model import ask, shutdown_handler, initialize_model_and_agent
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


def send_ready_notification(init_duration: float):
    """Send Webex notification that Pokedx is ready"""
    try:
        from bot.utils.enhanced_config import ModelConfig
        
        webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_pokedx)
        config = ModelConfig()

        # Format duration
        minutes = int(init_duration // 60)
        seconds = int(init_duration % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

        message = f"""🚀 **Pokedx SOC Bot is Ready!**
        
✅ **Status:** Fully initialized and running  
⚡ **Model:** {config.llm_model_name}
⏱️ **Startup Time:** {duration_str}
🤖 **Ready for:** Security analysis, threat intel, document search  

The {config.llm_model_name} SOC bot is now online and ready! 🎯"""

        webex_api.messages.create(
            toPersonEmail=CONFIG.my_email_address,
            markdown=message
        )
        logger.info("✅ Ready notification sent to Webex")
    except Exception as e:
        logger.error(f"Failed to send ready notification: {e}")


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

        bot_ready = True
        total_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"✅ Streamlined bot initialization completed in {total_time:.1f}s")
        return True

    except Exception as e:
        logger.error(f"Streamlined bot initialization failed: {e}", exc_info=True)
        bot_ready = False
        return False


def process_user_message(user_message: str, teams_message, activity) -> str:
    """Process user message and return response text"""
    if not user_message.strip():
        return ""

    logger.info(f"Processing message from {teams_message.personEmail}: {user_message[:100]}...")

    # Check if bot is ready
    if not bot_ready:
        return "🔄 I'm still starting up. Please try again in a moment."

    # Get response using streamlined SOC Q&A approach
    try:
        response_text = ask(
            user_message,
            user_id=teams_message.personId,
            room_id=teams_message.roomId
        )
    except Exception as e:
        logger.error(f"Error in streamlined SOC Q&A: {e}")
        return "❌ I encountered an error processing your message. Please try again."

    # Format for Webex
    if len(response_text) > 7000:
        response_text = response_text[:6900] + "\n\n*[Response truncated for message limits]*"

    logger.info(f"Sending response to {teams_message.personEmail}: {len(response_text)} chars")
    return response_text


class PokeDxBot(WebexBot):
    """Streamlined Pokedex bot"""

    def process_incoming_message(self, teams_message, activity):
        """Process incoming messages"""
        logger.info(f"Processing message: {getattr(teams_message, 'text', 'NO TEXT')[:50]}...")

        # Basic filtering - ignore bot messages and non-person actors
        if (hasattr(teams_message, 'personEmail') and 
            teams_message.personEmail == self.bot_display_name):
            return

        if activity.get('actor', {}).get('type') != 'PERSON':
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

            # Process message
            user_name = activity.get('actor', {}).get('displayName', 'Unknown')
            room_name = get_room_name(teams_message.roomId, self.access_token)
            start_time = datetime.now()

            response_text = process_user_message(raw_message, teams_message, activity)
            
            if response_text:
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                
                self.teams.messages.create(roomId=teams_message.roomId, markdown=response_text)
                log_conversation(user_name, raw_message, response_text, response_time, room_name)

        except Exception as e:
            logger.error(f"Error in message processing: {e}", exc_info=True)
            self.teams.messages.create(
                roomId=teams_message.roomId,
                text="❌ I encountered an error processing your message. Please try again."
            )


def create_webex_bot():
    """Create and configure the WebexBot instance"""
    return PokeDxBot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_rooms=[CONFIG.webex_room_id_vinay_test_space],
        approved_domains=['company.com'],
        bot_name="Pokedex"
    )


def graceful_shutdown():
    """Perform graceful shutdown"""
    global bot_ready, bot_instance
    bot_ready = False
    
    try:
        shutdown_handler()
        bot_instance = None
    except:
        pass


def main():
    """Main application entry point"""
    global bot_instance

    start_time = datetime.now()
    logger.info("🤖 Starting Pokedex Webex Bot...")

    # Initialize the bot
    if not initialize_bot():
        logger.error("❌ Failed to initialize bot. Exiting.")
        return 1

    try:
        # Create and start the WebEx bot
        logger.info("🌐 Creating WebEx bot connection...")
        bot_instance = create_webex_bot()

        logger.info("✅ Bot created successfully")
        logger.info(f"📧 Bot email: {WEBEX_BOT_EMAIL}")

        # Calculate total initialization time
        init_duration = (datetime.now() - start_time).total_seconds()

        from bot.utils.enhanced_config import ModelConfig
        config = ModelConfig()
        
        print(f"🚀 Pokedx is up and running with {config.llm_model_name} (startup in {init_duration:.1f}s)...")
        logger.info(f"🚀 Pokedx is up and running with {config.llm_model_name} (startup in {init_duration:.1f}s)...")

        # Send ready notification
        send_ready_notification(init_duration)

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