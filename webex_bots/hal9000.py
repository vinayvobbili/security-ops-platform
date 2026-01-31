#!/usr/bin/python3

# HAL9000 Test Bot - Command-based Architecture Experiment
"""
This is a test bot for experimenting with command-based routing.
The goal is to use WebexBot's native command routing instead of
a monolithic process_incoming_message override.

ARCHITECTURE:
- Each command (tipper, rules, contacts, etc.) is a separate Command class
- DefaultCommand handles unmatched messages via LLM
- HelpCommand provides custom help text
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import logging
from src.utils.logging_utils import setup_logging

setup_logging(
    bot_name='hal9000',
    log_level=logging.INFO,
    log_dir=str(PROJECT_ROOT / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager'],
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)

logging.getLogger('webex_bot').setLevel(logging.ERROR)
logging.getLogger('webex_bot.websockets.webex_websocket_client').setLevel(logging.WARNING)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webexpythonsdk').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

import csv
import os
import random
import signal
import atexit
from datetime import datetime
from typing import Optional

from pytz import timezone
from webex_bot.webex_bot import WebexBot
from webex_bot.models.command import Command

from my_config import get_config
from my_bot.core.my_model import (
    ask, initialize_model_and_agent,
    get_help_response,
    handle_tipper_command_with_metrics,
    handle_rules_command,
    handle_falcon_command
)
from my_bot.core.session_manager import get_session_manager
from src.utils.webex_utils import get_room_name
from src.utils.bot_messages import THINKING_MESSAGES, DONE_MESSAGES
from src.components.contacts_lookup import search_contacts_with_llm_with_metrics
from my_bot.tools.xsoar_tools import generate_executive_summary_with_metrics

from src.utils.ssl_config import configure_ssl_if_needed
configure_ssl_if_needed(verbose=True)

from src.utils.enhanced_websocket_client import patch_websocket_client
patch_websocket_client()

logger.warning("=" * 100)
logger.warning(f"🚀 HAL9000 TEST BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

CONFIG = get_config()

WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_hal9000
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_hal9000

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_ACCESS_TOKEN for hal9000 is required")
    sys.exit(1)

eastern = timezone('US/Eastern')
LOG_FILE_DIR = Path(__file__).parent.parent / 'data' / 'transient' / 'logs'


def log_conversation(user_name: str, user_prompt: str, bot_response: str, response_time: float, room_name: str):
    """Log complete conversation to CSV file for analytics"""
    try:
        log_file = LOG_FILE_DIR / "hal9000_conversations.csv"
        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')

        if not log_file.exists():
            os.makedirs(LOG_FILE_DIR, exist_ok=True)
            with open(log_file, "w", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerow([
                    "Person", "User Prompt", "Bot Response", "Response Length",
                    "Response Time (s)", "Webex Room", "Message Time"
                ])

        sanitized_prompt = user_prompt.replace('\n', ' ').replace('\r', ' ')[:500]
        sanitized_response = bot_response.replace('\n', ' ').replace('\r', ' ')[:1000]
        response_length = len(bot_response)
        response_time_rounded = round(response_time, 2)

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([
                user_name, sanitized_prompt, sanitized_response, response_length,
                response_time_rounded, room_name, now_eastern
            ])

    except Exception as e:
        logger.error(f"Error logging conversation: {e}")


def initialize_bot():
    """Initialize the bot components"""
    logger.info("🚀 Starting HAL9000 Bot Initialization...")
    start_time = datetime.now()

    try:
        from src.utils.webex_device_manager import cleanup_devices_on_startup
        import time
        cleanup_devices_on_startup(WEBEX_ACCESS_TOKEN, "HAL9000")
        logger.info("⏳ Waiting 3 seconds for Webex API to sync device deletions...")
        time.sleep(3)

        logger.info("Initializing LLM components...")
        if not initialize_model_and_agent():
            logger.error("Failed to initialize LLM components")
            return False

        session_manager = get_session_manager()
        cleaned_count = session_manager.cleanup_old_sessions()
        if cleaned_count > 0:
            logger.info(f"🧹 Cleaned up {cleaned_count} old conversation messages")

        total_time = (datetime.now() - start_time).total_seconds()

        try:
            from my_bot.core.state_manager import get_state_manager
            state_manager = get_state_manager()
            model_name = state_manager.model_config.llm_model_name if state_manager and hasattr(state_manager, 'model_config') else "Unknown"
        except (ImportError, AttributeError):
            model_name = "Unknown"

        startup_message = f"🚀 HAL9000 is up and running (startup in {total_time:.1f}s) using {model_name}..."
        logger.info(startup_message)
        print(startup_message)

        return True

    except Exception as e:
        logger.error(f"Bot initialization failed: {e}", exc_info=True)
        return False


# =============================================================================
# COMMAND CLASSES
# =============================================================================

class BaseHal9000Command(Command):
    """Base class for HAL9000 commands with common utilities."""

    BOT_NAMES = ['HAL9000', 'hal9000', 'Hal9000']

    def __init__(self, command_keyword: str, help_message: str = ""):
        super().__init__(command_keyword=command_keyword, help_message=help_message)
        self._webex_api = None

    def clean_message(self, message: str) -> str:
        """Strip bot name mentions and command keyword from message text."""
        import re
        cleaned = message
        for bot_name in self.BOT_NAMES:
            pattern = re.compile(re.escape(bot_name), re.IGNORECASE)
            cleaned = pattern.sub('', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        if self.command_keyword and cleaned.lower().startswith(self.command_keyword.lower()):
            cleaned = cleaned[len(self.command_keyword):].strip()
        logger.info(f"[clean_message] '{message}' -> '{cleaned}' (keyword: {self.command_keyword})")
        return cleaned

    def execute(self, message, attachment_actions, activity):
        """Override in subclasses."""
        raise NotImplementedError("Subclasses must implement execute()")

    @property
    def webex_api(self):
        """Lazy-loaded Webex API client."""
        if self._webex_api is None:
            from webexpythonsdk import WebexAPI
            self._webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_hal9000)
        return self._webex_api

    def send_thinking(self, room_id: str, parent_id: str = None) -> Optional[str]:
        """Send a thinking indicator and return the message ID."""
        try:
            thinking_message = random.choice(THINKING_MESSAGES)
            msg = self.webex_api.messages.create(
                roomId=room_id,
                parentId=parent_id,
                text=thinking_message
            )
            return msg.id
        except Exception as e:
            logger.warning(f"Failed to send thinking message: {e}")
            return None

    def update_thinking_done(self, message_id: Optional[str], room_id: str, response_time: float, metrics: dict = None):
        """Update thinking message to show completion with metrics."""
        if not message_id:
            return
        try:
            import requests
            done_prefix = random.choice(DONE_MESSAGES)
            if metrics and metrics.get('total_tokens', 0) > 0 and metrics.get('generation_time', 0) > 0:
                done_message = f"{done_prefix} ⚡ Time: **{response_time:.1f}s** ({metrics['prompt_time']:.1f}s prompt + {metrics['generation_time']:.1f}s gen) | Tokens: {metrics['input_tokens']}→{metrics['output_tokens']} | Speed: {metrics['tokens_per_sec']:.1f} tok/s"
            else:
                done_message = f"{done_prefix} ⚡ Response time: **{response_time:.1f}s**"

            edit_url = f'https://webexapis.com/v1/messages/{message_id}'
            headers = {'Authorization': f'Bearer {CONFIG.webex_bot_access_token_hal9000}', 'Content-Type': 'application/json'}
            requests.put(edit_url, headers=headers, json={'roomId': room_id, 'markdown': done_message})
        except Exception as e:
            logger.warning(f"Failed to update thinking message: {e}")

    def send_response(self, room_id: str, parent_id: str, content: str, file_path: str = None):
        """Send the response, optionally with a file attachment."""
        try:
            if file_path:
                import os
                if os.path.exists(file_path):
                    self.webex_api.messages.create(
                        roomId=room_id,
                        parentId=parent_id,
                        text=content,
                        files=[file_path]
                    )
                    os.remove(file_path)
                    logger.info(f"Uploaded and deleted file: {file_path}")
                    return
            if len(content) > 7000:
                content = content[:6900] + "\n\n*[Response truncated for message limits]*"
            self.webex_api.messages.create(roomId=room_id, parentId=parent_id, markdown=content)
        except Exception as e:
            logger.error(f"Failed to send response: {e}")


class HelpCommand(BaseHal9000Command):
    """Display custom help message with sample prompts."""

    def __init__(self):
        super().__init__(command_keyword="help", help_message="Show help and sample prompts")

    def execute(self, message, attachment_actions, activity):
        return get_help_response()


class TipperCommand(BaseHal9000Command):
    """Handle tipper analysis command: tipper <id>"""

    def __init__(self):
        super().__init__(command_keyword="tipper", help_message="Analyze a tipper: `tipper 12345`")

    def execute(self, message, attachment_actions, activity):
        import re
        from datetime import datetime

        text = self.clean_message(message)
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id

        match = re.search(r'#?(\d+)', text)
        if not match:
            return "❌ Usage: `tipper <id>`\n\nExample: `tipper 12345`"

        tipper_id = match.group(1)
        start_time = datetime.now()
        thinking_id = self.send_thinking(room_id, parent_id)

        try:
            result = handle_tipper_command_with_metrics(tipper_id, room_id)
            response_time = (datetime.now() - start_time).total_seconds()

            self.update_thinking_done(thinking_id, room_id, response_time, result)
            self.send_response(room_id, parent_id, result['content'])
            return None
        except Exception as e:
            logger.error(f"Tipper command error: {e}", exc_info=True)
            return f"❌ Error analyzing tipper: {e}"


class RulesCommand(BaseHal9000Command):
    """Handle detection rules search: rules <query>"""

    def __init__(self):
        super().__init__(command_keyword="rules", help_message="Search detection rules: `rules emotet`")

    def execute(self, message, attachment_actions, activity):
        from datetime import datetime

        query = self.clean_message(message)
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id

        if not query:
            return "❌ Usage: `rules <query>`\n\nExample: `rules emotet`"

        start_time = datetime.now()
        thinking_id = self.send_thinking(room_id, parent_id)

        try:
            result = handle_rules_command(query)
            response_time = (datetime.now() - start_time).total_seconds()

            self.update_thinking_done(thinking_id, room_id, response_time, result)
            self.send_response(room_id, parent_id, result['content'])
            return None
        except Exception as e:
            logger.error(f"Rules command error: {e}", exc_info=True)
            return f"❌ Error searching rules: {e}"


class ContactsCommand(BaseHal9000Command):
    """Handle contacts lookup: contacts <query>"""

    def __init__(self):
        super().__init__(command_keyword="contacts", help_message="Lookup contacts: `contacts john smith`")

    def execute(self, message, attachment_actions, activity):
        from datetime import datetime

        query = self.clean_message(message)
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id

        if not query:
            return "❌ Usage: `contacts <name or query>`\n\nExample: `contacts john smith`"

        start_time = datetime.now()
        thinking_id = self.send_thinking(room_id, parent_id)

        try:
            result = search_contacts_with_llm_with_metrics(query)
            response_time = (datetime.now() - start_time).total_seconds()

            self.update_thinking_done(thinking_id, room_id, response_time, result)
            self.send_response(room_id, parent_id, result['content'])
            return None
        except Exception as e:
            logger.error(f"Contacts command error: {e}", exc_info=True)
            return f"❌ Error looking up contacts: {e}"


class ExecsumCommand(BaseHal9000Command):
    """Handle executive summary: execsum <ticket_id>"""

    def __init__(self):
        super().__init__(command_keyword="execsum", help_message="Generate executive summary: `execsum 929947`")

    def execute(self, message, attachment_actions, activity):
        from datetime import datetime

        ticket_id = self.clean_message(message)
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id

        if not ticket_id:
            return "❌ Usage: `execsum <ticket_id>`\n\nExample: `execsum 929947`"

        start_time = datetime.now()
        thinking_id = self.send_thinking(room_id, parent_id)

        try:
            result = generate_executive_summary_with_metrics(ticket_id, "prod")
            response_time = (datetime.now() - start_time).total_seconds()

            self.update_thinking_done(thinking_id, room_id, response_time, result)
            self.send_response(room_id, parent_id, result['content'])
            return None
        except Exception as e:
            logger.error(f"Execsum command error: {e}", exc_info=True)
            return f"❌ Error generating executive summary: {e}"


class FalconCommand(BaseHal9000Command):
    """Handle CrowdStrike/Falcon commands: falcon <query>"""

    def __init__(self):
        super().__init__(command_keyword="falcon", help_message="CrowdStrike operations: `falcon get detections for HOST123`")

    def execute(self, message, attachment_actions, activity):
        from datetime import datetime

        query = self.clean_message(message)
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id

        if not query:
            return "❌ Usage: `falcon <query>`\n\nExamples:\n• `falcon get browser history from HOST123`\n• `falcon check containment for HOST456`\n• `falcon detections for LAPTOP789`"

        start_time = datetime.now()
        thinking_id = self.send_thinking(room_id, parent_id)

        try:
            result = handle_falcon_command(query, room_id=room_id)
            response_time = (datetime.now() - start_time).total_seconds()

            self.update_thinking_done(thinking_id, room_id, response_time, result)

            file_path = result.get('file_path')
            self.send_response(room_id, parent_id, result['content'], file_path)
            return None
        except Exception as e:
            logger.error(f"Falcon command error: {e}", exc_info=True)
            return f"❌ Error executing Falcon command: {e}"


class DefaultCommand(BaseHal9000Command):
    """Fallback command - routes unmatched messages to the LLM agent."""

    def __init__(self):
        super().__init__(command_keyword="", help_message="Ask me anything about SOC operations!")

    def execute(self, message, attachment_actions, activity):
        import threading
        from datetime import datetime

        raw_message = self.clean_message(message) if isinstance(message, str) else (message.text or "")
        room_id = attachment_actions.roomId
        parent_id = getattr(attachment_actions, 'parentId', None) or attachment_actions.id
        user_email = attachment_actions.personEmail

        if not raw_message:
            return None

        logger.info(f"[LLM INPUT] User: {user_email} | Message: {raw_message[:200]}...")

        start_time = datetime.now()

        # Send thinking indicator
        thinking_msg = None
        thinking_active = threading.Event()

        try:
            thinking_message = random.choice(THINKING_MESSAGES)
            thinking_msg = self.webex_api.messages.create(
                roomId=room_id,
                parentId=parent_id,
                text=thinking_message
            )
            thinking_active.set()

            def update_thinking_message():
                import time
                counter = 1
                max_edits = 9
                while thinking_active.is_set() and counter <= max_edits:
                    time.sleep(15)
                    if thinking_active.is_set():
                        try:
                            import requests
                            new_message = random.choice(THINKING_MESSAGES)
                            update_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                            headers = {
                                'Authorization': f'Bearer {CONFIG.webex_bot_access_token_hal9000}',
                                'Content-Type': 'application/json'
                            }
                            payload = {'roomId': room_id, 'text': f"{new_message} ({counter * 15}s)"}
                            response = requests.put(update_url, headers=headers, json=payload)
                            if response.status_code == 200:
                                counter += 1
                            else:
                                break
                        except Exception:
                            break

            thinking_thread = threading.Thread(target=update_thinking_message, daemon=True)
            thinking_thread.start()

        except Exception as e:
            logger.warning(f"Failed to send thinking message: {e}")
            thinking_msg = None

        # Process through LLM agent
        try:
            room_name = get_room_name(room_id, CONFIG.webex_bot_access_token_hal9000)
            result = ask(raw_message, user_id=user_email, room_id=room_name)
            response_text = result['content']
            metrics = {
                'input_tokens': result['input_tokens'],
                'output_tokens': result['output_tokens'],
                'total_tokens': result['total_tokens'],
                'prompt_time': result['prompt_time'],
                'generation_time': result['generation_time'],
                'tokens_per_sec': result['tokens_per_sec']
            }
            logger.info(f"[LLM OUTPUT] Tokens: {metrics['input_tokens']}→{metrics['output_tokens']} | Response: {response_text[:200]}...")
        except Exception as e:
            logger.error(f"Error in LLM agent processing: {e}")
            response_text = "❌ I encountered an error processing your message. Please try again."
            metrics = {}

        # Stop thinking updates
        if thinking_active:
            thinking_active.clear()

        response_time = (datetime.now() - start_time).total_seconds()

        # Update thinking message to done
        if thinking_msg and response_text:
            self.update_thinking_done(thinking_msg.id, room_id, response_time, metrics)

        # Send response
        if response_text:
            self.send_response(room_id, parent_id, response_text)

            user_name = activity.get('actor', {}).get('displayName', 'Unknown')
            room_name = get_room_name(room_id, CONFIG.webex_bot_access_token_hal9000)
            log_conversation(user_name, raw_message, response_text, response_time, room_name)
        else:
            logger.warning(f"Received empty response from LLM after {response_time:.1f}s")
            self.send_response(room_id, parent_id,
                "❌ I received an empty response. Please try rephrasing your question.")

        return None


# =============================================================================
# BOT CLASS - Using WebexBot's native command routing
# =============================================================================

class Bot(WebexBot):
    """HAL9000 Test Bot - uses standard command routing with LLM fallback"""
    pass


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 HAL9000 BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """HAL9000 main - Test bot with command-based architecture"""
    bot_name = "HAL9000"
    logger.info("Starting HAL9000 with command-based architecture")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    if not initialize_bot():
        logger.error("Failed to initialize bot components")
        return 1

    # Create bot instance with custom help command
    bot = Bot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_domains=[CONFIG.my_web_domain],
        bot_name=bot_name,
        help_command=HelpCommand()
    )

    # Register commands (specific commands first, then fallback)
    bot.add_command(TipperCommand())
    bot.add_command(RulesCommand())
    bot.add_command(ContactsCommand())
    bot.add_command(ExecsumCommand())
    bot.add_command(FalconCommand())
    bot.add_command(DefaultCommand())  # Fallback for unmatched messages -> LLM
    logger.info("Registered commands: tipper, rules, contacts, execsum, falcon + default (LLM fallback) + custom help")

    logger.info("🚀 HAL9000 is up and running with command-based architecture...")
    print("🚀 HAL9000 is up and running with command-based architecture...", flush=True)

    try:
        bot.run()
    except KeyboardInterrupt:
        logger.info("🛑 HAL9000 stopped by user (Ctrl+C)")
    except Exception as e:
        logger.error(f"❌ HAL9000 crashed: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    main()
