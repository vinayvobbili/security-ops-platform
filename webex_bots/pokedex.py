#!/usr/bin/python3

# the security assistant bot SOC Bot - LLM Agent Architecture
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

# Configure SSL for corporate proxy environments - MUST BE FIRST
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging FIRST before any imports that might use it
import logging

from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility (colors enabled by default)
setup_logging(
    bot_name='pokedex',
    log_level=logging.INFO,
    log_dir=str(PROJECT_ROOT / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager'],
    rotate_on_startup=False  # Keep logs continuous, rely on RotatingFileHandler for size-based rotation
)

logger = logging.getLogger(__name__)

# Note: Using vanilla WebexBot without resilience framework for testing

# Suppress noisy library logs manually since not using ResilientBot
logging.getLogger('webex_bot').setLevel(logging.ERROR)  # Suppress bot-to-bot and self-message warnings
logging.getLogger('webex_bot.websockets.webex_websocket_client').setLevel(logging.WARNING)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webexpythonsdk').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('websockets').setLevel(logging.WARNING)  # Suppress ping/pong keepalive noise
logging.getLogger('unstructured').setLevel(logging.WARNING)  # Suppress DETAIL level narrative analysis logs
logging.getLogger('src.utils.enhanced_websocket_client').setLevel(logging.WARNING)  # Suppress raw WebSocket message spam

# Now safe to import modules that use logging
import csv
import os
import random
import signal
import atexit
from datetime import datetime
from pytz import timezone
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from my_bot.core.my_model import (
    ask, initialize_model_and_agent,
    is_help_command, get_help_response,
    is_falcon_command, handle_falcon_command
)
from my_bot.core.session_manager import get_session_manager
from src.utils.webex_utils import get_room_name
from src.utils.bot_messages import (
    THINKING_MESSAGES,
    DONE_MESSAGES,
    CATEGORY_THINKING_MESSAGES,
    CATEGORY_DISPLAY_NAMES,
)
from my_bot.utils.webex_format import convert_markdown_tables

from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)  # Re-enabled for TLS-inspecting proxy environments

# Enhanced WebSocket client for websockets 14.x compatibility
from src.utils.enhanced_websocket_client import patch_websocket_client

patch_websocket_client()

# Log clear startup marker for visual separation in logs
logger.warning("=" * 100)
logger.warning(f"🚀 POKEDEX BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

CONFIG = get_config(bot_name='pokedex')

# Configuration
WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_pokedex
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_pokedex

# Network logging configuration - set to False to improve performance
SHOULD_LOG_NETWORK_TRAFFIC = False  # Change to False to disable network logging

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_ACCESS_TOKEN environment variable is required")
    import sys

    sys.exit(1)

# Logging configuration
eastern = timezone('US/Eastern')
LOG_FILE_DIR = Path(__file__).parent.parent / 'data' / 'transient' / 'logs'

# Contacts lookup using vector store + LLM
from src.components.contacts_lookup import search_contacts_with_llm_with_metrics


def log_conversation(user_name: str, user_prompt: str, bot_response: str, response_time: float, room_name: str):
    """Log complete conversation to SQLite for analytics."""
    try:
        from src.utils.bot_logs_db import log_conversation as _db_log
        now_eastern = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S')
        _db_log(
            bot="pokedex",
            person=user_name,
            user_prompt=user_prompt,
            bot_response=bot_response,
            response_length=len(bot_response),
            response_time_s=round(response_time, 2),
            room_name=room_name,
            message_time=now_eastern,
        )

    except Exception as e:
        logger.error(f"Error logging conversation: {e}")


def initialize_bot():
    """Initialize the bot components using streamlined approach"""

    logger.info("🚀 Starting Streamlined Bot Initialization...")
    start_time = datetime.now()

    try:
        # Clean up stale device registrations before starting
        from src.utils.webex_device_manager import cleanup_devices_on_startup
        import time
        cleanup_devices_on_startup(WEBEX_ACCESS_TOKEN, "the security assistant bot")

        # Give Webex API time to propagate device deletions (avoid "excessive registrations" error)
        logger.info("⏳ Waiting 3 seconds for Webex API to sync device deletions...")
        time.sleep(3)

        logger.info("Initializing streamlined SOC Q&A components...")

        if not initialize_model_and_agent():
            logger.error("Failed to initialize streamlined components")
            return False

        # Clean up old conversation sessions on startup
        session_manager = get_session_manager()
        cleaned_count = session_manager.cleanup_old_sessions()
        if cleaned_count > 0:
            logger.info(f"🧹 Cleaned up {cleaned_count} old conversation messages")

        # Preload the LLM model into Ollama memory with keep_alive=-1
        # This ensures the model stays loaded even if Pokédex stops
        from my_bot.core.state_manager import get_state_manager
        state_manager = get_state_manager()
        logger.info("🔥 Warming up LLM model (loading into Ollama memory with keep_alive=-1)...")
        if state_manager.fast_warmup():
            logger.info("✅ LLM model pre-loaded and will stay in Ollama memory")
        else:
            logger.warning("⚠️ LLM warmup failed - model will load on first query")

        # Set bot as ready immediately after core initialization
        total_time = (datetime.now() - start_time).total_seconds()

        # Get model information
        try:
            from my_bot.core.state_manager import get_state_manager
            state_manager = get_state_manager()
            model_name = state_manager.model_config.llm_model_name if state_manager and hasattr(state_manager, 'model_config') else "Unknown"
        except (ImportError, AttributeError):
            model_name = "Unknown"

        startup_message = f"🚀 the security assistant bot is up and running (startup in {total_time:.1f}s) using {model_name}..."
        logger.info(startup_message)
        print(startup_message)

        return True

    except Exception as e:
        logger.error(f"Streamlined bot initialization failed: {e}", exc_info=True)
        return False


# Room whitelist for Falcon/CrowdStrike commands - restricted due to powerful capabilities
FALCON_ALLOWED_ROOMS = [CONFIG.webex_room_id_threatcon_collab, CONFIG.webex_room_id_dev_test_space]


class _ThinkingMessagePool:
    """Thread-safe rotating-message pool for the per-request thinking thread.

    Starts on the generic THINKING_MESSAGES list. When the router decides which
    tool categories are needed, ``swap_for_categories`` is called to replace the
    pool with the union of category-specific messages. The thinking thread reads
    via ``next_message`` while the state-manager thread writes via
    ``swap_for_categories`` — a single lock guards the underlying list ref.

    Per-request scoping is mandatory: instantiate one pool per incoming Webex
    message so concurrent users don't share the same pool.
    """

    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self._messages = list(THINKING_MESSAGES)

    def swap_for_categories(self, categories):
        """Replace the pool with messages for the given categories.

        ``categories=None`` or empty → keep the generic pool. The router fall-
        back paths pass ``None``; we don't pick a random subset.
        """
        if not categories:
            return
        merged = []
        for cat in categories:
            cat_msgs = CATEGORY_THINKING_MESSAGES.get(cat)
            if cat_msgs:
                merged.extend(cat_msgs)
        if not merged:
            return
        with self._lock:
            self._messages = merged

    def next_message(self):
        """Return a random message from the current pool (thread-safe)."""
        with self._lock:
            return random.choice(self._messages)


def _format_done_message(response_time: float, metrics: dict = None) -> str:
    """Format the done message with optional LLM metrics."""
    done_prefix = random.choice(DONE_MESSAGES)
    if metrics and metrics.get('total_tokens', 0) > 0 and metrics.get('generation_time', 0) > 0:
        # Timing breakdown: show eval+gen split if server reported both, otherwise just LLM time
        prompt_time = metrics.get('prompt_time', 0)
        gen_time = metrics['generation_time']
        if prompt_time > 0:
            timing_str = f"{prompt_time:.1f}s eval + {gen_time:.1f}s gen"
        else:
            timing_str = f"{gen_time:.1f}s LLM"
        ttft_str = f" | TTFT: {metrics.get('first_token_time', 0):.2f}s" if metrics.get('iterations', 1) > 1 and metrics.get('first_token_time', 0) > 0 else ""
        route_str = f" | Route: {metrics['route']}" if metrics.get('route') else ""
        iter_str = f" | Loops: {metrics.get('iterations', 1)}"
        tok = (f"{metrics['input_tokens']}→{metrics['output_tokens']}"
               if metrics['input_tokens'] > 0 else str(metrics['output_tokens']))
        return f"{done_prefix} ⚡ Time: **{response_time:.1f}s** ({timing_str}) | Tokens: {tok} | TPS: {metrics['tokens_per_sec']:.1f}{ttft_str}{iter_str}{route_str}"
    return f"{done_prefix} ⚡ Response time: **{response_time:.1f}s**"


class Bot(WebexBot):
    """LLM Agent-powered SOC bot for Webex"""

    def _send_triage_action_card_if_needed(self, room_id: str, parent_msg_id: str):
        """Send triage action card as threaded reply if an on-demand triage just ran."""
        import threading
        try:
            from my_bot.tools.xsoar_tools import triage_xsoar_ticket
            results = getattr(triage_xsoar_ticket, '_triage_results', {})
            result = results.pop(threading.current_thread().ident, None)
            if result and result.llm_verdict:
                from webex_bots.cards.sentinel_cards import build_xsoar_triage_card
                card = build_xsoar_triage_card(result)
                self.teams.messages.create(
                    roomId=room_id,
                    parentId=parent_msg_id,
                    text=f"Actions for XSOAR #{result.ticket_id}",
                    attachments=[{
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card,
                    }],
                )
        except Exception as e:
            logger.warning(f"Could not send triage action card: {e}")

    def process_incoming_message(self, teams_message, activity):
        """Process incoming messages"""
        # Basic filtering - ignore bot messages and non-person actors
        bot_email = WEBEX_BOT_EMAIL  # Use the actual bot email from config
        if (hasattr(teams_message, 'personEmail') and
                teams_message.personEmail == bot_email):
            return  # Silently ignore bot's own messages (thinking indicators, etc.)

        if activity.get('actor', {}).get('type') != 'PERSON':
            return  # Silently ignore non-person actors

        # Only process 'post' verbs (new messages), ignore 'edit', 'acknowledge', etc.
        if activity.get('verb') != 'post':
            return  # Silently ignore non-post activities

        logger.info(f"Processing message: {getattr(teams_message, 'text', 'NO TEXT')[:50]}... | Activity verb: {activity.get('verb')}")

        try:
            # Clean message
            raw_message = teams_message.text or ""

            # Strip bot name mentions for command detection
            import re
            cleaned_message = raw_message
            bot_names = ['DnR_the security assistant bot', 'the security assistant bot', 'pokedex', 'dnr_pokedex']
            for bot_name in bot_names:
                pattern = re.compile(re.escape(bot_name), re.IGNORECASE)
                cleaned_message = pattern.sub('', cleaned_message)
            cleaned_message = re.sub(r'\s+', ' ', cleaned_message).strip()

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

            # Per-request rotating-message pool. Starts generic; the router
            # callback (passed into ask() below) swaps it to category-specific
            # messages once tool categories are decided. Pool MUST be local to
            # this handler — the security assistant bot serves concurrent users.
            thinking_pool = _ThinkingMessagePool()

            def _on_router_progress(categories=None):
                # Fired by state_manager.execute_routed_query after the router
                # stage. Two jobs:
                #   1. Swap the rotating pool to category-specific copy so the
                #      next 15s tick shows themed messages.
                #   2. Immediately edit the thinking message in Webex with a
                #      "🎯 Tools loaded: QRadar, CrowdStrike, ..." status so
                #      the user gets instant feedback (instead of waiting up to
                #      15s for the next rotation tick).
                # Non-blocking; state_manager wraps this in try/except so it
                # never aborts the main flow. Fallback paths pass categories=
                # None and skip the Webex edit (the rotation thread keeps the
                # generic pool running).
                thinking_pool.swap_for_categories(categories)

                if not categories or not thinking_msg:
                    return
                try:
                    labels = [
                        CATEGORY_DISPLAY_NAMES.get(c, c.replace('_', ' ').title())
                        for c in categories
                    ]
                    elapsed = (datetime.now() - start_time).total_seconds()
                    new_text = f"🎯 Tools loaded: {', '.join(labels)} ({elapsed:.0f}s)"
                    import requests
                    update_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                    update_headers = {
                        'Authorization': f'Bearer {self.access_token}',
                        'Content-Type': 'application/json',
                    }
                    payload = {
                        'roomId': teams_message.roomId,
                        'text': new_text,
                    }
                    requests.put(update_url, headers=update_headers, json=payload, timeout=5)
                except Exception as edit_err:
                    logger.debug(f"Tools-loaded edit failed (non-fatal): {edit_err}")

            # Note: Session management is handled inside the ask() function
            # The LLM agent automatically manages conversation context via SQLite

            # Send thinking indicator as a threaded reply for user engagement
            try:
                thinking_message = thinking_pool.next_message()
                # Use original parent ID if the incoming message is already a reply
                parent_id = teams_message.parentId if hasattr(teams_message, 'parentId') and teams_message.parentId else teams_message.id
                thinking_msg = self.teams.messages.create(
                    roomId=teams_message.roomId,
                    parentId=parent_id,  # Use original parent to avoid "reply to reply"
                    text=thinking_message
                )

                # Start background thread to update thinking message every 15 seconds
                import time
                thinking_active.set()

                def update_thinking_message():
                    counter = 1
                    max_edits = 9  # Limit to 9 edits to reserve the 10th for the final message
                    while thinking_active.is_set() and counter <= max_edits:
                        time.sleep(10)
                        if thinking_active.is_set():  # Check again after sleep
                            try:
                                new_message = thinking_pool.next_message()
                                # Try editing with proper API call format
                                import requests
                                update_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                                update_headers = {
                                    'Authorization': f'Bearer {self.access_token}',
                                    'Content-Type': 'application/json'
                                }
                                payload = {
                                    'roomId': teams_message.roomId,
                                    'text': f"{new_message} ({counter * 10}s)"
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

            # Empty metrics for non-LLM paths
            _empty = {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0,
                      'prompt_time': 0.0, 'generation_time': 0.0, 'tokens_per_sec': 0.0,
                      'first_token_time': 0.0, 'iterations': 1}

            # Check for help command - bypass LLM entirely (no tokens to track)
            if is_help_command(cleaned_message):
                response_text = get_help_response()
                metrics = _empty
            # Check for contacts command - direct lookup bypassing LLM agent
            elif cleaned_message.lower().startswith('contacts '):
                query = cleaned_message[9:].strip()  # Extract text after "contacts "
                if query:
                    metrics = search_contacts_with_llm_with_metrics(query)
                    response_text = metrics['content']
                else:
                    response_text = "❌ Usage: `contacts <name or query>`\n\nExample: `contacts endpoint protection`"
                    metrics = _empty
            # Check for falcon command - direct CrowdStrike operations (room-restricted)
            elif is_falcon_command(cleaned_message)[0]:
                # Silent failure if used from unauthorized room
                if teams_message.roomId not in FALCON_ALLOWED_ROOMS:
                    logger.warning(f"Falcon command blocked - unauthorized room: {teams_message.roomId}")
                    if thinking_active:
                        thinking_active.clear()
                    return
                _, falcon_query = is_falcon_command(cleaned_message)
                metrics = handle_falcon_command(falcon_query, room_id=teams_message.roomId)
                response_text = metrics['content']
                # Handle file upload for browser history
                file_path = metrics.get('file_path')
                if file_path:
                    import os
                    if os.path.exists(file_path):
                        parent_id = teams_message.parentId if hasattr(teams_message, 'parentId') and teams_message.parentId else teams_message.id
                        # Send file with initial response
                        self.teams.messages.create(
                            roomId=teams_message.roomId,
                            parentId=parent_id,
                            text=response_text,
                            files=[file_path]
                        )
                        logger.info(f"Uploaded file (kept for potential XSOAR attachment): {file_path}")
                        # Send follow-up prompt for XSOAR attachment
                        xsoar_prompt = f"📎 To attach this file to an XSOAR ticket, reply with the ticket number (e.g., `attach to 929947`).\n\n_File: `{file_path}`_"
                        self.teams.messages.create(
                            roomId=teams_message.roomId,
                            parentId=parent_id,
                            markdown=xsoar_prompt
                        )
                        response_text = None  # Signal that response was already sent with file
            else:
                # Process query through LLM agent
                try:
                    metrics = ask(
                        raw_message,
                        user_id=teams_message.personEmail,
                        room_id=teams_message.roomId,  # Use actual room ID, not display name
                        progress_callback=_on_router_progress,
                    )
                    response_text = metrics['content']
                except Exception as e:
                    logger.error(f"Error in LLM agent processing: {e}")
                    response_text = "❌ I encountered an error processing your message. Please try again."
                    metrics = _empty

            # Post-process: convert markdown tables and clean up spacing
            if response_text:
                response_text = convert_markdown_tables(response_text)
                # Remove excessive blank lines around horizontal rules (LLM outputs \n\n---\n\n)
                import re
                response_text = re.sub(r'\n{2,}(---+)\n{2,}', r'\n\1\n', response_text)

            # Format for Webex (skip if response was already sent with file)
            if response_text is None:
                # Response was already sent (e.g., with file attachment)
                # Just update thinking message and return
                if thinking_active:
                    thinking_active.clear()
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                if thinking_msg:
                    done_prefix = random.choice(DONE_MESSAGES)
                    done_message = f"{done_prefix} ⚡ Response time: **{response_time:.1f}s**"
                    try:
                        import requests
                        edit_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                        headers = {'Authorization': f'Bearer {CONFIG.webex_bot_access_token_pokedex}', 'Content-Type': 'application/json'}
                        requests.put(edit_url, headers=headers, json={'roomId': teams_message.roomId, 'markdown': done_message})
                    except Exception:
                        pass
                return

            if len(response_text) > 7000:
                response_text = response_text[:6900] + "\n\n*[Response truncated for message limits]*"

            logger.info(f"Sending response to {teams_message.personEmail}: {len(response_text)} chars")

            # Calculate response time
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()

            # ALWAYS stop thinking message updates (even if response is empty)
            if thinking_active:
                thinking_active.clear()

            # Done message logic - handle both success and empty response cases
            if response_text:
                # Success path - update thinking message to show completion

                # Update the final thinking message to show "Done!"
                if thinking_msg:
                    done_message = _format_done_message(response_time, metrics)
                    try:
                        # Update the thinking message to show completion (using Markdown)
                        import requests
                        edit_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                        headers = {'Authorization': f'Bearer {CONFIG.webex_bot_access_token_pokedex}', 'Content-Type': 'application/json'}
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
                    # Note: Tools like tipper_analysis send cards directly via Webex context
                    detail_msg = self.teams.messages.create(
                        roomId=teams_message.roomId,
                        parentId=parent_id,
                        markdown=response_text
                    )

                    # If this was an on-demand triage, send action card as threaded reply
                    self._send_triage_action_card_if_needed(teams_message.roomId, detail_msg.id)

                    log_conversation(user_name, raw_message, response_text, response_time, room_name)

                except Exception as threading_error:
                    logger.error(f"Error in threading/response: {threading_error}")
                    # Send response without threading as fallback
                    self.teams.messages.create(
                        roomId=teams_message.roomId,
                        text=response_text if isinstance(response_text, str) and len(response_text) < 7000 else "Response too long for message limits"
                    )

            else:
                # Empty response path - update thinking message and send error
                logger.warning(f"Received empty response from LLM after {response_time:.1f}s")

                # Update thinking message to show error
                if thinking_msg:
                    try:
                        import requests
                        edit_url = f'https://webexapis.com/v1/messages/{thinking_msg.id}'
                        headers = {'Authorization': f'Bearer {CONFIG.webex_bot_access_token_pokedex}', 'Content-Type': 'application/json'}
                        edit_data = {
                            'roomId': teams_message.roomId,
                            'markdown': f"⚠️ **Empty Response** | Time: **{response_time:.1f}s**"
                        }
                        requests.put(edit_url, headers=headers, json=edit_data)
                    except Exception as completion_error:
                        logger.warning(f"Could not update thinking message for empty response: {completion_error}")

                # Send error message to user
                try:
                    parent_id = teams_message.parentId if hasattr(teams_message, 'parentId') and teams_message.parentId else teams_message.id
                    self.teams.messages.create(
                        roomId=teams_message.roomId,
                        parentId=parent_id,
                        text="❌ I received an empty response from the LLM. This may indicate:\n• The LLM encountered an error\n• The response was filtered or blocked\n• A timeout occurred\n\nPlease try rephrasing your question or try again."
                    )
                except Exception as send_error:
                    logger.error(f"Could not send empty response error message: {send_error}")

        except Exception as e:
            logger.error(f"Error in message processing: {e}", exc_info=True)
            self.teams.messages.create(
                roomId=teams_message.roomId,
                text="❌ I encountered an error processing your message. Please try again."
            )


    def process_incoming_card_action(self, attachment_actions, activity):
        """Handle card action submissions (e.g., URL block confirmation)."""
        if attachment_actions.inputs.get('callback_keyword') == 'confirm_block_url':
            from my_bot.tools.block_url_tools import execute_url_block
            execute_url_block(
                room_id=attachment_actions.roomId,
                url=attachment_actions.inputs.get('url', ''),
                xsoar_ticket_id=attachment_actions.inputs.get('xsoar_ticket_id', '').strip(),
                reason=attachment_actions.inputs.get('reason', '').strip(),
                user_email=activity.get('actor', {}).get('emailAddress', 'unknown'),
                parent_msg_id=attachment_actions.messageId,
            )
            return

        super().process_incoming_card_action(attachment_actions, activity)


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 POKEDEX BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """Pokédex main - VANILLA WebexBot with NO resilience features for testing"""
    bot_name = "the security assistant bot"
    logger.info("Starting the security assistant bot with VANILLA WebexBot (no resilience, no patches)")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Initialize bot components first
    if not initialize_bot():
        logger.error("Failed to initialize bot components")
        return 1

    # Create bot instance
    bot = Bot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_domains=[CONFIG.my_web_domain],
        approved_rooms=[CONFIG.webex_room_id_threatcon_collab, CONFIG.webex_room_id_dev_test_space, CONFIG.webex_room_id_threat_tipper_analysis, CONFIG.webex_room_id_gosc_t2],
        bot_name=bot_name
    )

    # Run bot (simple and direct - no monitoring, no reconnection, no keepalive)
    logger.info("🚀 the security assistant bot is up and running with vanilla WebexBot...")
    print("🚀 the security assistant bot is up and running with vanilla WebexBot...", flush=True)
    print("", flush=True)
    print("📋 For detailed DEBUG logs, run in another terminal:", flush=True)
    print("   tail -f logs/pokedex.log", flush=True)
    print("", flush=True)

    try:
        bot.run()
    except KeyboardInterrupt:
        logger.info("🛑 the security assistant bot stopped by user (Ctrl+C)")
    except Exception as e:
        logger.error(f"❌ the security assistant bot crashed: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    main()
