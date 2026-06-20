#!/usr/bin/python3

"""
the Windows triage agent — Codebase & Software Engineering Tutor Bot

Teaches teammates how the IR platform works, explains code, and answers
Python/AI/LLM questions. Uses a curated ChromaDB index of source files.

Architecture: mirrors sleuth.py but uses MentorStateManager and mentor_ask().
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import logging

from src.utils.logging_utils import setup_logging

setup_logging(
    bot_name='mentor',
    log_level=logging.INFO,
    log_dir=str(PROJECT_ROOT / "logs"),
    info_modules=['__main__'],
    rotate_on_startup=False,
)

logger = logging.getLogger(__name__)

logging.getLogger('webex_bot').setLevel(logging.ERROR)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)
logging.getLogger('websockets').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

import atexit
import csv
import os
import random
import re
import signal
import threading
import time
from datetime import datetime

import requests
from pytz import timezone
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from my_bot.core.mentor_model import initialize_mentor, mentor_ask
from my_bot.core.mentor_state_manager import get_mentor_state_manager
from src.utils.bot_messages import MENTOR_THINKING_MESSAGES, DONE_MESSAGES
from src.utils.webex_utils import get_room_name
from my_bot.utils.webex_format import convert_markdown_tables
from src.utils.ssl_config import configure_ssl_if_needed
from src.utils.enhanced_websocket_client import patch_websocket_client

configure_ssl_if_needed(verbose=True)
patch_websocket_client()

logger.warning("=" * 100)
logger.warning(f"MENTOR BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

CONFIG = get_config(bot_name='mentor')
WEBEX_ACCESS_TOKEN = CONFIG.webex_bot_access_token_mentor
WEBEX_BOT_EMAIL = CONFIG.webex_bot_email_mentor
eastern = timezone('US/Eastern')
LOG_FILE_DIR = PROJECT_ROOT / 'data' / 'transient' / 'logs'

if not WEBEX_ACCESS_TOKEN:
    logger.error("WEBEX_BOT_ACCESS_TOKEN_MENTOR is required")
    sys.exit(1)


def log_conversation(user_name: str, user_prompt: str, bot_response: str,
                     response_time: float, room_name: str):
    """Log every conversation to SQLite for analytics and index tuning."""
    try:
        from src.utils.bot_logs_db import log_conversation as _db_log
        now_eastern = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S')
        _db_log(
            bot="mentor",
            person=user_name,
            user_prompt=user_prompt,
            bot_response=bot_response,
            response_length=len(bot_response),
            response_time_s=round(response_time, 2),
            room_name=room_name,
            message_time=now_eastern,
        )
    except Exception as e:
        logger.error(f"Conversation logging failed: {e}")


def _get_help_response() -> str:
    return """## 📚 the Windows triage agent — IR Codebase & XSOAR Tutor

I can explain how our bots and LLM features are built, and how our XSOAR automations work — with real code from the repos.

### 🤖 How our bots work
- *How does the security assistant bot decide which tool to call?*
- *Walk me through how a message goes from Webex to an LLM response in the security assistant bot*
- *How does the notification service work? What does it do?*
- *How does the thinking indicator work in the bots?*

### 🧠 How we use LLMs
- *How do we run LLMs locally on Apple Silicon?*
- *What's the difference between the router LLM and the analysis LLM?*
- *How does the two-stage LLM routing work?*

### 🔍 RAG & memory
- *How is ChromaDB used for RAG in this codebase?*
- *How do we embed documents and search them at query time?*
- *How does the session manager keep track of conversation history?*

### ⚙️ Under the hood
- *Show me how tool calling works — how does the LLM invoke a Python function?*
- *How does the scheduler trigger weekly jobs?*

### 🛡️ XSOAR playbooks & automations
- *What does the phishing investigation playbook do?*
- *How does the endpoint isolation automation work?*
- *Show me the ransomware response playbook*
- *What integrations does the [script name] automation use?*

**Tip:** The more specific your question, the better. *"How does X work?"* gets a much richer answer than *"Tell me about X"*
"""


def _format_done_message(response_time: float, metrics: dict = None) -> str:
    done_prefix = random.choice(DONE_MESSAGES)
    if metrics and metrics.get('total_tokens', 0) > 0 and metrics.get('generation_time', 0) > 0:
        gen_time = metrics['generation_time']
        timing_str = f"{gen_time:.1f}s LLM"
        tok = (f"{metrics['input_tokens']}→{metrics['output_tokens']}"
               if metrics['input_tokens'] > 0 else str(metrics['output_tokens']))
        msg = (f"{done_prefix} Time: **{response_time:.1f}s** ({timing_str}) | "
               f"Tokens: {tok} | "
               f"TPS: {metrics['tokens_per_sec']:.1f}")
        loops = metrics.get('iterations')
        if loops:
            msg += f" | Loops: {loops}"
        route = metrics.get('route')
        if route:
            msg += f" | Route: {route}"
        return msg
    return f"{done_prefix} Response time: **{response_time:.1f}s**"


def _edit_message(room_id: str, message_id: str, markdown: str):
    """Update an existing Webex message in-place."""
    try:
        requests.put(
            f"https://webexapis.com/v1/messages/{message_id}",
            headers={"Authorization": f"Bearer {WEBEX_ACCESS_TOKEN}",
                     "Content-Type": "application/json"},
            json={"roomId": room_id, "markdown": markdown},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Could not edit message: {e}")


def initialize_bot() -> bool:
    """Initialize the Windows triage agent components."""
    logger.info("Initializing the Windows triage agent...")
    start = datetime.now()

    try:
        from src.utils.webex_device_manager import cleanup_devices_on_startup
        cleanup_devices_on_startup(WEBEX_ACCESS_TOKEN, "the Windows triage agent")
        time.sleep(3)

        if not initialize_mentor():
            logger.error("the Windows triage agent initialization failed")
            return False

        from my_bot.core.session_manager import get_session_manager
        session_manager = get_session_manager()
        cleaned = session_manager.cleanup_old_sessions()
        if cleaned:
            logger.info(f"Cleaned {cleaned} old sessions")

        state_manager = get_mentor_state_manager()
        logger.info("Warming up LLM...")
        if state_manager.fast_warmup():
            logger.info("LLM warmed up successfully")
        else:
            logger.warning("LLM warmup failed — will load on first query")

        elapsed = (datetime.now() - start).total_seconds()
        logger.warning(f"the Windows triage agent ready in {elapsed:.1f}s")
        return True

    except Exception as e:
        logger.error(f"the Windows triage agent initialization error: {e}", exc_info=True)
        return False


class MentorBot(WebexBot):
    """the Windows triage agent codebase tutor bot."""

    def process_incoming_message(self, teams_message, activity):
        # Ignore bot's own messages
        if (hasattr(teams_message, 'personEmail')
                and teams_message.personEmail == WEBEX_BOT_EMAIL):
            return

        if activity.get('actor', {}).get('type') != 'PERSON':
            return

        if activity.get('verb') != 'post':
            return

        raw_message = teams_message.text or ""
        if not raw_message.strip():
            return

        user_name = activity.get('actor', {}).get('displayName', 'Unknown')
        room_name = get_room_name(teams_message.roomId, self.access_token)
        start_time = datetime.now()

        logger.info(f"Message from {teams_message.personEmail}: {raw_message[:80]}...")

        parent_id = (teams_message.parentId
                     if hasattr(teams_message, 'parentId') and teams_message.parentId
                     else teams_message.id)

        # --- Quick commands (no LLM, no thinking indicator) ---
        # Strip bot name mentions (group chat prefixes like "the Windows triage agent hi")
        from my_bot.core.mentor_model import BOT_NAMES
        cleaned = raw_message.strip()
        for _name in BOT_NAMES:
            cleaned = re.sub(re.escape(_name), "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,").lower()

        if cleaned in ('hi', 'hello', 'hey', 'status', 'health', 'are you working'):
            self.teams.messages.create(roomId=teams_message.roomId, parentId=parent_id,
                                       text="✅ System online and ready")
            log_conversation(user_name, raw_message, "hi", 0, room_name)
            return

        if cleaned in ('help', '?'):
            self.teams.messages.create(roomId=teams_message.roomId, parentId=parent_id,
                                       markdown=_get_help_response())
            log_conversation(user_name, raw_message, "help", 0, room_name)
            return

        # Clear session — instant response, no LLM
        from my_bot.core.mentor_model import _is_clear_session
        if _is_clear_session(cleaned):
            from my_bot.core.session_manager import get_session_manager
            session_key = f"mentor_{teams_message.personEmail}_{teams_message.roomId}"
            sm = get_session_manager()
            deleted = sm.delete_session(session_key)
            msg = ("✅ Session cleared! Starting fresh."
                   if deleted else "✅ Starting fresh! (No previous context found)")
            self.teams.messages.create(roomId=teams_message.roomId, parentId=parent_id, text=msg)
            log_conversation(user_name, raw_message, msg, 0, room_name)
            return

        # --- Thinking indicator (LLM queries only) ---
        _empty = {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0,
                  'prompt_time': 0.0, 'generation_time': 0.0, 'tokens_per_sec': 0.0,
                  'first_token_time': 0.0}
        thinking_msg = None
        thinking_active = threading.Event()
        try:
            thinking_msg = self.teams.messages.create(
                roomId=teams_message.roomId,
                parentId=parent_id,
                text=random.choice(MENTOR_THINKING_MESSAGES),
            )
            thinking_active.set()

            def _update_thinking():
                counter = 1
                while thinking_active.is_set() and counter <= 9:
                    time.sleep(30)
                    if thinking_active.is_set():
                        _edit_message(
                            teams_message.roomId,
                            thinking_msg.id,
                            f"{random.choice(MENTOR_THINKING_MESSAGES)} ({counter * 30}s)",
                        )
                        counter += 1

            threading.Thread(target=_update_thinking, daemon=True).start()
        except Exception as e:
            logger.warning(f"Could not send thinking message: {e}")
            thinking_msg = None

        # --- Query ---
        try:
            metrics = mentor_ask(
                raw_message,
                user_id=teams_message.personEmail,
                room_id=teams_message.roomId,
            )
            response_text = metrics['content']
        except Exception as e:
            logger.error(f"mentor_ask error: {e}")
            response_text = "❌ I encountered an error. Please try again."
            metrics = _empty

        # Post-process
        if response_text:
            response_text = convert_markdown_tables(response_text)
        if response_text and len(response_text) > 7000:
            response_text = response_text[:6900] + "\n\n*[Response truncated]*"

        response_time = (datetime.now() - start_time).total_seconds()
        thinking_active.clear()

        # Update thinking message to done
        if thinking_msg:
            _edit_message(
                teams_message.roomId,
                thinking_msg.id,
                _format_done_message(response_time, metrics),
            )

        # Send response
        if response_text:
            try:
                self.teams.messages.create(
                    roomId=teams_message.roomId,
                    parentId=parent_id,
                    markdown=response_text,
                )
                log_conversation(user_name, raw_message, response_text, response_time, room_name)
            except Exception as e:
                logger.error(f"Failed to send response: {e}")
                self.teams.messages.create(
                    roomId=teams_message.roomId,
                    text=response_text[:7000],
                )
        else:
            logger.warning(f"Empty response after {response_time:.1f}s")
            if thinking_msg:
                _edit_message(
                    teams_message.roomId,
                    thinking_msg.id,
                    f"⚠️ Empty response | Time: **{response_time:.1f}s**",
                )
            try:
                self.teams.messages.create(
                    roomId=teams_message.roomId,
                    parentId=parent_id,
                    text="❌ I received an empty response. Please try rephrasing your question.",
                )
            except Exception:
                pass


def _shutdown_handler(_signum=None, _frame=None):
    logger.warning("=" * 100)
    logger.warning(f"MENTOR BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    if not initialize_bot():
        logger.error("Failed to initialize the Windows triage agent")
        return 1

    bot = MentorBot(
        teams_bot_token=WEBEX_ACCESS_TOKEN,
        approved_domains=[CONFIG.my_web_domain],
        bot_name="the Windows triage agent",
    )

    logger.warning("the Windows triage agent is up and running...")
    print("the Windows triage agent is up and running...", flush=True)
    print(f"  Logs: tail -f {PROJECT_ROOT}/logs/mentor.log", flush=True)

    try:
        bot.run()
    except KeyboardInterrupt:
        logger.info("the Windows triage agent stopped by user")
    except Exception as e:
        logger.error(f"the Windows triage agent crashed: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    main()
