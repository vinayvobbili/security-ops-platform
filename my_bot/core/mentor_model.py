"""
the Windows triage agent Model Interface

Mirrors my_model.py but uses MentorStateManager and the Windows triage agent-specific help text.
Session keys are namespaced with 'mentor_' to avoid mixing with the security assistant bot sessions.
"""

import logging
import re
import time

from my_bot.core.session_manager import get_session_manager
from my_bot.core.mentor_state_manager import get_mentor_state_manager

logger = logging.getLogger(__name__)

BOT_NAMES = ["the Windows triage agent", "Mentor", "mentor", "mentor", "mentor"]

HELP_TEXT = """## the Windows triage agent — Codebase Tutor

### What I can help with
- How features in the IR platform are implemented
- Walking through code in any module (bots, services, tools, components)
- Searching the Knowledge Base wiki for SOC procedures, threat intel, and runbooks
- Explaining Python concepts, patterns, and best practices
- AI/LLM topics: prompting, RAG, tool calling, fine-tuning, etc.
- Finding where something lives in the codebase

### Commands
- `help` — show this message
- `clear session` — reset conversation memory

### Example questions
```
How does the security assistant bot route tool calls?
Show me how the domain monitoring alerts work
Explain how ChromaDB is used here
What does the wiki say about phishing response?
How do I write a LangChain tool?
What's the difference between RAG and fine-tuning?
Walk me through the scheduler.py job pattern
```

> Note: I will never show API keys or secrets. Code snippets are sourced from the actual codebase index."""


def _metrics(content="", **overrides):
    result = {
        "content": content,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "prompt_time": 0.0,
        "generation_time": 0.0,
        "tokens_per_sec": 0.0,
        "first_token_time": 0.0,
    }
    result.update(overrides)
    return result


def _is_help(query: str) -> bool:
    q = query.lower().strip()
    return q in ("help", "?") or q.startswith("help ") or q.endswith(" help")


def _is_clear_session(query: str) -> bool:
    q = query.lower().strip()
    actions = ["clear", "reset", "forget", "new", "start"]
    targets = ["session", "conversation", "memory", "context", "history"]
    fresh = ["start fresh", "start over", "new session", "new conversation"]
    if any(p in q for p in fresh):
        return True
    return any(a in q for a in actions) and any(t in q for t in targets)


def initialize_mentor() -> bool:
    """Initialize the Windows triage agent LLM, embeddings, and codebase index."""
    state_manager = get_mentor_state_manager()
    success = state_manager.initialize_all_components()
    if success:
        logger.info("the Windows triage agent initialized successfully")
    else:
        logger.error("the Windows triage agent initialization failed")
    return success


def mentor_ask(user_message: str, user_id: str = "default", room_id: str = "default") -> dict:
    """
    the Windows triage agent Q&A — same pattern as ask() in my_model.py but for the tutor bot.

    Session keys are prefixed with 'mentor_' to namespace away from the security assistant bot.
    """
    start_time = time.time()

    try:
        if not user_message or not user_message.strip():
            return _metrics("Ask me anything about the codebase or Python/AI topics!")

        query = user_message.strip()

        # Strip bot name mentions (group chat mentions)
        for name in BOT_NAMES:
            query = re.sub(re.escape(name), "", query, flags=re.IGNORECASE)
        query = re.sub(r"\s+", " ", query).strip(" ,")

        if not query:
            return _metrics("Ask me anything about the codebase or Python/AI topics!")

        session_key = f"mentor_{user_id}_{room_id}"
        session_manager = get_session_manager()
        session_manager.cleanup_old_sessions()

        if _is_clear_session(query):
            deleted = session_manager.delete_session(session_key)
            msg = ("✅ Session cleared! Starting fresh."
                   if deleted else "✅ Starting fresh! (No previous context found)")
            return _metrics(msg)

        if _is_help(query):
            return _metrics(HELP_TEXT)

        # Ensure state manager is initialized
        state_manager = get_mentor_state_manager()
        if not state_manager.is_initialized:
            logger.info("Lazy-initializing the Windows triage agent on first request...")
            if not state_manager.initialize_all_components():
                return _metrics("❌ the Windows triage agent not ready — initialization failed. Check the LLM connection.")

        conversation_context = session_manager.get_conversation_context(session_key)

        agent_input = query
        if conversation_context:
            agent_input = conversation_context + " " + query

        try:
            from src.utils.tool_logging import set_logging_context
            set_logging_context(session_key)
        except Exception:
            pass

        try:
            result = state_manager.execute_routed_query(agent_input)
        except Exception as e:
            logger.error(f"the Windows triage agent agent error: {e}")
            result = _metrics("❌ An error occurred. Please try again.")

        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", result["content"])

        elapsed = time.time() - start_time
        if elapsed > 25:
            logger.warning(f"the Windows triage agent slow response: {elapsed:.1f}s")

        return result

    except Exception as e:
        logger.error(f"mentor_ask failed: {e}")
        return _metrics("❌ An error occurred. Please try again.")
