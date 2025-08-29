# /services/my_model.py
"""
Security Operations LLM Agent Interface

Core functionality:
- Initialize LLM agent with document search and security tools
- Pass user messages to agent for intelligent processing
- Agent decides what tools to use and how to respond

Created for Acme Security Operations
"""
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pokedex_bot.core.state_manager import get_state_manager

logging.basicConfig(level=logging.INFO)

# Simple in-memory session storage
# Format: {session_key: deque([{"role": "user/assistant", "content": str, "timestamp": datetime}, ...])}
conversation_sessions = defaultdict(lambda: deque(maxlen=30))  # Keep last 30 messages per session
session_cleanup_interval = timedelta(hours=24)  # Clean up sessions older than 24 hours


def cleanup_old_sessions():
    """Remove sessions older than cleanup interval"""
    cutoff_time = datetime.now() - session_cleanup_interval
    sessions_to_remove = []

    for session_key, messages in conversation_sessions.items():
        if messages and messages[-1]["timestamp"] < cutoff_time:
            sessions_to_remove.append(session_key)

    for session_key in sessions_to_remove:
        del conversation_sessions[session_key]
        logging.debug(f"Cleaned up old session: {session_key}")


def add_to_session(session_key: str, role: str, content: str):
    """Add a message to the session history"""
    message = {
        "role": role,
        "content": content,
        "timestamp": datetime.now()
    }
    conversation_sessions[session_key].append(message)


def get_conversation_context(session_key: str, max_messages: int = 20, max_context_chars: int = 4000) -> str:
    """Get recent conversation history for context, respecting token limits"""
    messages = conversation_sessions.get(session_key, deque())
    if not messages:
        return ""

    # Get recent messages, working backwards to fit within character limit
    recent_messages = list(messages)
    context_parts = []
    total_chars = 0

    # Add messages from most recent backwards, until we hit limits
    for msg in reversed(recent_messages[-max_messages:]):
        role = "User" if msg["role"] == "user" else "Assistant"
        msg_text = f"{role}: {msg['content']}"

        # Check if adding this message would exceed our context limit
        if total_chars + len(msg_text) + 100 > max_context_chars:  # 100 char buffer
            break

        context_parts.insert(0, msg_text)  # Insert at beginning to maintain chronological order
        total_chars += len(msg_text) + 1  # +1 for newline

        # Stop if we have enough messages
        if len(context_parts) >= max_messages:
            break

    if context_parts:
        context = "\n\nPrevious conversation:\n" + "\n".join(context_parts) + "\n\nCurrent question:"
        logging.debug(f"Context added: {len(context_parts)} messages, {len(context)} chars")
        return context

    return ""


def get_session_info(session_key: str = None) -> dict:
    """Get session information for debugging"""
    if session_key:
        messages = list(conversation_sessions.get(session_key, deque()))
        return {
            "session_key": session_key,
            "message_count": len(messages),
            "messages": messages
        }
    else:
        return {
            "total_sessions": len(conversation_sessions),
            "session_keys": list(conversation_sessions.keys())
        }


def initialize_model_and_agent():
    """Initialize the LLM, embeddings, and agent"""
    state_manager = get_state_manager()
    success = state_manager.initialize_all_components()

    if success:
        logging.info("SecurityBot initialized successfully")
    else:
        logging.error("SecurityBot initialization failed")

    return success


def ask(user_message: str, user_id: str = "default", room_id: str = "default") -> str:
    """
    SOC Q&A function using LLM agent architecture:
    1. Pass message to LLM agent
    2. Agent decides what tools/documents are needed
    3. Agent handles all processing and formatting
    4. Returns complete response with proper attribution
    """

    start_time = time.time()

    try:
        # Basic validation
        if not user_message or not user_message.strip():
            return "Please ask me a question!"

        query = user_message.strip()

        # Remove bot name prefixes if present (common in group chats)
        bot_names = ['DnR_Pokedex', 'Pokedex', 'pokedex', 'dnr_pokedex']
        for bot_name in bot_names:
            if query.lower().startswith(bot_name.lower()):
                query = query[len(bot_name):].strip()
                break

        # Create unique session key for user + room combination
        session_key = f"{user_id}_{room_id}"

        # Get session manager for context
        state_manager = get_state_manager()
        if state_manager and not state_manager.is_initialized:
            logging.error("State manager not initialized. Bot must be initialized before use.")
            return "❌ Bot not ready. Please try again in a moment."

        # Clean up old sessions periodically
        cleanup_old_sessions()

        # Get conversation context from session history
        conversation_context = get_conversation_context(session_key)

        # All queries go to LLM agent - no hardcoded bypasses

        # STEP 1: Always pass query to LLM agent - let it decide everything
        try:
            agent_executor = state_manager.get_agent_executor() if state_manager else None
            logging.info(f"Agent executor available: {agent_executor is not None}")

            if agent_executor:
                # Prepare input with conversation context
                agent_input = query
                if conversation_context:
                    agent_input = conversation_context + " " + query
                    logging.debug(f"Added conversation context to query")

                # Let the LLM agent handle everything - document search, tool usage, decisions
                logging.info(f"Passing query to LLM agent: {query[:100]}...")
                agent_result = agent_executor.invoke({"input": agent_input})
                logging.info(f"Agent result received")

                if agent_result and 'output' in agent_result:
                    # Agent handled it completely - store in session and return
                    final_response = agent_result['output']

                    # Store user message and bot response in session
                    add_to_session(session_key, "user", query)
                    add_to_session(session_key, "assistant", final_response)
                else:
                    logging.warning(f"No output in agent result: {agent_result}")
                    final_response = "❌ No response from agent. Please try again."
            else:
                logging.error("Agent executor not available - system not properly initialized")
                final_response = "❌ System not ready. Please try again in a moment."

        except Exception as e:
            logging.error(f"Failed to invoke agent: {e}")
            final_response = "❌ An error occurred. Please try again or contact support."

        elapsed = time.time() - start_time
        if elapsed > 25:
            logging.warning(f"Response took {elapsed:.1f}s")

        return final_response

    except Exception as e:
        logging.error(f"Ask function failed: {e}")
        return "❌ An error occurred. Please try again or contact support."
