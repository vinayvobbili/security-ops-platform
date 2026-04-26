"""
MCP-backed model interface for HAL9000.

Drop-in replacement for my_model.py — same function signatures, but tool
execution routes through the MCP server instead of in-process LangChain tools.

Commands that bypass the LLM (help, falcon, tipper, rules) are re-exported
unchanged from my_model.py.
"""
import logging
import time

from my_bot.core.session_manager import get_session_manager
from my_bot.core.mcp_state_manager import get_mcp_state_manager

# Re-export command handlers unchanged — these don't use the tool pipeline
from my_bot.core.my_model import (  # noqa: F401
    is_help_command,
    get_help_response,
    is_falcon_command,
    handle_falcon_command,
    is_rules_command,
    handle_rules_command,
)

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def _metrics(content="", **overrides):
    """Build a standard metrics response dict."""
    result = {
        'content': content,
        'input_tokens': 0,
        'output_tokens': 0,
        'total_tokens': 0,
        'prompt_time': 0.0,
        'generation_time': 0.0,
        'tokens_per_sec': 0.0,
        'first_token_time': 0.0,
    }
    result.update(overrides)
    return result


def initialize_model_and_agent():
    """Initialize the MCP-backed LLM agent.

    Returns:
        bool: True if initialization successful, False otherwise
    """
    state_manager = get_mcp_state_manager()
    success = state_manager.initialize_all_components()

    if success:
        logger.info("MCP-backed SecurityBot initialized successfully")
    else:
        logger.error("MCP-backed SecurityBot initialization failed")

    return success


def _is_clear_session_command(query_text: str) -> bool:
    """Detect if user wants to clear session context."""
    query_lower = query_text.lower().strip()

    action_keywords = ['clear', 'reset', 'delete', 'forget', 'erase', 'remove']
    target_keywords = ['conversation', 'chat', 'history', 'session', 'context', 'messages', 'memory', 'talked']

    fresh_phrases = [
        'start fresh', 'start afresh',
        'start a new session', 'start a new conversation',
        'new conversation', 'new session',
        'start over', 'begin again',
        'forget what we talked'
    ]

    if any(phrase in query_lower for phrase in fresh_phrases):
        return True

    has_action = any(action in query_lower for action in action_keywords)
    has_target = any(target in query_lower for target in target_keywords)
    return has_action and has_target


def ask(user_message: str, user_id: str = "default", room_id: str = "default") -> dict:
    """MCP-backed SOC Q&A — same interface as my_model.ask().

    Routes tool calls through the MCP server for A/B comparison.
    """
    start_time = time.time()

    try:
        if not user_message or not user_message.strip():
            return _metrics("Please ask me a question!")

        import re

        query = user_message.strip()
        original_query = query

        # Remove bot name mentions
        bot_names = ['DnR_the security assistant bot', 'the security assistant bot', 'pokedex', 'dnr_pokedex',
                     'HAL9000', 'hal9000', 'the orchestration service', 'jarvis',
                     'the notification service', 'toodles', 'the alert triage service', 'barnacles']

        removed_names = []
        for bot_name in bot_names:
            if bot_name.lower() in query.lower():
                pattern = re.compile(re.escape(bot_name), re.IGNORECASE)
                query = pattern.sub('', query)
                removed_names.append(bot_name)

        query = re.sub(r'\s+', ' ', query)
        query = re.sub(r'[,\s]*,\s*', ', ', query)
        query = query.strip(' ,')

        if removed_names:
            logger.info(f"Removed bot names {removed_names} from query: '{original_query}' -> '{query}'")

        session_key = f"{user_id}_{room_id}"

        state_manager = get_mcp_state_manager()
        if state_manager and not state_manager.is_initialized:
            logger.info("Lazy-initializing MCP components on first request...")
            if not state_manager.initialize_all_components():
                logger.error("Lazy initialization failed.")
                return _metrics("❌ Bot not ready. Initialization failed — check Ollama and MCP server connectivity.")

        session_manager = get_session_manager()
        session_manager.cleanup_old_sessions()

        conversation_context = session_manager.get_conversation_context(session_key)

        if _is_clear_session_command(query):
            deleted = session_manager.delete_session(session_key)
            if deleted:
                final_response = "✅ Session context cleared! Starting fresh with no memory of our previous conversation."
            else:
                final_response = "✅ Starting a new session! (No previous context found)"
            return _metrics(final_response)

        # Workflow routing
        try:
            from my_bot.workflows.router import (
                is_workflow_command, parse_workflow_request, get_workflow_help
            )

            if is_workflow_command(query):
                parsed = parse_workflow_request(query)
                workflow_type = parsed["workflow_type"]
                workflow_query = parsed["workflow_query"]

                if workflow_query.lower().strip() in ("help", "?", ""):
                    help_text = get_workflow_help()
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", help_text)
                    return _metrics(help_text)

                if workflow_type == "ioc_investigation":
                    logger.info(f"Routing to IOC investigation workflow for: {parsed['ioc_value']}")
                    from my_bot.workflows.ioc_investigation import run_ioc_investigation
                    result = run_ioc_investigation(workflow_query)
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", result['content'])
                    return result

                elif workflow_type == "incident_response":
                    logger.info(f"Routing to incident response workflow for ticket: {parsed['ticket_id']}")
                    from my_bot.workflows.incident_response import run_incident_response
                    result = run_incident_response(workflow_query)
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", result['content'])
                    return result

                else:
                    error_msg = f"Could not determine workflow type. Use `workflow help` for usage.\n\nParsed: IOC={parsed['ioc_value']}, Ticket={parsed['ticket_id']}"
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", error_msg)
                    return _metrics(error_msg)

        except ImportError as e:
            logger.warning(f"LangGraph workflows not available: {e}")
        except Exception as e:
            logger.error(f"Workflow routing error: {e}")

        # Help command
        if is_help_command(query):
            return _metrics(get_help_response())

        # Rules command
        is_rules, rules_query = is_rules_command(query)
        if is_rules:
            return handle_rules_command(rules_query)

        # Quick responses
        simple_query = query.lower().strip()
        if simple_query in ['hi', 'status', 'health', 'are you working']:
            final_response = "✅ System online and ready"
            session_manager.add_message(session_key, "user", query)
            session_manager.add_message(session_key, "assistant", final_response)
            elapsed = time.time() - start_time
            if elapsed > 25:
                logger.warning(f"Response took {elapsed:.1f}s")
            return _metrics(final_response)

        # Complex queries → MCP-routed LLM execution
        try:
            logger.info("Using MCP-routed LLM execution")

            agent_input = query
            if conversation_context:
                context_chars = len(conversation_context)
                query_chars = len(query)
                estimated_context_tokens = context_chars // 4
                logger.info(
                    f"📝 Session context: {context_chars} chars (~{estimated_context_tokens} tokens) + "
                    f"{query_chars} char query = {context_chars + query_chars + 1} total chars"
                )
                agent_input = conversation_context + " " + query

            logger.info(f"Passing query to MCP-routed LLM: {query[:100]}...")

            from src.utils.tool_logging import set_logging_context
            set_logging_context(session_key)

            result = state_manager.execute_routed_query(agent_input)

        except Exception as e:
            logger.error(f"Failed to invoke MCP agent: {e}")
            result = _metrics("❌ An error occurred. Please try again or contact support.")

        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", result['content'])

        elapsed = time.time() - start_time
        if elapsed > 25:
            logger.warning(f"Response took {elapsed:.1f}s")

        return result

    except Exception as e:
        logger.error(f"Ask function failed: {e}")
        return _metrics("❌ An error occurred. Please try again or contact support.")
