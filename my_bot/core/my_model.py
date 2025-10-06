# /services/my_model.py
"""
Security Operations LLM Agent Interface

Core functionality:
- Initialize LLM agent with document search and security tools
- Pass user messages to agent for intelligent processing
- Agent decides what tools to use and how to respond
- Persistent conversation storage with SQLite database
- Enhanced error recovery with graceful fallbacks
- Session management across bot restarts

Features:
- SQLite-based conversation persistence (30 messages per session)
- Intelligent retry logic with exponential backoff
- Context-aware fallback responses when tools fail
- Automatic session cleanup and health monitoring
- 4K character context window with token limits

Created for Acme Security Operations
"""
import logging
import time
from my_bot.core.state_manager import get_state_manager
from my_bot.core.session_manager import get_session_manager

logging.basicConfig(level=logging.ERROR)


def run_health_tests_command() -> str:
    """Execute health tests and return formatted results"""
    try:
        from my_bot.tests.system_health_tests import run_health_tests

        # Run the health tests
        logging.info("🔬 Running health tests via chat command...")
        test_results = run_health_tests()

        # Format results for chat response
        total_tests = len(test_results)
        passed_tests = sum(1 for result in test_results.values() if result.get('status') == 'PASS')
        failed_tests = total_tests - passed_tests

        # Create summary
        if failed_tests == 0:
            status_emoji = "✅"
            status_text = "ALL TESTS PASSED"
        elif failed_tests <= 2:
            status_emoji = "⚠️"
            status_text = "SOME TESTS FAILED"
        else:
            status_emoji = "❌"
            status_text = "MULTIPLE TESTS FAILED"

        response = f"🔬 **Health Test Report**\\n\\n"
        response += f"{status_emoji} **Status**: {status_text}\\n"
        response += f"📊 **Summary**: {passed_tests}/{total_tests} tests passed\\n\\n"

        # Add individual test results
        for test_name, result in test_results.items():
            status = result.get('status', 'UNKNOWN')
            duration = result.get('duration', 'N/A')
            emoji = "✅" if status == 'PASS' else "❌"

            response += f"{emoji} **{test_name}**: {status} ({duration})\\n"

            # Add error details for failed tests
            if status in ['FAIL', 'ERROR'] and result.get('error'):
                response += f"└─ Error: {result['error']}\\n"

        return response

    except Exception as e:
        logging.error(f"Failed to run health tests: {e}")
        return f"❌ **Health Test Error**\\n\\nFailed to execute health tests: {str(e)}\\n\\n💡 **Manual run**: `python pokedex_bot/tests/system_health_tests.py`"


def initialize_model_and_agent():
    """
    Initialize the LLM, embeddings, and agent with enhanced capabilities.

    Initializes:
    - State manager for LLM and agent components
    - Session manager for persistent conversation storage
    - Error recovery manager for graceful failure handling

    Returns:
        bool: True if initialization successful, False otherwise
    """
    state_manager = get_state_manager()
    success = state_manager.initialize_all_components()

    if success:
        logging.info("SecurityBot initialized successfully")
    else:
        logging.error("SecurityBot initialization failed")

    return success


def ask(user_message: str, user_id: str = "default", room_id: str = "default") -> str:
    """
    SOC Q&A function with persistent sessions and enhanced error recovery:

    1. Retrieves conversation context from persistent SQLite storage
    2. Passes message to LLM agent with enhanced error handling
    3. Agent decides what tools/documents are needed with retry logic
    4. Gracefully handles tool failures with context-aware fallbacks
    5. Stores conversation in persistent session for future context
    6. Returns complete response with proper attribution

    Features:
    - Persistent conversation context across bot restarts
    - Enhanced error recovery with intelligent fallbacks
    - Automatic session cleanup and health monitoring
    - Fast responses for simple queries (health, greetings)

    Args:
        user_message: The user's question or request
        user_id: Unique identifier for the user (default: "default")
        room_id: Unique identifier for the chat room (default: "default")

    Returns:
        str: Complete response from the SOC assistant
    """

    start_time = time.time()

    try:
        # Basic validation
        if not user_message or not user_message.strip():
            return "Please ask me a question!"

        import re

        query = user_message.strip()
        original_query = query

        # Remove bot name mentions from anywhere in the message (common in group chats)
        bot_names = ['DnR_Pokedex', 'Pokedex', 'pokedex', 'dnr_pokedex',
                     'HAL9000', 'hal9000', 'Jarvais', 'jarvais',
                     'Toodles', 'toodles', 'Barnacles', 'barnacles']

        # Remove all bot name mentions from anywhere in the message
        removed_names = []
        for bot_name in bot_names:
            if bot_name.lower() in query.lower():
                # Use case-insensitive replacement
                pattern = re.compile(re.escape(bot_name), re.IGNORECASE)
                query = pattern.sub('', query)
                removed_names.append(bot_name)

        # Clean up extra whitespace and commas left by removals
        query = re.sub(r'\s+', ' ', query)  # Multiple spaces -> single space
        query = re.sub(r'[,\s]*,\s*', ', ', query)  # Clean up commas
        query = query.strip(' ,')  # Remove leading/trailing spaces and commas

        if removed_names:
            logging.info(f"Removed bot names {removed_names} from query: '{original_query}' -> '{query}'")

        # Create unique session key for user + room combination
        session_key = f"{user_id}_{room_id}"

        # Get session manager for context
        state_manager = get_state_manager()
        if state_manager and not state_manager.is_initialized:
            logging.error("State manager not initialized. Bot must be initialized before use.")
            return "❌ Bot not ready. Please try again in a moment."

        # Get session manager for persistent sessions
        session_manager = get_session_manager()

        # Clean up old sessions periodically
        session_manager.cleanup_old_sessions()

        # Get conversation context from session history
        conversation_context = session_manager.get_conversation_context(session_key)

        # Quick responses for simple queries (performance optimization)
        simple_query = query.lower().strip()
        if simple_query in ['hi', 'status', 'health', 'are you working']:
            final_response = "✅ System online and ready"

            # Store simple interaction in session
            session_manager.add_message(session_key, "user", query)
            session_manager.add_message(session_key, "assistant", final_response)

            elapsed = time.time() - start_time
            if elapsed > 25:
                logging.warning(f"Response took {elapsed:.1f}s")
            return final_response

        # STEP 1: For complex queries, pass to LLM agent - let it decide everything
        try:
            # Use direct execution with native tool calling
            logging.info(f"Using direct LLM execution")

            # Prepare input with conversation context
            agent_input = query
            if conversation_context:
                agent_input = conversation_context + " " + query
                logging.debug(f"Added conversation context to query")

            # Let the 70B model handle everything directly - no agent framework
            logging.info(f"Passing query to direct LLM: {query[:100]}...")

            # Set logging context for tool calls
            from src.utils.tool_logging import set_logging_context
            set_logging_context(session_key)

            final_response = state_manager.execute_query(agent_input)

        except Exception as e:
            logging.error(f"Failed to invoke agent: {e}")
            final_response = "❌ An error occurred. Please try again or contact support."

        # Store user message and bot response in session
        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", final_response)

        elapsed = time.time() - start_time
        if elapsed > 25:
            logging.warning(f"Response took {elapsed:.1f}s")

        return final_response

    except Exception as e:
        logging.error(f"Ask function failed: {e}")
        return "❌ An error occurred. Please try again or contact support."


def ask_stream(user_message: str, user_id: str = "default", room_id: str = "default"):
    """
    SOC Q&A function with streaming support for real-time responses.

    Similar to ask() but yields response tokens as they are generated,
    enabling real-time streaming to browser clients.

    Args:
        user_message: The user's question or request
        user_id: Unique identifier for the user (default: "default")
        room_id: Unique identifier for the chat room (default: "default")

    Yields:
        str: Response tokens as they are generated
    """
    try:
        # Basic validation
        if not user_message or not user_message.strip():
            yield "Please ask me a question!"
            return

        import re

        query = user_message.strip()
        original_query = query

        # Remove bot name mentions
        bot_names = ['DnR_Pokedex', 'Pokedex', 'pokedex', 'dnr_pokedex',
                     'HAL9000', 'hal9000', 'Jarvais', 'jarvais',
                     'Toodles', 'toodles', 'Barnacles', 'barnacles']

        for bot_name in bot_names:
            if bot_name.lower() in query.lower():
                pattern = re.compile(re.escape(bot_name), re.IGNORECASE)
                query = pattern.sub('', query)

        # Clean up whitespace
        query = re.sub(r'\s+', ' ', query)
        query = re.sub(r'[,\s]*,\s*', ', ', query)
        query = query.strip(' ,')

        # Create session key
        session_key = f"{user_id}_{room_id}"

        # Get state manager
        state_manager = get_state_manager()
        if state_manager and not state_manager.is_initialized:
            yield "❌ Bot not ready. Please try again in a moment."
            return

        # Get session manager
        session_manager = get_session_manager()
        session_manager.cleanup_old_sessions()

        # Get conversation context
        conversation_context = session_manager.get_conversation_context(session_key)

        # Quick responses for simple queries
        simple_query = query.lower().strip()
        if simple_query in ['hi', 'status', 'health', 'are you working']:
            response = "✅ System online and ready"
            session_manager.add_message(session_key, "user", query)
            session_manager.add_message(session_key, "assistant", response)
            yield response
            return

        # Prepare input with context
        agent_input = query
        if conversation_context:
            agent_input = conversation_context + " " + query

        # Set logging context
        from src.utils.tool_logging import set_logging_context
        set_logging_context(session_key)

        # Stream response
        full_response = ""
        for token in state_manager.execute_query_stream(agent_input):
            full_response += token
            yield token

        # Store conversation
        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", full_response)

    except Exception as e:
        logging.error(f"Ask stream function failed: {e}")
        yield "❌ An error occurred. Please try again or contact support."
