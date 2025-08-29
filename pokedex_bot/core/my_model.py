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
from pokedex_bot.core.state_manager import get_state_manager
from pokedex_bot.core.session_manager import get_session_manager
from pokedex_bot.core.error_recovery import get_recovery_manager, enhanced_agent_wrapper

logging.basicConfig(level=logging.INFO)




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

        # Get session manager for persistent sessions
        session_manager = get_session_manager()
        
        # Clean up old sessions periodically
        session_manager.cleanup_old_sessions()

        # Get conversation context from session history
        conversation_context = session_manager.get_conversation_context(session_key)

        # Quick responses for simple queries (performance optimization)
        simple_query = query.lower().strip()
        if simple_query in ['status', 'health', 'are you working', 'hello', 'hi']:
            if simple_query in ['status', 'health', 'are you working']:
                final_response = "✅ System online and ready"
            else:  # greetings
                final_response = """👋 Hello! I'm your SOC Q&A Assistant

I'm here to help with security operations by searching our local SOC documentation and using available security tools.

🔒 Security Note: I operate in a secure environment with:
• Access to internal SOC documents and procedures
• Integration with security tools (CrowdStrike, Tanium, etc.)
• No internet access - all responses from local resources only

❓ How I can help:
• Answer questions about security procedures
• Search SOC documentation and runbooks
• Check device status and containment
• Provide step-by-step incident response guidance

Just ask me any security-related question!"""
            
            # Store simple interaction in session
            session_manager.add_message(session_key, "user", query)
            session_manager.add_message(session_key, "assistant", final_response)
            
            elapsed = time.time() - start_time
            if elapsed > 25:
                logging.warning(f"Response took {elapsed:.1f}s")
            return final_response

        # STEP 1: For complex queries, pass to LLM agent - let it decide everything
        try:
            agent_executor = state_manager.get_agent_executor() if state_manager else None
            logging.info(f"Agent executor available: {agent_executor is not None}")

            if agent_executor:
                # Prepare input with conversation context
                agent_input = query
                if conversation_context:
                    agent_input = conversation_context + " " + query
                    logging.debug(f"Added conversation context to query")

                # Let the LLM agent handle everything with enhanced error recovery
                logging.info(f"Passing query to LLM agent: {query[:100]}...")
                recovery_manager = get_recovery_manager()
                
                try:
                    final_response = enhanced_agent_wrapper(agent_executor, agent_input, recovery_manager)
                    # Store user message and bot response in session
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", final_response)
                except Exception as e:
                    logging.error(f"Enhanced agent wrapper failed: {e}")
                    final_response = recovery_manager.get_fallback_response('general', query)
                    # Still store the interaction for context
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", final_response)
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
