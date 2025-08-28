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
from bot.core.state_manager import get_state_manager

logging.basicConfig(level=logging.INFO)


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
        session_manager = state_manager.get_session_manager() if state_manager else None

        # Get conversation context if available (use more of the 8K context window)
        # conversation_context is available but not currently used in this simplified flow

        # Handle simple commands
        if query.lower() in ['hello', 'hi']:
            simple_response = """👋 Hello! I'm your SOC Q&A Assistant

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
            # Store interaction in session
            if session_manager:
                try:
                    session_manager.add_interaction(session_key, query, simple_response)
                except Exception as e:
                    logging.warning(f"Failed to store session interaction: {e}")
            return simple_response
        elif query.lower() in ['status', 'health']:
            simple_response = "✅ System online and ready"
            # Store interaction in session
            if session_manager:
                try:
                    session_manager.add_interaction(session_key, query, simple_response)
                except Exception as e:
                    logging.warning(f"Failed to store session interaction: {e}")
            return simple_response
        elif query.lower() == 'help':
            simple_response = "🤖 I can search security documents and provide security guidance."
            # Store interaction in session
            if session_manager:
                try:
                    session_manager.add_interaction(session_key, query, simple_response)
                except Exception as e:
                    logging.warning(f"Failed to store session interaction: {e}")
            return simple_response

        # STEP 1: Always pass query to LLM agent - let it decide everything
        try:
            agent_executor = state_manager.get_agent_executor() if state_manager else None
            logging.info(f"Agent executor available: {agent_executor is not None}")
            
            if agent_executor:
                # Let the LLM agent handle everything - document search, tool usage, decisions
                logging.info(f"Passing query to LLM agent: {query}")
                agent_result = agent_executor.invoke({"input": query})
                logging.info(f"Agent result: {agent_result}")
                
                if agent_result and 'output' in agent_result:
                    # Agent handled it completely - store session and return
                    final_response = agent_result['output']
                else:
                    logging.warning(f"No output in agent result: {agent_result}")
                    final_response = "❌ No response from agent. Please try again."
            else:
                logging.error("Agent executor not available - system not properly initialized")
                final_response = "❌ System not ready. Please try again in a moment."
                
        except Exception as e:
            logging.error(f"Failed to invoke agent: {e}")
            final_response = "❌ An error occurred. Please try again or contact support."

        # Store interaction in session for context continuity
        if session_manager:
            try:
                session_manager.add_interaction(session_key, query, final_response)
            except Exception as e:
                logging.warning(f"Failed to store session interaction: {e}")

        elapsed = time.time() - start_time
        if elapsed > 25:
            logging.warning(f"Response took {elapsed:.1f}s")

        return final_response

    except Exception as e:
        logging.error(f"Ask function failed: {e}")
        return "❌ An error occurred. Please try again or contact support."
