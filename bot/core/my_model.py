# /services/my_model.py
"""
Simple Security Operations RAG Bot

Core functionality:
- Initialize Ollama LLM with documents and tools
- Process user messages and return responses for Webex

Created for MetLife Security Operations
"""
import logging
import time
from bot.core.state_manager import get_state_manager
from bot.utils.utilities import preprocess_message, format_for_chat, get_query_type

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
    Main function to process user queries and return Webex responses
    
    Args:
        user_message: The user's question
        user_id: User identifier
        room_id: Room identifier
        
    Returns:
        Formatted response for Webex
    """
    try:
        # First check: Ignore lorem ipsum messages (demo clearing messages) before any processing
        if "lorem ipsum" in user_message.lower() and len(user_message) > 300:
            logging.info("Ignoring lorem ipsum message to prevent bot from processing its own demo clearing output")
            return ""  # Return empty string to prevent response
        
        # Clean the message
        cleaned_message = preprocess_message(user_message)
        if not cleaned_message.strip():
            return "I didn't receive a message. Please ask me something!"

        # Get initialized components
        state_manager = get_state_manager()
        if not state_manager.is_initialized:
            return "⚠️ System not initialized. Please contact administrator."

        agent_executor = state_manager.get_agent_executor()
        if not agent_executor:
            return "❌ Bot not properly initialized. Please contact administrator."

        # Handle simple status commands
        if cleaned_message.lower() in ['status', 'health', 'health check']:
            return "✅ **System Status: Online**\n\nBot is operational and ready for queries."
        
        elif cleaned_message.lower() in ['metrics', 'stats', 'performance']:
            # Get detailed metrics for management/demo
            performance_monitor = state_manager.get_performance_monitor()
            if performance_monitor:
                from bot.utils.reporting import generate_metrics_summary_report, format_metrics_summary_for_chat
                summary = generate_metrics_summary_report(performance_monitor)
                return format_metrics_summary_for_chat(summary)
            else:
                return "📊 **Metrics not available** - Performance monitoring not initialized."
        
        elif cleaned_message.lower() in ['help', 'commands']:
            return """🤖 **Available Commands:**

• **Document Search**: Search security policies and procedures
• **CrowdStrike**: Check device status (if available)  
• **Weather**: Get weather information
• **System Commands**: `status`, `metrics`, `help`
• **General Questions**: Ask me anything!

💡 Use natural language - I'll understand your questions."""
        
        elif cleaned_message.lower() in ['hello', 'hi', 'hey']:
            return """👋 **Hello! I'm your SOC Q&A Assistant**

I'm here to help with security operations by searching our **local SOC documentation** and using available **security tools**.

🔒 **Security Note**: I operate in a secure environment with:
• Access to internal SOC documents and procedures
• Integration with security tools (CrowdStrike, Tanium, etc.)
• **No internet access** - all responses from local resources only

❓ **How I can help:**
• Answer questions about security procedures
• Search SOC documentation and runbooks  
• Check device status and containment
• Provide step-by-step incident response guidance

Just ask me any security-related question!"""

        # Check for natural language demo clearing requests
        demo_clear_keywords = ['clear the room', 'clear room', 'new demo', 'demo prep', 'prepare demo', 'clean chat', 'clear chat for demo', 'demo clear']
        if any(keyword in cleaned_message.lower() for keyword in demo_clear_keywords):
            # Generate a comprehensive 2000-word lorem ipsum message
            lorem_text = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. 

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem.

Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur? At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga.

Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem.

Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur? At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi.

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem.

Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.

Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur? At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident.

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum et dolorum fuga.

Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae.

Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat. Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo."""
            
            return f"🧹 **Demo Space Cleared**\n\n{lorem_text}\n\n---\n✅ **Chat window cleared - Ready for demo!**\n\n*Note: This message will push previous conversations up in the chat history.*"


        # Start performance tracking
        performance_monitor = state_manager.get_performance_monitor()
        query_type = get_query_type(cleaned_message)
        start_time = time.time()
        
        if performance_monitor:
            performance_monitor.start_request(user_id, query_type)

        try:
            # Get conversation context (room-specific)
            session_manager = state_manager.get_session_manager()
            session_key = f"{user_id}_{room_id}"
            context = session_manager.get_context(session_key, limit=3) if session_manager else None
            
            # Prepare query with context
            if context:
                full_query = f"Context from recent conversation:\n{context}\n\nCurrent question: {cleaned_message}"
            else:
                full_query = cleaned_message

            # Get response from agent
            result = agent_executor.invoke({"input": full_query})
            response = result.get('output', 'I encountered an issue processing your request.')

            # Format for Webex and store in session
            formatted_response = format_for_chat(response)
            if session_manager:
                session_manager.add_interaction(session_key, cleaned_message, formatted_response)

            # End performance tracking (success)
            if performance_monitor:
                response_time = time.time() - start_time
                performance_monitor.end_request(user_id, response_time, error=False)

            return formatted_response
            
        except Exception as query_error:
            # End performance tracking (error)
            if performance_monitor:
                response_time = time.time() - start_time
                performance_monitor.end_request(user_id, response_time, error=True)
            raise query_error

    except Exception as e:
        logging.error(f"Error in ask function: {e}", exc_info=True)
        return f"❌ I encountered an error: {str(e)}"


# Utility functions for backward compatibility
def warmup():
    """Warm up the model"""
    return get_state_manager().warmup()


def health_check():
    """Simple health check"""
    state_manager = get_state_manager()
    if state_manager.is_initialized:
        return "✅ **System Status: Healthy**\n\nAll components operational."
    else:
        return "⚠️ **System Not Initialized**"


def shutdown_handler():
    """Simple shutdown handler for compatibility"""
    logging.info("Bot shutting down...")