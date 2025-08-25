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