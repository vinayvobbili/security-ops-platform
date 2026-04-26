"""the security assistant bot Chat Handler for Web Dashboard."""

import logging
from typing import Dict, Any, Generator

logger = logging.getLogger(__name__)


def check_pokedex_status(get_state_manager_func) -> Dict[str, Any]:
    """Health check endpoint for Pokédex chat availability.

    Args:
        get_state_manager_func: Function to get state manager

    Returns:
        Dictionary with status information
    """
    logger.debug("Checking the security assistant bot status")

    try:
        state_manager = get_state_manager_func()

        if not state_manager:
            return {
                'ready': False,
                'status': 'not_initialized',
                'message': 'the security assistant bot chat is not available. Please ensure all components are initialized.',
                'instructions': [
                    'Restart the web server with ENABLE_POKEDEX_CHAT = True'
                ]
            }

        # Lazy-initialize if startup was skipped (SKIP_POKEDEX_WARMUP)
        if not state_manager.is_initialized:
            logger.info("Lazy-initializing the security assistant bot on first status check...")
            if not state_manager.initialize_all_components():
                return {
                    'ready': False,
                    'status': 'init_failed',
                    'message': 'the security assistant bot initialization failed. Check Ollama connectivity.',
                    'instructions': [
                        'Ensure Ollama is running and accessible'
                    ]
                }

        # Perform health check
        health = state_manager.health_check()
        components = health.get('components', {})

        # Check if core LLM components are working
        core_ready = components.get('llm', False) and components.get('embeddings', False)

        if health.get('status') == 'initialized':
            return {
                'ready': True,
                'status': 'healthy',
                'message': 'the security assistant bot chat is ready',
                'components': components
            }
        elif core_ready:
            return {
                'ready': True,
                'status': 'partial',
                'message': 'the security assistant bot chat is ready (without document search)',
                'components': components
            }
        else:
            return {
                'ready': False,
                'status': 'partial',
                'message': 'the security assistant bot chat core components not ready',
                'components': components
            }

    except Exception as exc:
        logger.error(f"Error checking the security assistant bot status: {exc}")
        return {
            'ready': False,
            'status': 'error',
            'message': 'Error checking chat status',
            'error': str(exc)
        }


def handle_pokedex_chat(
    user_message: str,
    session_id: str,
    user_ip: str,
    ask_func
) -> str:
    """Handle the security assistant bot chat messages.

    Args:
        user_message: User's message
        session_id: Session identifier
        user_ip: User's IP address
        ask_func: Function to call for LLM response

    Returns:
        Response text from LLM

    Raises:
        Exception: If LLM response fails
    """
    logger.info(f"Processing the security assistant bot chat message from {user_ip}")

    # Use IP address + session ID as identifier
    user_identifier = f"web_{user_ip}_{session_id}"

    response_text = ask_func(
        user_message,
        user_id=user_identifier,
        room_id="web_chat"
    )

    return response_text


def handle_pokedex_chat_stream(
    user_message: str,
    session_id: str,
    user_ip: str,
    ask_stream_func,
    get_state_manager_func
) -> Generator[str, None, None]:
    """Streaming handler for Pokédex chat messages.

    Args:
        user_message: User's message
        session_id: Session identifier
        user_ip: User's IP address
        ask_stream_func: Function to call for streaming LLM response
        get_state_manager_func: Function to get state manager

    Yields:
        Tokens from LLM response stream

    Raises:
        Exception: If streaming fails
    """
    logger.info(f"Processing streaming the security assistant bot chat message from {user_ip}")

    # Clean up old sessions before processing
    state_manager = get_state_manager_func()
    if state_manager and hasattr(state_manager, 'session_manager'):
        state_manager.session_manager.cleanup_old_sessions()

    # Use IP address + session ID as identifier
    user_identifier = f"web_{user_ip}_{session_id}"

    for token in ask_stream_func(
        user_message,
        user_id=user_identifier,
        room_id="web_chat"
    ):
        yield token
