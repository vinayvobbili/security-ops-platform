"""Pokedex Chat Handler for Web Dashboard."""

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
    logger.debug("Checking Pokedex status")

    try:
        state_manager = get_state_manager_func()

        if not state_manager or not state_manager.is_initialized:
            return {
                'ready': False,
                'status': 'not_initialized',
                'message': 'Pokedex chat is not available. Please ensure all components are initialized.',
                'instructions': [
                    'Restart the web server with ENABLE_POKEDEX_CHAT = True'
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
                'message': 'Pokedex chat is ready',
                'components': components
            }
        elif core_ready:
            return {
                'ready': True,
                'status': 'partial',
                'message': 'Pokedex chat is ready (without document search)',
                'components': components
            }
        else:
            return {
                'ready': False,
                'status': 'partial',
                'message': 'Pokedex chat core components not ready',
                'components': components
            }

    except Exception as exc:
        logger.error(f"Error checking Pokedex status: {exc}")
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
    """Handle Pokedex chat messages.

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
    logger.info(f"Processing Pokedex chat message from {user_ip}")

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
    logger.info(f"Processing streaming Pokedex chat message from {user_ip}")

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
