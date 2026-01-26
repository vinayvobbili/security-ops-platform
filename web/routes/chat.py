"""Chat routes: Pokedex AI chat, Toodles chat."""

import json
import logging

from flask import Blueprint, jsonify, render_template, request, session, current_app

from src.utils.logging_utils import log_web_activity
from src.components.web import pokedex_handler, toodles_handler, approved_testing_handler
from web.config import CONFIG, EASTERN, prod_list_handler, prod_ticket_handler

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

# Lazy imports for Pokedex components
POKEDEX_AVAILABLE = True

try:
    from my_bot.core.my_model import ask, ask_stream
    from my_bot.core.state_manager import get_state_manager
except Exception as e:
    logger.warning(f"Pokedex components unavailable: {e}")
    POKEDEX_AVAILABLE = False

    def ask(*_args, **_kwargs):
        return "Model not available in this environment"

    def ask_stream(*_args, **_kwargs):
        yield "Model not available in this environment"

    def get_state_manager():
        return None


# --- Pokedex Chat ---

@chat_bp.route('/pokedex')
@log_web_activity
def pokedex_chat():
    """Pokedex AI chat interface"""
    return render_template('pokedex_chat.html')


@chat_bp.route('/api/pokedex-status')
def api_pokedex_status():
    """Health check endpoint for Pokédex chat availability"""
    status = pokedex_handler.check_pokedex_status(get_state_manager)
    return jsonify(status)


@chat_bp.route('/api/pokedex-chat', methods=['POST'])
@log_web_activity
def api_pokedex_chat():
    """API endpoint for Pokedex chat messages"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        response_text = pokedex_handler.handle_pokedex_chat(
            user_message,
            session_id,
            request.remote_addr,
            ask
        )

        return jsonify({'success': True, 'response': response_text})

    except Exception as exc:
        logger.error(f"Error in Pokedex chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to get response from AI. Please try again.'}), 500


@chat_bp.route('/api/pokedex-chat-stream', methods=['POST'])
@log_web_activity
def api_pokedex_chat_stream():
    """Streaming API endpoint for Pokédex chat messages using Server-Sent Events"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        def generate():
            """Generator function for Server-Sent Events"""
            try:
                for token in pokedex_handler.handle_pokedex_chat_stream(
                    user_message,
                    session_id,
                    request.remote_addr,
                    ask_stream,
                    get_state_manager
                ):
                    yield f"data: {json.dumps({'token': token})}\n\n"

                yield f"data: {json.dumps({'done': True})}\n\n"

            except Exception as stream_err:
                logger.error(f"Error in streaming response: {stream_err}", exc_info=True)
                yield f"data: {json.dumps({'error': 'Streaming error occurred'})}\n\n"

        return current_app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )

    except Exception as exc:
        logger.error(f"Error in Pokedex streaming chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An unexpected error occurred. Please try again.'}), 500


# --- Toodles Chat ---

@chat_bp.route('/toodles')
@log_web_activity
def toodles_chat():
    """Toodles chat interface - password protected"""
    return render_template('toodles_chat.html')


@chat_bp.route('/api/toodles/login', methods=['POST'])
def api_toodles_login():
    """API endpoint for Toodles authentication"""
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()

        success, error = toodles_handler.authenticate_toodles(password, CONFIG.toodles_password)

        if success:
            session['toodles_authenticated'] = True
            session['toodles_user_email'] = email
            session.permanent = True
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            return jsonify({'success': False, 'error': error}), 401

    except Exception as exc:
        logger.error(f"Error in Toodles login: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@chat_bp.route('/api/toodles/logout', methods=['POST'])
def api_toodles_logout():
    """API endpoint to logout from Toodles"""
    session.pop('toodles_authenticated', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@chat_bp.route('/api/toodles/create-x-ticket', methods=['POST'])
@log_web_activity
def api_create_x_ticket():
    """API endpoint to create X ticket"""
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        details = data.get('details', '').strip()
        detection_source = data.get('detection_source', '').strip()
        user_email = data.get('user_email', '').strip()

        if not title or not details or not detection_source:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_x_ticket(
            title,
            details,
            detection_source,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating X ticket: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@chat_bp.route('/api/toodles/approved-testing', methods=['POST'])
@log_web_activity
def api_approved_testing():
    """API endpoint to add approved testing entry"""
    try:
        data = request.get_json()

        try:
            message = approved_testing_handler.submit_toodles_approved_testing(
                data,
                prod_list_handler,
                CONFIG.team_name,
                EASTERN,
                request.remote_addr
            )
            return jsonify({'success': True, 'message': message})

        except ValueError as val_err:
            return jsonify({'success': False, 'error': str(val_err)}), 400

    except Exception as exc:
        logger.error(f"Error adding approved testing: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@chat_bp.route('/api/toodles/ioc-hunt', methods=['POST'])
@log_web_activity
def api_ioc_hunt():
    """API endpoint to create IOC hunt"""
    try:
        data = request.get_json()
        ioc_title = data.get('ioc_title', '').strip()
        iocs = data.get('iocs', '').strip()
        user_email = data.get('user_email', '').strip()

        if not ioc_title or not iocs:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_ioc_hunt(
            ioc_title,
            iocs,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating IOC hunt: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@chat_bp.route('/api/toodles/threat-hunt', methods=['POST'])
@log_web_activity
def api_threat_hunt():
    """API endpoint to create threat hunt"""
    try:
        data = request.get_json()
        threat_title = data.get('threat_title', '').strip()
        threat_description = data.get('threat_description', '').strip()
        user_email = data.get('user_email', '').strip()

        if not threat_title or not threat_description:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_threat_hunt(
            threat_title,
            threat_description,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating threat hunt: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@chat_bp.route('/api/toodles/oncall', methods=['GET'])
@log_web_activity
def api_oncall():
    """API endpoint to get on-call information"""
    try:
        on_call_person = toodles_handler.get_oncall_info()
        return jsonify({'success': True, 'data': on_call_person})

    except Exception as exc:
        logger.error(f"Error getting on-call info: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500
