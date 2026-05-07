"""Chat routes: the security assistant bot AI chat, the notification service chat, page-context chat widget."""

import json
import logging
import time

from flask import Blueprint, jsonify, render_template, request, session, current_app

from src.utils.logging_utils import log_web_activity, get_client_ip
from src.components.web import pokedex_handler, toodles_handler, approved_testing_handler
from src.components.web import page_chat_handler
from web.config import CONFIG, EASTERN, prod_list_handler, prod_ticket_handler
from web.extensions import limiter

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

# Lazy-init a lightweight LLM for the control-efficacy analytics chat widget
_dp_llm = None


def _get_dp_llm():
    global _dp_llm
    if _dp_llm is None:
        from my_bot.utils.llm_factory import create_llm
        _dp_llm = create_llm(temperature=0.1)
    return _dp_llm

# Lazy imports for the security assistant bot components
POKEDEX_AVAILABLE = True

try:
    from my_bot.core.my_model import ask, ask_stream
    from my_bot.core.state_manager import get_state_manager
except Exception as e:
    logger.warning(f"the security assistant bot components unavailable: {e}")
    POKEDEX_AVAILABLE = False

    def ask(*_args, **_kwargs):
        return "Model not available in this environment"

    def ask_stream(*_args, **_kwargs):
        yield "Model not available in this environment"

    def get_state_manager():
        return None


# --- the security assistant bot Chat ---

@chat_bp.route('/pokedex')
@log_web_activity
def pokedex_chat():
    """the security assistant bot AI chat interface"""
    return render_template('pokedex_chat.html')


@chat_bp.route('/api/pokedex-status')
@limiter.limit("30 per minute")
@log_web_activity
def api_pokedex_status():
    """Health check endpoint for Pokédex chat availability"""
    status = pokedex_handler.check_pokedex_status(get_state_manager)
    return jsonify(status)


@chat_bp.route('/api/pokedex-chat', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_pokedex_chat():
    """API endpoint for the security assistant bot chat messages"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if len(user_message) > 4000:
            return jsonify({'success': False, 'error': 'Message too long (max 4,000 characters)'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        response_text = pokedex_handler.handle_pokedex_chat(
            user_message,
            session_id,
            get_client_ip(),
            ask
        )

        return jsonify({'success': True, 'response': response_text})

    except Exception as exc:
        logger.error(f"Error in the security assistant bot chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to get response from AI. Please try again.'}), 500


@chat_bp.route('/api/pokedex-chat-stream', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_pokedex_chat_stream():
    """Streaming API endpoint for Pokédex chat messages using Server-Sent Events"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if len(user_message) > 4000:
            return jsonify({'success': False, 'error': 'Message too long (max 4,000 characters)'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        # Capture request context values before entering generator
        user_ip = get_client_ip()

        def generate():
            """Generator function for Server-Sent Events"""
            try:
                start_time = time.time()
                first_token_time = None
                stream_metrics = None

                for token in pokedex_handler.handle_pokedex_chat_stream(
                    user_message,
                    session_id,
                    user_ip,
                    ask_stream,
                    get_state_manager
                ):
                    if isinstance(token, dict) and token.get('_metrics'):
                        stream_metrics = token
                        continue

                    if first_token_time is None:
                        first_token_time = time.time()

                    yield f"data: {json.dumps({'token': token})}\n\n"

                # Build done event with optional metrics
                elapsed = round(time.time() - start_time, 1)
                ttft = round(first_token_time - start_time, 1) if first_token_time else None

                done_payload = {'done': True}
                if stream_metrics:
                    done_payload['metrics'] = {
                        'time': elapsed,
                        'eval_time': stream_metrics.get('eval_time'),
                        'gen_time': stream_metrics.get('gen_time'),
                        'input_tokens': stream_metrics.get('input_tokens'),
                        'output_tokens': stream_metrics.get('output_tokens'),
                        'speed': stream_metrics.get('speed'),
                        'iterations': stream_metrics.get('iterations'),
                        'route': stream_metrics.get('route'),
                        'ttft': ttft,
                    }

                yield f"data: {json.dumps(done_payload)}\n\n"

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
        logger.error(f"Error in the security assistant bot streaming chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An unexpected error occurred. Please try again.'}), 500


# --- the notification service Chat ---

@chat_bp.route('/toodles')
@log_web_activity
def toodles_chat():
    """the notification service chat interface - password protected"""
    return render_template('toodles_chat.html')


@chat_bp.route('/api/toodles/login', methods=['POST'])
@limiter.limit("5 per minute")
@log_web_activity
def api_toodles_login():
    """API endpoint for the notification service authentication"""
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
        logger.error(f"Error in the notification service login: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@chat_bp.route('/api/toodles/logout', methods=['POST'])
@log_web_activity
def api_toodles_logout():
    """API endpoint to logout from the notification service"""
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
            get_client_ip(),
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating X ticket: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


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
                get_client_ip()
            )
            return jsonify({'success': True, 'message': message})

        except ValueError as val_err:
            return jsonify({'success': False, 'error': str(val_err)}), 400

    except Exception as exc:
        logger.error(f"Error adding approved testing: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


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
            get_client_ip(),
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating IOC hunt: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


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
            get_client_ip(),
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating threat hunt: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@chat_bp.route('/api/toodles/oncall', methods=['GET'])
@log_web_activity
def api_oncall():
    """API endpoint to get on-call information"""
    try:
        on_call_person = toodles_handler.get_oncall_info()
        return jsonify({'success': True, 'data': on_call_person})

    except Exception as exc:
        logger.error(f"Error getting on-call info: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- Page-Context Chat Widget (shared across all dashboard pages) ---

@chat_bp.route('/api/page-chat/stream', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_page_chat_stream():
    """Streaming chat widget. The page sends its own context as report_md."""
    try:
        data = request.get_json()
        user_message = (data.get('message') or '').strip()
        report_md = (data.get('report_md') or '').strip()
        session_id = (data.get('session_id') or '').strip()

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400
        if len(user_message) > 2000:
            return jsonify({'success': False, 'error': 'Message too long (max 2 000 chars)'}), 400
        if not report_md:
            return jsonify({'success': False, 'error': 'No report context provided'}), 400
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        llm = _get_dp_llm()
        if llm is None:
            return jsonify({'success': False, 'error': 'LLM unavailable'}), 503

        def generate():
            try:
                for payload in page_chat_handler.handle_chat_stream(
                    user_message, report_md, session_id, llm
                ):
                    yield f"data: {json.dumps(payload)}\n\n"
            except Exception as err:
                logger.error("Page chat stream error: %s", err, exc_info=True)
                yield f"data: {json.dumps({'error': 'Streaming error'})}\n\n"

        return current_app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    except Exception as exc:
        logger.error("Page chat error: %s", exc, exc_info=True)
        return jsonify({'success': False, 'error': 'Chat error'}), 500


@chat_bp.route('/api/page-chat/clear', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_page_chat_clear():
    """Clear conversation history for the caller's session."""
    data = request.get_json(silent=True) or {}
    session_id = (data.get('session_id') or '').strip()
    if not session_id:
        return jsonify({'success': False, 'error': 'Session ID is required'}), 400
    page_chat_handler.clear_history(session_id)
    return jsonify({'success': True})


# --- Docs Library RAG Chat ---

@chat_bp.route('/api/docs-library/chat/stream', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_docs_library_chat_stream():
    """RAG chat over the local document store. Retrieves relevant chunks from ChromaDB then streams an LLM response."""
    from src.components.web import docs_library_chat_handler as dl_chat
    try:
        data = request.get_json()
        user_message = (data.get('message') or '').strip()
        session_id = (data.get('session_id') or '').strip()

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400
        if len(user_message) > 2000:
            return jsonify({'success': False, 'error': 'Message too long (max 2 000 chars)'}), 400
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        llm = _get_dp_llm()
        if llm is None:
            return jsonify({'success': False, 'error': 'LLM unavailable'}), 503

        def generate():
            try:
                for payload in dl_chat.handle_chat_stream(user_message, session_id, llm):
                    yield f"data: {json.dumps(payload)}\n\n"
            except Exception as err:
                logger.error("Docs library chat stream error: %s", err, exc_info=True)
                yield f"data: {json.dumps({'error': 'Streaming error'})}\n\n"

        return current_app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    except Exception as exc:
        logger.error("Docs library chat error: %s", exc, exc_info=True)
        return jsonify({'success': False, 'error': 'Chat error'}), 500


@chat_bp.route('/api/docs-library/chat/clear', methods=['POST'])
@limiter.limit("10 per minute")
@log_web_activity
def api_docs_library_chat_clear():
    """Clear docs library chat session history."""
    from src.components.web import docs_library_chat_handler as dl_chat
    data = request.get_json(silent=True) or {}
    session_id = (data.get('session_id') or '').strip()
    if not session_id:
        return jsonify({'success': False, 'error': 'Session ID is required'}), 400
    dl_chat.clear_history(session_id)
    return jsonify({'success': True})
