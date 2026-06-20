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

Created for Security Operations
"""
import logging
import re
import time

from my_bot.core.session_manager import get_session_manager
from my_bot.core.state_manager import get_state_manager

logging.basicConfig(level=logging.ERROR)

logger = logging.getLogger(__name__)

# Qwen3-Coder occasionally appends a stray `<tool_call>` tag (sometimes a full
# malformed block) after its final answer when the chat template hasn't been
# fully compiled — vllm-mlx's `qwen3_coder` parser only strips well-formed
# `<tool_call>...</tool_call>` pairs, so the leak reaches the user. See the
# matching note in `mentor_state_manager.py:241`.
_LEAKED_TOOL_CALL_TAIL_RE = re.compile(r"\s*<tool_call>.*\Z", re.DOTALL)
_LEAKED_TOOL_CALL_CLOSE_RE = re.compile(r"</tool_call>")


def _strip_leaked_tool_call_tags(text: str) -> str:
    if not text or "<tool_call>" not in text and "</tool_call>" not in text:
        return text
    cleaned = _LEAKED_TOOL_CALL_TAIL_RE.sub("", text)
    cleaned = _LEAKED_TOOL_CALL_CLOSE_RE.sub("", cleaned)
    return cleaned.rstrip()


def _metrics(content="", **overrides):
    """Build a standard metrics response dict. Use overrides for non-zero values."""
    result = {
        'content': _strip_leaked_tool_call_tags(content) if isinstance(content, str) else content,
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


def is_help_command(query_text: str) -> bool:
    """
    Detect if user is asking for help with using the bot.

    Args:
        query_text: The user's query string

    Returns:
        bool: True if the query is a help command, False otherwise
    """
    query_lower = query_text.lower().strip()

    # Direct help commands
    help_phrases = [
        'help', 'help me', 'how do i use', 'how to use',
        'what can you do', 'what do you do', 'show commands',
        'list commands', 'available commands', 'usage',
        'how does this work', 'instructions'
    ]

    return any(phrase == query_lower or query_lower.startswith(phrase + ' ') or query_lower.endswith(' ' + phrase) for phrase in help_phrases)


def get_help_response() -> str:
    """
    Return formatted help text with sample prompts for each tool category.

    Returns:
        str: Formatted help message for Webex
    """
    return """## 📟 Sleuth

### ⚡ Commands

- `help` - Show this help message
- `workflow <request>` - Run multi-step investigation workflows
- `tipper 12345` - Analyze threat tipper & post to AZDO
- `contacts EMEA` - Look up escalation contacts
- `execsum 929947` - Generate XSOAR ticket executive summary
- `falcon get browser history from HOST123` - Collect browser history via RTR
- `block url <domain>` - Block a URL via XSOAR (restricted rooms only)
- `clear my session` - Reset conversation memory

### 🔄 Workflow (multi-step investigations)

```
workflow investigate 1.2.3.4
workflow full analysis of evil-domain.com
workflow investigate XSOAR ticket 929947
workflow help
```

---

### 💬 Sample Prompts

> *Tip: Explicitly name the tool for best results*

🎫 **XSOAR**
`Use suggest remediation for XSOAR ticket 929947`
`Use generate executive summary for 929947`

🦠 **VirusTotal**
`Check IP 8.8.8.8 on VirusTotal`
`Look up domain evil.com on VirusTotal`

🚨 **AbuseIPDB**
`Check IP <internal-host> on AbuseIPDB`
`Has <internal-host> been reported for abuse?`

🔍 **URLScan**
`Search URLScan for example.com`
`Scan this URL on URLScan: https://suspicious.com`

🌐 **Shodan**
`Check 8.8.8.8 on Shodan`
`Look up example.com infrastructure on Shodan`

🔓 **HaveIBeenPwned**
`Has user@example.com been breached?`
`Check example.com for breached emails`

🌑 **IntelligenceX**
`Search IntelX for example.com`
`Check dark web for mentions of my-company.com`

🦠 **abuse.ch**
`Check if evil-domain.com is in abuse.ch`
`Is <internal-host> a botnet C2 server?`

📊 **QRadar**
`Search QRadar for IP <internal-host>`
`Get QRadar offense 12345`

🔮 **Vectra**
`Show recent Vectra detections`
`Find Vectra entity for SERVER01`

🔮 **Recorded Future**
`Look up IP 8.8.8.8 on Recorded Future`
`Search for APT28 threat actor`

🦅 **CrowdStrike**
`Is HOST123 contained in CrowdStrike?`
`Get CrowdStrike details for HOST123`
`falcon get browser history from HOST123`
`falcon check detections for HOST123`

🏢 **ServiceNow**
`Get ServiceNow details for HOST123`
`Look up HOST123 in ServiceNow CMDB`

💻 **Tanium**
`Look up WORKSTATION-001 in Tanium`
`Search Tanium for endpoints matching NYC-PC`

🛡️ **Detection Rules**
`rules emotet`
`rules search cobalt strike`
`detection rules for APT29`

📚 **Docs & Staffing**
`Who's on shift?`
`Search docs for phishing`"""



def is_rules_command(query_text: str) -> tuple:
    """
    Detect if user is requesting detection rules search.

    Supports patterns like:
    - "rules emotet"
    - "rules search APT29"
    - "detection rules for qakbot"
    - "search rules cobalt strike"

    Args:
        query_text: The user's query string

    Returns:
        tuple: (is_rules_command: bool, search_query: str or None)
    """
    import re
    query_lower = query_text.lower().strip()

    patterns = [
        r'^rules?\s+(?:search\s+)?(.+)$',                    # rules emotet, rule search emotet
        r'^(?:search\s+)?(?:detection\s+)?rules?\s+(?:for\s+)?(.+)$',  # detection rules for emotet
        r'^search\s+rules?\s+(.+)$',                          # search rules cobalt strike
    ]

    for pattern in patterns:
        match = re.match(pattern, query_lower)
        if match:
            search_query = match.group(1).strip()
            # Don't match if query is just "sync" or "stats" (those are CLI-only)
            if search_query in ("sync", "stats", "--sync", "--stats"):
                return (False, None)
            return (True, search_query)

    return (False, None)


def handle_rules_command(query: str) -> dict:
    """
    Handle the detection rules search command.

    Args:
        query: The search query

    Returns:
        dict with 'content' and token metrics (all zeros since no LLM used)
    """
    try:
        from src.components.tipper_analyzer.rules import search_rules
        from src.components.tipper_analyzer.rules.formatters import format_rules_for_display

        logger.info(f"Searching detection rules for: {query}")
        result = search_rules(query, k=10)
        return _metrics(format_rules_for_display(result))

    except Exception as e:
        logger.error(f"Rules command error: {e}", exc_info=True)
        return _metrics(f"Failed to search detection rules: {e}")


def is_falcon_command(query_text: str) -> tuple:
    """
    Detect if user is requesting a CrowdStrike/Falcon operation.

    Supports patterns like:
    - "falcon get browser history from HOST123"
    - "falcon check containment status for HOST456"
    - "falcon detections for LAPTOP789"
    - "cs get device details for SERVER01"

    Args:
        query_text: The user's query string

    Returns:
        tuple: (is_falcon_command: bool, falcon_query: str or None)
    """
    import re
    query_lower = query_text.lower().strip()

    # Match "falcon <query>" or "cs <query>" prefixes
    patterns = [
        r'^falcon\s+(.+)$',
        r'^crowdstrike\s+(.+)$',
        r'^cs\s+(.+)$',
    ]

    for pattern in patterns:
        match = re.match(pattern, query_lower)
        if match:
            falcon_query = match.group(1).strip()
            return (True, falcon_query)

    return (False, None)


def handle_falcon_command(query: str, room_id: str = None) -> dict:
    """
    Handle CrowdStrike/Falcon commands using LLM with CrowdStrike tools.

    This function processes falcon commands by:
    1. Passing the query to an LLM agent with CrowdStrike tools
    2. The LLM decides which tool to call and extracts parameters
    3. Handling file uploads for large results (e.g., browser history)

    Args:
        query: The falcon query (without the "falcon" prefix)
        room_id: Optional Webex room ID for file uploads

    Returns:
        dict with 'content', 'file_path' (optional), and token metrics
    """
    # Simple tool-calling approach: LLM picks the tool, we execute it once
    try:
        import time
        from langchain_core.messages import SystemMessage, HumanMessage

        # Import CrowdStrike tools (including browser history collection)
        from my_bot.tools.crowdstrike_tools import (
            get_device_containment_status,
            get_device_online_status,
            get_device_details_cs,
            get_crowdstrike_detections,
            get_crowdstrike_detection_details,
            search_crowdstrike_detections_by_hostname,
            get_crowdstrike_incidents,
            get_crowdstrike_incident_details,
            collect_browser_history,
            get_crowdstrike_host_vulnerabilities,
            search_crowdstrike_vulns_by_cve,
            get_crowdstrike_quarantine_files,
            get_crowdstrike_identity_risk,
            get_crowdstrike_high_risk_identities,
            run_endpoint_command,
            run_endpoint_diagnostic,
            get_and_clear_generated_file_path
        )

        cs_tools = [
            get_device_containment_status,
            get_device_online_status,
            get_device_details_cs,
            get_crowdstrike_detections,
            get_crowdstrike_detection_details,
            search_crowdstrike_detections_by_hostname,
            get_crowdstrike_incidents,
            get_crowdstrike_incident_details,
            collect_browser_history,
            get_crowdstrike_host_vulnerabilities,
            search_crowdstrike_vulns_by_cve,
            get_crowdstrike_quarantine_files,
            get_crowdstrike_identity_risk,
            get_crowdstrike_high_risk_identities,
            run_endpoint_command,
            run_endpoint_diagnostic
        ]

        # Build a tool lookup by name
        tool_map = {t.name: t for t in cs_tools}

        # Get the LLM from state manager
        state_manager = get_state_manager()
        if not state_manager or not state_manager.llm:
            return _metrics("❌ LLM not initialized. Please try again.", file_path=None)

        # Bind tools to the LLM
        llm_with_tools = state_manager.llm.bind_tools(cs_tools)

        # System prompt for CrowdStrike operations
        cs_system_prompt = """You are a CrowdStrike/Falcon expert assistant for security operations.
You have access to CrowdStrike tools for device management, detection analysis, incident response, and RTR operations.

Always use the appropriate tool to answer CrowdStrike-related questions.
Extract parameters like hostname from the user's query.
Call exactly one tool to fulfill the request."""

        messages = [
            SystemMessage(content=cs_system_prompt),
            HumanMessage(content=query)
        ]

        start_time = time.time()

        # Step 1: Ask LLM which tool to call
        response = llm_with_tools.invoke(messages)

        # Step 2: If LLM made a tool call, execute it
        output = ""
        if response.tool_calls:
            tool_call = response.tool_calls[0]  # Take the first tool call
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            logger.info(f"Falcon tool call: {tool_name}({tool_args})")

            if tool_name in tool_map:
                tool_result = tool_map[tool_name].invoke(tool_args)
                output = tool_result
            else:
                output = f"Unknown tool: {tool_name}"
        else:
            # LLM responded without calling a tool
            output = response.content

        execution_time = time.time() - start_time

        # Check if a file was generated (e.g., browser history Excel)
        file_path = get_and_clear_generated_file_path()

        return _metrics(output or 'No response from CrowdStrike agent',
                        file_path=file_path, prompt_time=execution_time)

    except Exception as e:
        logger.error(f"Falcon command error: {e}", exc_info=True)
        return _metrics(f"❌ **Falcon Command Failed**\n\nError processing CrowdStrike request: {e}",
                        file_path=None)


def _is_clear_session_command(query_text: str) -> bool:
    """Detect the exact 'clear my session' command (case insensitive).

    Clears the bot's conversation memory, NOT the Webex chat history.
    """
    return query_text.strip().lower() == 'clear my session'


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
        return f"❌ **Health Test Error**\\n\\nFailed to execute health tests: {str(e)}\\n\\n💡 **Manual run**: `python sleuth_bot/tests/system_health_tests.py`"


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


def ask(user_message: str, user_id: str = "default", room_id: str = "default", progress_callback=None) -> dict:
    """
    SOC Q&A function with persistent sessions and enhanced error recovery:

    1. Retrieves conversation context from persistent SQLite storage
    2. Passes message to LLM agent with enhanced error handling
    3. Agent decides what tools/documents are needed with retry logic
    4. Gracefully handles tool failures with context-aware fallbacks
    5. Stores conversation in persistent session for future context
    6. Returns complete response with proper attribution and token counts

    Features:
    - Persistent conversation context across bot restarts
    - Enhanced error recovery with intelligent fallbacks
    - Automatic session cleanup and health monitoring
    - Fast responses for simple queries (health, greetings)
    - Token usage tracking for performance monitoring

    Args:
        user_message: The user's question or request
        user_id: Unique identifier for the user (default: "default")
        room_id: Unique identifier for the chat room (default: "default")

    Returns:
        dict: {
            'content': str,             # The response text
            'input_tokens': int,        # Number of input tokens
            'output_tokens': int,       # Number of output tokens
            'total_tokens': int,        # Total tokens used
            'prompt_time': float,       # Seconds spent processing prompt
            'generation_time': float,   # Seconds spent generating response
            'tokens_per_sec': float,    # Output tokens per second
            'first_token_time': float   # Seconds until first token generated
        }
    """

    start_time = time.time()

    try:
        # Basic validation
        if not user_message or not user_message.strip():
            return _metrics("Please ask me a question!")

        import re

        query = user_message.strip()
        original_query = query

        # Remove bot name mentions from anywhere in the message (common in group chats)
        bot_names = ['DnR_Sleuth', 'Sleuth', 'sleuth', 'dnr_sleuth',
                     'HAL9000', 'hal9000', 'Jarvis', 'jarvis',
                     'Aide', 'aide', 'Relay', 'relay']

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
            logging.info("Lazy-initializing Sleuth components on first request...")
            if not state_manager.initialize_all_components():
                logging.error("Lazy initialization failed.")
                return _metrics("❌ Bot not ready. Initialization failed — check Ollama connectivity.")

        # Get session manager for persistent sessions
        session_manager = get_session_manager()

        # Clean up old sessions periodically
        session_manager.cleanup_old_sessions()

        # Get conversation context from session history
        conversation_context = session_manager.get_conversation_context(session_key)

        # Check for session context clear command using flexible keyword matching
        # This handles variations like "clear session context", "start fresh", "new session", etc.
        if _is_clear_session_command(query):
            # Clear the user's session context (bot's memory, not Webex chat history)
            deleted = session_manager.delete_session(session_key)
            if deleted:
                final_response = "✅ Session context cleared! Starting fresh with no memory of our previous conversation."
            else:
                final_response = "✅ Starting a new session! (No previous context found)"

            return _metrics(final_response)

        # Check for explicit 'workflow' command (before help check to handle 'workflow help')
        try:
            from my_bot.workflows.router import (
                is_workflow_command, parse_workflow_request, get_workflow_help
            )

            if is_workflow_command(query):
                parsed = parse_workflow_request(query)
                workflow_type = parsed["workflow_type"]
                workflow_query = parsed["workflow_query"]

                # Handle "workflow help"
                if workflow_query.lower().strip() in ("help", "?", ""):
                    help_text = get_workflow_help()
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", help_text)
                    return _metrics(help_text)

                if workflow_type == "ioc_investigation":
                    logging.info(f"Routing to IOC investigation workflow for: {parsed['ioc_value']}")
                    from my_bot.workflows.ioc_investigation import run_ioc_investigation
                    result = run_ioc_investigation(workflow_query)
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", result['content'])
                    return result

                elif workflow_type == "incident_response":
                    logging.info(f"Routing to incident response workflow for ticket: {parsed['ticket_id']}")
                    from my_bot.workflows.incident_response import run_incident_response
                    result = run_incident_response(workflow_query)
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", result['content'])
                    return result

                else:
                    # Unknown workflow type - provide help
                    error_msg = f"Could not determine workflow type. Use `workflow help` for usage.\n\nParsed: IOC={parsed['ioc_value']}, Ticket={parsed['ticket_id']}"
                    session_manager.add_message(session_key, "user", query)
                    session_manager.add_message(session_key, "assistant", error_msg)
                    return _metrics(error_msg)

        except ImportError as e:
            logging.warning(f"LangGraph workflows not available: {e}")
        except Exception as e:
            logging.error(f"Workflow routing error: {e}")

        # Check for help command
        if is_help_command(query):
            return _metrics(get_help_response())

        # Check for rules command (e.g., "rules emotet")
        is_rules, rules_query = is_rules_command(query)
        if is_rules:
            return handle_rules_command(rules_query)

        # Quick responses for simple queries (performance optimization)
        simple_query = query.lower().strip()
        if simple_query in ['hi', 'status', 'health', 'are you working']:
            final_response = "Hi 👋🏾"

            # Store simple interaction in session
            session_manager.add_message(session_key, "user", query)
            session_manager.add_message(session_key, "assistant", final_response)

            elapsed = time.time() - start_time
            if elapsed > 25:
                logging.warning(f"Response took {elapsed:.1f}s")
            return _metrics(final_response)

        # STEP 1: For complex queries, pass to LLM agent - let it decide everything
        try:
            # Use direct execution with native tool calling
            logging.info(f"Using direct LLM execution")

            # Prepare input with conversation context
            agent_input = query
            if conversation_context:
                context_chars = len(conversation_context)
                query_chars = len(query)
                total_chars = context_chars + query_chars + 1  # +1 for space
                # Rough estimate: ~4 chars per token for English text
                estimated_context_tokens = context_chars // 4
                logging.info(
                    f"📝 Session context: {context_chars} chars (~{estimated_context_tokens} tokens) + "
                    f"{query_chars} char query = {total_chars} total chars"
                )
                agent_input = conversation_context + " " + query

            # Let the 70B model handle everything directly - no agent framework
            logging.info(f"Passing query to direct LLM: {query[:100]}...")

            # Set logging context for tool calls
            from src.utils.tool_logging import set_logging_context
            set_logging_context(session_key)

            # execute_query now returns a dict with content, token counts, and timing data
            result = state_manager.execute_routed_query(agent_input, progress_callback=progress_callback)

        except Exception as e:
            logging.error(f"Failed to invoke agent: {e}")
            result = _metrics("❌ An error occurred. Please try again or contact support.")

        if isinstance(result.get('content'), str):
            result['content'] = _strip_leaked_tool_call_tags(result['content'])

        # Store user message and bot response in session
        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", result['content'])

        elapsed = time.time() - start_time
        if elapsed > 25:
            logging.warning(f"Response took {elapsed:.1f}s")

        return result

    except Exception as e:
        logging.error(f"Ask function failed: {e}")
        return _metrics("❌ An error occurred. Please try again or contact support.")


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

        # Remove bot name mentions
        bot_names = ['DnR_Sleuth', 'Sleuth', 'sleuth', 'dnr_sleuth',
                     'HAL9000', 'hal9000', 'Jarvis', 'jarvis',
                     'Aide', 'aide', 'Relay', 'relay']

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
            logging.info("Lazy-initializing Sleuth components on first request (stream)...")
            if not state_manager.initialize_all_components():
                logging.error("Lazy initialization failed.")
                yield "❌ Bot not ready. Initialization failed — check Ollama connectivity."
                return

        # Get session manager
        session_manager = get_session_manager()
        session_manager.cleanup_old_sessions()

        # Get conversation context
        conversation_context = session_manager.get_conversation_context(session_key)

        # Check for session context clear command using flexible keyword matching
        if _is_clear_session_command(query):
            # Clear the user's session context (bot's memory, not Webex chat history)
            deleted = session_manager.delete_session(session_key)
            if deleted:
                response = "✅ Session context cleared! Starting fresh with no memory of our previous conversation."
            else:
                response = "✅ Starting a new session! (No previous context found)"
            yield response
            return

        # Check for help command
        if is_help_command(query):
            yield get_help_response()
            return

        # Quick responses for simple queries
        simple_query = query.lower().strip()
        if simple_query in ['hi', 'status', 'health', 'are you working']:
            response = "Hi 👋🏾"
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
            if isinstance(token, dict):
                # Metrics dict from state_manager — pass through without adding to response
                yield token
                continue
            full_response += token
            yield token

        # Store conversation
        session_manager.add_message(session_key, "user", query)
        session_manager.add_message(session_key, "assistant", full_response)

    except Exception as e:
        logging.error(f"Ask stream function failed: {e}")
        yield "❌ An error occurred. Please try again or contact support."
