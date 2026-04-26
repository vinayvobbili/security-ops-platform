"""Claude API State Manager — drop-in replacement for SecurityBotStateManager.

Uses the Anthropic SDK for LLM calls while keeping all existing LangChain
@tool functions unchanged.  The tools are converted to Claude API format
at init time and invoked via the same `.invoke(args)` interface.

Key differences from the Ollama backend:
- Single-call architecture (no router stage — Claude handles routing natively)
- Anthropic SDK `client.messages.create()` instead of LangChain ChatOllama
- Token stats from `response.usage` instead of Ollama response_metadata
- No context window limit management (Claude handles this server-side)
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import anthropic

from my_bot.core.tool_converter import convert_all_tools
from my_bot.core.state_manager import (
    SecurityBotStateManager,
    FINAL_RESPONSE_PREFIX,
    _truncate_tool_result,
)
from my_config import get_config

logger = logging.getLogger(__name__)


class ClaudeStateManager(SecurityBotStateManager):
    """State manager that routes the security assistant bot queries through Claude API.

    Inherits from SecurityBotStateManager so that:
    - All tool registration (TOOL_CATEGORIES, all_tools) is reused
    - Ollama LLM + embeddings are still initialized (needed for RAG, triage, etc.)
    - health_check, warmup, shutdown handlers all work unchanged

    Only the query execution path is overridden to use Claude.
    """

    # Claude API timeout (seconds) — generous to allow multi-tool conversations
    CLAUDE_TIMEOUT_SECONDS = 300

    def __init__(self):
        super().__init__()
        self._claude_client: Optional[anthropic.Anthropic] = None
        self._claude_model: str = ""
        self._claude_tools: list = []   # Claude API format tool definitions
        self._cached_tools: list = []   # Same, with cache_control on last entry

    def initialize_all_components(self) -> bool:
        """Initialize all components including Claude API client."""
        # Initialize Ollama components (embeddings, RAG, tool registration)
        if not super().initialize_all_components():
            return False

        # Initialize Claude API client
        config = get_config()
        api_key = config.claude_api_key
        if not api_key:
            logger.error("CLAUDE_API_KEY not set — ClaudeStateManager cannot function")
            return False

        self._claude_client = anthropic.Anthropic(api_key=api_key)
        self._claude_model = config.claude_model or "claude-sonnet-4-6"

        # Convert LangChain tools to Claude API format
        self._claude_tools = convert_all_tools(self.all_tools)

        # Build cached version: adding cache_control to the last tool tells Claude
        # to cache everything before that point (system prompt + all tool definitions).
        # This avoids paying full input-token price on every call for the static prefix.
        self._cached_tools = list(self._claude_tools)
        if self._cached_tools:
            last = dict(self._cached_tools[-1])
            last["cache_control"] = {"type": "ephemeral"}
            self._cached_tools[-1] = last

        logger.info(
            f"Claude API initialized: model={self._claude_model}, "
            f"{len(self._claude_tools)} tools converted, prompt caching enabled"
        )
        return True

    def _execute_with_tools(self, query: str, tools: list) -> dict:
        """Agentic loop using Claude API instead of Ollama.

        This replaces the parent's _execute_with_tools entirely.
        The `tools` parameter is a list of LangChain tool objects (used for
        the router's category-based selection in the parent).  For Claude,
        we send ALL tools since Claude handles routing natively.
        """
        if not self._claude_client:
            return self._error_response("Claude API client not initialized")

        try:
            # Build tool map from the provided LangChain tools
            tool_map = {tool.name: tool for tool in tools}

            # Use pre-built cached tools — cache_control on the last entry tells
            # Claude to cache system prompt + all tool definitions across calls.
            claude_tools = self._cached_tools

            # Capture logging context for child threads
            from src.utils.tool_logging import get_logging_context, set_logging_context
            _caller_session_id = get_logging_context()

            messages = [{"role": "user", "content": query}]

            total_input_tokens = 0
            total_output_tokens = 0
            tools_used = []
            max_iterations = 5
            tool_call_counts: dict[str, int] = {}
            MAX_PER_TOOL_CALLS = 2
            wall_clock_start = time.monotonic()

            for iteration in range(1, max_iterations + 1):
                # Check wall-clock timeout
                elapsed = time.monotonic() - wall_clock_start
                if elapsed > self.CLAUDE_TIMEOUT_SECONDS:
                    logger.error(f"Claude agentic loop timed out after {elapsed:.1f}s")
                    return self._error_response(
                        f"Query took too long (>{self.CLAUDE_TIMEOUT_SECONDS}s). Please try again."
                    )

                # Call Claude API — system prompt wrapped in list for cache_control
                response = self._claude_client.messages.create(
                    model=self._claude_model,
                    max_tokens=4096,
                    system=[{
                        "type": "text",
                        "text": self._get_system_prompt(),
                        "cache_control": {"type": "ephemeral"},
                    }],
                    tools=claude_tools,
                    messages=messages,
                )

                # Accumulate token usage
                total_input_tokens += response.usage.input_tokens
                total_output_tokens += response.usage.output_tokens
                cache_read = getattr(response.usage, 'cache_read_input_tokens', 0) or 0
                cache_created = getattr(response.usage, 'cache_creation_input_tokens', 0) or 0

                logger.info(
                    f"Claude iter {iteration}: {response.usage.input_tokens} in / "
                    f"{response.usage.output_tokens} out | "
                    f"cache read={cache_read} created={cache_created} | "
                    f"stop={response.stop_reason}"
                )

                # If no tool use, we're done
                if response.stop_reason != "tool_use":
                    # Extract text content
                    text_parts = [
                        block.text for block in response.content
                        if block.type == "text"
                    ]
                    final_text = "\n".join(text_parts) if text_parts else ""
                    break

                # Process tool calls
                # Add the assistant message (with tool_use blocks) to conversation
                messages.append({"role": "assistant", "content": response.content})

                # Collect tool_use blocks
                tool_use_blocks = [
                    block for block in response.content
                    if block.type == "tool_use"
                ]

                for block in tool_use_blocks:
                    if block.name not in tools_used:
                        tools_used.append(block.name)

                # Execute tools in parallel
                def execute_single_tool(block):
                    set_logging_context(_caller_session_id)
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id
                    logger.info(f"Executing tool: {tool_name}")

                    # Enforce per-tool call limit to prevent any tool from looping
                    tool_call_counts[tool_name] = tool_call_counts.get(tool_name, 0) + 1
                    if tool_call_counts[tool_name] > MAX_PER_TOOL_CALLS:
                        logger.warning(
                            f"{tool_name} call #{tool_call_counts[tool_name]} blocked "
                            f"(limit: {MAX_PER_TOOL_CALLS})"
                        )
                        return {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": f"You have already called {tool_name} {MAX_PER_TOOL_CALLS} times. "
                                       "Do NOT call this tool again. "
                                       "Provide your answer using the information already gathered.",
                        }

                    if tool_name in tool_map:
                        try:
                            result = tool_map[tool_name].invoke(tool_input)
                        except Exception as e:
                            logger.error(f"Error executing tool {tool_name}: {e}", exc_info=True)
                            result = "The tool encountered an error. Please try again."
                    else:
                        logger.error(f"Tool not found: {tool_name}")
                        result = "The requested tool is not available."

                    result_str = _truncate_tool_result(str(result), tool_name)
                    return {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result_str,
                    }

                tool_results = []
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {
                        executor.submit(execute_single_tool, block): block
                        for block in tool_use_blocks
                    }
                    for future in as_completed(futures):
                        tool_results.append(future.result())

                # Check for FINAL_RESPONSE short-circuit
                final_content = None
                for tr in tool_results:
                    content = tr.get("content", "")
                    if content.startswith(FINAL_RESPONSE_PREFIX):
                        final_content = content[len(FINAL_RESPONSE_PREFIX):]
                        break

                if final_content is not None:
                    logger.info(f"Tool returned final response — skipping Claude iteration {iteration + 1}")
                    final_text = final_content
                    break

                # Add tool results to conversation
                messages.append({"role": "user", "content": tool_results})

            else:
                # Max iterations exhausted
                logger.warning(f"Max iterations ({max_iterations}) exhausted")
                final_text = (
                    "I reached the maximum number of tool calls. "
                    "Here's what I found so far based on the information gathered."
                )

            total_time = time.monotonic() - wall_clock_start
            tokens_per_sec = total_output_tokens / total_time if total_time > 0 else 0.0

            return {
                'content': final_text,
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens': total_input_tokens + total_output_tokens,
                'prompt_time': 0.0,  # Not available from Claude API
                'generation_time': total_time,
                'tokens_per_sec': tokens_per_sec,
                'first_token_time': 0.0,
                'iterations': iteration,
                'tools_used': tools_used,
            }

        except anthropic.APIError as e:
            logger.warning(f"Claude API error, falling back to Ollama: {e}")
            return super()._execute_with_tools(query, tools)
        except Exception as e:
            logger.warning(f"Claude execution error, falling back to Ollama: {e}")
            return super()._execute_with_tools(query, tools)

    def execute_routed_query(self, query: str, progress_callback=None) -> dict:
        """Single-call architecture — Claude handles routing natively.

        No separate router stage needed. Send all tools and let Claude decide.
        Falls back to Ollama if Claude client isn't available.
        progress_callback is accepted for API compatibility but unused — Claude
        needs no router stage so there is no intermediate progress to report.
        """
        if not self._claude_client:
            logger.warning("Claude client not initialized, falling back to Ollama")
            return super().execute_routed_query(query)

        return self._execute_with_tools(query, self.all_tools)

    def execute_query(self, query: str) -> dict:
        """Execute query with all tools (backward compat)."""
        if not self._claude_client:
            return super().execute_query(query)
        return self._execute_with_tools(query, self.all_tools)

    def execute_query_stream(self, query: str):
        """Streaming query using Claude API.

        Uses Claude's streaming API to yield tokens as they arrive.
        For tool-calling iterations, runs non-streaming, then streams
        the final response. Falls back to Ollama on any Claude error.
        """
        if not self._claude_client:
            logger.warning("Claude client not initialized, falling back to Ollama stream")
            yield from super().execute_query_stream(query)
            return

        try:
            from src.utils.tool_logging import get_logging_context, set_logging_context
            _caller_session_id = get_logging_context()

            tool_map = {tool.name: tool for tool in self.all_tools}
            messages = [{"role": "user", "content": query}]

            total_input_tokens = 0
            total_output_tokens = 0
            tools_used = []
            max_iterations = 5
            tool_call_counts: dict[str, int] = {}
            MAX_PER_TOOL_CALLS = 2
            wall_clock_start = time.monotonic()

            for iteration in range(1, max_iterations + 1):
                elapsed = time.monotonic() - wall_clock_start
                if elapsed > self.CLAUDE_TIMEOUT_SECONDS:
                    yield f"Query timed out after {elapsed:.1f}s."
                    return

                # Non-streaming call for tool-calling iterations
                response = self._claude_client.messages.create(
                    model=self._claude_model,
                    max_tokens=4096,
                    system=[{
                        "type": "text",
                        "text": self._get_system_prompt(),
                        "cache_control": {"type": "ephemeral"},
                    }],
                    tools=self._cached_tools,
                    messages=messages,
                )

                total_input_tokens += response.usage.input_tokens
                total_output_tokens += response.usage.output_tokens
                cache_read = getattr(response.usage, 'cache_read_input_tokens', 0) or 0
                cache_created = getattr(response.usage, 'cache_creation_input_tokens', 0) or 0
                logger.debug(
                    f"Claude stream iter {iteration}: cache read={cache_read} created={cache_created}"
                )

                if response.stop_reason != "tool_use":
                    # Final response — yield text content
                    for block in response.content:
                        if block.type == "text":
                            yield block.text
                    break

                # Process tool calls (same as _execute_with_tools)
                messages.append({"role": "assistant", "content": response.content})

                tool_use_blocks = [
                    block for block in response.content
                    if block.type == "tool_use"
                ]

                for block in tool_use_blocks:
                    if block.name not in tools_used:
                        tools_used.append(block.name)

                def execute_single_tool(block):
                    set_logging_context(_caller_session_id)
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    if tool_name in tool_map:
                        try:
                            result = tool_map[tool_name].invoke(tool_input)
                        except Exception as e:
                            logger.error(f"Error executing tool {tool_name}: {e}", exc_info=True)
                            result = "The tool encountered an error."
                    else:
                        result = "The requested tool is not available."

                    return {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": _truncate_tool_result(str(result), tool_name),
                    }

                tool_results = []
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {
                        executor.submit(execute_single_tool, b): b
                        for b in tool_use_blocks
                    }
                    for future in as_completed(futures):
                        tool_results.append(future.result())

                # Check FINAL_RESPONSE short-circuit
                for tr in tool_results:
                    content = tr.get("content", "")
                    if content.startswith(FINAL_RESPONSE_PREFIX):
                        yield content[len(FINAL_RESPONSE_PREFIX):]
                        total_time = time.monotonic() - wall_clock_start
                        speed = total_output_tokens / total_time if total_time > 0 else 0.0
                        yield {
                            '_metrics': True,
                            'input_tokens': total_input_tokens,
                            'output_tokens': total_output_tokens,
                            'eval_time': 0.0,
                            'gen_time': round(total_time, 1),
                            'speed': round(speed, 1),
                            'iterations': iteration,
                            'route': ' → '.join(tools_used) if tools_used else 'claude',
                        }
                        return

                messages.append({"role": "user", "content": tool_results})

            # Emit metrics as final item
            total_time = time.monotonic() - wall_clock_start
            speed = total_output_tokens / total_time if total_time > 0 else 0.0
            route = ' → '.join(tools_used) if tools_used else 'claude'
            yield {
                '_metrics': True,
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'eval_time': 0.0,
                'gen_time': round(total_time, 1),
                'speed': round(speed, 1),
                'iterations': iteration,
                'route': route,
            }

        except (anthropic.APIError, Exception) as e:
            logger.warning(f"Claude stream error, falling back to Ollama: {e}")
            yield from super().execute_query_stream(query)

    @staticmethod
    def _error_response(msg: str) -> dict:
        return {
            'content': f"❌ {msg}",
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': 0.0,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
            'first_token_time': 0.0,
            'iterations': 0,
        }
