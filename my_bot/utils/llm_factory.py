"""LLM factory — the ONE place that knows which provider class to use.

Every other module uses abstract LangChain types (BaseChatModel, Embeddings).
To switch providers (OpenAI-compat, Ollama, Bedrock, etc.) change THIS file only.
"""

import os
import logging
import re
import time
from typing import Optional

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from my_bot.utils.enhanced_config import ModelConfig

logger = logging.getLogger(__name__)


def _no_keepalive_http_client(timeout: float = 600.0) -> httpx.Client:
    """httpx.Client with keepalive disabled.

    Long-lived bot processes have been observed hanging for ~115s on iter-2 LLM
    calls when openai's pool reuses an idle keepalive connection that the mlx-lm
    server has already torn down — TCP retransmits expire before the client
    notices. Forcing a fresh connection per request side-steps the whole class.
    """
    return httpx.Client(
        timeout=timeout,
        limits=httpx.Limits(max_keepalive_connections=0, max_connections=10),
    )


def create_llm(config: ModelConfig = None, **overrides) -> BaseChatModel:
    """Create the main LLM instance.

    Args:
        config: ModelConfig (uses defaults if None)
        **overrides: Any kwargs to override (e.g. temperature=0.5)
    """
    config = config or ModelConfig()
    kwargs = dict(
        model=config.llm_model_name,
        temperature=config.temperature,
        base_url=config.m1_analysis_base_url,  # m1 analysis — GLM-4.7-Flash (port 8015)
        api_key="not-needed",
        timeout=300.0,
        http_client=_no_keepalive_http_client(timeout=600.0),
        extra_body={
            "chat_template_kwargs": {"enable_thinking": False},
        },
    )
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


def create_router_llm(config: ModelConfig = None, **overrides) -> BaseChatModel:
    """Create the lightweight router LLM instance."""
    config = config or ModelConfig()
    kwargs = dict(
        model=config.router_model_name or config.llm_model_name,
        temperature=config.temperature,
        base_url=config.m1_router_base_url,  # m1 router — Qwen3-8B (port 8016)
        api_key="not-needed",
        timeout=300.0,
        http_client=_no_keepalive_http_client(timeout=300.0),
    )
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


def create_embeddings(config: ModelConfig = None, **overrides) -> Embeddings:
    """Create the embeddings instance."""
    config = config or ModelConfig()
    embedding_url = getattr(config, 'embeds_base_url', None) or config.m1_analysis_base_url  # embeddings — Qwen3-Embedding (studio1:8004)
    kwargs = dict(
        model=config.embedding_model_name,
        base_url=embedding_url,
        api_key="not-needed",
    )
    kwargs.update(overrides)
    return OpenAIEmbeddings(**kwargs)


# ---------------------------------------------------------------------------
# Structured-output helper
# ---------------------------------------------------------------------------

def structured_output(llm: BaseChatModel, schema, max_retries: int = 1):
    """Wrap ``llm.with_structured_output`` using ``method="json_mode"``.

    Why: the default method on ChatOpenAI in LangChain 0.3+ is ``"json_schema"``,
    which sends ``response_format={"type":"json_schema", "strict":true}``.
    vllm-mlx responds by running grammar-constrained decoding, masking logits to
    the schema's FSM at every step. Complex schemas (oneOf/$defs/enums + long
    prefills) have been observed wedging the decoder, blocking every other
    request behind it for minutes. ``json_mode`` sends only
    ``{"type":"json_object"}`` — LangChain still injects the schema into the
    prompt and validates the response with Pydantic post-hoc.

    Retries once on any exception (Pydantic ValidationError, JSON parse errors,
    transient transport hiccups) to absorb the rare invalid-JSON response that
    json_mode is more susceptible to vs strict json_schema decoding.
    """
    inner = llm.with_structured_output(schema, method="json_mode")

    class _RetryingStructured:
        def invoke(self, input, **kwargs):
            last_err: Optional[Exception] = None
            for attempt in range(max_retries + 1):
                try:
                    return inner.invoke(input, **kwargs)
                except Exception as e:
                    last_err = e
                    if attempt < max_retries:
                        logger.warning(
                            "structured_output(%s) attempt %d/%d failed: %s: %s — retrying",
                            getattr(schema, "__name__", str(schema)),
                            attempt + 1, max_retries + 1,
                            type(e).__name__, str(e)[:200],
                        )
                        continue
                    raise
            assert last_err is not None
            raise last_err

    return _RetryingStructured()


class FailoverChatModel(BaseChatModel):
    """Wraps two LLMs — tries primary, falls back to secondary on connection errors.

    Delegates all calls (invoke, stream, etc.) to the primary LLM. If the primary
    raises a connection-related error, transparently retries with the secondary.
    """

    primary: BaseChatModel
    secondary: BaseChatModel
    _active: str = "primary"

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "failover"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        try:
            result = self.primary._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            if self._active != "primary":
                logger.info("Failover: primary LLM recovered")
                self._active = "primary"
            return result
        except Exception as exc:
            if _is_connection_error(exc):
                logger.warning("Failover: primary LLM down (%s), switching to secondary", type(exc).__name__)
                self._active = "secondary"
                return self.secondary._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            raise

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        try:
            first_chunk = None
            stream = self.primary._stream(messages, stop=stop, run_manager=run_manager, **kwargs)
            for chunk in stream:
                if first_chunk is None:
                    first_chunk = True
                    if self._active != "primary":
                        logger.info("Failover: primary LLM recovered")
                        self._active = "primary"
                yield chunk
        except Exception as exc:
            if _is_connection_error(exc) and first_chunk is None:
                logger.warning("Failover: primary LLM down (%s), switching to secondary", type(exc).__name__)
                self._active = "secondary"
                yield from self.secondary._stream(messages, stop=stop, run_manager=run_manager, **kwargs)
            else:
                raise


def _is_connection_error(exc: Exception) -> bool:
    """Check if an exception is a connection/network error worth failing over."""
    error_names = ("ConnectionError", "ConnectError", "RemoteProtocolError",
                   "ConnectionRefusedError", "TimeoutError", "ReadTimeout")
    # Check the exception itself and its chain
    current = exc
    while current:
        if type(current).__name__ in error_names:
            return True
        if "Connection" in type(current).__name__ or "connection" in str(current).lower()[:100]:
            return True
        current = current.__cause__ or current.__context__
        if current is exc:
            break
    return False


def create_failover_llm(primary_url: str, secondary_url: str,
                        temperature: float = 0.1, **kwargs) -> FailoverChatModel:
    """Create an LLM with automatic failover between two endpoints.

    Args:
        primary_url: Primary LLM base URL (e.g. http://localhost:8015/v1)
        secondary_url: Secondary/fallback LLM base URL (e.g. http://localhost:8011/v1)
        temperature: LLM temperature (default 0.1)
        **kwargs: Extra kwargs passed to both ChatOpenAI instances
    """
    import requests as _req

    def _make_client(base_url):
        model = ""
        try:
            resp = _req.get(f"{base_url}/models", timeout=5)
            models = resp.json().get("data", [])
            if models:
                model = models[0]["id"]
        except Exception:
            pass
        return ChatOpenAI(
            model=model or "default", temperature=temperature,
            base_url=base_url, api_key="not-needed", **kwargs,
        )

    primary = _make_client(primary_url)
    secondary = _make_client(secondary_url)
    logger.info("Failover LLM: primary=%s, secondary=%s", primary_url, secondary_url)
    return FailoverChatModel(primary=primary, secondary=secondary)


def extract_token_metrics(meta: Optional[dict]) -> dict:
    """Extract token counts from LangChain response_metadata.

    Works with both OpenAI-compatible (ChatOpenAI / mlx-lm / vllm) and
    Ollama (ChatOllama) metadata formats. Returns a dict with:
        input_tokens, output_tokens, prompt_time, generation_time
    All values default to 0 if not found.
    """
    if not meta:
        return {'input_tokens': 0, 'output_tokens': 0, 'prompt_time': 0.0, 'generation_time': 0.0}

    # OpenAI-compatible: token_usage or usage dict
    usage = meta.get('token_usage') or meta.get('usage') or {}
    input_tokens = usage.get('prompt_tokens', 0) or meta.get('prompt_eval_count', 0)
    output_tokens = usage.get('completion_tokens', 0) or meta.get('eval_count', 0)

    # Timing: Ollama provides nanoseconds, OpenAI-compat doesn't provide timing
    prompt_time = 0.0
    generation_time = 0.0
    if 'prompt_eval_duration' in meta:
        prompt_time = meta['prompt_eval_duration'] / 1e9
    if 'eval_duration' in meta:
        generation_time = meta['eval_duration'] / 1e9

    return {
        'input_tokens': input_tokens,
        'output_tokens': output_tokens,
        'prompt_time': prompt_time,
        'generation_time': generation_time,
    }


# --- Non-tool final-answer synthesis (shared by the bot managers) -----------
# Tool-calling must run on the local model (a dedicated synthesis model can't bind tools), but the final
# natural-language answer needs no tools — compose it on the synthesis model to keep that
# generation off a contended local GPU. The tool-loop model emits a cheap marker
# instead of writing the long answer; we then synthesize from the tool results.
# Kill switch: SLEUTH_SYNTHESIS=false reverts to all-m1 behavior.
SYNTH_ENABLED = os.getenv("SLEUTH_SYNTHESIS", "true").strip().lower() in ("1", "true", "yes", "on")
SYNTH_MARKER = "<<READY_TO_ANSWER>>"
SYNTH_DIRECTIVE = (
    "\n\n## ANSWER PROTOCOL\n"
    "Your job is to GATHER data by calling the tools the request needs — a dedicated step then "
    "composes the user-facing answer from the tool results, so you do NOT write the prose answer "
    "yourself. Call every tool the request needs (you may call several at once), then stop. Do not "
    "narrate your plan and do not write a summary. If — and only if — the request genuinely needs "
    "no tools at all (e.g. a greeting, or a question answerable with no lookup), just answer it "
    "directly."
)
SYNTH_SYSTEM_PROMPT = (
    "You are an expert Security Operations Center (SOC) assistant composing the FINAL answer for "
    "the user. You are given the user's request and the raw results already gathered from security "
    "tools. Write a complete, accurate, well-formatted markdown answer using ONLY that data. Do not "
    "mention tools, this instruction, or the gathering process. If the data is empty or "
    "inconclusive, say so plainly. "
    "Reproduce all timestamps, IP addresses, hostnames, IDs, and indicators EXACTLY as they appear "
    "in the data — never reformat, convert, or drop any part of them (in particular, keep timezone "
    "labels like 'EDT'/'EST' and any defanging such as '[.]' intact). "
    "If the data contains any markdown links — especially a 'Verify at source' or deep link — keep "
    "them verbatim and include them in your answer so the user can click through to verify."
)

# Re-prompt issued when a model signals readiness before gathering data (see
# is_premature_synth_marker). Every agentic loop that uses the synthesis protocol
# wires this same nudge so the recovery is identical across bots.
SYNTH_GATHER_FIRST_NUDGE = (
    "You signaled you are ready to answer, but you have NOT called any tool yet, so no data "
    "has been gathered. Do NOT signal readiness before gathering data. Call the appropriate "
    "tool NOW to get the information needed to answer this request."
)


def is_premature_synth_marker(content: str, tools_bound: bool, tools_called: bool) -> bool:
    """True if the model signaled it's ready to answer (synthesis marker, or empty
    content) WITHOUT calling any tool, even though tools were bound for the query.

    This is the synthesis protocol's safety invariant, enforced identically by
    every consumer's agentic loop: synthesizing in this state composes an answer
    from ZERO tool data — e.g. a false "no hosts found" for a live IOC. It is a
    structural conflict check (tools were bound ↔ none were called), NOT a
    content heuristic. The caller owns the bounded re-prompt + loop continuation
    (loop control is per-manager); this owns the decision.
    """
    if not (tools_bound and not tools_called):
        return False
    raw = (content or "").strip()
    return SYNTH_MARKER in raw or raw == ""

# synthesis-always handoff: after a tool round the loop composes the answer on the synthesis model
# directly instead of bouncing the full context back to the local model just to detect "done"
# (the dominant cost under the local model contention, and the tool-loop model follows the marker protocol only
# inconsistently). To keep multi-step queries correct, the synthesizer may decide
# the gathered data is insufficient and request one more tool round via this token;
# the loop then nudges the local model to fetch the missing piece and synthesizes again.
SYNTH_NEED_MARKER = "<<NEED:"
_NEED_RE = re.compile(r"<<NEED:\s*(.*?)>>", re.DOTALL)
SYNTH_NEED_CLAUSE = (
    "\n\nSUFFICIENCY CHECK: if the gathered data is clearly INSUFFICIENT to answer the request and "
    "a specific additional security lookup would obtain the missing piece, do NOT guess or write a "
    "partial answer. Instead reply with EXACTLY this and nothing else: "
    "<<NEED: a short description of the additional data required>>. "
    "Request more ONLY when another lookup would genuinely help — if the data is simply empty or "
    "negative (e.g. no hosts/detections found), that IS the answer: write it, do not request more. "
    "One nuance: if the user EXPLICITLY requested a specific investigative step (e.g. per-host browser "
    "history, a process/execution timeline, or a named lookup) and there is NO tool output for that "
    "step yet, you MUST request it with <<NEED: ...>> — an empty or negative result from a DIFFERENT "
    "lookup does not satisfy a step the user asked for that has not been run."
)
# Nudge appended for m1's next tool round when the synthesizer requests more data.
SYNTH_NEED_NUDGE = (
    "The data gathered so far is not enough to fully answer the request. Still needed: {need}. "
    "Call the appropriate tool now to obtain it. If no tool can provide it, do not loop — we will "
    "answer with what we have."
)


_VERIFY_LINK_PREFIX = "🔗 Verify at source:"
# Match a verify link anywhere in tool output — keyed on the ASCII marker rather
# than the 🔗 emoji so it is recovered whether a Sleuth tool emitted it as a bare
# markdown line OR an MCP tool rode it in a dict field that JSON serialization
# unicode-escaped the emoji out of. Captures (label, url).
_VERIFY_RE = re.compile(r"Verify at source:\s*\[([^\]]*)\]\((https?://[^)\s]+)\)")


def ensure_verify_links(final_content: str, messages: list) -> str:
    """Guarantee any 'Verify at source' deep link a tool produced survives into
    the final answer — WITHOUT duplicating one the composer kept in reworded form.

    A tool emits its verify link with its own output, but the answer is composed
    afterwards (the synthesis model or the local model prose) and may either drop the link OR reproduce it with
    different wording/preamble. So we dedup by the link's URL, not its text: recover
    each distinct tool verify link, and append it only if its URL (the stable part)
    is absent from the answer. Works for both tool flavors — a Sleuth string tool's
    bare markdown line and an MCP dict tool's serialized 'verify_at_source' field —
    by matching the ASCII marker (the 🔗 may be JSON-escaped) and rebuilding a clean
    line. Deterministic (no model dependency, no heuristic), idempotent.
    """
    answer = final_content or ""
    seen_urls = set()
    candidates = []  # (clean_line, url)
    for msg in messages:
        if not (isinstance(msg, dict) and msg.get("role") == "tool"):
            continue
        for label, url in _VERIFY_RE.findall(str(msg.get("content", ""))):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            candidates.append((f"{_VERIFY_LINK_PREFIX} [{label}]({url})", url))
    # Present already if the URL (the stable part) is in the answer — this also
    # catches the composer rewording the link text but keeping the URL.
    missing = [line for line, url in candidates if url not in answer]
    if missing:
        answer = (answer.rstrip() + "\n\n" + "\n".join(missing)).strip()
    return answer


_SYNTH_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
_synth_llm_singleton = None


def get_synth_llm(timeout: int = 90) -> BaseChatModel:
    """Shared a dedicated synthesis model synthesizer (lazy singleton) with internal the local model fallback."""
    global _synth_llm_singleton
    if _synth_llm_singleton is None:
        _synth_llm_singleton = create_llm(timeout=timeout)
    return _synth_llm_singleton


def _run_synth(system_prompt: str, query: str, messages: list) -> tuple:
    """Invoke the synthesis model over a clean, model-portable context (flattened
    role=='tool' outputs as text) — many models reject orphaned tool messages.
    Returns (content, {"generation_time", "output_tokens"})."""
    tool_blocks = []
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "tool":
            c = str(msg.get("content", "")).strip()
            if c:
                tool_blocks.append(c)
    gathered = "\n\n---\n\n".join(tool_blocks).strip()
    synth_user = f"User request:\n{query}\n\n"
    synth_user += (f"Data gathered from security tools:\n{gathered}\n\n"
                   if gathered else "No tool data was gathered.\n\n")
    synth_user += "Write the complete final answer for the user now."
    synth_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": synth_user},
    ]
    start = time.monotonic()
    resp = get_synth_llm().invoke(synth_messages)
    elapsed = time.monotonic() - start
    content = _SYNTH_THINK_RE.sub("", getattr(resp, "content", "") or "").strip()
    out_tok = 0
    if getattr(resp, "usage_metadata", None):
        out_tok = resp.usage_metadata.get("output_tokens", 0)
    if not out_tok:
        out_tok = extract_token_metrics(getattr(resp, "response_metadata", None))["output_tokens"]
    return content, {"generation_time": elapsed, "output_tokens": out_tok}


def synthesize_final_answer(query: str, messages: list) -> tuple:
    """Compose the final user-facing answer on the synthesis model from gathered tool results.
    Returns (content, {"generation_time", "output_tokens"}). No sufficiency hatch —
    used as the terminal compose (e.g. the kill-switch/marker fallback path)."""
    return _run_synth(SYNTH_SYSTEM_PROMPT, query, messages)


def synthesize_or_request_more(query: str, messages: list) -> tuple:
    """synthesis-always handoff: compose the answer from gathered tool results, OR — if
    the data is insufficient for a multi-step query — request one more tool round.

    Returns (content, metrics, need): when the synthesizer can answer, content is
    the final answer and need is None; when it needs more data, content is None and
    need is a short description of what's missing (the caller nudges the local model for it and
    re-synthesizes). Legitimate empty/negative results are answered, not re-queried
    (see SYNTH_NEED_CLAUSE). Raises on the synthesis model failure — caller falls back to the tool-loop model."""
    content, metrics = _run_synth(SYNTH_SYSTEM_PROMPT + SYNTH_NEED_CLAUSE, query, messages)
    m = _NEED_RE.search(content or "")
    if m:
        return None, metrics, (m.group(1).strip() or "additional data")
    return content, metrics, None
