"""LLM factory — the ONE place that knows which provider class to use.

Every other module uses abstract LangChain types (BaseChatModel, Embeddings).
To switch providers (OpenAI-compat, Ollama, Bedrock, etc.) change THIS file only.
"""

import logging
import re
import time
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from my_bot.utils.enhanced_config import ModelConfig

logger = logging.getLogger(__name__)


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
    )
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


def create_embeddings(config: ModelConfig = None, **overrides) -> Embeddings:
    """Create the embeddings instance."""
    config = config or ModelConfig()
    embedding_url = getattr(config, 'm3_embeds_base_url', None) or config.m1_analysis_base_url  # m3 embeddings — Qwen3-Embedding (port 8019)
    kwargs = dict(
        model=config.embedding_model_name,
        base_url=embedding_url,
        api_key="not-needed",
    )
    kwargs.update(overrides)
    return OpenAIEmbeddings(**kwargs)


# ---------------------------------------------------------------------------
# the internal LLM gateway Chat Model — GPT-4.1 via the company's the internal LLM gateway gateway, m1 fallback
# ---------------------------------------------------------------------------

_metiq_client = None


def _get_metiq_client():
    """Lazy-init a shared the internal LLM gateway client (singleton)."""
    global _metiq_client
    if _metiq_client is None:
        from services.metiq import the internal LLM gatewayClient
        _metiq_client = the internal LLM gatewayClient()
        logger.info("the internal LLM gateway client configured=%s", _metiq_client.is_configured())
    return _metiq_client


def _sanitize_metiq(text: str) -> str:
    """Strip control chars that break JSON parsers downstream.

    the internal LLM gateway (GPT-4.1) doesn't honour response_format and may emit literal
    control chars inside JSON string values.  Preserves \\n, \\r, \\t.
    """
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)


def _split_langchain_messages(messages):
    """Convert LangChain messages into the internal LLM gateway's (prompt, history) format.

    the internal LLM gateway has no system role — system messages are merged as a prefix to
    the last user turn.  Prior messages become history entries with
    User/Agent capitalisation.
    """
    systems, conv = [], []
    for m in messages:
        content = m.content
        if isinstance(content, list):
            content = "\n".join(
                p.get("text", "") for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            )
        if isinstance(m, SystemMessage):
            if content:
                systems.append(content)
        elif isinstance(m, HumanMessage):
            conv.append({"role": "User", "content": content})
        elif isinstance(m, AIMessage):
            conv.append({"role": "Agent", "content": content})

    if not conv:
        return "", []

    last = conv[-1]
    history = conv[:-1]
    prompt = last["content"] if last["role"] == "User" else ""
    if systems:
        prompt = "\n\n".join(systems) + ("\n\n" + prompt if prompt else "")
    return prompt, history


class the internal LLM gatewayChatModel(BaseChatModel):
    """LangChain chat model: the internal LLM gateway (GPT-4.1) primary, m1 fallback.

    - _generate (invoke): the internal LLM gateway first, m1 on any failure
    - _stream:            m1 directly (the internal LLM gateway doesn't support streaming)
    - Sanitizes the internal LLM gateway responses (strips control characters)
    """

    fallback: BaseChatModel
    model_name: str = "metiq-gpt-4.1"
    metiq_timeout: int = 60
    fallback_enabled: bool = True

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "metiq"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        try:
            client = _get_metiq_client()
            if not client.is_configured():
                raise RuntimeError("the internal LLM gateway not configured")

            prompt, history = _split_langchain_messages(messages)
            if not prompt:
                raise ValueError("No user message in conversation")

            t0 = time.time()
            resp = client.chat(message=prompt, history=history,
                               timeout=self.metiq_timeout)
            dt_ms = (time.time() - t0) * 1000.0

            content = _sanitize_metiq((resp.get("content") or "").strip())
            tokens = resp.get("tokensUsed") or 0
            logger.info("the internal LLM gateway: tokens=%d took=%.0fms", tokens, dt_ms)

            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content=content))],
                llm_output={
                    "token_usage": {
                        "completion_tokens": tokens,
                        "prompt_tokens": 0,
                        "total_tokens": tokens,
                    },
                    "model_name": self.model_name,
                },
            )
        except Exception as exc:
            if not self.fallback_enabled:
                raise
            logger.warning("the internal LLM gateway failed (%s: %s), falling back to m1",
                           type(exc).__name__, exc)
            return self.fallback._generate(
                messages, stop=stop, run_manager=run_manager, **kwargs)

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        """the internal LLM gateway doesn't support streaming — delegate to m1."""
        yield from self.fallback._stream(
            messages, stop=stop, run_manager=run_manager, **kwargs)


def create_metiq_llm(config: ModelConfig = None, metiq_timeout: int = 60,
                     **fallback_overrides) -> the internal LLM gatewayChatModel:
    """Create a the internal LLM gateway chat model with automatic m1 fallback.

    the internal LLM gateway (GPT-4.1) handles non-streaming requests.  Streaming and the internal LLM gateway
    failures fall back to m1 analysis (GLM-4.7-Flash, port 8015).

    Args:
        config: ModelConfig (uses defaults if None)
        metiq_timeout: Timeout for the internal LLM gateway API calls (default 60s)
        **fallback_overrides: kwargs for the m1 fallback ChatOpenAI
            (e.g. temperature, max_tokens, extra_body)
    """
    config = config or ModelConfig()
    fallback_kwargs = dict(
        model=config.llm_model_name,
        base_url=config.m1_analysis_base_url,  # m1 analysis — GLM-4.7-Flash (port 8015)
        api_key="not-needed",
        timeout=300.0,
    )
    fallback_kwargs.update(fallback_overrides)
    return the internal LLM gatewayChatModel(
        fallback=ChatOpenAI(**fallback_kwargs),
        metiq_timeout=metiq_timeout,
    )


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
