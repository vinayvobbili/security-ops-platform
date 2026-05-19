"""LLM factory — the ONE place that knows which provider class to use.

Every other module uses abstract LangChain types (BaseChatModel, Embeddings).
To switch providers (OpenAI-compat, Ollama, Bedrock, etc.) change THIS file only.
"""

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
