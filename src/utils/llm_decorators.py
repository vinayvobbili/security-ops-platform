"""
LLM-Specific Decorators for Optimizing LLM Tool Calls

Provides five backend-agnostic decorators for any LLM inference server
(Ollama, vLLM, MLX-LM, etc.) used with LangChain:

1. @llm_cache        - TTL-based response caching for repeated LLM queries
2. @validate_args    - Input validation for tool arguments before execution
3. @structured_output - Parse & validate JSON output, retry on parse failure
4. @llm_fallback     - Chain fallback strategies when primary LLM call fails
5. @llm_retry        - LLM-aware retry for transient inference server failures

Inspired by: https://www.kdnuggets.com/5-powerful-python-decorators-to-optimize-llm-applications

Usage:
    from src.utils.llm_decorators import llm_cache, validate_args, structured_output, llm_fallback, llm_retry

    @llm_cache(ttl_seconds=300)
    def expensive_llm_call(query: str) -> str:
        return llm.invoke(query).content

    @validate_args(hostname=r'^[A-Za-z0-9._-]+$')
    @tool
    def get_device_info(hostname: str) -> str:
        ...

    @structured_output(schema={"type": "object", "required": ["severity", "summary"]})
    def analyze_alert(text: str) -> dict:
        ...
"""

import hashlib
import json
import logging
import re
import time
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Common validation patterns for security tool arguments
# ---------------------------------------------------------------------------
HOSTNAME_PATTERN = r'^[A-Za-z0-9._-]{1,63}$'
IP_ADDRESS_PATTERN = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
DOMAIN_PATTERN = r'^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$'
EMAIL_PATTERN = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
HASH_PATTERN = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'


# ---------------------------------------------------------------------------
# 1. @llm_cache — TTL-based response caching
# ---------------------------------------------------------------------------

# Module-level cache store: {key: (result, expiry_timestamp)}
_llm_cache_store: dict[str, tuple[Any, float]] = {}


def llm_cache(ttl_seconds: int = 300, maxsize: int = 128):
    """Cache LLM call results with time-to-live expiration.

    Unlike functools.lru_cache, this supports TTL so stale security data
    doesn't persist across shifts. Cache keys are derived from all args.

    Args:
        ttl_seconds: Time-to-live in seconds (default 5 minutes).
        maxsize: Maximum number of cached entries (default 128).

    Example:
        @llm_cache(ttl_seconds=600)
        def summarize_ticket(ticket_id: str) -> str:
            return llm.invoke(f"Summarize ticket {ticket_id}").content
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Build cache key from function name + arguments
            key_data = f"{func.__module__}.{func.__qualname__}:{args}:{sorted(kwargs.items())}"
            cache_key = hashlib.sha256(key_data.encode()).hexdigest()

            now = time.time()

            # Check cache hit
            if cache_key in _llm_cache_store:
                cached_result, expiry = _llm_cache_store[cache_key]
                if now < expiry:
                    logger.debug(f"Cache hit for {func.__name__} (expires in {expiry - now:.0f}s)")
                    return cached_result
                else:
                    del _llm_cache_store[cache_key]

            # Cache miss — execute function
            result = func(*args, **kwargs)

            # Evict oldest entries if at capacity
            if len(_llm_cache_store) >= maxsize:
                oldest_key = min(_llm_cache_store, key=lambda k: _llm_cache_store[k][1])
                del _llm_cache_store[oldest_key]

            _llm_cache_store[cache_key] = (result, now + ttl_seconds)
            logger.debug(f"Cached result for {func.__name__} (TTL: {ttl_seconds}s)")
            return result

        # Expose cache management for testing/monitoring
        wrapper.cache_clear = lambda: _llm_cache_store.clear()
        wrapper.cache_info = lambda: {
            'size': len(_llm_cache_store),
            'maxsize': maxsize,
            'ttl_seconds': ttl_seconds
        }
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 2. @validate_args — Input validation for tool arguments
# ---------------------------------------------------------------------------

def validate_args(**patterns: str):
    """Validate tool arguments against regex patterns before execution.

    Catches bad input early (before wasting an LLM call or API request).
    Returns a descriptive error string instead of raising, since LangChain
    tools should return error messages the LLM can reason about.

    Args:
        **patterns: Keyword args mapping parameter names to regex patterns.

    Example:
        @tool
        @validate_args(
            hostname=r'^[A-Za-z0-9._-]{1,63}$',
            ip_address=r'^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$'
        )
        def lookup_device(hostname: str, ip_address: str) -> str:
            ...
    """
    # Pre-compile patterns
    compiled = {name: re.compile(pattern) for name, pattern in patterns.items()}

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            for param_name, pattern in compiled.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    if value is not None and isinstance(value, str):
                        if not pattern.match(value):
                            msg = (
                                f"Invalid {param_name}: '{value}' does not match "
                                f"expected format (pattern: {patterns[param_name]})"
                            )
                            logger.warning(f"Validation failed in {func.__name__}: {msg}")
                            return f"Error: {msg}"

            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 3. @structured_output — Parse & validate JSON from LLM responses
# ---------------------------------------------------------------------------

def structured_output(
    schema: Optional[dict] = None,
    required_keys: Optional[list[str]] = None,
    max_retries: int = 1,
    retry_prompt: str = "Your previous response was not valid JSON. Please respond with ONLY a JSON object."
):
    """Parse and validate JSON output from an LLM call.

    If the wrapped function returns a string, this decorator attempts to
    parse it as JSON and validate against the provided schema. On parse
    failure, it can optionally retry the function with a corrective prompt.

    Args:
        schema: JSON-like dict describing expected structure. Only checks
                top-level 'required' keys if present (lightweight validation
                without jsonschema dependency).
        required_keys: List of keys that must be present in the parsed output.
                      Shorthand alternative to schema with required field.
        max_retries: Number of parse-failure retries (default 1).
        retry_prompt: Hint appended to guide the LLM on retry.

    Example:
        @structured_output(required_keys=["severity", "summary", "indicators"])
        def analyze_alert(alert_text: str) -> dict:
            response = llm.invoke(f"Analyze this alert as JSON: {alert_text}")
            return response.content  # Returns string, decorator parses to dict
    """
    # Determine required keys from either parameter
    _required = set(required_keys or [])
    if schema and 'required' in schema:
        _required.update(schema['required'])

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_error = None

            for attempt in range(max_retries + 1):
                result = func(*args, **kwargs)

                # If already a dict, just validate
                if isinstance(result, dict):
                    parsed = result
                elif isinstance(result, str):
                    # Try to extract JSON from the response (LLMs often wrap in markdown)
                    parsed = _extract_json(result)
                    if parsed is None:
                        last_error = f"Could not parse JSON from response: {result[:200]}"
                        logger.warning(
                            f"{func.__name__} attempt {attempt + 1}: {last_error}"
                        )
                        if attempt < max_retries:
                            # Append retry hint to kwargs if the function accepts it
                            kwargs['_retry_hint'] = retry_prompt
                            continue
                        break
                else:
                    # Not a string or dict — return as-is
                    return result

                # Validate required keys
                missing = _required - set(parsed.keys())
                if missing:
                    last_error = f"Missing required keys: {missing}"
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}: {last_error}"
                    )
                    if attempt < max_retries:
                        kwargs['_retry_hint'] = (
                            f"{retry_prompt} Must include keys: {list(_required)}"
                        )
                        continue
                    break

                return parsed

            # All attempts failed — return error dict
            logger.error(f"{func.__name__} structured output validation failed: {last_error}")
            return {"error": last_error, "raw_response": str(result)[:500]}

        return wrapper
    return decorator


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON object from LLM response text.

    Handles common patterns:
    - Pure JSON string
    - JSON wrapped in ```json ... ``` markdown blocks
    - JSON embedded in surrounding text
    """
    # Try direct parse first
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass

    # Try extracting from markdown code blocks
    code_block_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if code_block_match:
        try:
            return json.loads(code_block_match.group(1).strip())
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding first { ... } block
    brace_match = re.search(r'\{.*\}', text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group())
        except (json.JSONDecodeError, ValueError):
            pass

    return None


# ---------------------------------------------------------------------------
# 4. @llm_fallback — Chain fallback strategies
# ---------------------------------------------------------------------------

def llm_fallback(*fallback_funcs: Callable, catch: tuple = (Exception,)):
    """Chain fallback functions when the primary LLM call fails.

    Tries the decorated function first. On failure, tries each fallback
    in order. Useful for degrading gracefully from a full LLM call to
    a template-based response or cached result.

    Args:
        *fallback_funcs: Functions to try in order if primary fails.
                         Each receives the same args/kwargs as the primary.
        catch: Exception types to catch (default: all Exceptions).

    Example:
        def template_fallback(query: str) -> str:
            return "Unable to process with LLM. Please try again later."

        def cached_fallback(query: str) -> str:
            return get_cached_response(query) or "No cached response available."

        @llm_fallback(cached_fallback, template_fallback)
        def smart_query(query: str) -> str:
            return llm.invoke(query).content
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Try primary function
            try:
                result = func(*args, **kwargs)
                if result is not None:
                    return result
            except catch as e:
                logger.warning(f"{func.__name__} failed: {type(e).__name__}: {e}")

            # Try each fallback in order
            for i, fallback in enumerate(fallback_funcs):
                try:
                    fb_name = getattr(fallback, '__name__', f'fallback_{i}')
                    logger.info(f"Trying fallback: {fb_name}")
                    result = fallback(*args, **kwargs)
                    if result is not None:
                        logger.info(f"Fallback {fb_name} succeeded")
                        return result
                except Exception as e:
                    fb_name = getattr(fallback, '__name__', f'fallback_{i}')
                    logger.warning(f"Fallback {fb_name} failed: {type(e).__name__}: {e}")

            # All fallbacks exhausted
            logger.error(f"{func.__name__}: all fallbacks exhausted")
            return None

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 5. @llm_retry — LLM-aware retry for transient inference server failures
# ---------------------------------------------------------------------------

# Backend-agnostic transient error patterns common across LLM inference
# servers (Ollama, vLLM, MLX-LM, TGI, etc.)
_LLM_RETRYABLE_PATTERNS = [
    'connection refused',       # Server not ready / restarting
    'connection reset',         # Network interruption
    'model is being loaded',    # Model loading into VRAM/memory
    'model not found',          # Model still downloading
    'timeout',                  # Slow inference
    'timed out',
    'broken pipe',              # Connection dropped mid-stream
    'eof',                      # Unexpected end of response
    'internal server error',    # Server crash/restart
    '503',                      # Service unavailable
    '502',                      # Bad gateway (reverse proxy)
    'overloaded',               # vLLM/TGI queue full
    'too many requests',        # Rate limited
    '429',                      # Rate limit HTTP code
]


def llm_retry(
    max_attempts: int = 3,
    initial_delay: float = 2.0,
    backoff: float = 2.0,
    max_delay: float = 30.0,
    on_retry: Optional[Callable[[int, Exception], None]] = None,
):
    """Retry decorator for transient LLM inference server failures.

    Backend-agnostic — works with any inference server (Ollama, vLLM,
    MLX-LM, TGI, etc.). Unlike the generic with_retry in retry_utils.py,
    this decorator:
    - Classifies LLM-specific transient errors (model loading, overloaded, etc.)
    - Uses longer default delays (inference servers are slow to recover)

    Args:
        max_attempts: Maximum total attempts (default 3).
        initial_delay: Seconds before first retry (default 2.0).
        backoff: Multiplier for exponential backoff (default 2.0).
        max_delay: Maximum delay between retries (default 30s).
        on_retry: Optional callback(attempt, exception) called before each retry.

    Example:
        @llm_retry(max_attempts=3, initial_delay=2.0)
        def query_llm(prompt: str) -> str:
            return llm.invoke(prompt).content
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    error_str = str(e).lower()

                    # Check if this is a retryable LLM error
                    is_retryable = any(
                        pattern in error_str for pattern in _LLM_RETRYABLE_PATTERNS
                    )

                    if not is_retryable:
                        logger.error(
                            f"{func.__name__} failed with non-retryable error: "
                            f"{type(e).__name__}: {e}"
                        )
                        raise

                    if attempt >= max_attempts - 1:
                        break

                    delay = min(initial_delay * (backoff ** attempt), max_delay)
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_attempts} failed: "
                        f"{type(e).__name__}: {e}. Retrying in {delay:.1f}s..."
                    )

                    if on_retry:
                        try:
                            on_retry(attempt + 1, e)
                        except Exception:
                            pass

                    time.sleep(delay)

            logger.error(
                f"{func.__name__} failed after {max_attempts} attempts: "
                f"{type(last_exception).__name__}: {last_exception}"
            )
            raise last_exception

        return wrapper
    return decorator
