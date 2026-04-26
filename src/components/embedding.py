"""
Shared Embedding Backend

Provides pluggable embedding functions used by all indexers (tipper, XSOAR, etc.).
Configured via environment variables:
  EMBEDDING_BACKEND: "remote" (default) or "sentence-transformers" or "vllm-mlx"
  EMBEDDING_API_URL: Base URL of the remote embedding server (default: http://localhost:8019/v1 — m3 embeddings)
  EMBEDDING_MODEL: model name passed in the request (optional; mlx-lm uses loaded model)

Architecture:
  - Lab-VM (app server): uses "remote" backend → calls Mac's mlx-lm via SSH reverse tunnel
  - Mac (inference engine): uses "vllm-mlx" backend → calls mlx-lm /v1/embeddings locally
  - SSH reverse tunnel forwards Mac's embedding port to lab-vm:8019
"""

import logging
import os
import time
from typing import List

import requests

logger = logging.getLogger(__name__)

EMBEDDING_API_URL_DEFAULT = "http://localhost:8019/v1"  # m3 embeddings — Qwen3-Embedding (mac-m3)


class RemoteEmbeddingFunction:
    """Calls the vllm-mlx embedding API over HTTP (typically via SSH reverse tunnel).

    Used by the app server (lab-vm) to offload embedding computation
    to the inference engine (Mac). Speaks the OpenAI-compatible /v1/embeddings format.
    """

    def __init__(self, api_url: str = None):
        self.api_url = (api_url or EMBEDDING_API_URL_DEFAULT).rstrip("/")
        self.model = os.environ.get("EMBEDDING_MODEL", "")
        logger.info(f"Using remote embedding server: {self.api_url}")

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts via remote API."""
        payload = {"input": input}
        if self.model:
            payload["model"] = self.model

        for attempt in range(3):
            try:
                response = requests.post(
                    f"{self.api_url}/embeddings",
                    json=payload,
                    timeout=600
                )
                response.raise_for_status()
                data = response.json()["data"]
                return [item["embedding"] for item in data]
            except Exception as e:
                if attempt < 2:
                    logger.warning(f"Remote embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Remote embedding server unavailable: {e}")


class VllmMlxEmbeddingFunction:
    """Embedding function using vllm-mlx OpenAI-compatible /v1/embeddings endpoint."""

    def __init__(self):
        from my_bot.utils.embedding_function import OpenAIEmbeddingFunction
        self._fn = OpenAIEmbeddingFunction()

    def __call__(self, input: List[str]) -> List[List[float]]:
        return self._fn(input)


# Legacy alias
OllamaEmbeddingFunction = VllmMlxEmbeddingFunction


class SentenceTransformerEmbeddingFunction:
    """Embedding function using sentence-transformers (local, no API needed).

    Uses BAAI/bge-large-en-v1.5 by default — a strong information-retrieval
    model with 1024 dimensions. Only used on the inference Mac.
    """

    def __init__(self, model_name: str = "BAAI/bge-large-en-v1.5"):
        try:
            import truststore
            truststore.inject_into_ssl()
        except ImportError:
            pass
        from sentence_transformers import SentenceTransformer
        logger.info(f"Loading sentence-transformer model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self._dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Model loaded: {model_name} ({self._dimension} dims)")

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""
        embeddings = self.model.encode(input, normalize_embeddings=True)
        return embeddings.tolist()


def get_embedding_function():
    """Factory function to create the configured embedding backend.

    Reads EMBEDDING_BACKEND env var:
      "remote"                - calls embedding API server (default, for lab-vm)
      "sentence-transformers" - runs model locally via sentence-transformers
      "vllm-mlx"              - calls vllm-mlx /v1/embeddings (for Mac)
    """
    import os
    backend = os.environ.get("EMBEDDING_BACKEND", "remote").lower()

    if backend == "sentence-transformers":
        model = os.environ.get("EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5")
        logger.info(f"Using sentence-transformers backend: {model}")
        return SentenceTransformerEmbeddingFunction(model_name=model)
    elif backend == "vllm-mlx":
        logger.info("Using vllm-mlx embedding backend")
        return VllmMlxEmbeddingFunction()
    else:
        api_url = os.environ.get("EMBEDDING_API_URL", EMBEDDING_API_URL_DEFAULT)
        logger.info(f"Using remote embedding backend: {api_url}")
        return RemoteEmbeddingFunction(api_url=api_url)
