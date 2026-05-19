"""
Shared Embedding Backend

Provides pluggable embedding functions used by all indexers (tipper, XSOAR, etc.).
Configured via environment variables:
  EMBEDDING_BACKEND: "remote" (default), "sentence-transformers", or "vllm-mlx"
  EMBEDDING_MODEL: model name passed in the request (optional)

Architecture:
  - Lab-VM (app server): "remote" / "vllm-mlx" both call studio1 /v1/embeddings
    via config.embeds_base_url + config.embeds_api_key (bearer auth).
  - Mac (inference engine): runs the embedding model locally.
"""

import logging
import os
from typing import List

logger = logging.getLogger(__name__)


class VllmMlxEmbeddingFunction:
    """Embedding function using vllm-mlx OpenAI-compatible /v1/embeddings endpoint.

    Reads config.embeds_base_url + config.embeds_api_key from my_config.
    """

    def __init__(self):
        from my_bot.utils.embedding_function import OpenAIEmbeddingFunction
        self._fn = OpenAIEmbeddingFunction()

    def __call__(self, input: List[str]) -> List[List[float]]:
        return self._fn(input)


OllamaEmbeddingFunction = VllmMlxEmbeddingFunction
RemoteEmbeddingFunction = VllmMlxEmbeddingFunction


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
    backend = os.environ.get("EMBEDDING_BACKEND", "remote").lower()

    if backend == "sentence-transformers":
        model = os.environ.get("EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5")
        logger.info(f"Using sentence-transformers backend: {model}")
        return SentenceTransformerEmbeddingFunction(model_name=model)

    logger.info(f"Using vllm-mlx embedding backend (config.embeds_base_url)")
    return VllmMlxEmbeddingFunction()
