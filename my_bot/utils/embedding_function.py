"""OpenAI-compatible embedding function for ChromaDB.

Replaces the previous OllamaEmbeddingFunction classes with a single shared
implementation that talks to the OpenAI-compatible /v1/embeddings endpoint
served by vllm-mlx.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import requests

logger = logging.getLogger(__name__)


class OpenAIEmbeddingFunction:
    """ChromaDB-compatible embedding function using OpenAI-compatible API."""

    def __init__(self, model: str = None, base_url: str = None, batch_size: int = 10):
        if model is None or base_url is None:
            from my_config import get_config
            _cfg = get_config()
            model = model or _cfg.embedding_model
            base_url = base_url or _cfg.m3_embeds_base_url
        self.model = model
        # Ensure base_url ends without trailing slash, then append /embeddings
        self.api_url = f"{base_url.rstrip('/')}/embeddings"
        self.batch_size = batch_size

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts using batch API calls."""
        if not input:
            return []

        # For small inputs, use single batch call
        if len(input) <= self.batch_size:
            return self._embed_batch(input)

        # For large inputs, process in parallel batches
        all_embeddings = [None] * len(input)
        batches = []

        for i in range(0, len(input), self.batch_size):
            batch_texts = input[i:i + self.batch_size]
            batches.append((i, batch_texts))

        logger.info(f"Processing {len(input)} texts in {len(batches)} batches...")

        # max_workers=1: vllm-mlx serializes embedding requests anyway; parallel calls
        # just queue up and exceed the per-request timeout.
        max_workers = 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_batch = {
                executor.submit(self._embed_batch, batch_texts): (start_idx, batch_texts)
                for start_idx, batch_texts in batches
            }

            for future in as_completed(future_to_batch):
                start_idx, batch_texts = future_to_batch[future]
                try:
                    batch_embeddings = future.result()
                    for j, embedding in enumerate(batch_embeddings):
                        all_embeddings[start_idx + j] = embedding
                except Exception as e:
                    logger.error(f"Batch embedding failed at index {start_idx}: {e}")
                    # Fallback: try individual embeddings for failed batch
                    for j, text in enumerate(batch_texts):
                        try:
                            all_embeddings[start_idx + j] = self._embed_single(text)
                        except Exception as inner_e:
                            logger.error(f"Single embedding fallback failed: {inner_e}")
                            raise

        return all_embeddings

    def _embed_batch(self, texts: List[str], max_retries: int = 3) -> List[List[float]]:
        """Generate embeddings for a batch of texts in a single API call."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "input": texts},
                    timeout=600,
                )
                response.raise_for_status()
                result = response.json()
                # OpenAI format: data[].embedding sorted by data[].index
                data = sorted(result["data"], key=lambda x: x["index"])
                return [item["embedding"] for item in data]
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Batch embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed batch of {len(texts)} texts: {e}")

    def _embed_single(self, text: str, max_retries: int = 3) -> List[float]:
        """Generate embedding for a single text (fallback method)."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "input": [text]},
                    timeout=60,
                )
                response.raise_for_status()
                result = response.json()
                return result["data"][0]["embedding"]
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed text: {e}")
