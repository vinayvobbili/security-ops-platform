"""Minimal LLM initialization for tipper analyzer.

This module provides a lightweight way to initialize just the LLM
without loading the full state_manager (which imports all tools and
their clients).
"""

import logging
from typing import Optional

from langchain_ollama import ChatOllama, OllamaEmbeddings

logger = logging.getLogger(__name__)

# Singleton LLM instance
_llm: Optional[ChatOllama] = None
_embeddings: Optional[OllamaEmbeddings] = None

# Configuration (matching state_manager settings)
LLM_MODEL = "glm-4.7-flash"
EMBEDDING_MODEL = "nomic-embed-text"
NUM_CTX = 16384
TEMPERATURE = 0.1


def ensure_llm_initialized() -> None:
    """Ensure LLM is initialized (creates singleton if needed)."""
    global _llm, _embeddings

    if _llm is not None:
        return

    logger.info(f"Connecting to LLM: {LLM_MODEL}...")
    _llm = ChatOllama(
        model=LLM_MODEL,
        temperature=TEMPERATURE,
        keep_alive=-1,
        num_ctx=NUM_CTX,
        client_kwargs={'timeout': 300.0},
    )
    logger.info(f"Connected to {LLM_MODEL} (num_ctx={NUM_CTX})")

    logger.info(f"Connecting to embeddings: {EMBEDDING_MODEL}...")
    _embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)
    logger.info(f"Connected to {EMBEDDING_MODEL}")


def get_llm() -> Optional[ChatOllama]:
    """Get the LLM instance."""
    ensure_llm_initialized()
    return _llm


def get_llm_with_temperature(temperature: float) -> ChatOllama:
    """Get LLM with custom temperature."""
    ensure_llm_initialized()
    return ChatOllama(
        model=LLM_MODEL,
        temperature=temperature,
        keep_alive=-1,
        num_ctx=NUM_CTX,
        client_kwargs={'timeout': 300.0},
    )


def get_embeddings() -> Optional[OllamaEmbeddings]:
    """Get the embeddings instance."""
    ensure_llm_initialized()
    return _embeddings
