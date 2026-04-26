"""Minimal LLM initialization for tipper analyzer.

This module provides a lightweight way to initialize just the LLM
without loading the full state_manager (which imports all tools and
their clients).
"""

import logging
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.embeddings import Embeddings

from my_bot.utils.llm_factory import create_llm, create_router_llm, create_embeddings
from my_bot.utils.enhanced_config import ModelConfig

logger = logging.getLogger(__name__)

# Singleton instances
_llm: Optional[BaseChatModel] = None
_router_llm: Optional[BaseChatModel] = None
_embeddings: Optional[Embeddings] = None
_model_config: Optional[ModelConfig] = None


def _get_config() -> ModelConfig:
    global _model_config
    if _model_config is None:
        _model_config = ModelConfig()
    return _model_config


def ensure_llm_initialized() -> None:
    """Ensure LLM is initialized (creates singleton if needed)."""
    global _llm, _embeddings

    if _llm is not None:
        return

    cfg = _get_config()
    logger.info(f"Connecting to LLM: {cfg.llm_model_name}...")
    _llm = create_llm(cfg)
    logger.info(f"Connected to {cfg.llm_model_name}")

    logger.info(f"Connecting to embeddings: {cfg.embedding_model_name}...")
    _embeddings = create_embeddings(cfg)
    logger.info(f"Connected to {cfg.embedding_model_name}")


def get_llm() -> Optional[BaseChatModel]:
    """Get the LLM instance."""
    ensure_llm_initialized()
    return _llm


def get_llm_with_temperature(temperature: float) -> BaseChatModel:
    """Get LLM with custom temperature."""
    ensure_llm_initialized()
    return create_llm(_get_config(), temperature=temperature)


def get_embeddings() -> Optional[Embeddings]:
    """Get the embeddings instance."""
    ensure_llm_initialized()
    return _embeddings


def get_router_llm() -> Optional[BaseChatModel]:
    """Get the lightweight router LLM (Qwen3-8B). Used for cheap auxiliary
    passes like the XSOAR triage critic where the main analysis LLM would be
    overkill."""
    global _router_llm
    if _router_llm is None:
        try:
            _router_llm = create_router_llm(_get_config())
        except Exception as e:
            logger.warning(f"Router LLM init failed: {e}")
            return None
    return _router_llm
