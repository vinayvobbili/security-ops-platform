"""Bridge between IR's RAG building blocks and the `attestq` kernel.

attestq (https://pypi.org/project/attestq) is our open-source kernel for answering
questionnaires/controls from an evidence corpus: retrieve -> rerank -> confidence
gate -> draft. It was extracted from this very codebase (Customer Assurance +
TPCRA) so both can share one implementation instead of each hand-rolling the
mechanics and drifting apart.

This module adapts IR's existing pieces onto attestq's injectable interfaces, so
we keep using our own embeddings, reranker, Chroma collections (NO data
migration), and a local LLM — attestq only owns the orchestration:

  - LocalLLMChat         : a local LLM as an attestq ChatFn
  - ChromaCollectionStore: an attestq VectorStore over an EXISTING Chroma
                           collection (optional per-namespace metadata filter),
                           preserving IR's 1 - dist/2 similarity score
  - LangchainReranker    : wraps document_processor.rerank_documents as a Reranker
  - build_engine         : assembles an attestq Engine from the above

Generic on purpose — feature handlers inject their own collection, prompt
builder, parser, gate threshold, and "insufficient evidence" outcome.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional, Sequence

from attestq import Citation, Engine, Hit

logger = logging.getLogger(__name__)


def _l2_distance_to_score(dist: Optional[float]) -> Optional[float]:
    """IR's Chroma L2 distance -> [0,1] similarity (matches the legacy handlers)."""
    if dist is None:
        return None
    return max(0.0, min(1.0, 1.0 - (dist / 2.0)))


class LocalLLMChat:
    """An attestq ChatFn backed by a local LLM.

    Records the source of the last call (`last_source` = "local_llm") so callers
    can label provenance, and raises on an empty completion so the caller's
    degraded-eval path engages instead of persisting a blank answer.
    """

    def __init__(self, timeout: int = 90):
        from my_bot.utils.llm_factory import create_llm

        self.timeout = timeout
        self._llm = create_llm(timeout=timeout)
        self.last_source = "local_llm"

    def is_configured(self) -> bool:
        return self._llm is not None

    def __call__(self, prompt: str) -> str:
        from langchain_core.messages import HumanMessage

        resp = self._llm.invoke([HumanMessage(content=prompt)])
        raw = (getattr(resp, "content", None) or "").strip()
        self.last_source = "local_llm"
        if not raw:
            raise RuntimeError("empty response from model")
        return raw


class ChromaCollectionStore:
    """An attestq VectorStore over an existing chromadb collection.

    Read-optimized: query + count are the hot path (ingestion stays in the feature
    handler, which already populates the collection). `namespace_field` maps
    attestq's namespace onto a metadata filter (e.g. "assessment_id" for
    per-vendor isolation); leave it None for a single shared corpus.
    """

    def __init__(
        self,
        collection,
        namespace_field: Optional[str] = None,
        namespace_cast: Callable[[str], Any] = str,
        distance_to_score: Callable[[Optional[float]], Optional[float]] = _l2_distance_to_score,
    ):
        self._c = collection
        self._field = namespace_field
        self._cast = namespace_cast
        self._dist = distance_to_score

    def _where(self, namespace: str) -> Optional[dict]:
        if not self._field:
            return None
        return {self._field: self._cast(namespace)}

    def add(self, ids, texts, embeddings, metadatas, namespace="default") -> None:
        metas = list(metadatas)
        if self._field:
            metas = [{**dict(m), self._field: self._cast(namespace)} for m in metas]
        self._c.upsert(ids=list(ids), documents=list(texts),
                       metadatas=metas, embeddings=[list(e) for e in embeddings])

    def query(self, embedding: Sequence[float], k: int, namespace: str = "default") -> List[Hit]:
        try:
            res = self._c.query(
                query_embeddings=[list(embedding)],
                n_results=k,
                where=self._where(namespace),
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:  # chroma hiccup -> treat as no evidence, not a crash
            logger.warning(f"[attestq_bridge] chroma query failed: {e}")
            return []

        hits: List[Hit] = []
        ids0 = (res.get("ids") or [[]])[0]
        docs0 = (res.get("documents") or [[]])[0]
        metas0 = (res.get("metadatas") or [[]])[0]
        dists0 = (res.get("distances") or [[]])[0]
        for i in range(len(ids0)):
            dist = dists0[i] if i < len(dists0) else None
            meta = dict(metas0[i] or {}) if i < len(metas0) else {}
            hits.append(Hit(
                id=ids0[i],
                text=docs0[i] if i < len(docs0) else "",
                score=self._dist(dist) or 0.0,
                metadata={"source": meta.get("source", "evidence"), **meta},
            ))
        return hits

    def count(self, namespace: str = "default") -> int:
        try:
            res = self._c.get(where=self._where(namespace), include=[])
            return len(res.get("ids") or [])
        except Exception as e:
            logger.warning(f"[attestq_bridge] chroma count failed: {e}")
            return 0


class LangchainReranker:
    """Wraps document_processor.rerank_documents as an attestq Reranker.

    Reorders by the cross-encoder but keeps each hit's original retrieval score,
    so citation scores stay on the embedder's scale and the retrieval-based
    confidence gate is unaffected. Falls back to input order if the endpoint is
    down (mirrors the legacy handlers).
    """

    def rerank(self, query: str, hits: Sequence[Hit], top_k: int) -> List[Hit]:
        hits = list(hits)
        if not hits:
            return []
        try:
            from langchain_core.documents import Document as LCDocument

            from my_bot.document.document_processor import rerank_documents
            lc = [LCDocument(page_content=h.text,
                             metadata={"_id": h.id, "_score": h.score, "_source": h.source})
                  for h in hits]
            lc = rerank_documents(query, lc, top_k=top_k)
            return [Hit(id=d.metadata.get("_id", ""),
                        text=d.page_content,
                        score=d.metadata.get("_score") or 0.0,
                        metadata={"source": d.metadata.get("_source", "evidence")})
                    for d in lc]
        except Exception as e:
            logger.warning(f"[attestq_bridge] rerank failed, raw order: {e}")
            return hits[:top_k]


def build_engine(
    *,
    chat: Callable[[str], str],
    embed: Callable[[Sequence[str]], List[List[float]]],
    store: ChromaCollectionStore,
    prompt_builder,
    response_parser,
    min_confidence: float,
    insufficient_determination: str,
    insufficient_summary: str,
    reranker: Optional[LangchainReranker] = None,
    k: int = 12,
    rerank_top_k: int = 8,
) -> Engine:
    """Assemble an attestq Engine from IR's injected pieces.

    Gates on the retrieval (cosine) score so `min_confidence` stays calibrated to
    the embedder's similarity scale; the reranker only reorders the context.
    """
    return Engine(
        chat=chat,
        embed=embed,
        store=store,
        reranker=reranker if reranker is not None else LangchainReranker(),
        k=k,
        rerank_top_k=rerank_top_k,
        min_confidence=min_confidence,
        gate_on="retrieval",
        insufficient_determination=insufficient_determination,
        insufficient_summary=insufficient_summary,
        prompt_builder=prompt_builder,
        response_parser=response_parser,
    )


def citations_to_rows(citations: Sequence[Citation]) -> List[dict]:
    """attestq Citations -> the {source_path, chunk_text, score} rows IR persists."""
    return [{"source_path": c.source, "chunk_text": c.snippet, "score": c.score}
            for c in citations]
