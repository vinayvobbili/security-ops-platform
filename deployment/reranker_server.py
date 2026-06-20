"""Shared cross-encoder reranker HTTP service.

Loads a cross-encoder model once at startup and exposes /rerank (POST) and
/health (GET). Scores are sigmoid-normalized to [0,1] so clients can treat
them as relevance probabilities.

This is the app-agnostic reranker used by every IR RAG path that opts in via
`my_bot.document.document_processor.rerank_documents`. First consumer is the
Customer Assurance drafting flow; other RAG apps (Sleuth ticket search,
Mentor code search, docs_library, detection rules catalog) can opt in with
a one-line call at their retrieval site.

Runs on studio1 (was mac-m3 until 2026-05-07) hosting the BGE-reranker-v2-m3
fine-tune on MPS. Exposed to lab-vm1 over SSH reverse tunnel on the same port.

Env vars:
  RERANKER_MODEL            HF model id. Default: cross-encoder/ms-marco-MiniLM-L-6-v2
  RERANKER_HOST             Bind host. Default: 127.0.0.1
  RERANKER_PORT             Bind port. Default: 8020
  RERANKER_MAX_CANDIDATES   Hard upper bound on per-request batch. Default: 100
"""

import logging
import math
import os
import time
from typing import Any, Dict, List

from flask import Flask, jsonify, request
from sentence_transformers import CrossEncoder
from waitress import serve

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ir-reranker")

MODEL_NAME = os.environ.get("RERANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
HOST = os.environ.get("RERANKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("RERANKER_PORT", "8020"))
MAX_CANDIDATES = int(os.environ.get("RERANKER_MAX_CANDIDATES", "100"))
DEVICE = os.environ.get("RERANKER_DEVICE")  # "mps" on studio1, None = auto (CPU) on lab-vm1

app = Flask(__name__)
_model: CrossEncoder = None
_load_time_s: float = 0.0


def _get_model() -> CrossEncoder:
    global _model, _load_time_s
    if _model is None:
        logger.info(f"loading reranker model: {MODEL_NAME} device={DEVICE or 'auto'}")
        t0 = time.time()
        kwargs = {}
        if DEVICE:
            kwargs["device"] = DEVICE
        _model = CrossEncoder(MODEL_NAME, **kwargs)
        _load_time_s = time.time() - t0
        logger.info(f"reranker loaded in {_load_time_s:.1f}s")
    return _model


def _sigmoid(x: float) -> float:
    # Clamp to avoid overflow on extreme logits.
    if x >= 0:
        ex = math.exp(-x)
        return 1.0 / (1.0 + ex)
    ex = math.exp(x)
    return ex / (1.0 + ex)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model": MODEL_NAME,
        "loaded": _model is not None,
        "load_time_s": round(_load_time_s, 2),
    })


@app.route("/v1/models", methods=["GET"])
def models():
    # OpenAI-compatible stub so Mission Control / generic health probes can
    # hit this endpoint the same way they hit mlx-lm.
    return jsonify({
        "object": "list",
        "data": [
            {"id": MODEL_NAME, "object": "model", "created": int(time.time()), "owned_by": "ir-reranker"},
        ],
    })


@app.route("/rerank", methods=["POST"])
def rerank():
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    query = (payload.get("query") or "").strip()
    documents: List[str] = payload.get("documents") or []
    try:
        top_k = int(payload.get("top_k") or len(documents))
    except (TypeError, ValueError):
        top_k = len(documents)

    if not query or not documents:
        return jsonify({"results": []})

    if len(documents) > MAX_CANDIDATES:
        logger.warning(f"request over MAX_CANDIDATES={MAX_CANDIDATES}, truncating from {len(documents)}")
        documents = documents[:MAX_CANDIDATES]

    model = _get_model()
    pairs = [[query, d or ""] for d in documents]

    t0 = time.time()
    try:
        raw_scores = model.predict(pairs, show_progress_bar=False)
    except Exception as e:
        logger.exception("rerank inference failed")
        return jsonify({"error": str(e)}), 500
    dt_ms = (time.time() - t0) * 1000.0

    scored = [
        {"index": i, "score": _sigmoid(float(s)), "text": documents[i]}
        for i, s in enumerate(raw_scores)
    ]
    scored.sort(key=lambda x: x["score"], reverse=True)
    top = scored[:max(0, top_k)]

    logger.info(f"rerank n={len(documents)} top_k={top_k} took={dt_ms:.1f}ms top_score={top[0]['score']:.3f}" if top else f"rerank n={len(documents)} empty top")
    return jsonify({"results": top, "latency_ms": round(dt_ms, 1), "model": MODEL_NAME})


if __name__ == "__main__":
    _get_model()  # eager-load so /health reflects true readiness
    logger.info(f"listening on http://{HOST}:{PORT}")
    serve(app, host=HOST, port=PORT, threads=2)
