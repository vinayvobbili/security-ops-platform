#!/usr/bin/env python3
"""
Embedding API Server

Lightweight HTTP server that serves sentence-transformer embeddings.
Runs on the inference Mac and is accessed by lab-vm via SSH reverse tunnel.

Usage:
    python3 misc_scripts/embedding_server.py              # default port 11435
    python3 misc_scripts/embedding_server.py --port 11435

Endpoints:
    POST /embed     {"texts": ["text1", "text2"]} -> {"embeddings": [[...], [...]]}
    GET  /health    -> {"status": "ok", "model": "...", "dimensions": 1024}
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MODEL_NAME = os.environ.get("EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5")


def create_app():
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    # Lazy-load model on first request
    _state = {"model": None, "dimension": None}

    def get_model():
        if _state["model"] is None:
            try:
                import truststore
                truststore.inject_into_ssl()
            except ImportError:
                pass
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading model: {MODEL_NAME}")
            _state["model"] = SentenceTransformer(MODEL_NAME)
            _state["dimension"] = _state["model"].get_sentence_embedding_dimension()
            logger.info(f"Model loaded: {MODEL_NAME} ({_state['dimension']} dims)")
        return _state["model"], _state["dimension"]

    @app.route("/health", methods=["GET"])
    def health():
        model, dim = get_model()
        return jsonify({"status": "ok", "model": MODEL_NAME, "dimensions": dim})

    @app.route("/embed", methods=["POST"])
    def embed():
        data = request.get_json()
        texts = data.get("texts", [])
        if not texts:
            return jsonify({"error": "No texts provided"}), 400

        model, _ = get_model()
        embeddings = model.encode(texts, normalize_embeddings=True)
        return jsonify({"embeddings": embeddings.tolist()})

    return app


def main():
    parser = argparse.ArgumentParser(description="Embedding API Server")
    parser.add_argument("--port", type=int, default=11436)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    app = create_app()

    # Pre-load model at startup
    with app.app_context():
        from flask import g
        logger.info("Pre-loading embedding model...")
        app.test_client().get("/health")

    logger.info(f"Embedding server listening on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
