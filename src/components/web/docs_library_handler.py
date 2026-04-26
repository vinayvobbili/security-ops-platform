"""Docs Library handler — list, upload, delete docs and manage vector store."""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

# Paths (src/components/web/ → up 3 levels → project root)
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_DOCS_DIR = os.path.join(_PROJECT_ROOT, "local_pdfs_docs")
_CHROMA_PATH = os.path.join(_PROJECT_ROOT, "chroma_documents")

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls"}


def _fmt_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def list_docs() -> List[Dict[str, Any]]:
    """Return docs in local_pdfs_docs/ sorted by filename."""
    docs = []
    if not os.path.exists(_DOCS_DIR):
        return docs
    for fname in sorted(os.listdir(_DOCS_DIR), key=str.lower):
        fpath = os.path.join(_DOCS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(fname)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue
        stat = os.stat(fpath)
        docs.append({
            "filename": fname,
            "ext": ext,
            "size": stat.st_size,
            "size_str": _fmt_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return docs


def get_chroma_stats() -> Dict[str, Any]:
    """Return stats from the local_documents ChromaDB collection."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=_CHROMA_PATH)
        existing = {c.name for c in client.list_collections()}
        if "local_documents" not in existing:
            return {"status": "empty", "total_chunks": 0}
        col = client.get_collection("local_documents")
        count = col.count()
        return {"status": "initialized" if count > 0 else "empty", "total_chunks": count}
    except Exception as exc:
        logger.error("Error reading chroma stats: %s", exc)
        return {"status": "error", "total_chunks": 0, "error": str(exc)}


def save_uploaded_file(file_storage) -> Dict[str, Any]:
    """Save a Werkzeug FileStorage to local_pdfs_docs/. Returns file metadata."""
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise ValueError("Invalid filename")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    os.makedirs(_DOCS_DIR, exist_ok=True)
    dest = os.path.join(_DOCS_DIR, filename)
    file_storage.save(dest)
    stat = os.stat(dest)
    return {"filename": filename, "size": stat.st_size, "size_str": _fmt_size(stat.st_size)}


def delete_doc(filename: str) -> bool:
    """Delete a doc from local_pdfs_docs/. Returns True if deleted."""
    safe = secure_filename(filename)
    if not safe:
        return False
    fpath = os.path.join(_DOCS_DIR, safe)
    if not os.path.isfile(fpath):
        return False
    os.remove(fpath)
    return True


def sync_vector_store() -> Dict[str, Any]:
    """Incrementally sync the vector store (skip already-indexed chunks)."""
    try:
        from my_bot.document.document_processor import DocumentProcessor
        proc = DocumentProcessor(pdf_directory=_DOCS_DIR, chroma_path=_CHROMA_PATH)
        before = proc.collection.count()
        success = proc.sync_documents()
        after = proc.collection.count()
        return {"success": success, "chunks_before": before, "chunks_after": after,
                "new_chunks": max(0, after - before)}
    except Exception as exc:
        logger.error("Vector store sync failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}


def rebuild_vector_store() -> Dict[str, Any]:
    """Delete and fully rebuild the ChromaDB collection from all docs."""
    try:
        from my_bot.document.document_processor import DocumentProcessor
        proc = DocumentProcessor(pdf_directory=_DOCS_DIR, chroma_path=_CHROMA_PATH)
        success = proc.rebuild_index()
        after = proc.collection.count()
        return {"success": success, "chunks_after": after}
    except Exception as exc:
        logger.error("Vector store rebuild failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
