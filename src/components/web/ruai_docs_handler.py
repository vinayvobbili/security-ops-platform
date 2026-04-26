"""RUAI Docs handler — upload, delete, and embed reference documents.

Two consumption modes:
  - `load_all_text()` — full text of all docs for direct prompt stuffing
  - `rebuild_vector_store()` — chunk + embed into ChromaDB for RAG retrieval
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DOCS_DIR = _PROJECT_ROOT / "data" / "ruai_screening" / "reference_docs"
CHROMA_PATH = _PROJECT_ROOT / "data" / "transient" / "chroma_ruai_docs"
COLLECTION_NAME = "ruai_docs"

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls"}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB


def _fmt_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def list_docs() -> List[Dict[str, Any]]:
    """Return docs sorted by filename."""
    docs = []
    if not DOCS_DIR.exists():
        return docs
    for fpath in sorted(DOCS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not fpath.is_file():
            continue
        ext = fpath.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue
        stat = fpath.stat()
        docs.append({
            "filename": fpath.name,
            "ext": ext,
            "size": stat.st_size,
            "size_str": _fmt_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return docs


def get_chroma_stats() -> Dict[str, Any]:
    """Return stats from the ruai_docs ChromaDB collection."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        existing = {c.name for c in client.list_collections()}
        if COLLECTION_NAME not in existing:
            return {"status": "empty", "total_chunks": 0}
        col = client.get_collection(COLLECTION_NAME)
        count = col.count()
        return {"status": "indexed" if count > 0 else "empty", "total_chunks": count}
    except Exception as exc:
        logger.error("Error reading RUAI docs chroma stats: %s", exc)
        return {"status": "error", "total_chunks": 0, "error": str(exc)}


def save_uploaded_file(file_storage) -> Dict[str, Any]:
    """Save an uploaded file. Returns file metadata."""
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise ValueError("Invalid filename")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    dest = DOCS_DIR / filename
    file_storage.save(str(dest))
    stat = dest.stat()
    if stat.st_size > MAX_FILE_SIZE:
        dest.unlink()
        raise ValueError(f"File too large ({_fmt_size(stat.st_size)}). Max: {_fmt_size(MAX_FILE_SIZE)}")
    return {"filename": filename, "size": stat.st_size, "size_str": _fmt_size(stat.st_size)}


def delete_doc(filename: str) -> bool:
    """Delete a doc. Returns True if deleted."""
    safe = secure_filename(filename)
    if not safe:
        return False
    fpath = DOCS_DIR / safe
    if not fpath.is_file():
        return False
    fpath.unlink()
    return True


# --- Text extraction (for prompt stuffing) ---

def _extract_text(fpath: Path) -> str:
    """Extract plain text from a single document."""
    ext = fpath.suffix.lower()
    try:
        if ext == ".pdf":
            from langchain_community.document_loaders import PyPDFLoader
            docs = PyPDFLoader(str(fpath)).load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())
        elif ext in (".docx", ".doc"):
            from langchain_community.document_loaders import UnstructuredWordDocumentLoader
            docs = UnstructuredWordDocumentLoader(str(fpath)).load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())
        elif ext in (".xlsx", ".xls"):
            from langchain_community.document_loaders import UnstructuredExcelLoader
            docs = UnstructuredExcelLoader(str(fpath)).load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())
    except Exception as exc:
        logger.warning("Failed to extract text from %s: %s", fpath.name, exc)
    return ""


def load_all_text() -> str:
    """Load full text of all reference docs for direct prompt stuffing.

    Returns a single string with each document delimited by its filename.
    Use this when the corpus is small enough to fit in the context window.
    """
    if not DOCS_DIR.exists():
        return ""
    parts = []
    for fpath in sorted(DOCS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not fpath.is_file() or fpath.suffix.lower() not in ALLOWED_EXTENSIONS:
            continue
        text = _extract_text(fpath)
        if text.strip():
            parts.append(f"=== {fpath.name} ===\n{text.strip()}")
    return "\n\n".join(parts)


# --- Vector store (for RAG retrieval) ---

def rebuild_vector_store() -> Dict[str, Any]:
    """Delete and fully rebuild the ChromaDB collection from all docs."""
    try:
        import chromadb
        from my_bot.document.document_processor import DocumentProcessor

        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        existing = {c.name for c in client.list_collections()}
        if COLLECTION_NAME in existing:
            client.delete_collection(COLLECTION_NAME)

        proc = DocumentProcessor(pdf_directory=str(DOCS_DIR), chroma_path=str(CHROMA_PATH))
        proc._client = client
        proc._collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"description": "RUAI reference documents for AI screening reviews"},
        )
        success = proc.sync_documents()
        after = proc._collection.count()
        logger.info("RUAI docs vector store rebuilt: %d chunks", after)
        return {"success": success, "chunks_after": after}
    except Exception as exc:
        logger.error("RUAI docs vector store rebuild failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
