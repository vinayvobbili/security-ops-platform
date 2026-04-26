"""
Wiki Compiler — Karpathy-style LLM Knowledge Base

Reads raw source documents from local_pdfs_docs/ and compiles them into
structured, cross-linked markdown wiki articles stored in wiki_articles/.

The LLM reads each document and produces a clean encyclopedia-style article
with backlinks to related articles. A periodic "lint" pass finds gaps and
adds cross-links between existing articles.

Usage:
    # Full compile (all docs)
    python my_bot/document/wiki_compiler.py compile

    # Incremental compile (new/changed docs only)
    python my_bot/document/wiki_compiler.py update

    # Lint pass (cross-link and gap-check existing articles)
    python my_bot/document/wiki_compiler.py lint
"""

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from openai import OpenAI

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent.parent
DOCS_DIR = _PROJECT_ROOT / "local_pdfs_docs"
WIKI_DIR = _PROJECT_ROOT / "wiki_articles"
WIKI_META = WIKI_DIR / ".wiki_meta.json"

# Extensions the compiler can ingest
INGESTABLE_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".md", ".txt"}

# LLM client (lazy-loaded)
_client: Optional[OpenAI] = None
_model_id: Optional[str] = None


def _get_client() -> OpenAI:
    """Lazy-load OpenAI-compatible client pointing at the local LLM."""
    global _client
    if _client:
        return _client
    base_url = (
        os.environ.get("WIKI_LLM_BASE_URL")
        or os.environ.get("POKEDEX_LLM_BASE_URL")
        or os.environ.get("LLM_BASE_URL", "http://localhost:8015/v1")  # m1 analysis (GLM-4.7-Flash)
    )
    logger.info(f"Wiki compiler LLM base URL: {base_url}")
    _client = OpenAI(base_url=base_url, api_key="not-needed")
    return _client


def _get_model_id() -> str:
    """Auto-discover model ID from the /models endpoint (cached)."""
    global _model_id
    if _model_id:
        return _model_id
    try:
        models = _get_client().models.list()
        if models.data:
            _model_id = models.data[0].id
            logger.info(f"Wiki compiler using model: {_model_id}")
            return _model_id
    except Exception as e:
        logger.warning(f"Could not discover model ID: {e}")
    return "default"


def _clean_llm_response(raw: str) -> str:
    """Strip thinking tags and preamble — real output starts at first heading."""
    if "</think>" in raw:
        raw = raw.split("</think>")[-1].strip()
    elif "<think>" in raw:
        raw = raw.split("<think>")[0].strip()
    m = re.search(r"^#", raw, re.MULTILINE)
    if m:
        raw = raw[m.start():]
    return raw.strip()


def _llm_call(system: str, user: str, assistant_prefix: str = "", max_tokens: int = 4096) -> str:
    """Make a single LLM call with optional assistant prefix-filling."""
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    if assistant_prefix:
        messages.append({"role": "assistant", "content": assistant_prefix})

    resp = _get_client().chat.completions.create(
        model=_get_model_id(),
        messages=messages,
        temperature=0.1,
        max_tokens=max_tokens,
        timeout=180,
    )
    content = resp.choices[0].message.content or ""
    if assistant_prefix:
        content = assistant_prefix + content
    return _clean_llm_response(content)


# ---------------------------------------------------------------------------
# Document extraction — reuses LangChain loaders from DocumentProcessor
# ---------------------------------------------------------------------------

def _extract_text(filepath: Path) -> Optional[str]:
    """Extract plain text from a document file."""
    ext = filepath.suffix.lower()
    try:
        if ext in (".md", ".txt"):
            return filepath.read_text(encoding="utf-8", errors="replace")

        if ext == ".pdf":
            from langchain_community.document_loaders import PyPDFLoader
            loader = PyPDFLoader(str(filepath))
            docs = loader.load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())

        if ext in (".doc", ".docx"):
            from langchain_community.document_loaders import UnstructuredWordDocumentLoader
            loader = UnstructuredWordDocumentLoader(str(filepath))
            docs = loader.load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())

        if ext in (".xlsx", ".xls"):
            from langchain_community.document_loaders import UnstructuredExcelLoader
            loader = UnstructuredExcelLoader(str(filepath))
            docs = loader.load()
            return "\n\n".join(d.page_content for d in docs if d.page_content.strip())

    except Exception as e:
        logger.error(f"Failed to extract text from {filepath.name}: {e}")
    return None


def _file_hash(filepath: Path) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(filename: str) -> str:
    """Convert a filename to a wiki-safe slug for the article filename."""
    name = Path(filename).stem
    slug = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug or "untitled"


# ---------------------------------------------------------------------------
# Metadata tracking — which docs have been compiled and when
# ---------------------------------------------------------------------------

def _load_meta() -> Dict:
    """Load the wiki metadata file."""
    if WIKI_META.exists():
        try:
            return json.loads(WIKI_META.read_text())
        except Exception:
            pass
    return {"compiled": {}, "last_lint": None}


def _save_meta(meta: Dict) -> None:
    """Save the wiki metadata file."""
    WIKI_META.parent.mkdir(parents=True, exist_ok=True)
    WIKI_META.write_text(json.dumps(meta, indent=2))


# ---------------------------------------------------------------------------
# Compilation prompts
# ---------------------------------------------------------------------------

COMPILE_SYSTEM = """\
You are a knowledge base compiler. Your job is to read a raw source document \
and produce a clean, structured wiki article in markdown.

RULES:
- Write in an encyclopedia style — neutral, factual, comprehensive
- Use markdown headers (##, ###) to organize sections logically
- Extract ALL key facts, procedures, decisions, and data points
- If the document mentions other topics or concepts, add a "Related Topics" \
section at the bottom with bracketed links like [[topic-name]]
- Use tables for structured data when appropriate
- Keep technical accuracy — do not hallucinate facts not in the source
- If the source is unclear or incomplete, note it with "(source unclear)"
- Do NOT include a disclaimer or preamble — start directly with the article title"""

COMPILE_USER = """\
Compile the following document into a structured wiki article.

SOURCE FILENAME: {filename}

DOCUMENT CONTENT:
{content}"""

LINT_SYSTEM = """\
You are a wiki maintenance bot. You receive a list of existing wiki article \
titles and their first few lines. Your job is to suggest cross-links and \
identify gaps.

Respond with ONLY valid JSON:
{{
  "cross_links": [
    {{"from": "article-slug", "to": "article-slug", "reason": "brief reason"}}
  ],
  "gaps": [
    {{"topic": "missing topic name", "reason": "why this should exist"}}
  ]
}}"""

LINT_USER = """\
Here are the current wiki articles:

{summaries}

Analyze the articles above and suggest:
1. Cross-links between articles that should reference each other
2. Gaps — topics that are mentioned but don't have their own article yet"""


# ---------------------------------------------------------------------------
# Core compilation logic
# ---------------------------------------------------------------------------

def compile_document(filepath: Path, existing_titles: List[str] = None) -> Optional[str]:
    """Compile a single document into a wiki article. Returns the article markdown."""
    text = _extract_text(filepath)
    if not text or len(text.strip()) < 50:
        logger.warning(f"Skipping {filepath.name} — too short or empty")
        return None

    # Truncate very long documents to fit context window
    max_chars = 60000
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[Document truncated for processing]"

    prompt = COMPILE_USER.format(filename=filepath.name, content=text)

    if existing_titles:
        prompt += f"\n\nEXISTING WIKI ARTICLES (link to these with [[slug]] where relevant):\n"
        prompt += "\n".join(f"- [[{t}]]" for t in existing_titles)

    logger.info(f"Compiling {filepath.name} ({len(text)} chars)...")
    start = time.time()
    article = _llm_call(COMPILE_SYSTEM, prompt, assistant_prefix="# ")
    elapsed = time.time() - start
    logger.info(f"Compiled {filepath.name} in {elapsed:.1f}s")
    return article


def compile_all(force: bool = False) -> Dict[str, any]:
    """Compile all documents in DOCS_DIR into wiki articles.

    Args:
        force: If True, recompile even if the source hasn't changed.

    Returns:
        Stats dict with counts of compiled, skipped, and failed articles.
    """
    WIKI_DIR.mkdir(parents=True, exist_ok=True)
    meta = _load_meta()
    stats = {"compiled": 0, "skipped": 0, "failed": 0, "total": 0}

    if not DOCS_DIR.exists():
        logger.warning(f"Docs directory not found: {DOCS_DIR}")
        return stats

    # Gather source files
    sources = []
    for f in sorted(DOCS_DIR.iterdir()):
        if f.is_file() and f.suffix.lower() in INGESTABLE_EXTENSIONS:
            sources.append(f)
    stats["total"] = len(sources)

    if not sources:
        logger.info("No source documents found")
        return stats

    # Gather existing article titles for cross-linking
    existing_titles = [p.stem for p in WIKI_DIR.glob("*.md")]

    for filepath in sources:
        slug = _slug(filepath.name)
        current_hash = _file_hash(filepath)
        prev_hash = meta["compiled"].get(filepath.name, {}).get("hash")

        if not force and prev_hash == current_hash:
            logger.debug(f"Skipping {filepath.name} — unchanged")
            stats["skipped"] += 1
            continue

        try:
            article = compile_document(filepath, existing_titles)
            if not article:
                stats["failed"] += 1
                continue

            out_path = WIKI_DIR / f"{slug}.md"
            out_path.write_text(article, encoding="utf-8")

            meta["compiled"][filepath.name] = {
                "hash": current_hash,
                "slug": slug,
                "compiled_at": datetime.now().isoformat(),
            }
            existing_titles.append(slug)
            stats["compiled"] += 1
            logger.info(f"Wrote {out_path.name}")

        except Exception as e:
            logger.error(f"Failed to compile {filepath.name}: {e}")
            stats["failed"] += 1

    _save_meta(meta)
    logger.info(f"Wiki compile done: {stats}")
    return stats


def compile_incremental() -> Dict[str, any]:
    """Compile only new or changed documents."""
    return compile_all(force=False)


def compile_full_rebuild() -> Dict[str, any]:
    """Force-recompile all documents."""
    return compile_all(force=True)


# ---------------------------------------------------------------------------
# Lint pass — cross-link and gap analysis
# ---------------------------------------------------------------------------

def lint_wiki() -> Optional[Dict]:
    """Run a lint pass over existing wiki articles.

    Returns parsed JSON with cross_links and gaps suggestions,
    or None on failure.
    """
    articles = sorted(WIKI_DIR.glob("*.md"))
    if not articles:
        logger.info("No wiki articles to lint")
        return None

    # Build summaries (title + first 3 lines of each article)
    summaries = []
    for article_path in articles:
        try:
            lines = article_path.read_text(encoding="utf-8").splitlines()
            preview = "\n".join(lines[:5])
            summaries.append(f"### {article_path.stem}\n{preview}")
        except Exception:
            continue

    if not summaries:
        return None

    prompt = LINT_USER.format(summaries="\n\n".join(summaries))
    logger.info(f"Running wiki lint on {len(summaries)} articles...")

    raw = _llm_call(LINT_SYSTEM, prompt, max_tokens=2048)

    # Parse JSON from response
    try:
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        logger.warning("Lint pass returned invalid JSON")
    return None


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------

def _parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Parse YAML frontmatter from markdown content.

    Returns (metadata_dict, content_without_frontmatter).
    """
    if not content.startswith("---\n"):
        return {}, content
    end = content.find("\n---\n", 4)
    if end == -1:
        return {}, content
    fm_str = content[4:end]
    body = content[end + 5:]
    try:
        meta = yaml.safe_load(fm_str) or {}
    except yaml.YAMLError:
        meta = {}
    return meta, body


def _build_alias_index() -> Dict[str, str]:
    """Map every alias → canonical slug for wikilink resolution."""
    index: Dict[str, str] = {}
    WIKI_DIR.mkdir(parents=True, exist_ok=True)
    for path in WIKI_DIR.glob("*.md"):
        if path.name.startswith(".") or path.name.startswith("_"):
            continue
        slug = path.stem
        index[slug] = slug
        try:
            content = path.read_text(encoding="utf-8")
            meta, _ = _parse_frontmatter(content)
            for alias in meta.get("aliases", []):
                index.setdefault(str(alias), slug)
        except Exception:
            pass
    return index


# ---------------------------------------------------------------------------
# Article listing and reading (used by web routes and the Windows triage agent)
# ---------------------------------------------------------------------------

def list_articles() -> List[Dict[str, Any]]:
    """List all wiki articles with frontmatter metadata."""
    WIKI_DIR.mkdir(parents=True, exist_ok=True)
    articles = []
    for path in sorted(WIKI_DIR.glob("*.md")):
        if path.name.startswith(".") or path.name.startswith("_"):
            continue
        stat = path.stat()
        try:
            content = path.read_text(encoding="utf-8")
            meta, _ = _parse_frontmatter(content)
        except Exception:
            meta = {}

        title = meta.get("title") or path.stem.replace("-", " ").title()
        articles.append({
            "slug": path.stem,
            "filename": path.name,
            "title": title,
            "tags": meta.get("tags", []),
            "date": meta.get("date"),
            "aliases": meta.get("aliases", []),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return articles


def read_article(slug: str) -> Optional[str]:
    """Read a wiki article by slug. Returns markdown body (frontmatter stripped)."""
    path = WIKI_DIR / f"{slug}.md"
    if path.exists() and path.is_file():
        content = path.read_text(encoding="utf-8")
        _, body = _parse_frontmatter(content)
        return body
    return None


def get_article_meta(slug: str) -> Optional[Dict[str, Any]]:
    """Read frontmatter metadata for a wiki article."""
    path = WIKI_DIR / f"{slug}.md"
    if not (path.exists() and path.is_file()):
        return None
    try:
        content = path.read_text(encoding="utf-8")
        meta, _ = _parse_frontmatter(content)
        return meta
    except Exception:
        return {}


def get_backlinks(slug: str) -> List[Dict[str, str]]:
    """Find all articles that contain a wikilink to this slug or its aliases."""
    # Build the set of names that resolve to this slug
    path = WIKI_DIR / f"{slug}.md"
    target_names = {slug}
    if path.exists():
        try:
            content = path.read_text(encoding="utf-8")
            meta, _ = _parse_frontmatter(content)
            for alias in meta.get("aliases", []):
                target_names.add(str(alias))
        except Exception:
            pass

    backlinks = []
    for article_path in sorted(WIKI_DIR.glob("*.md")):
        if article_path.name.startswith(".") or article_path.name.startswith("_"):
            continue
        if article_path.stem == slug:
            continue
        try:
            content = article_path.read_text(encoding="utf-8")
            meta, body = _parse_frontmatter(content)
            # Check if any [[link]] in the body matches our target names
            links_in_article = set(re.findall(r"\[\[([^\]|]+?)(?:\|[^\]]+)?\]\]", body))
            if links_in_article & target_names:
                title = meta.get("title") or article_path.stem.replace("-", " ").title()
                backlinks.append({"slug": article_path.stem, "title": title})
        except Exception:
            continue
    return backlinks


def get_graph_data() -> Dict[str, Any]:
    """Return graph nodes and edges for the wiki knowledge graph."""
    alias_index = _build_alias_index()
    articles = list_articles()
    slug_set = {a["slug"] for a in articles}

    nodes = []
    links = []
    seen_edges = set()

    for a in articles:
        # Determine primary group from first category tag
        group = "other"
        for t in a["tags"]:
            if "/" in t:
                group = t.split("/")[0]
                break
        nodes.append({
            "id": a["slug"],
            "title": a["title"],
            "group": group,
            "tags": a["tags"],
        })

        # Read body for outbound wikilinks
        path = WIKI_DIR / a["filename"]
        try:
            content = path.read_text(encoding="utf-8")
            _, body = _parse_frontmatter(content)
            raw_links = re.findall(r"\[\[([^\]|]+?)(?:\|[^\]]+)?\]\]", body)
            for link in raw_links:
                target = alias_index.get(link, link)
                if target in slug_set and target != a["slug"]:
                    edge_key = tuple(sorted([a["slug"], target]))
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        links.append({"source": a["slug"], "target": target})
        except Exception:
            continue

    return {"nodes": nodes, "links": links}


def search_articles(query: str, max_results: int = 10) -> List[Dict[str, str]]:
    """Keyword search across wiki articles including frontmatter titles.

    Returns list of dicts with slug, title, and matching snippet.
    """
    query_lower = query.lower()
    query_terms = query_lower.split()
    results = []

    WIKI_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(WIKI_DIR.glob("*.md")):
        if path.name.startswith(".") or path.name.startswith("_"):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            meta, body = _parse_frontmatter(content)
            title = meta.get("title") or path.stem.replace("-", " ").title()

            # Search against title + body (not raw frontmatter)
            searchable = (title + "\n" + " ".join(meta.get("tags", [])) + "\n" + body).lower()

            score = sum(1 for term in query_terms if term in searchable)
            # Bonus for title match
            title_lower = title.lower()
            score += sum(2 for term in query_terms if term in title_lower)
            if score == 0:
                continue

            # Extract a snippet from body
            body_lower = body.lower()
            snippet = ""
            for term in query_terms:
                idx = body_lower.find(term)
                if idx >= 0:
                    start = max(0, idx - 80)
                    end = min(len(body), idx + 120)
                    snippet = "..." + body[start:end].replace("\n", " ").strip() + "..."
                    break

            results.append({
                "slug": path.stem,
                "title": title,
                "tags": meta.get("tags", []),
                "score": score,
                "snippet": snippet,
            })
        except Exception:
            continue

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:max_results]


def get_all_tags() -> List[Dict[str, Any]]:
    """Return all unique tags with article counts, sorted by count descending."""
    tag_counts: Dict[str, int] = {}
    for path in sorted(WIKI_DIR.glob("*.md")):
        if path.name.startswith(".") or path.name.startswith("_"):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            meta, _ = _parse_frontmatter(content)
            for tag in meta.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        except Exception:
            continue
    return sorted(
        [{"tag": t, "count": c} for t, c in tag_counts.items()],
        key=lambda x: (-x["count"], x["tag"]),
    )


def get_wiki_stats() -> Dict[str, Any]:
    """Return wiki statistics."""
    meta = _load_meta()
    articles = list_articles()
    total_size = sum(a["size"] for a in articles)
    all_tags = set()
    for a in articles:
        all_tags.update(a["tags"])
    return {
        "article_count": len(articles),
        "total_size": total_size,
        "total_size_str": f"{total_size / 1024:.1f} KB" if total_size < 1024 * 1024 else f"{total_size / (1024 * 1024):.1f} MB",
        "sources_compiled": len(meta.get("compiled", {})),
        "tag_count": len(all_tags),
        "last_lint": meta.get("last_lint"),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cmd = sys.argv[1] if len(sys.argv) > 1 else "update"

    if cmd == "compile":
        stats = compile_full_rebuild()
        print(f"Full compile: {stats}")
    elif cmd == "update":
        stats = compile_incremental()
        print(f"Incremental update: {stats}")
    elif cmd == "lint":
        result = lint_wiki()
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("No lint results")
    else:
        print(f"Usage: {sys.argv[0]} [compile|update|lint]")
