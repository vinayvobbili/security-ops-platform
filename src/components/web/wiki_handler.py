"""Wiki Knowledge Base handler — list, compile, search, and read wiki articles."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def list_articles() -> List[Dict[str, Any]]:
    """Return all wiki articles with frontmatter metadata."""
    from my_bot.document.wiki_compiler import list_articles
    return list_articles()


def read_article(slug: str) -> Optional[str]:
    """Read a single wiki article by slug (frontmatter stripped)."""
    from my_bot.document.wiki_compiler import read_article
    return read_article(slug)


def get_article_meta(slug: str) -> Optional[Dict[str, Any]]:
    """Read frontmatter metadata for a wiki article."""
    from my_bot.document.wiki_compiler import get_article_meta
    return get_article_meta(slug)


def get_backlinks(slug: str) -> List[Dict[str, str]]:
    """Find all articles that link to this slug."""
    from my_bot.document.wiki_compiler import get_backlinks
    return get_backlinks(slug)


def get_graph_data() -> Dict[str, Any]:
    """Return graph nodes and edges for the knowledge graph."""
    from my_bot.document.wiki_compiler import get_graph_data
    return get_graph_data()


def get_all_tags() -> List[Dict[str, Any]]:
    """Return all unique tags with counts."""
    from my_bot.document.wiki_compiler import get_all_tags
    return get_all_tags()


def search_articles(query: str) -> List[Dict[str, str]]:
    """Search wiki articles by keyword."""
    from my_bot.document.wiki_compiler import search_articles
    return search_articles(query)


def get_stats() -> Dict[str, Any]:
    """Return wiki statistics."""
    from my_bot.document.wiki_compiler import get_wiki_stats
    return get_wiki_stats()


def compile_incremental() -> Dict[str, Any]:
    """Compile new/changed documents into wiki articles."""
    from my_bot.document.wiki_compiler import compile_incremental
    return compile_incremental()


def compile_full() -> Dict[str, Any]:
    """Force-recompile all documents."""
    from my_bot.document.wiki_compiler import compile_full_rebuild
    return compile_full_rebuild()


def run_lint() -> Optional[Dict]:
    """Run lint pass for cross-links and gaps."""
    from my_bot.document.wiki_compiler import lint_wiki
    return lint_wiki()
