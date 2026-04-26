"""Knowledge base wiki search tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def wiki_search(query: str) -> str:
    """Search the team's Knowledge Base wiki for articles on SOC topics.

    The wiki contains compiled articles on threat actors, runbooks, tools,
    procedures, and team-specific knowledge. Use for questions about
    operational procedures, past incidents, or documented team knowledge.

    Args:
        query: Search query describing what to find in the wiki
    """
    try:
        from my_bot.document.wiki_compiler import search_articles, read_article

        results = search_articles(query, max_results=3)
        if not results:
            return "No wiki articles matched that query."

        output_parts = []
        for r in results:
            content = read_article(r["slug"])
            if content:
                if len(content) > 3000:
                    content = content[:3000] + "\n\n[Article truncated]"
                title = r["slug"].replace("-", " ").title()
                output_parts.append(f"## {title}\n_Source: wiki/{r['slug']}.md_\n\n{content}")

        if not output_parts:
            return "Wiki articles were found but could not be read."

        return "\n\n---\n\n".join(output_parts)

    except Exception as e:
        logger.error(f"Wiki search failed: {e}")
        return f"Wiki search error: {e}"
