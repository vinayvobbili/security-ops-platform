"""Wiki Knowledge Base search tool for Mentor."""

import logging

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)


@readonly_tool
@log_tool_call
def search_wiki(query: str) -> str:
    """Search the team's Knowledge Base wiki for compiled articles on SOC topics, \
threat actors, runbooks, tools, and procedures.

    The wiki contains structured articles compiled from uploaded documents. \
Use this for questions about team knowledge, operational procedures, \
threat intelligence, or any topic the team has documented.

    Args:
        query: Search query describing what to find in the wiki
    """
    try:
        from my_bot.document.wiki_compiler import search_articles, read_article

        results = search_articles(query, max_results=3)
        if not results:
            return "No wiki articles matched that query. Try different keywords or check if the wiki has been compiled."

        output_parts = []
        for r in results:
            # Include the full article content (truncated) for the top results
            content = read_article(r["slug"])
            if content:
                # Truncate to keep tool results manageable
                if len(content) > 3000:
                    content = content[:3000] + "\n\n[Article truncated — full article available in the wiki]"
                title = r["slug"].replace("-", " ").title()
                output_parts.append(f"## {title}\n_Source: wiki/{r['slug']}.md_\n\n{content}")

        if not output_parts:
            return "Wiki articles were found but could not be read."

        return "\n\n---\n\n".join(output_parts)

    except Exception as e:
        logger.error(f"Wiki search failed: {e}")
        return f"Wiki search error: {e}"
