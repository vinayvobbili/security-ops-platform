"""Convert LangChain @tool functions to Anthropic Claude API tool format.

Each LangChain tool has:
  .name         — tool name string
  .description  — docstring / description
  .args_schema  — Pydantic model (BaseModel subclass) with input schema

Claude API expects:
  {"name": ..., "description": ..., "input_schema": <JSON Schema dict>}
"""

import logging

logger = logging.getLogger(__name__)


def langchain_tool_to_claude(tool) -> dict:
    """Convert a single LangChain @tool to Claude API tool definition.

    Args:
        tool: A LangChain tool object (decorated with @tool).

    Returns:
        dict in Claude API tool format, or None if conversion fails.
    """
    try:
        name = tool.name
        description = tool.description or ""

        # Get JSON schema from the Pydantic args model
        if hasattr(tool, "args_schema") and tool.args_schema is not None:
            schema = tool.args_schema.model_json_schema()
        else:
            # Fallback: tool with no parameters
            schema = {"type": "object", "properties": {}}

        # Claude API doesn't want these Pydantic metadata keys
        for key in ("title", "$defs", "definitions"):
            schema.pop(key, None)

        # Ensure top-level type is "object"
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})

        # Clean nested property titles (Pydantic adds "title" to each field)
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)

        return {
            "name": name,
            "description": description,
            "input_schema": schema,
        }
    except Exception as e:
        logger.error(f"Failed to convert tool '{getattr(tool, 'name', '?')}': {e}")
        return None


def convert_all_tools(tools: list) -> list:
    """Convert a list of LangChain tools to Claude API format.

    Skips any tools that fail conversion and logs a warning.

    Returns:
        List of Claude API tool definition dicts.
    """
    claude_tools = []
    for tool in tools:
        converted = langchain_tool_to_claude(tool)
        if converted:
            claude_tools.append(converted)
        else:
            logger.warning(f"Skipped tool: {getattr(tool, 'name', '?')}")
    logger.info(f"Converted {len(claude_tools)}/{len(tools)} tools to Claude API format")
    return claude_tools
