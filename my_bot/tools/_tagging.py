"""LangChain @tool wrappers that attach a readonly/mutating tag.

Fail-closed convention: tools without a "readonly" tag are NOT exposed via
the public /pokedex web page or the public MCP endpoint. Always use one of
these two decorators in place of bare @tool — bare @tool yields an
untagged BaseTool which the public filters will reject.

Both helpers preserve LangChain's bare-decorator ergonomics:

    @readonly_tool
    @validate_args(...)
    def get_xsoar_ticket(...): ...

The underlying object is exactly the BaseTool produced by `@tool`; we just
set its .tags field after construction.
"""
from langchain_core.tools import tool as _lc_tool


def _make(tag: str):
    def decorator(fn):
        bt = _lc_tool(fn)
        bt.tags = [tag]
        return bt

    return decorator


readonly_tool = _make("readonly")
mutating_tool = _make("mutating")
