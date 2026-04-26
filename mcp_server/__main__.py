"""Allow running with: python -m mcp_server"""
from mcp_server.server import mcp, logger

if __name__ == "__main__":
    logger.info("Starting IR Unified MCP Server on http://127.0.0.1:8200")
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8200)
