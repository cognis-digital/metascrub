"""METASCRUB MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from metascrub.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-metascrub[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-metascrub[mcp]'")
        return 1
    app = FastMCP("metascrub")

    @app.tool()
    def metascrub_scan(target: str) -> str:
        """Strip identifying metadata from docs/images before release. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
