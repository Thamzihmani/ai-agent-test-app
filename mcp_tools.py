# mcp_tools.py
# Purpose: MCP tool implementations with deliberately seeded security vulnerabilities.
#          Used as a static analysis target for the aisec repository scan.
#          DO NOT deploy — intentionally insecure for testing only.
# Author: Thamizhmani
# Date: 2026-09-16
# Modified: 2026-09-17 — Add FastMCP server + @mcp.tool decorators for scanner detection.

import sqlite3
import subprocess

class _StubMCP:
    """No-op MCP stub used when mcp package is not installed."""

    def tool(self, fn):
        return fn


try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("AgentTools MCP Server")
except ImportError:
    mcp = _StubMCP()


# ── VULNERABILITY R-05: Path traversal in file-read tool ─────────────────────
# SAST should flag open(file_path) with no sanitization as HIGH.
@mcp.tool
def read_file(file_path: str) -> str:
    """Read a file by path. No path sanitization — vulnerable to traversal."""
    with open(file_path, "r") as f:  # nosec (intentional)
        return f.read()


# ── VULNERABILITY R-06: Raw SQL in query tool ─────────────────────────────────
# SAST should flag unsanitized SQL passed to execute() as HIGH.
@mcp.tool
def execute_query(query: str) -> list:
    """Execute an arbitrary SQL query. No parameterization."""
    conn = sqlite3.connect("data.db")
    rows = conn.execute(query).fetchall()  # nosec (intentional)
    conn.close()
    return rows


# ── VULNERABILITY: Command injection in shell tool ────────────────────────────
@mcp.tool
def run_command(command: str) -> str:
    """Run a shell command. No allowlist — full injection surface."""
    result = subprocess.run(  # nosec (intentional)
        command, shell=True, capture_output=True, text=True
    )
    return result.stdout


# ── VULNERABILITY: Sends email to unvalidated address ────────────────────────
@mcp.tool
def send_email(to_address: str, body: str) -> dict:
    """Send email without validating or allowlisting recipient."""
    return {"sent": True, "to": to_address, "preview": body[:50]}


MCP_TOOL_REGISTRY = {
    "read_file": read_file,
    "execute_query": execute_query,
    "run_command": run_command,
    "send_email": send_email,
}


def dispatch_tool(tool_name: str, params: dict):
    """Dispatch a tool call — no authorization check before execution."""
    handler = MCP_TOOL_REGISTRY.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    return handler(**params)
