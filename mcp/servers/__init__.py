"""
MCP Servers Package
"""

from mcp.servers.burp_mcp import BurpMCPServer, BURP_MCP_TOOLS, handle_burp_mcp_call
from mcp.servers.nuclei_mcp import NucleiMCPServer, NUCLEI_MCP_TOOLS, handle_nuclei_mcp_call
from mcp.servers.playwright_mcp import PlaywrightMCPServer, PLAYWRIGHT_MCP_TOOLS, handle_playwright_mcp_call
from mcp.servers.recon_mcp import ReconMCPServer, RECON_MCP_TOOLS, handle_recon_mcp_call
from mcp.servers.db_mcp import DatabaseMCPServer, DB_MCP_TOOLS, handle_db_mcp_call
from mcp.servers.ai_mcp import AIMCPServer, AI_MCP_TOOLS, handle_ai_mcp_call
from mcp.servers.strix_mcp import StrixMCPServer, STRIX_MCP_TOOLS, handle_strix_mcp_call
from mcp.client import MCPClient, mcp_client, get_mcp_client, close_mcp_client

__all__ = [
    'BurpMCPServer',
    'BURP_MCP_TOOLS',
    'handle_burp_mcp_call',
    'NucleiMCPServer',
    'NUCLEI_MCP_TOOLS',
    'handle_nuclei_mcp_call',
    'PlaywrightMCPServer',
    'PLAYWRIGHT_MCP_TOOLS',
    'handle_playwright_mcp_call',
    'ReconMCPServer',
    'RECON_MCP_TOOLS',
    'handle_recon_mcp_call',
    'DatabaseMCPServer',
    'DB_MCP_TOOLS',
    'handle_db_mcp_call',
    'AIMCPServer',
    'AI_MCP_TOOLS',
    'handle_ai_mcp_call',
    'StrixMCPServer',
    'STRIX_MCP_TOOLS',
    'handle_strix_mcp_call',
    'MCPClient',
    'mcp_client',
    'get_mcp_client',
    'close_mcp_client',
]