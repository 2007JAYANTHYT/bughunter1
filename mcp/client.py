"""
MCP Client
Unified client for interacting with all MCP servers
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

from core.config_manager import get_config


@dataclass
class MCPServer:
    """MCP Server configuration"""
    name: str
    module_path: str
    tools: List[Dict]
    enabled: bool = True


class MCPClient:
    """Unified client for all MCP servers"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.servers: Dict[str, Any] = {}
        self.server_configs: Dict[str, MCPServer] = {}
        self._initialized = False

    async def initialize(self):
        """Initialize all MCP servers"""
        if self._initialized:
            return

        # Import and create server instances
        from mcp.servers.burp_mcp import BurpMCPServer, BURP_MCP_TOOLS
        from mcp.servers.nuclei_mcp import NucleiMCPServer, NUCLEI_MCP_TOOLS
        from mcp.servers.playwright_mcp import PlaywrightMCPServer, PLAYWRIGHT_MCP_TOOLS
        from mcp.servers.recon_mcp import ReconMCPServer, RECON_MCP_TOOLS
        from mcp.servers.db_mcp import DatabaseMCPServer, DB_MCP_TOOLS
        from mcp.servers.ai_mcp import AIMCPServer, AI_MCP_TOOLS
        from mcp.servers.strix_mcp import StrixMCPServer, STRIX_MCP_TOOLS

        self.servers = {
            "burp": BurpMCPServer(self.config),
            "nuclei": NucleiMCPServer(self.config),
            "playwright": PlaywrightMCPServer(self.config),
            "recon": ReconMCPServer(self.config),
            "db": DatabaseMCPServer(self.config),
            "ai": AIMCPServer(self.config),
            "strix": StrixMCPServer(self.config),
        }

        self.server_configs = {
            "burp": MCPServer("burp", "mcp.servers.burp_mcp", BURP_MCP_TOOLS),
            "nuclei": MCPServer("nuclei", "mcp.servers.nuclei_mcp", NUCLEI_MCP_TOOLS),
            "playwright": MCPServer("playwright", "mcp.servers.playwright_mcp", PLAYWRIGHT_MCP_TOOLS),
            "recon": MCPServer("recon", "mcp.servers.recon_mcp", RECON_MCP_TOOLS),
            "db": MCPServer("db", "mcp.servers.db_mcp", DB_MCP_TOOLS),
            "ai": MCPServer("ai", "mcp.servers.ai_mcp", AI_MCP_TOOLS),
            "strix": MCPServer("strix", "mcp.servers.strix_mcp", STRIX_MCP_TOOLS),
        }

        # Initialize servers that need async setup
        await self.servers["playwright"].__aenter__()

        self._initialized = True

    async def close(self):
        """Close all MCP servers"""
        if "playwright" in self.servers:
            await self.servers["playwright"].__aexit__(None, None, None)
        self._initialized = False

    def list_servers(self) -> Dict[str, Any]:
        """List all available MCP servers and their tools"""
        return {
            name: {
                "enabled": config.enabled,
                "tools_count": len(config.tools),
                "tools": [t["name"] for t in config.tools],
            }
            for name, config in self.server_configs.items()
        }

    def list_all_tools(self) -> List[Dict]:
        """List all tools across all servers"""
        all_tools = []
        for server_name, config in self.server_configs.items():
            for tool in config.tools:
                tool_copy = tool.copy()
                tool_copy["server"] = server_name
                all_tools.append(tool_copy)
        return all_tools

    async def call_tool(self, server_name: str, tool_name: str, arguments: Dict) -> Dict[str, Any]:
        """Call a tool on a specific server"""
        if not self._initialized:
            await self.initialize()

        if server_name not in self.servers:
            return {"success": False, "error": f"Server not found: {server_name}"}

        server = self.servers[server_name]

        # Route to appropriate handler
        handler_map = {
            "burp": self._handle_burp_call,
            "nuclei": self._handle_nuclei_call,
            "playwright": self._handle_playwright_call,
            "recon": self._handle_recon_call,
            "db": self._handle_db_call,
            "ai": self._handle_ai_call,
            "strix": self._handle_strix_call,
        }

        if server_name not in handler_map:
            return {"success": False, "error": f"No handler for server: {server_name}"}

        handler = handler_map[server_name]
        return await handler(server, tool_name, arguments)

    async def _handle_burp_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.burp_mcp import handle_burp_mcp_call
        return await handle_burp_mcp_call(server, tool_name, arguments)

    async def _handle_nuclei_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.nuclei_mcp import handle_nuclei_mcp_call
        return await handle_nuclei_mcp_call(server, tool_name, arguments)

    async def _handle_playwright_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.playwright_mcp import handle_playwright_mcp_call
        return await handle_playwright_mcp_call(server, tool_name, arguments)

    async def _handle_recon_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.recon_mcp import handle_recon_mcp_call
        return await handle_recon_mcp_call(server, tool_name, arguments)

    async def _handle_db_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.db_mcp import handle_db_mcp_call
        return await handle_db_mcp_call(server, tool_name, arguments)

    async def _handle_ai_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.ai_mcp import handle_ai_mcp_call
        return await handle_ai_mcp_call(server, tool_name, arguments)

    async def _handle_strix_call(self, server, tool_name: str, arguments: Dict) -> Dict:
        from mcp.servers.strix_mcp import handle_strix_mcp_call
        return await handle_strix_mcp_call(server, tool_name, arguments)

    # High-level workflow methods
    async def run_full_recon(self, program_name: str, depth: str = "normal") -> Dict:
        """Run full reconnaissance"""
        return await self.call_tool("recon", "recon_full", {"program_name": program_name, "depth": depth})

    async def run_nuclei_scan(self, targets: List[str], severity: List[str] = None) -> Dict:
        """Run Nuclei scan"""
        return await self.call_tool("nuclei", "nuclei_scan", {
            "targets": targets,
            "severity": severity or ["critical", "high", "medium", "low"],
        })

    async def start_browser(self, context_id: str = None) -> Dict:
        """Start browser context"""
        return await self.call_tool("playwright", "playwright_new_context", {"context_id": context_id})

    async def navigate_browser(self, context_id: str, url: str) -> Dict:
        """Navigate browser to URL"""
        return await self.call_tool("playwright", "playwright_navigate", {"context_id": context_id, "url": url})

    async def take_screenshot(self, context_id: str, finding_info: Dict = None) -> Dict:
        """Take screenshot"""
        return await self.call_tool("playwright", "playwright_screenshot", {
            "context_id": context_id,
            "annotated": True,
            "finding_info": finding_info,
        })

    async def analyze_with_ai(self, endpoint: Dict) -> Dict:
        """Analyze endpoint with AI"""
        return await self.call_tool("ai", "ai_analyze_endpoint", {"endpoint": endpoint})

    async def generate_poc(self, vuln: Dict) -> Dict:
        """Generate POC with AI"""
        return await self.call_tool("ai", "ai_generate_poc", {"vuln": vuln})

    async def validate_finding(self, finding: Dict) -> Dict:
        """Validate finding with AI"""
        return await self.call_tool("ai", "ai_validate_finding", {"finding": finding})

    async def chain_vulns(self, findings: List[Dict]) -> Dict:
        """Find vulnerability chains"""
        return await self.call_tool("ai", "ai_chain_vulnerabilities", {"findings": findings})

    async def run_strix_workflow(self, workflow_id: str, targets: List[str]) -> Dict:
        """Run Strix pentest workflow"""
        return await self.call_tool("strix", "strix_run_workflow", {"workflow_id": workflow_id, "targets": targets})

    async def get_db_stats(self, program_id: int) -> Dict:
        """Get database statistics"""
        return await self.call_tool("db", "db_get_stats", {"program_id": program_id})

    async def list_findings(self, filters: Dict = None) -> Dict:
        """List findings"""
        return await self.call_tool("db", "db_list_findings", {"filters": filters or {}})

    async def create_program(self, name: str, platform: str = "custom", **kwargs) -> Dict:
        """Create program"""
        return await self.call_tool("db", "db_create_program", {
            "name": name,
            "platform": platform,
            **kwargs
        })


# Global MCP client instance
mcp_client = MCPClient()


async def get_mcp_client() -> MCPClient:
    """Get initialized MCP client"""
    if not mcp_client._initialized:
        await mcp_client.initialize()
    return mcp_client


async def close_mcp_client():
    """Close MCP client"""
    await mcp_client.close()