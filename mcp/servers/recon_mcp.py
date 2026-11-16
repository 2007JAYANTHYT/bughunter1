"""
Recon MCP Server
Provides MCP tools for reconnaissance operations
"""

import asyncio
import json
from typing import Dict, Any, List, Optional

from core.config_manager import get_config
from recon.recon_orchestrator import ReconOrchestrator, run_full_recon
from recon.subdomain_enum import SubdomainEnumerator, run_subdomain_enum
from recon.service_discovery import ServiceDiscovery, run_service_discovery
from recon.content_discovery import ContentDiscovery, run_content_discovery


class ReconMCPServer:
    """MCP Server for reconnaissance operations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()

    async def run_full_recon(self, program_name: str, depth: str = "normal") -> Dict[str, Any]:
        """Run complete reconnaissance pipeline"""
        try:
            orchestrator = ReconOrchestrator(program_name, self.config)
            results = await orchestrator.run(depth)

            return {
                "success": True,
                "program": program_name,
                "depth": depth,
                "stats": results.stats,
                "subdomains_count": len(results.subdomains),
                "services_count": len(results.services),
                "endpoints_count": len(results.endpoints),
                "errors": results.errors,
                "summary": results.get_summary(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_subdomains(self, program_name: str, depth: str = "normal") -> Dict[str, Any]:
        """Run subdomain enumeration"""
        try:
            results = await run_subdomain_enum(program_name, depth)

            return {
                "success": True,
                "program": program_name,
                "count": len(results),
                "subdomains": [
                    {
                        "subdomain": r.subdomain,
                        "source": r.source.value,
                        "ip": r.ip,
                        "cname": r.cname,
                        "verified": r.verified,
                        "status_code": r.status_code,
                        "title": r.title,
                        "technology": r.technology,
                        "is_wildcard": r.is_wildcard,
                    }
                    for r in results
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def discover_services(self, program_name: str, target_ids: List[int] = None) -> Dict[str, Any]:
        """Run service discovery"""
        try:
            results = await run_service_discovery(program_name, target_ids)

            return {
                "success": True,
                "program": program_name,
                "count": len(results),
                "services": [
                    {
                        "target_id": r.target_id,
                        "ip": r.ip,
                        "port": r.port,
                        "service": r.service,
                        "service_type": r.service_type.value,
                        "version": r.version,
                        "banner": r.banner,
                        "tls_info": r.tls_info,
                        "is_cdn": r.is_cdn,
                        "cdn_provider": r.cdn_provider,
                        "asn": r.asn,
                        "asn_name": r.asn_name,
                    }
                    for r in results
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def discover_content(self, program_name: str, depth: str = "normal") -> Dict[str, Any]:
        """Run content discovery"""
        try:
            results = await run_content_discovery(program_name, depth)

            return {
                "success": True,
                "program": program_name,
                "count": len(results),
                "endpoints": [
                    {
                        "url": r.url,
                        "method": r.method,
                        "parameters": r.parameters,
                        "source": r.source,
                        "status_code": r.status_code,
                        "content_length": r.content_length,
                        "title": r.title,
                        "technology": r.technology,
                    }
                    for r in results
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# MCP Tool definitions
RECON_MCP_TOOLS = [
    {
        "name": "recon_full",
        "description": "Run complete reconnaissance pipeline",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_name": {"type": "string", "description": "Program name"},
                "depth": {"type": "string", "description": "Recon depth: quick, normal, deep", "default": "normal"},
            },
            "required": ["program_name"],
        },
    },
    {
        "name": "recon_subdomains",
        "description": "Run subdomain enumeration",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_name": {"type": "string", "description": "Program name"},
                "depth": {"type": "string", "description": "Recon depth: quick, normal, deep", "default": "normal"},
            },
            "required": ["program_name"],
        },
    },
    {
        "name": "recon_services",
        "description": "Run service discovery",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_name": {"type": "string", "description": "Program name"},
                "target_ids": {"type": "array", "items": {"type": "integer"}, "description": "Specific target IDs"},
            },
            "required": ["program_name"],
        },
    },
    {
        "name": "recon_content",
        "description": "Run content discovery",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_name": {"type": "string", "description": "Program name"},
                "depth": {"type": "string", "description": "Recon depth: quick, normal, deep", "default": "normal"},
            },
            "required": ["program_name"],
        },
    },
]


async def handle_recon_mcp_call(server: ReconMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Recon"""
    method_map = {
        "recon_full": server.run_full_recon,
        "recon_subdomains": server.enumerate_subdomains,
        "recon_services": server.discover_services,
        "recon_content": server.discover_content,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)