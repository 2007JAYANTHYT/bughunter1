"""
Burp Suite MCP Server
Provides MCP tools for Burp Suite integration
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

from core.config_manager import get_config
from validation.burp_integration import BurpIntegration, MitmproxyFallback, BurpCapture


class BurpMCPServer:
    """MCP Server for Burp Suite operations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.burp = BurpIntegration(self.config)
        self.mitmproxy = MitmproxyFallback(self.config)

    async def get_proxy_history(self, url_filter: str = None, limit: int = 100) -> Dict[str, Any]:
        """Get proxy history from Burp"""
        try:
            history = await self.burp._get_proxy_history(url_filter)
            return {
                "success": True,
                "count": len(history),
                "history": history[:limit],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def start_scan(self, url: str) -> Dict[str, Any]:
        """Start Burp active scan"""
        try:
            scan_id = await self.burp._start_scan(url)
            if scan_id:
                return {"success": True, "scan_id": scan_id}
            return {"success": False, "error": "Failed to start scan"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status"""
        try:
            async with self.burp._http_session() as session:
                async with session.get(
                    f"{self.burp.api_url}/v0.1/scans/{scan_id}",
                    headers=self.burp._auth_headers()
                ) as resp:
                    if resp.status == 200:
                        return {"success": True, "status": await resp.json()}
            return {"success": False, "error": "Failed to get scan status"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_scan_issues(self, scan_id: str) -> Dict[str, Any]:
        """Get issues from completed scan"""
        try:
            issues = await self.burp._get_scan_issues(scan_id)
            return {"success": True, "count": len(issues), "issues": issues}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def export_issue(self, issue_id: str) -> Dict[str, Any]:
        """Export full issue details"""
        try:
            issue = await self.burp.export_issue(issue_id)
            if issue:
                return {"success": True, "issue": issue}
            return {"success": False, "error": "Issue not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def capture_traffic(self, target_url: str, actions: List[str] = None) -> Dict[str, Any]:
        """Capture browser traffic through Burp"""
        try:
            # This would need a ScanTarget object
            from hunting.scanner_orchestrator import ScanTarget
            target = ScanTarget(target_id=0, url=target_url)
            capture = await self.burp.capture_traffic(target, actions)
            return {
                "success": True,
                "capture": {
                    "target_url": capture.target_url,
                    "requests_count": len(capture.requests),
                    "responses_count": len(capture.responses),
                    "proxy_history_count": len(capture.proxy_history),
                    "capture_time": capture.capture_time,
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_mitmproxy_traffic(self) -> Dict[str, Any]:
        """Get captured traffic from mitmproxy"""
        try:
            traffic = await self.mitmproxy.get_captured_traffic()
            return {
                "success": True,
                "requests_count": len(traffic.get("requests", [])),
                "responses_count": len(traffic.get("responses", [])),
                "traffic": traffic,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def start_mitmproxy(self) -> Dict[str, Any]:
        """Start mitmproxy capture"""
        try:
            await self.mitmproxy.start_proxy()
            return {"success": True, "message": "mitmproxy started"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def stop_mitmproxy(self) -> Dict[str, Any]:
        """Stop mitmproxy capture"""
        try:
            await self.mitmproxy.stop_proxy()
            return {"success": True, "message": "mitmproxy stopped"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration for browser"""
        return self.burp.get_proxy_config()


# MCP Tool definitions
BURP_MCP_TOOLS = [
    {
        "name": "burp_get_proxy_history",
        "description": "Get proxy history from Burp Suite",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_filter": {"type": "string", "description": "Filter by URL pattern"},
                "limit": {"type": "integer", "description": "Maximum entries to return", "default": 100},
            },
        },
    },
    {
        "name": "burp_start_scan",
        "description": "Start Burp Suite active scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to scan"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "burp_get_scan_status",
        "description": "Get status of a Burp scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "burp_get_scan_issues",
        "description": "Get vulnerabilities found by Burp scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "burp_export_issue",
        "description": "Export full issue details with request/response",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_id": {"type": "string", "description": "Issue ID"},
            },
            "required": ["issue_id"],
        },
    },
    {
        "name": "burp_capture_traffic",
        "description": "Capture browser traffic through Burp proxy",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL"},
                "actions": {"type": "array", "items": {"type": "string"}, "description": "Actions to perform"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "burp_get_mitmproxy_traffic",
        "description": "Get captured traffic from mitmproxy",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "burp_start_mitmproxy",
        "description": "Start mitmproxy capture",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "burp_stop_mitmproxy",
        "description": "Stop mitmproxy capture",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "burp_get_proxy_config",
        "description": "Get proxy configuration for browser",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


async def handle_burp_mcp_call(server: BurpMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Burp"""
    method_map = {
        "burp_get_proxy_history": server.get_proxy_history,
        "burp_start_scan": server.start_scan,
        "burp_get_scan_status": server.get_scan_status,
        "burp_get_scan_issues": server.get_scan_issues,
        "burp_export_issue": server.export_issue,
        "burp_capture_traffic": server.capture_traffic,
        "burp_get_mitmproxy_traffic": server.get_mitmproxy_traffic,
        "burp_start_mitmproxy": server.start_mitmproxy,
        "burp_stop_mitmproxy": server.stop_mitmproxy,
        "burp_get_proxy_config": lambda: server.get_proxy_config(),
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)