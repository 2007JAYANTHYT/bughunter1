"""
Strix Pentester MCP Server
Integration with Strix Pentester platform (if available)
"""

import asyncio
import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StrixWorkflow:
    """Strix pentest workflow"""
    id: str
    name: str
    description: str
    steps: List[Dict]
    targets: List[str]


@dataclass
class StrixExploitModule:
    """Strix exploit module"""
    id: str
    name: str
    vuln_type: str
    description: str
    requirements: List[str]
    payload_template: str


class StrixMCPServer:
    """MCP Server for Strix Pentester integration"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.api_url = os.getenv("STRIX_API_URL", "https://api.strixpentester.com")
        self.api_key = os.getenv("STRIX_API_KEY", "")
        self.enabled = bool(self.api_key)

        # Local fallback workflows
        self.local_workflows = self._load_local_workflows()
        self.local_modules = self._load_local_modules()

    def _load_local_workflows(self) -> Dict[str, StrixWorkflow]:
        """Load built-in pentest workflows"""
        return {
            "web_app_full": StrixWorkflow(
                id="web_app_full",
                name="Full Web Application Assessment",
                description="Complete web application pentest methodology",
                steps=[
                    {"phase": "recon", "tools": ["subfinder", "httpx", "katana"], "description": "Subdomain enumeration and content discovery"},
                    {"phase": "vuln_scan", "tools": ["nuclei", "dalfox", "sqlmap"], "description": "Automated vulnerability scanning"},
                    {"phase": "manual_testing", "tools": ["burp", "custom_payloads"], "description": "Manual vulnerability testing"},
                    {"phase": "validation", "tools": ["playwright", "burp"], "description": "Real browser validation"},
                    {"phase": "reporting", "tools": ["report_generator"], "description": "Generate professional reports"},
                ],
                targets=[],
            ),
            "api_testing": StrixWorkflow(
                id="api_testing",
                name="API Security Testing",
                description="REST/GraphQL API security assessment",
                steps=[
                    {"phase": "discovery", "tools": ["swagger", "introspection"], "description": "API endpoint discovery"},
                    {"phase": "auth_testing", "tools": ["jwt_tool", "oauth_test"], "description": "Authentication/authorization testing"},
                    {"phase": "input_validation", "tools": ["fuzzing", "injection_tests"], "description": "Input validation testing"},
                    {"phase": "rate_limiting", "tools": ["load_test"], "description": "Rate limiting and DoS testing"},
                ],
                targets=[],
            ),
            "mobile_app": StrixWorkflow(
                id="mobile_app",
                name="Mobile Application Assessment",
                description="Mobile app security assessment",
                steps=[
                    {"phase": "static_analysis", "tools": ["mobsf", "apktool"], "description": "Static code analysis"},
                    {"phase": "dynamic_analysis", "tools": ["frida", "objection"], "description": "Runtime analysis"},
                    {"phase": "network_analysis", "tools": ["burp", "mitmproxy"], "description": "Network traffic analysis"},
                    {"phase": "storage_analysis", "tools": ["sqlite", "keychain"], "description": "Local storage analysis"},
                ],
                targets=[],
            ),
            "cloud_infra": StrixWorkflow(
                id="cloud_infra",
                name="Cloud Infrastructure Assessment",
                description="AWS/Azure/GCP security assessment",
                steps=[
                    {"phase": "enum", "tools": ["cloud_enum", "prowler"], "description": "Cloud resource enumeration"},
                    {"phase": "iam", "tools": ["iam_analyzer"], "description": "IAM policy analysis"},
                    {"phase": "network", "tools": ["vpc_analyzer"], "description": "Network configuration review"},
                    {"phase": "serverless", "tools": ["lambda_analyzer"], "description": "Serverless function analysis"},
                ],
                targets=[],
            ),
        }

    def _load_local_modules(self) -> Dict[str, StrixExploitModule]:
        """Load built-in exploit modules"""
        return {
            "xss_reflected": StrixExploitModule(
                id="xss_reflected",
                name="Reflected XSS Exploit",
                vuln_type="xss",
                description="Generate reflected XSS payloads with context awareness",
                requirements=["reflection_context", "waf_info"],
                payload_template="<script>alert(document.domain)</script>",
            ),
            "sqli_union": StrixExploitModule(
                id="sqli_union",
                name="UNION-based SQL Injection",
                vuln_type="sqli",
                description="Extract data via UNION injection",
                requirements=["column_count", "data_types"],
                payload_template="' UNION SELECT {columns}--",
            ),
            "ssrf_cloud_metadata": StrixExploitModule(
                id="ssrf_cloud_metadata",
                name="Cloud Metadata SSRF",
                vuln_type="ssrf",
                description="Access cloud metadata endpoints",
                requirements=["cloud_provider"],
                payload_template="http://169.254.169.254/latest/meta-data/",
            ),
            "rce_deserialization": StrixExploitModule(
                id="rce_deserialization",
                name="Java Deserialization RCE",
                vuln_type="rce",
                description="Exploit Java deserialization via gadget chains",
                requirements=["gadget_chain", "target_version"],
                payload_template="[YSOSERIAL_PAYLOAD]",
            ),
            "idor_mass_assignment": StrixExploitModule(
                id="idor_mass_assignment",
                name="IDOR via Mass Assignment",
                vuln_type="idor",
                description="Exploit mass assignment for privilege escalation",
                requirements=["api_endpoint", "writable_fields"],
                payload_template='{"user_id": 1, "role": "admin"}',
            ),
            "jwt_alg_confusion": StrixExploitModule(
                id="jwt_alg_confusion",
                name="JWT Algorithm Confusion",
                vuln_type="auth_bypass",
                description="Exploit JWT alg none/RS256-HS256 confusion",
                requirements=["public_key", "token_structure"],
                payload_template='{"alg": "none", "typ": "JWT"}',
            ),
            "race_condition_limit": StrixExploitModule(
                id="race_condition_limit",
                name="Race Condition - Limit Overrun",
                vuln_type="race_condition",
                description="Exceed rate limits via concurrent requests",
                requirements=["endpoint", "limit_value"],
                payload_template="async_concurrent_requests(100)",
            ),
        }

    async def run_workflow(self, workflow_id: str, targets: List[str]) -> Dict[str, Any]:
        """Run a pentest workflow"""
        if not self.enabled:
            # Use local workflows
            if workflow_id in self.local_workflows:
                workflow = self.local_workflows[workflow_id]
                workflow.targets = targets
                return {
                    "success": True,
                    "workflow": workflow.id,
                    "name": workflow.name,
                    "steps": workflow.steps,
                    "targets": targets,
                    "mode": "local",
                }
            return {"success": False, "error": f"Workflow not found: {workflow_id}"}

        # Remote API call
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/workflows/{workflow_id}/run",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"targets": targets}
                ) as resp:
                    if resp.status == 200:
                        return {"success": True, "result": await resp.json()}
                    return {"success": False, "error": f"API error: {resp.status}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Get workflow details"""
        if workflow_id in self.local_workflows:
            w = self.local_workflows[workflow_id]
            return {"success": True, "workflow": w.__dict__}
        return {"success": False, "error": "Workflow not found"}

    async def list_workflows(self) -> Dict[str, Any]:
        """List available workflows"""
        workflows = []
        for w in self.local_workflows.values():
            workflows.append({
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "steps": len(w.steps),
            })
        return {"success": True, "workflows": workflows}

    async def run_exploit_module(self, module_id: str, parameters: Dict) -> Dict[str, Any]:
        """Run an exploit module"""
        if module_id in self.local_modules:
            module = self.local_modules[module_id]
            return {
                "success": True,
                "module": module.id,
                "name": module.name,
                "payload": module.payload_template,
                "parameters": parameters,
                "mode": "local",
            }
        return {"success": False, "error": f"Module not found: {module_id}"}

    async def get_exploit_module(self, module_id: str) -> Dict[str, Any]:
        """Get exploit module details"""
        if module_id in self.local_modules:
            m = self.local_modules[module_id]
            return {"success": True, "module": m.__dict__}
        return {"success": False, "error": "Module not found"}

    async def list_exploit_modules(self, vuln_type: str = None) -> Dict[str, Any]:
        """List available exploit modules"""
        modules = []
        for m in self.local_modules.values():
            if vuln_type is None or m.vuln_type == vuln_type:
                modules.append({
                    "id": m.id,
                    "name": m.name,
                    "vuln_type": m.vuln_type,
                    "description": m.description,
                })
        return {"success": True, "modules": modules}

    async def get_methodology(self, methodology_id: str) -> Dict[str, Any]:
        """Get pentest methodology"""
        methodologies = {
            "owasp_wstg": {
                "id": "owasp_wstg",
                "name": "OWASP Web Security Testing Guide",
                "version": "4.2",
                "categories": [
                    "Information Gathering",
                    "Configuration and Deployment Management Testing",
                    "Identity Management Testing",
                    "Authentication Testing",
                    "Authorization Testing",
                    "Session Management Testing",
                    "Input Validation Testing",
                    "Error Handling Testing",
                    "Cryptography Testing",
                    "Business Logic Testing",
                    "Client-side Testing",
                    "API Testing",
                ],
            },
            "pt es": {
                "id": "ptes",
                "name": "Penetration Testing Execution Standard",
                "version": "2018",
                "phases": [
                    "Pre-engagement Interactions",
                    "Intelligence Gathering",
                    "Threat Modeling",
                    "Vulnerability Analysis",
                    "Exploitation",
                    "Post Exploitation",
                    "Reporting",
                ],
            },
            "owasp_mastg": {
                "id": "owasp_mastg",
                "name": "OWASP Mobile Application Security Testing Guide",
                "version": "1.6",
                "categories": [
                    "Mobile App Taxonomy",
                    "Mobile App Security Testing",
                    "Static Analysis",
                    "Dynamic Analysis",
                    "Reverse Engineering",
                    "Tampering and Runtime Analysis",
                ],
            },
        }

        if methodology_id in methodologies:
            return {"success": True, "methodology": methodologies[methodology_id]}
        return {"success": False, "error": "Methodology not found"}

    async def list_methodologies(self) -> Dict[str, Any]:
        """List available methodologies"""
        return {
            "success": True,
            "methodologies": [
                {"id": "owasp_wstg", "name": "OWASP WSTG", "version": "4.2"},
                {"id": "ptes", "name": "PTES", "version": "2018"},
                {"id": "owasp_mastg", "name": "OWASP MASTG", "version": "1.6"},
            ]
        }


# MCP Tool definitions
STRIX_MCP_TOOLS = [
    {
        "name": "strix_run_workflow",
        "description": "Run a pentest workflow",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_id": {"type": "string", "description": "Workflow ID"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "Target URLs/domains"},
            },
            "required": ["workflow_id", "targets"],
        },
    },
    {
        "name": "strix_get_workflow",
        "description": "Get workflow details",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_id": {"type": "string"},
            },
            "required": ["workflow_id"],
        },
    },
    {
        "name": "strix_list_workflows",
        "description": "List available workflows",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "strix_run_exploit_module",
        "description": "Run an exploit module",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_id": {"type": "string"},
                "parameters": {"type": "object"},
            },
            "required": ["module_id"],
        },
    },
    {
        "name": "strix_get_exploit_module",
        "description": "Get exploit module details",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_id": {"type": "string"},
            },
            "required": ["module_id"],
        },
    },
    {
        "name": "strix_list_exploit_modules",
        "description": "List available exploit modules",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string"},
            },
        },
    },
    {
        "name": "strix_get_methodology",
        "description": "Get pentest methodology",
        "inputSchema": {
            "type": "object",
            "properties": {
                "methodology_id": {"type": "string"},
            },
            "required": ["methodology_id"],
        },
    },
    {
        "name": "strix_list_methodologies",
        "description": "List available methodologies",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


async def handle_strix_mcp_call(server: StrixMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Strix"""
    method_map = {
        "strix_run_workflow": server.run_workflow,
        "strix_get_workflow": server.get_workflow,
        "strix_list_workflows": server.list_workflows,
        "strix_run_exploit_module": server.run_exploit_module,
        "strix_get_exploit_module": server.get_exploit_module,
        "strix_list_exploit_modules": server.list_exploit_modules,
        "strix_get_methodology": server.get_methodology,
        "strix_list_methodologies": server.list_methodologies,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)


# Need to import aiohttp for remote calls
import aiohttp
from core.config_manager import get_config