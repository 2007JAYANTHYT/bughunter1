"""
Nuclei MCP Server
Provides MCP tools for Nuclei vulnerability scanning
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from core.config_manager import get_config
from hunting.nuclei_manager import NucleiManager, NucleiTemplate, TemplateBuilder


class NucleiMCPServer:
    """MCP Server for Nuclei operations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.nuclei_manager = NucleiManager(self.config)

    async def scan(self, targets: List[str], templates: List[str] = None,
                   severity: List[str] = None, tags: List[str] = None,
                   exclude_tags: List[str] = None, rate_limit: int = 150) -> Dict[str, Any]:
        """Run Nuclei scan on targets"""
        try:
            # Write targets to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(targets))
                target_file = f.name

            try:
                cmd = [
                    "nuclei", "-l", target_file,
                    "-silent", "-json",
                    "-rate-limit", str(rate_limit),
                    "-retries", "2",
                    "-timeout", "10",
                ]

                if severity:
                    cmd.extend(["-severity", ",".join(severity)])
                if tags:
                    cmd.extend(["-tags", ",".join(tags)])
                if exclude_tags:
                    cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
                if templates:
                    for t in templates:
                        cmd.extend(["-t", t])

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                findings = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            findings.append({
                                "template_id": data.get('template-id', ''),
                                "name": data.get('info', {}).get('name', ''),
                                "severity": data.get('info', {}).get('severity', 'info'),
                                "url": data.get('url', ''),
                                "matched_at": data.get('matched-at', ''),
                                "extracted": data.get('extracted-results', []),
                            })
                        except Exception:
                            pass

                return {
                    "success": True,
                    "targets_scanned": len(targets),
                    "findings_count": len(findings),
                    "findings": findings,
                }
            finally:
                Path(target_file).unlink(missing_ok=True)

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_single(self, target: str, template: str = None) -> Dict[str, Any]:
        """Scan a single target with optional specific template"""
        return await self.scan([target], templates=[template] if template else None)

    async def get_templates(self, tags: List[str] = None, search: str = None) -> Dict[str, Any]:
        """Get available Nuclei templates"""
        try:
            if search:
                templates = self.nuclei_manager.search_templates(search)
            else:
                templates = self.nuclei_manager.get_templates_for_target([])  # Would need technologies

            template_list = []
            for t in templates:
                template_list.append({
                    "id": t.id,
                    "name": t.name,
                    "description": t.description,
                    "severity": t.severity,
                    "tags": t.tags,
                    "authors": t.authors,
                    "references": t.references,
                })

            return {
                "success": True,
                "count": len(template_list),
                "templates": template_list,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_templates(self) -> Dict[str, Any]:
        """Update Nuclei templates"""
        try:
            success = self.nuclei_manager.update_templates()
            return {"success": success, "message": "Templates updated" if success else "Update failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def validate_template(self, template_path: str) -> Dict[str, Any]:
        """Validate a Nuclei template"""
        try:
            result = self.nuclei_manager.validate_template(template_path)
            return {"success": True, "validation": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_template(self, template_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a custom Nuclei template"""
        try:
            builder = TemplateBuilder(
                template_data.get('id', 'custom-template'),
                template_data.get('name', 'Custom Template'),
                template_data.get('severity', 'medium')
            )

            if 'description' in template_data:
                builder.set_description(template_data['description'])
            if 'tags' in template_data:
                builder.add_tags(template_data['tags'])
            if 'references' in template_data:
                for ref in template_data['references']:
                    builder.add_reference(ref)

            for req in template_data.get('requests', []):
                if req.get('method') == 'GET':
                    builder.add_get_request(
                        req.get('path', ['/']),
                        matchers=req.get('matchers'),
                        extractors=req.get('extractors')
                    )
                elif req.get('method') == 'POST':
                    builder.add_post_request(
                        req.get('path', ['/']),
                        req.get('body', ''),
                        headers=req.get('headers'),
                        matchers=req.get('matchers'),
                        extractors=req.get('extractors')
                    )

            # Save template
            custom_dir = Path(self.nuclei_manager.custom_templates_dir)
            custom_dir.mkdir(parents=True, exist_ok=True)
            template_file = custom_dir / f"{template_data.get('id', 'custom-template')}.yaml"
            builder.save(str(template_file))

            return {"success": True, "template_path": str(template_file)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_stats(self) -> Dict[str, Any]:
        """Get template statistics"""
        try:
            stats = self.nuclei_manager.get_template_stats()
            return {"success": True, "stats": stats}
        except Exception as e:
            return {"success": False, "error": str(e)}


# MCP Tool definitions
NUCLEI_MCP_TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Run Nuclei vulnerability scan on targets",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "Target URLs"},
                "templates": {"type": "array", "items": {"type": "string"}, "description": "Specific templates to run"},
                "severity": {"type": "array", "items": {"type": "string"}, "description": "Severity levels: critical, high, medium, low, info"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Template tags to include"},
                "exclude_tags": {"type": "array", "items": {"type": "string"}, "description": "Template tags to exclude"},
                "rate_limit": {"type": "integer", "description": "Requests per second", "default": 150},
            },
            "required": ["targets"],
        },
    },
    {
        "name": "nuclei_scan_single",
        "description": "Scan a single target with optional specific template",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "template": {"type": "string", "description": "Specific template ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_get_templates",
        "description": "Get available Nuclei templates",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags"},
                "search": {"type": "string", "description": "Search query"},
            },
        },
    },
    {
        "name": "nuclei_update_templates",
        "description": "Update Nuclei templates from repository",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nuclei_validate_template",
        "description": "Validate a Nuclei template",
        "inputSchema": {
            "type": "object",
            "properties": {
                "template_path": {"type": "string", "description": "Path to template file"},
            },
            "required": ["template_path"],
        },
    },
    {
        "name": "nuclei_create_template",
        "description": "Create a custom Nuclei template",
        "inputSchema": {
            "type": "object",
            "properties": {
                "template_data": {"type": "object", "description": "Template configuration"},
            },
            "required": ["template_data"],
        },
    },
    {
        "name": "nuclei_get_stats",
        "description": "Get Nuclei template statistics",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


async def handle_nuclei_mcp_call(server: NucleiMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Nuclei"""
    method_map = {
        "nuclei_scan": server.scan,
        "nuclei_scan_single": server.scan_single,
        "nuclei_get_templates": server.get_templates,
        "nuclei_update_templates": server.update_templates,
        "nuclei_validate_template": server.validate_template,
        "nuclei_create_template": server.create_template,
        "nuclei_get_stats": server.get_stats,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)