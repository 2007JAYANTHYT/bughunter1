"""
AI MCP Server
Provides MCP tools for AI-powered hunting and analysis
"""

import asyncio
import json
from typing import Dict, Any, List, Optional

from core.config_manager import get_config
from hunting.ai_hunter import AIHunter, PotentialVuln, POC, ValidationResult, ChainedExploit, VulnerabilityAnalyzer


class AIMCPServer:
    """MCP Server for AI-powered hunting operations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.ai_hunter = AIHunter(self.config)
        self.analyzer = VulnerabilityAnalyzer(self.ai_hunter)

    async def analyze_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze endpoint for potential vulnerabilities"""
        try:
            vulns = await self.ai_hunter.analyze_endpoint(endpoint)

            return {
                "success": True,
                "endpoint": endpoint.get('url', ''),
                "vulnerabilities": [
                    {
                        "vuln_type": v.vuln_type,
                        "severity": v.severity,
                        "title": v.title,
                        "description": v.description,
                        "parameter": v.parameter,
                        "payload": v.payload,
                        "reasoning": v.reasoning,
                        "confidence": v.confidence,
                        "suggested_poc": v.suggested_poc,
                    }
                    for v in vulns
                ],
                "count": len(vulns),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def analyze_technology(self, technology: str, targets: List[Dict]) -> Dict[str, Any]:
        """Analyze targets for technology-specific vulnerabilities"""
        try:
            vulns = await self.ai_hunter.analyze_technology(technology, targets)

            return {
                "success": True,
                "technology": technology,
                "targets_analyzed": len(targets),
                "vulnerabilities": [
                    {
                        "vuln_type": v.vuln_type,
                        "severity": v.severity,
                        "title": v.title,
                        "description": v.description,
                        "target_url": v.target_url,
                        "parameter": v.parameter,
                        "payload": v.payload,
                        "reasoning": v.reasoning,
                        "confidence": v.confidence,
                    }
                    for v in vulns
                ],
                "count": len(vulns),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_poc(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Generate proof-of-concept for a vulnerability"""
        try:
            # Convert to PotentialVuln
            potential_vuln = PotentialVuln(
                vuln_type=vuln.get('vuln_type', ''),
                severity=vuln.get('severity', 'P4'),
                title=vuln.get('title', ''),
                description=vuln.get('description', ''),
                target_url=vuln.get('target_url', ''),
                parameter=vuln.get('parameter', ''),
                payload=vuln.get('payload', ''),
                reasoning=vuln.get('reasoning', ''),
                confidence=vuln.get('confidence', 0.0),
                suggested_poc=vuln.get('suggested_poc', ''),
            )

            poc = await self.ai_hunter.generate_poc(potential_vuln)

            return {
                "success": True,
                "poc": {
                    "vuln_type": poc.vuln_type,
                    "target_url": poc.target_url,
                    "steps": poc.steps,
                    "curl_command": poc.curl_command,
                    "python_script": poc.python_script,
                    "playwright_script": poc.playwright_script,
                    "expected_result": poc.expected_result,
                    "validation_steps": poc.validation_steps,
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def validate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a finding using AI"""
        try:
            validation = await self.ai_hunter.validate_finding(finding)

            return {
                "success": True,
                "validation": {
                    "is_valid": validation.is_valid,
                    "confidence": validation.confidence,
                    "reasoning": validation.reasoning,
                    "false_positive_indicators": validation.false_positive_indicators,
                    "impact_assessment": validation.impact_assessment,
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def chain_vulnerabilities(self, findings: List[Dict]) -> Dict[str, Any]:
        """Find vulnerability chains"""
        try:
            chains = await self.ai_hunter.chain_vulns(findings)

            return {
                "success": True,
                "chains": [
                    {
                        "chain_name": c.chain_name,
                        "vulnerabilities": c.vulnerabilities,
                        "description": c.description,
                        "impact": c.impact,
                        "poc_steps": c.poc_steps,
                        "severity": c.severity,
                    }
                    for c in chains
                ],
                "count": len(chains),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def suggest_payloads(self, vuln_type: str, context: Dict) -> Dict[str, Any]:
        """Suggest context-aware payloads"""
        try:
            payloads = await self.analyzer.suggest_payloads(vuln_type, context)
            return {"success": True, "payloads": payloads, "count": len(payloads)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def assess_impact(self, finding: Dict) -> Dict[str, Any]:
        """Assess business impact of a finding"""
        try:
            impact = await self.analyzer.assess_impact(finding)
            return {"success": True, "impact": impact}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def prioritize_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Prioritize findings by exploitability and impact"""
        try:
            prioritized = await self.analyzer.prioritize_findings(findings)
            return {"success": True, "prioritized": prioritized}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about configured AI models"""
        ai_config = self.config.load_hunting().ai_hunting

        return {
            "success": True,
            "models": {
                "primary": ai_config.models.primary,
                "code": ai_config.models.code,
                "reasoning": ai_config.models.reasoning,
                "fast": ai_config.models.fast,
            },
            "parameters": {
                "max_tokens": ai_config.max_tokens,
                "temperature": ai_config.temperature,
                "context_window": ai_config.context_window,
            },
            "prompts_dir": ai_config.prompts.prompts_dir,
        }


# MCP Tool definitions
AI_MCP_TOOLS = [
    {
        "name": "ai_analyze_endpoint",
        "description": "Analyze endpoint for potential vulnerabilities using AI",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "parameters": {"type": "object"},
                        "technology": {"type": "array", "items": {"type": "string"}},
                        "headers": {"type": "object"},
                        "status_code": {"type": "integer"},
                    },
                    "required": ["url"],
                },
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "ai_analyze_technology",
        "description": "Analyze targets for technology-specific vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technology": {"type": "string"},
                "targets": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["technology", "targets"],
        },
    },
    {
        "name": "ai_generate_poc",
        "description": "Generate proof-of-concept for a vulnerability",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln": {"type": "object", "description": "Vulnerability details"},
            },
            "required": ["vuln"],
        },
    },
    {
        "name": "ai_validate_finding",
        "description": "Validate a finding using AI (false positive check)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object", "description": "Finding details"},
            },
            "required": ["finding"],
        },
    },
    {
        "name": "ai_chain_vulnerabilities",
        "description": "Find vulnerability chains for higher impact",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "ai_suggest_payloads",
        "description": "Suggest context-aware payloads",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string"},
                "context": {"type": "object", "description": "Context: reflection_context, waf, technology, param_type"},
            },
            "required": ["vuln_type", "context"],
        },
    },
    {
        "name": "ai_assess_impact",
        "description": "Assess business impact of a finding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object"},
            },
            "required": ["finding"],
        },
    },
    {
        "name": "ai_prioritize_findings",
        "description": "Prioritize findings by exploitability and impact",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "ai_get_model_info",
        "description": "Get configured AI model information",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


async def handle_ai_mcp_call(server: AIMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for AI"""
    method_map = {
        "ai_analyze_endpoint": server.analyze_endpoint,
        "ai_analyze_technology": server.analyze_technology,
        "ai_generate_poc": server.generate_poc,
        "ai_validate_finding": server.validate_finding,
        "ai_chain_vulnerabilities": server.chain_vulnerabilities,
        "ai_suggest_payloads": server.suggest_payloads,
        "ai_assess_impact": server.assess_impact,
        "ai_prioritize_findings": server.prioritize_findings,
        "ai_get_model_info": server.get_model_info,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)