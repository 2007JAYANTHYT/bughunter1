"""
AI-Powered Hunting Engine
Multi-model AI analysis for vulnerability discovery, POC generation, and validation
"""

import asyncio
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config_manager import get_config
from core.scope_fetcher import ScopeChecker


@dataclass
class PotentialVuln:
    vuln_type: str
    severity: str  # P1-P4
    title: str
    description: str
    target_url: str
    parameter: str = ""
    payload: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    suggested_poc: str = ""


@dataclass
class POC:
    vuln_type: str
    target_url: str
    steps: List[str] = field(default_factory=list)
    curl_command: str = ""
    python_script: str = ""
    playwright_script: str = ""
    expected_result: str = ""
    validation_steps: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float
    reasoning: str
    false_positive_indicators: List[str] = field(default_factory=list)
    impact_assessment: str = ""


@dataclass
class ChainedExploit:
    chain_name: str
    vulnerabilities: List[str]  # Finding IDs
    description: str
    impact: str
    poc_steps: List[str] = field(default_factory=list)
    severity: str = "P1"


class AIHunter:
    """Multi-model AI hunting engine"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.ai_config = config_manager.load_hunting().ai_hunting
        self.models = self.ai_config.models
        self.model_endpoints = {
            "primary": "llama3.1:70b",
            "code": "deepseek-coder:33b",
            "reasoning": "nemotron3-ultra",
            "fast": "phi3:14b",
        }
        self.prompts_dir = Path(self.ai_config.prompts.prompts_dir)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)
        self._init_default_prompts()

    def _init_default_prompts(self):
        """Initialize default prompt templates"""
        prompts = {
            "analyze_endpoint": """You are an expert bug bounty hunter. Analyze this endpoint for potential vulnerabilities.

ENDPOINT DETAILS:
- URL: {url}
- Method: {method}
- Parameters: {parameters}
- Technology Stack: {technology}
- Response Headers: {headers}
- Status Code: {status_code}

TASK: Identify potential vulnerabilities. For each, provide:
1. Vulnerability type (xss, sqli, ssrf, rce, idor, auth_bypass, logic, etc.)
2. Severity (P1-P4)
3. Title
4. Description
5. Affected parameter
6. Suggested payload
7. Reasoning
8. Confidence (0.0-1.0)

Focus on HIGH-IMPACT vulnerabilities only (P1-P3). Ignore low-impact/info findings.
Output as JSON array.""",

            "generate_poc": """You are an expert exploit developer. Generate a working proof-of-concept for this vulnerability.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Target URL: {target_url}
- Parameter: {parameter}
- Payload: {payload}
- Technology: {technology}
- Description: {description}

TASK: Generate a complete POC including:
1. Step-by-step reproduction steps
2. cURL command
3. Python script using requests
4. Playwright script for browser reproduction
5. Expected result
6. Validation steps

Make the POC practical and executable. Output as JSON.""",

            "validate_finding": """You are a senior security researcher validating a potential vulnerability finding.

FINDING DETAILS:
- Type: {vuln_type}
- Target: {target_url}
- Parameter: {parameter}
- Payload Used: {payload}
- Response: {response}
- Evidence: {evidence}

TASK: Determine if this is a TRUE POSITIVE or FALSE POSITIVE.
Analyze:
1. Does the payload actually execute/reflect?
2. Is the impact real?
3. Are there false positive indicators? (WAF blocks, generic errors, etc.)
4. What is the actual impact?

Output as JSON with: is_valid (bool), confidence (0.0-1.0), reasoning, false_positive_indicators, impact_assessment.""",

            "chain_vulns": """You are an expert in vulnerability chaining. Analyze these findings for potential exploit chains.

FINDINGS:
{findings}

TASK: Identify vulnerability chains that could lead to higher impact.
Consider:
1. XSS -> CSRF -> Account Takeover
2. SSRF -> Cloud Metadata -> RCE
3. IDOR -> Info Disclosure -> Privilege Escalation
4. Race Condition -> Logic Bypass -> Financial Impact
5. Auth Bypass -> Session Fixation -> Admin Access

Output as JSON array of chains with: chain_name, vulnerabilities, description, impact, poc_steps, severity.""",

            "analyze_technology": """You are a security researcher specializing in {technology} security.

TARGETS:
{targets}

TASK: Identify technology-specific vulnerabilities for {technology}.
Consider:
- Known CVEs for this version
- Common misconfigurations
- Default credentials
- Framework-specific issues
- Middleware vulnerabilities
- Template injection patterns
- Deserialization issues

Output as JSON array of potential vulnerabilities with type, severity, title, description, parameter, payload, reasoning, confidence.""",
        }

        for name, content in prompts.items():
            prompt_file = self.prompts_dir / f"{name}.txt"
            if not prompt_file.exists():
                prompt_file.write_text(content)

    async def _call_ollama(self, model: str, prompt: str, system_prompt: str = "") -> str:
        """Call Ollama API"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "system": system_prompt,
                        "stream": False,
                        "options": {
                            "temperature": self.ai_config.temperature,
                            "top_p": 0.9,
                            "num_ctx": self.ai_config.context_window,
                        }
                    }
                )
                response.raise_for_status()
                return response.json().get("response", "")
        except Exception as e:
            print(f"Ollama error ({model}): {e}")
            return ""

    async def _call_ollama_json(self, model: str, prompt: str, system_prompt: str = "") -> Dict[str, Any]:
        """Call Ollama and parse JSON response"""
        response = await self._call_ollama(model, prompt, system_prompt)
        try:
            # Try to extract JSON from response
            start = response.find('[')
            end = response.rfind(']') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])

            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except Exception:
            pass
        return {}

    async def analyze_endpoint(self, endpoint: Dict[str, Any]) -> List[PotentialVuln]:
        """Analyze a single endpoint for vulnerabilities"""
        prompt = self._load_prompt("analyze_endpoint").format(
            url=endpoint.get('url', ''),
            method=endpoint.get('method', 'GET'),
            parameters=json.dumps(endpoint.get('parameters', {})),
            technology=', '.join(endpoint.get('technology', [])),
            headers=json.dumps(endpoint.get('headers', {})),
            status_code=endpoint.get('status_code', ''),
        )

        system_prompt = "You are an expert bug bounty hunter. Output only valid JSON array."

        response = await self._call_ollama_json(
            self.model_endpoints["primary"],
            prompt,
            system_prompt
        )

        vulns = []
        if isinstance(response, list):
            for item in response:
                vulns.append(PotentialVuln(
                    vuln_type=item.get('vulnerability_type', item.get('type', '')),
                    severity=item.get('severity', 'P4'),
                    title=item.get('title', ''),
                    description=item.get('description', ''),
                    target_url=endpoint.get('url', ''),
                    parameter=item.get('parameter', ''),
                    payload=item.get('payload', ''),
                    reasoning=item.get('reasoning', ''),
                    confidence=item.get('confidence', 0.0),
                    suggested_poc=item.get('poc', ''),
                ))

        # Filter by confidence
        return [v for v in vulns if v.confidence >= 0.6]

    async def analyze_technology(self, technology: str, targets: List[Dict]) -> List[PotentialVuln]:
        """Analyze targets for technology-specific vulnerabilities"""
        prompt = self._load_prompt("analyze_technology").format(
            technology=technology,
            targets=json.dumps([{
                'url': t.get('url', ''),
                'method': t.get('method', 'GET'),
                'parameters': t.get('parameters', {}),
            } for t in targets[:20]], indent=2)
        )

        system_prompt = f"You are a security researcher specializing in {technology} security. Output only valid JSON array."

        response = await self._call_ollama_json(
            self.model_endpoints["primary"],
            prompt,
            system_prompt
        )

        vulns = []
        if isinstance(response, list):
            for item in response:
                vulns.append(PotentialVuln(
                    vuln_type=item.get('vulnerability_type', item.get('type', '')),
                    severity=item.get('severity', 'P4'),
                    title=item.get('title', ''),
                    description=item.get('description', ''),
                    target_url=item.get('target_url', targets[0].get('url', '') if targets else ''),
                    parameter=item.get('parameter', ''),
                    payload=item.get('payload', ''),
                    reasoning=item.get('reasoning', ''),
                    confidence=item.get('confidence', 0.0),
                    suggested_poc=item.get('poc', ''),
                ))

        return [v for v in vulns if v.confidence >= 0.6]

    async def generate_poc(self, vuln: PotentialVuln) -> POC:
        """Generate proof-of-concept for a vulnerability"""
        prompt = self._load_prompt("generate_poc").format(
            vuln_type=vuln.vuln_type,
            target_url=vuln.target_url,
            parameter=vuln.parameter,
            payload=vuln.payload,
            technology="",  # Would be filled from target
            description=vuln.description,
        )

        system_prompt = "You are an expert exploit developer. Output only valid JSON."

        response = await self._call_ollama_json(
            self.model_endpoints["code"],
            prompt,
            system_prompt
        )

        return POC(
            vuln_type=vuln.vuln_type,
            target_url=vuln.target_url,
            steps=response.get('steps', []),
            curl_command=response.get('curl_command', ''),
            python_script=response.get('python_script', ''),
            playwright_script=response.get('playwright_script', ''),
            expected_result=response.get('expected_result', ''),
            validation_steps=response.get('validation_steps', []),
        )

    async def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate a finding using AI"""
        prompt = self._load_prompt("validate_finding").format(
            vuln_type=finding.get('vuln_type', ''),
            target_url=finding.get('target_url', ''),
            parameter=finding.get('parameter', ''),
            payload=finding.get('payload', ''),
            response=finding.get('response', '')[:5000],  # Limit size
            evidence=json.dumps(finding.get('evidence', {})),
        )

        system_prompt = "You are a senior security researcher. Output only valid JSON."

        response = await self._call_ollama_json(
            self.model_endpoints["primary"],
            prompt,
            system_prompt
        )

        return ValidationResult(
            is_valid=response.get('is_valid', False),
            confidence=response.get('confidence', 0.0),
            reasoning=response.get('reasoning', ''),
            false_positive_indicators=response.get('false_positive_indicators', []),
            impact_assessment=response.get('impact_assessment', ''),
        )

    async def chain_vulns(self, findings: List[Dict]) -> List[ChainedExploit]:
        """Find vulnerability chains"""
        prompt = self._load_prompt("chain_vulns").format(
            findings=json.dumps(findings, indent=2)
        )

        system_prompt = "You are an expert in vulnerability chaining. Output only valid JSON array."

        response = await self._call_ollama_json(
            self.model_endpoints["reasoning"],
            prompt,
            system_prompt
        )

        chains = []
        if isinstance(response, list):
            for item in response:
                chains.append(ChainedExploit(
                    chain_name=item.get('chain_name', ''),
                    vulnerabilities=item.get('vulnerabilities', []),
                    description=item.get('description', ''),
                    impact=item.get('impact', ''),
                    poc_steps=item.get('poc_steps', []),
                    severity=item.get('severity', 'P1'),
                ))

        return chains

    def _load_prompt(self, name: str) -> str:
        """Load prompt from file"""
        prompt_file = self.prompts_dir / f"{name}.txt"
        if prompt_file.exists():
            return prompt_file.read_text()
        return ""


class VulnerabilityAnalyzer:
    """Analyzes vulnerability patterns and suggests hunting strategies"""

    def __init__(self, ai_hunter: AIHunter):
        self.ai = ai_hunter

    async def suggest_payloads(self, vuln_type: str, context: Dict) -> List[str]:
        """Suggest context-aware payloads"""
        prompt = f"""
        Suggest payloads for {vuln_type} vulnerability in this context:
        - Reflection context: {context.get('reflection_context', 'unknown')}
        - WAF detected: {context.get('waf', 'none')}
        - Technology: {context.get('technology', 'unknown')}
        - Parameter type: {context.get('param_type', 'string')}

        Output as JSON array of payloads with bypass techniques.
        """

        response = await self.ai._call_ollama_json(
            self.ai.model_endpoints["code"],
            prompt,
            "You are a payload expert. Output only valid JSON array."
        )

        if isinstance(response, list):
            return [item.get('payload', '') for item in response if item.get('payload')]
        return []

    async def assess_impact(self, finding: Dict) -> Dict[str, Any]:
        """Assess business impact of a finding"""
        prompt = f"""
        Assess the business impact of this vulnerability:
        - Type: {finding.get('vuln_type')}
        - Target: {finding.get('target_url')}
        - Description: {finding.get('description')}
        - Data exposed: {finding.get('data_exposed', 'unknown')}
        - User impact: {finding.get('user_impact', 'unknown')}

        Provide CVSS score, vector, and business impact description.
        Output as JSON.
        """

        response = await self.ai._call_ollama_json(
            self.ai.model_endpoints["reasoning"],
            prompt,
            "You are a senior security consultant. Output only valid JSON."
        )

        return response

    async def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize findings by exploitability and impact"""
        prompt = f"""
        Prioritize these findings by exploitability and business impact:
        {json.dumps(findings, indent=2)}

        Consider:
        1. Exploitability (ease of exploitation)
        2. Business impact
        3. Chaining potential
        4. Prevalence (is this a common issue?)

        Output as JSON array with priority_score (0-100) and reasoning.
        """

        response = await self.ai._call_ollama_json(
            self.ai.model_endpoints["reasoning"],
            prompt,
            "You are a senior pentester. Output only valid JSON array."
        )

        if isinstance(response, list):
            return response
        return []


# Convenience functions
async def analyze_target_with_ai(target: Dict) -> List[PotentialVuln]:
    """Analyze a target with AI hunter"""
    hunter = AIHunter(get_config())
    return await hunter.analyze_endpoint(target)


async def generate_poc_with_ai(vuln: PotentialVuln) -> POC:
    """Generate POC with AI"""
    hunter = AIHunter(get_config())
    return await hunter.generate_poc(vuln)


async def validate_with_ai(finding: Dict) -> ValidationResult:
    """Validate finding with AI"""
    hunter = AIHunter(get_config())
    return await hunter.validate_finding(finding)