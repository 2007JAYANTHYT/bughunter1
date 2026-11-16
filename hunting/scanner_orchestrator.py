"""
Scanner Orchestrator
Coordinates multiple vulnerability scanners: Nuclei, DalFox, SQLMap, custom payloads, AI
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp

from core.config_manager import get_config
from core.database import db_manager, TargetCRUD, EndpointCRUD, FindingCRUD, FindingStatus, FindingSeverity
from core.scope_fetcher import ScopeChecker, ScopeFetcher
from hunting.nuclei_manager import NucleiManager
from hunting.ai_hunter import AIHunter
from hunting.payload_manager import PayloadManager


class ScannerType(str, Enum):
    NUCLEI = "nuclei"
    DALFOX = "dalfox"
    SQLMAP = "sqlmap"
    CUSTOM = "custom"
    AI = "ai"


@dataclass
class ScanTarget:
    target_id: int
    url: str
    method: str = "GET"
    parameters: Dict[str, Any] = field(default_factory=dict)
    technology: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityFinding:
    scanner: ScannerType
    vuln_type: str
    severity: str  # P1-P4
    title: str
    description: str
    target: ScanTarget
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)
    template_id: str = ""  # For Nuclei templates
    matched_at: str = ""


class ScannerOrchestrator:
    """Orchestrates multiple vulnerability scanners"""

    def __init__(self, program_name: str, config_manager=None):
        self.program_name = program_name
        self.config = config_manager or get_config()
        self.hunting_config = self.config.load_hunting()
        self.program = None
        self.scope_checker: Optional[ScopeChecker] = None
        self.targets: List[ScanTarget] = []
        self.findings: List[VulnerabilityFinding] = []

        # Initialize sub-scanners
        self.nuclei_manager = NucleiManager(self.config)
        self.ai_hunter = AIHunter(self.config)
        self.payload_manager = PayloadManager(self.config)

    async def initialize(self):
        """Initialize the orchestrator"""
        await self._load_program_and_scope()
        await self._load_targets()

    async def _load_program_and_scope(self):
        """Load program and scope"""
        async with ScopeFetcher(self.config) as fetcher:
            scope = await fetcher.fetch_program_scope(self.program_name)
        self.scope_checker = ScopeChecker(scope)

        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            self.program = await ProgramCRUD.get_by_name(session, self.program_name)
            if not self.program:
                raise ValueError(f"Program not found: {self.program_name}")

    async def _load_targets(self):
        """Load targets from database and convert to ScanTarget"""
        async with db_manager.get_session() as session:
            targets = await TargetCRUD.get_by_program(session, self.program.id)

            for target in targets:
                if not target.subdomain:
                    continue

                # Check scope
                if self.scope_checker:
                    result = self.scope_checker.check(target.subdomain)
                    if not result.in_scope:
                        continue

                # Build base URLs
                urls = self._build_urls_for_target(target)

                # Get endpoints for each URL
                for url in urls:
                    endpoints = await EndpointCRUD.get_by_target(session, target.id)
                    for ep in endpoints:
                        if self._check_scope(ep.url):
                            self.targets.append(ScanTarget(
                                target_id=target.id,
                                url=ep.url,
                                method=ep.method,
                                parameters=ep.parameters or {},
                                technology=target.technology or [],
                            ))

                    # Also add base URL if no endpoints
                    if not endpoints:
                        for url in urls:
                            if self._check_scope(url):
                                self.targets.append(ScanTarget(
                                    target_id=target.id,
                                    url=url,
                                    method="GET",
                                    parameters={},
                                    technology=target.technology or [],
                                ))

    def _build_urls_for_target(self, target) -> List[str]:
        """Build URLs for a target"""
        urls = []
        if target.subdomain:
            if target.port in [80, 443]:
                scheme = "https" if target.port == 443 else "http"
                urls.append(f"{scheme}://{target.subdomain}")
            else:
                scheme = "https" if target.port == 443 else "http"
                urls.append(f"{scheme}://{target.subdomain}:{target.port}")
        return urls

    def _check_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        if not self.scope_checker:
            return True
        try:
            result = self.scope_checker.check_url(url)
            return result.in_scope
        except Exception:
            return True

    async def run_all_scanners(self) -> List[VulnerabilityFinding]:
        """Run all enabled scanners"""
        all_findings = []

        # Run scanners in parallel
        scanner_tasks = []

        if self.hunting_config.scanners.nuclei.enabled:
            scanner_tasks.append(self._run_nuclei())

        if self.hunting_config.scanners.dalfox.enabled:
            scanner_tasks.append(self._run_dalfox())

        if self.hunting_config.scanners.sqlmap.enabled:
            scanner_tasks.append(self._run_sqlmap())

        if self.hunting_config.scanners.custom_payloads.enabled:
            scanner_tasks.append(self._run_custom_payloads())

        if self.hunting_config.ai_hunting.enabled:
            scanner_tasks.append(self._run_ai_hunting())

        # Run specialized hunters
        if self.hunting_config.specialized.xss:
            scanner_tasks.append(self._run_xss_hunter())
        if self.hunting_config.specialized.sqli:
            scanner_tasks.append(self._run_sqli_hunter())
        if self.hunting_config.specialized.ssrf:
            scanner_tasks.append(self._run_ssrf_hunter())
        if self.hunting_config.specialized.rce:
            scanner_tasks.append(self._run_rce_hunter())
        if self.hunting_config.specialized.auth:
            scanner_tasks.append(self._run_auth_hunter())
        if self.hunting_config.specialized.logic:
            scanner_tasks.append(self._run_logic_hunter())
        if self.hunting_config.specialized.api:
            scanner_tasks.append(self._run_api_hunter())

        # Execute all scanners
        results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

        # Collect findings
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                print(f"Scanner error: {result}")

        # Deduplicate findings
        self.findings = self._deduplicate_findings(all_findings)

        # Save to database
        await self._save_findings()

        return self.findings

    async def _run_nuclei(self) -> List[VulnerabilityFinding]:
        """Run Nuclei scanner"""
        findings = []

        if not self.targets:
            return findings

        # Write targets to file
        urls = [t.url for t in self.targets]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(urls))
            target_file = f.name

        try:
            config = self.hunting_config.scanners.nuclei
            cmd = [
                "nuclei", "-l", target_file,
                "-silent", "-json",
                "-rate-limit", str(config.rate_limit),
                "-retries", "2",
                "-timeout", "10",
                "-severity", ",".join(config.severity),
            ]

            # Add tags filters
            if config.tags:
                cmd.extend(["-tags", ",".join(config.tags)])
            if config.exclude_tags:
                cmd.extend(["-exclude-tags", ",".join(config.exclude_tags)])

            # Add custom templates
            if config.custom_templates:
                cmd.extend(["-t", config.templates_path])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        finding = self._parse_nuclei_result(data)
                        if finding:
                            findings.append(finding)
                    except Exception:
                        pass
        finally:
            Path(target_file).unlink(missing_ok=True)

        return findings

    def _parse_nuclei_result(self, data: Dict) -> Optional[VulnerabilityFinding]:
        """Parse Nuclei JSON output"""
        try:
            # Map Nuclei severity to P1-P4
            severity_map = {
                "critical": "P1",
                "high": "P2",
                "medium": "P3",
                "low": "P4",
                "info": "P4",
            }

            # Find matching target
            matched_url = data.get('matched-at', '') or data.get('url', '')
            target = None
            for t in self.targets:
                if t.url in matched_url or matched_url in t.url:
                    target = t
                    break

            if not target:
                # Create minimal target
                target = ScanTarget(target_id=0, url=matched_url)

            return VulnerabilityFinding(
                scanner=ScannerType.NUCLEI,
                vuln_type=data.get('info', {}).get('classification', {}).get('cve-id', ['unknown'])[0].lower().replace('cve-', ''),
                severity=severity_map.get(data.get('info', {}).get('severity', 'info').lower(), 'P4'),
                title=data.get('info', {}).get('name', 'Nuclei Finding'),
                description=data.get('info', {}).get('description', ''),
                target=target,
                evidence={
                    "nuclei": data,
                    "matched_at": data.get('matched-at', ''),
                    "extracted_results": data.get('extracted-results', []),
                },
                poc=data.get('curl-command', ''),
                confidence=0.9,
                tags=data.get('info', {}).get('tags', []),
                template_id=data.get('template-id', ''),
                matched_at=data.get('timestamp', datetime.utcnow().isoformat()),
            )
        except Exception:
            return None

    async def _run_dalfox(self) -> List[VulnerabilityFinding]:
        """Run DalFox for XSS scanning"""
        findings = []

        # Filter targets with parameters
        param_targets = [t for t in self.targets if t.parameters or '?' in t.url]

        for target in param_targets[:50]:  # Limit
            try:
                cmd = [
                    "dalfox", "url", target.url,
                    "--silent", "--json",
                    "--worker", str(self.hunting_config.scanners.dalfox.worker),
                    "--timeout", "10",
                ]

                if self.hunting_config.scanners.dalfox.blind_xss:
                    # Would need a blind XSS callback URL
                    pass

                if self.hunting_config.scanners.dalfox.mining:
                    cmd.append("--mining")

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                try:
                    data = json.loads(stdout.decode())
                    for issue in data.get('issues', []):
                        findings.append(VulnerabilityFinding(
                            scanner=ScannerType.DALFOX,
                            vuln_type="xss",
                            severity="P3",  # Default, would be refined
                            title=f"XSS in {issue.get('parameter', 'parameter')}",
                            description=issue.get('description', ''),
                            target=target,
                            evidence={"dalfox": issue},
                            poc=issue.get('poc', ''),
                            confidence=0.85,
                        ))
                except Exception:
                    pass
            except Exception as e:
                print(f"DalFox error for {target.url}: {e}")

        return findings

    async def _run_sqlmap(self) -> List[VulnerabilityFinding]:
        """Run SQLMap for SQL injection"""
        findings = []

        # Filter targets with parameters
        param_targets = [t for t in self.targets if t.parameters]

        for target in param_targets[:30]:  # Limit
            try:
                config = self.hunting_config.scanners.sqlmap
                cmd = [
                    "sqlmap", "-u", target.url,
                    "--batch", "--threads", str(config.threads),
                    "--level", str(config.level),
                    "--risk", str(config.risk),
                    "--output-dir", "/tmp/sqlmap",
                    "--flush-session",
                    "--json-output", "/tmp/sqlmap_output.json",
                ]

                # Add parameters if POST
                if target.method == "POST" and target.parameters:
                    data_str = "&".join(f"{k}={v}" for k, v in target.parameters.items())
                    cmd.extend(["--data", data_str])

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                # Parse JSON output
                output_file = Path("/tmp/sqlmap_output.json")
                if output_file.exists():
                    try:
                        data = json.loads(output_file.read_text())
                        for db, tables in data.items():
                            if isinstance(tables, dict):
                                findings.append(VulnerabilityFinding(
                                    scanner=ScannerType.SQLMAP,
                                    vuln_type="sqli",
                                    severity="P1",
                                    title=f"SQL Injection in {target.url}",
                                    description=f"SQLMap confirmed SQL injection. Database: {db}",
                                    target=target,
                                    evidence={"sqlmap": data},
                                    poc="",
                                    confidence=0.95,
                                ))
                    except Exception:
                        pass
            except Exception as e:
                print(f"SQLMap error for {target.url}: {e}")

        return findings

    async def _run_custom_payloads(self) -> List[VulnerabilityFinding]:
        """Run custom payload testing"""
        findings = []

        # Get payloads for different vuln types
        payload_types = ["xss", "sqli", "ssrf", "rce", "auth"]

        for vuln_type in payload_types:
            payloads = self.payload_manager.get_payloads(vuln_type)
            if not payloads:
                continue

            # Test payloads against targets with parameters
            param_targets = [t for t in self.targets if t.parameters]

            for target in param_targets[:20]:  # Limit
                for param_name in target.parameters.keys():
                    for payload in payloads[:10]:  # Limit payloads per param
                        # This would need actual HTTP requests
                        # Simplified - just prepare findings
                        pass

        return findings

    async def _run_ai_hunting(self) -> List[VulnerabilityFinding]:
        """Run AI-powered hunting"""
        findings = []

        # Group targets by technology
        tech_groups = {}
        for target in self.targets:
            for tech in target.technology:
                if tech not in tech_groups:
                    tech_groups[tech] = []
                tech_groups[tech].append(target)

        # Run AI analysis for each technology group
        for tech, targets in tech_groups.items():
            ai_findings = await self.ai_hunter.analyze_technology(tech, targets[:20])
            findings.extend(ai_findings)

        return findings

    async def _run_xss_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized XSS hunter"""
        from hunting.specialized.xss_hunter import XSSHunter
        hunter = XSSHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_sqli_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized SQLi hunter"""
        from hunting.specialized.sqli_hunter import SQLiHunter
        hunter = SQLiHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_ssrf_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized SSRF hunter"""
        from hunting.specialized.ssrf_hunter import SSRFHunter
        hunter = SSRFHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_rce_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized RCE hunter"""
        from hunting.specialized.rce_hunter import RCEHunter
        hunter = RCEHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_auth_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized Auth hunter"""
        from hunting.specialized.auth_hunter import AuthHunter
        hunter = AuthHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_logic_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized Logic hunter"""
        from hunting.specialized.logic_hunter import LogicHunter
        hunter = LogicHunter(self.config)
        return await hunter.hunt(self.targets)

    async def _run_api_hunter(self) -> List[VulnerabilityFinding]:
        """Run specialized API hunter"""
        from hunting.specialized.api_hunter import APIHunter
        hunter = APIHunter(self.config)
        return await hunter.hunt(self.targets)

    def _deduplicate_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Deduplicate findings by URL, vuln_type, and parameter"""
        seen = set()
        unique = []

        for finding in findings:
            # Create deduplication key
            key_parts = [
                finding.target.url,
                finding.vuln_type,
                finding.scanner.value,
            ]
            if finding.target.parameters:
                key_parts.append(str(sorted(finding.target.parameters.keys())))

            key = "|".join(key_parts)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    async def _save_findings(self):
        """Save findings to database"""
        if not self.program:
            return

        async with db_manager.get_session() as session:
            for finding in self.findings:
                # Find or create target
                target_id = finding.target.target_id
                if target_id == 0:
                    # Try to find by URL
                    from core.database import Target
                    from sqlalchemy import select
                    parsed = urlparse(finding.target.url)
                    stmt = select(Target).where(
                        Target.program_id == self.program.id,
                        Target.subdomain == parsed.hostname
                    )
                    result = await session.execute(stmt)
                    db_target = result.scalar_one_or_none()
                    if db_target:
                        target_id = db_target.id

                # Find endpoint
                endpoint_id = None
                if target_id:
                    from core.database import Endpoint
                    from sqlalchemy import select
                    stmt = select(Endpoint).where(
                        Endpoint.target_id == target_id,
                        Endpoint.url == finding.target.url
                    )
                    result = await session.execute(stmt)
                    db_endpoint = result.scalar_one_or_none()
                    if db_endpoint:
                        endpoint_id = db_endpoint.id

                # Create finding
                db_finding = Finding(
                    program_id=self.program.id,
                    target_id=target_id,
                    endpoint_id=endpoint_id,
                    vuln_type=finding.vuln_type,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    evidence=finding.evidence,
                    poc=finding.poc,
                    status=FindingStatus.NEW.value,
                    tags=finding.tags,
                )
                await FindingCRUD.create(session, db_finding)


async def run_hunting(program_name: str) -> List[VulnerabilityFinding]:
    """Run vulnerability hunting for a program"""
    orchestrator = ScannerOrchestrator(program_name)
    await orchestrator.initialize()
    return await orchestrator.run_all_scanners()