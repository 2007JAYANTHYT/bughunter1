"""
Scope Fetcher - Fetches and parses bug bounty program scopes from various platforms
"""

import os
import re
import json
import yaml
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


class Platform(Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    CUSTOM = "custom"


class ScopeType(Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class ScopeRule:
    """A single scope rule (domain, CIDR, wildcard, regex)"""
    pattern: str
    scope_type: ScopeType
    description: str = ""
    is_wildcard: bool = False
    is_cidr: bool = False
    is_regex: bool = False

    def matches(self, target: str) -> bool:
        """Check if target matches this scope rule"""
        target = target.lower().strip()
        pattern = self.pattern.lower().strip()

        if self.is_cidr:
            return self._match_cidr(target, pattern)
        elif self.is_regex:
            return self._match_regex(target, pattern)
        elif self.is_wildcard:
            return self._match_wildcard(target, pattern)
        else:
            return self._match_exact(target, pattern)

    def _match_exact(self, target: str, pattern: str) -> bool:
        return target == pattern or target.endswith('.' + pattern)

    def _match_wildcard(self, target: str, pattern: str) -> bool:
        # Convert wildcard to regex
        regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
        return bool(re.match(f'^{regex_pattern}$', target))

    def _match_cidr(self, target: str, pattern: str) -> bool:
        import ipaddress
        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(pattern, strict=False)
            return target_ip in network
        except ValueError:
            return False

    def _match_regex(self, target: str, pattern: str) -> bool:
        try:
            return bool(re.match(pattern, target))
        except re.error:
            return False


@dataclass
class ProgramScope:
    """Complete scope for a program"""
    program_name: str
    platform: Platform
    in_scope: List[ScopeRule] = field(default_factory=list)
    out_of_scope: List[ScopeRule] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """Program policy rules"""
    max_severity: str = "P1"
    banned_vuln_types: List[str] = field(default_factory=list)
    rate_limit_rpm: int = 100
    require_poc: bool = True
    poc_formats: List[str] = field(default_factory=lambda: ["video", "screenshots", "curl"])
    special_rules: List[str] = field(default_factory=list)
    disclosure_timeline_days: int = 90


@dataclass
class ScopeCheckResult:
    """Result of scope check"""
    in_scope: bool
    matched_rule: Optional[ScopeRule] = None
    out_of_scope_match: Optional[ScopeRule] = None
    reason: str = ""


class ScopeFetcher:
    """Fetches scopes from various bug bounty platforms"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_program_scope(self, program_name: str) -> ProgramScope:
        """Fetch scope for a program by name"""
        program = self.config.get_program(program_name)
        if not program:
            raise ValueError(f"Program not found: {program_name}")

        platform = Platform(program.platform.lower())

        if platform == Platform.HACKERONE:
            return await self._fetch_hackerone_scope(program)
        elif platform == Platform.BUGCROWD:
            return await self._fetch_bugcrowd_scope(program)
        elif platform == Platform.INTIGRITI:
            return await self._fetch_intigriti_scope(program)
        elif platform == Platform.YESWEHACK:
            return await self._fetch_yeswehack_scope(program)
        else:
            return await self._fetch_custom_scope(program)

    async def _fetch_hackerone_scope(self, program) -> ProgramScope:
        """Fetch scope from HackerOne GraphQL API"""
        token = os.getenv(program.auth.env_var) if program.auth.env_var else None
        if not token:
            raise ValueError(f"HackerOne token not found in env var: {program.auth.env_var}")

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        query = """
        query GetProgramScope($handle: String!) {
            team(handle: $handle) {
                structured_scopes(first: 100) {
                    edges {
                        node {
                            asset_identifier
                            asset_type
                            confidence
                            eligible_for_bounty
                            eligible_for_submission
                            instruction
                            max_severity
                        }
                    }
                }
            }
        }
        """

        variables = {"handle": program.handle}

        async with self.session.post(
            "https://api.hackerone.com/graphql",
            headers=headers,
            json={"query": query, "variables": variables}
        ) as resp:
            data = await resp.json()

        scope = ProgramScope(
            program_name=program.name,
            platform=Platform.HACKERONE,
            raw_data=data
        )

        edges = data.get("data", {}).get("team", {}).get("structured_scopes", {}).get("edges", [])
        for edge in edges:
            node = edge["node"]
            asset = node["asset_identifier"]
            scope_type = ScopeType.IN_SCOPE if node["eligible_for_submission"] else ScopeType.OUT_OF_SCOPE

            rule = self._parse_scope_rule(asset, node.get("instruction", ""), scope_type)
            if scope_type == ScopeType.IN_SCOPE:
                scope.in_scope.append(rule)
            else:
                scope.out_of_scope.append(rule)

        return scope

    async def _fetch_bugcrowd_scope(self, program) -> ProgramScope:
        """Fetch scope from Bugcrowd API"""
        token = os.getenv(program.auth.env_var) if program.auth.env_var else None
        if not token:
            raise ValueError(f"Bugcrowd token not found in env var: {program.auth.env_var}")

        headers = {
            "Authorization": f"Token {token}",
            "Accept": "application/json",
        }

        async with self.session.get(
            f"https://api.bugcrowd.com/programs/{program.handle}/scopes",
            headers=headers
        ) as resp:
            data = await resp.json()

        scope = ProgramScope(
            program_name=program.name,
            platform=Platform.BUGCROWD,
            raw_data=data
        )

        for item in data.get("scopes", []):
            scope_type = ScopeType.IN_SCOPE if item.get("eligible_for_bounty", True) else ScopeType.OUT_OF_SCOPE
            rule = self._parse_scope_rule(item["target"], item.get("instruction", ""), scope_type)
            if scope_type == ScopeType.IN_SCOPE:
                scope.in_scope.append(rule)
            else:
                scope.out_of_scope.append(rule)

        return scope

    async def _fetch_intigriti_scope(self, program) -> ProgramScope:
        """Fetch scope from Intigriti API"""
        token = os.getenv(program.auth.env_var) if program.auth.env_var else None
        if not token:
            raise ValueError(f"Intigriti token not found in env var: {program.auth.env_var}")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        async with self.session.get(
            f"https://api.intigriti.com/external/researcher/v1/programs/{program.handle}",
            headers=headers
        ) as resp:
            data = await resp.json()

        scope = ProgramScope(
            program_name=program.name,
            platform=Platform.INTIGRITI,
            raw_data=data
        )

        for item in data.get("scopes", []):
            scope_type = ScopeType.IN_SCOPE if item.get("eligibleForBounty", True) else ScopeType.OUT_OF_SCOPE
            rule = self._parse_scope_rule(item["endpoint"], item.get("instruction", ""), scope_type)
            if scope_type == ScopeType.IN_SCOPE:
                scope.in_scope.append(rule)
            else:
                scope.out_of_scope.append(rule)

        return scope

    async def _fetch_yeswehack_scope(self, program) -> ProgramScope:
        """Fetch scope from YesWeHack API"""
        token = os.getenv(program.auth.env_var) if program.auth.env_var else None
        if not token:
            raise ValueError(f"YesWeHack token not found in env var: {program.auth.env_var}")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        async with self.session.get(
            f"https://api.yeswehack.com/programs/{program.handle}/scopes",
            headers=headers
        ) as resp:
            data = await resp.json()

        scope = ProgramScope(
            program_name=program.name,
            platform=Platform.YESWEHACK,
            raw_data=data
        )

        for item in data.get("scopes", []):
            scope_type = ScopeType.IN_SCOPE if item.get("in_scope", True) else ScopeType.OUT_OF_SCOPE
            rule = self._parse_scope_rule(item["scope"], item.get("description", ""), scope_type)
            if scope_type == ScopeType.IN_SCOPE:
                scope.in_scope.append(rule)
            else:
                scope.out_of_scope.append(rule)

        return scope

    async def _fetch_custom_scope(self, program) -> ProgramScope:
        """Load scope from local YAML file"""
        scope_file = program.scope_file
        if not scope_file or not Path(scope_file).exists():
            # Check default location
            default_path = Path("config/scopes") / f"{program.name}.yaml"
            if default_path.exists():
                scope_file = str(default_path)
            else:
                raise FileNotFoundError(f"Scope file not found: {scope_file}")

        with open(scope_file, 'r') as f:
            data = yaml.safe_load(f)

        scope = ProgramScope(
            program_name=program.name,
            platform=Platform.CUSTOM,
            raw_data=data
        )

        for item in data.get("in_scope", []):
            rule = self._parse_scope_rule(item["pattern"], item.get("description", ""), ScopeType.IN_SCOPE)
            scope.in_scope.append(rule)

        for item in data.get("out_of_scope", []):
            rule = self._parse_scope_rule(item["pattern"], item.get("description", ""), ScopeType.OUT_OF_SCOPE)
            scope.out_of_scope.append(rule)

        return scope

    def _parse_scope_rule(self, pattern: str, description: str, scope_type: ScopeType) -> ScopeRule:
        """Parse a scope pattern and determine its type"""
        rule = ScopeRule(pattern=pattern, scope_type=scope_type, description=description)

        # Check for CIDR
        if '/' in pattern and not pattern.startswith('*.'):
            try:
                import ipaddress
                ipaddress.ip_network(pattern, strict=False)
                rule.is_cidr = True
            except ValueError:
                pass

        # Check for wildcard
        if '*' in pattern:
            rule.is_wildcard = True

        # Check for regex (if wrapped in /.../)
        if pattern.startswith('/') and pattern.endswith('/'):
            rule.is_regex = True
            rule.pattern = pattern[1:-1]

        return rule

    def load_scope_from_file(self, file_path: str) -> ProgramScope:
        """Load scope from a YAML/JSON file"""
        path = Path(file_path)
        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        scope = ProgramScope(
            program_name=path.stem,
            platform=Platform.CUSTOM,
            raw_data=data
        )

        for item in data.get("in_scope", []):
            if isinstance(item, str):
                rule = self._parse_scope_rule(item, "", ScopeType.IN_SCOPE)
            else:
                rule = self._parse_scope_rule(item["pattern"], item.get("description", ""), ScopeType.IN_SCOPE)
            scope.in_scope.append(rule)

        for item in data.get("out_of_scope", []):
            if isinstance(item, str):
                rule = self._parse_scope_rule(item, "", ScopeType.OUT_OF_SCOPE)
            else:
                rule = self._parse_scope_rule(item["pattern"], item.get("description", ""), ScopeType.OUT_OF_SCOPE)
            scope.out_of_scope.append(rule)

        return scope


class PolicyEngine:
    """Enforces program policies"""

    def __init__(self, config_manager):
        self.config = config_manager

    def load_policy(self, program_name: str) -> Policy:
        """Load policy for a program"""
        program = self.config.get_program(program_name)
        if not program:
            raise ValueError(f"Program not found: {program_name}")

        policy = Policy()

        # Load from program config
        policy.max_severity = program.policy.max_severity
        policy.banned_vuln_types = program.policy.banned_types
        policy.rate_limit_rpm = program.policy.rate_limit
        policy.require_poc = program.policy.require_poc
        policy.poc_formats = [program.policy.poc_format] if isinstance(program.policy.poc_format, str) else program.policy.poc_format

        # Load from policy file if exists
        if program.policy.file and Path(program.policy.file).exists():
            with open(program.policy.file, 'r') as f:
                file_policy = yaml.safe_load(f)
                policy.banned_vuln_types.extend(file_policy.get("banned_vuln_types", []))
                policy.special_rules.extend(file_policy.get("special_rules", []))
                policy.disclosure_timeline_days = file_policy.get("disclosure_timeline_days", 90)

        return policy

    def validate_finding(self, finding, policy: Policy) -> Dict[str, Any]:
        """Validate a finding against policy"""
        issues = []

        # Check severity
        severity_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        max_sev_order = severity_order.get(policy.max_severity, 4)
        finding_sev_order = severity_order.get(finding.severity, 4)

        if finding_sev_order > max_sev_order:
            issues.append(f"Severity {finding.severity} exceeds max allowed {policy.max_severity}")

        # Check banned vuln types
        if finding.vuln_type.lower() in [v.lower() for v in policy.banned_vuln_types]:
            issues.append(f"Vulnerability type {finding.vuln_type} is banned for this program")

        return {
            "valid": len(issues) == 0,
            "issues": issues
        }

    def check_rate_limit(self, program_name: str, requests_made: int, time_window_minutes: int = 1) -> bool:
        """Check if rate limit allows more requests"""
        policy = self.load_policy(program_name)
        return requests_made < policy.rate_limit_rpm

    def get_poc_requirements(self, vuln_type: str, policy: Policy) -> List[str]:
        """Get POC requirements for a vulnerability type"""
        base = policy.poc_formats.copy()

        # Add type-specific requirements
        if vuln_type.lower() in ["xss", "csrf"]:
            if "video" not in base:
                base.append("video")
        elif vuln_type.lower() in ["sqli", "rce", "ssrf"]:
            if "curl" not in base:
                base.append("curl")

        return base


class ScopeChecker:
    """Checks if targets are in scope"""

    def __init__(self, scope: ProgramScope):
        self.scope = scope

    def check(self, target: str) -> ScopeCheckResult:
        """Check if a target is in scope"""
        target = target.lower().strip()

        # First check out-of-scope (higher priority)
        for rule in self.scope.out_of_scope:
            if rule.matches(target):
                return ScopeCheckResult(
                    in_scope=False,
                    out_of_scope_match=rule,
                    reason=f"Matched out-of-scope rule: {rule.pattern}"
                )

        # Then check in-scope
        for rule in self.scope.in_scope:
            if rule.matches(target):
                return ScopeCheckResult(
                    in_scope=True,
                    matched_rule=rule,
                    reason=f"Matched in-scope rule: {rule.pattern}"
                )

        return ScopeCheckResult(
            in_scope=False,
            reason="No matching in-scope rule found"
        )

    def check_url(self, url: str) -> ScopeCheckResult:
        """Check if a URL is in scope (extracts hostname)"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            return self.check(hostname)
        except Exception:
            return ScopeCheckResult(in_scope=False, reason="Invalid URL")

    def filter_targets(self, targets: List[str]) -> Dict[str, List[str]]:
        """Filter a list of targets into in-scope and out-of-scope"""
        in_scope = []
        out_of_scope = []

        for target in targets:
            result = self.check(target)
            if result.in_scope:
                in_scope.append(target)
            else:
                out_of_scope.append(target)

        return {
            "in_scope": in_scope,
            "out_of_scope": out_of_scope
        }