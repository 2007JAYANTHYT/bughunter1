"""
Vulnerability Chaining Engine
Finds and exploits vulnerability chains for higher impact
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core.config_manager import get_config
from hunting.ai_hunter import AIHunter, ChainedExploit
from reporting.bug_database import BugDatabaseManager, BugRecord


class ChainType(str, Enum):
    """Types of vulnerability chains"""
    XSS_TO_CSRF_TO_ATO = "xss_csrf_ato"           # XSS -> CSRF -> Account Takeover
    SSRF_TO_METADATA_TO_RCE = "ssrf_metadata_rce" # SSRF -> Cloud Metadata -> RCE
    IDOR_TO_INFO_TO_PRIVESC = "idor_info_privesc" # IDOR -> Info Disclosure -> Privilege Escalation
    RACE_TO_LOGIC_TO_FINANCIAL = "race_logic_financial" # Race Condition -> Logic Bypass -> Financial Impact
    AUTH_BYPASS_TO_SESSION_TO_ADMIN = "auth_session_admin" # Auth Bypass -> Session Fixation -> Admin Access
    XSS_TO_KEYLOGGER_TO_CREDS = "xss_keylogger_creds" # XSS -> Keylogger -> Credential Theft
    SQLI_TO_RCE = "sqli_rce"                      # SQLi -> RCE (via file write / xp_cmdshell)
    DESERIAL_TO_RCE = "deserial_rce"              # Deserialization -> RCE
    TEMPLATE_INJ_TO_RCE = "template_rce"          # SSTI -> RCE
    FILE_UPLOAD_TO_RCE = "upload_rce"             # File Upload -> RCE


@dataclass
class ChainLink:
    """A single link in a vulnerability chain"""
    step: int
    vuln_type: str
    finding_id: int
    description: str
    prerequisites: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)  # What this step enables
    confidence: float = 0.8


@dataclass
class ExploitChain:
    """Complete exploit chain"""
    chain_id: str
    chain_type: ChainType
    name: str
    description: str
    links: List[ChainLink] = field(default_factory=list)
    overall_severity: str = "P1"
    impact: str = ""
    poc_steps: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    confidence: float = 0.0


class ChainFinder:
    """Finds vulnerability chains from existing findings"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.ai_hunter = AIHunter(self.config)
        self.bug_db = BugDatabaseManager(self.config)

        # Define chain patterns
        self.chain_patterns = {
            ChainType.XSS_TO_CSRF_TO_ATO: {
                "required": ["xss", "csrf"],
                "optional": ["idor", "auth_bypass"],
                "severity": "P1",
                "description": "XSS enables CSRF which leads to account takeover",
            },
            ChainType.SSRF_TO_METADATA_TO_RCE: {
                "required": ["ssrf"],
                "optional": ["rce", "deserialization"],
                "severity": "P1",
                "description": "SSRF accesses cloud metadata leading to RCE",
            },
            ChainType.IDOR_TO_INFO_TO_PRIVESC: {
                "required": ["idor"],
                "optional": ["information_disclosure", "auth_bypass", "privilege_escalation"],
                "severity": "P1",
                "description": "IDOR leaks info enabling privilege escalation",
            },
            ChainType.RACE_TO_LOGIC_TO_FINANCIAL: {
                "required": ["race_condition"],
                "optional": ["logic", "price_manipulation", "coupon_abuse"],
                "severity": "P1",
                "description": "Race condition bypasses logic for financial gain",
            },
            ChainType.AUTH_BYPASS_TO_SESSION_TO_ADMIN: {
                "required": ["auth_bypass"],
                "optional": ["session_fixation", "privilege_escalation"],
                "severity": "P1",
                "description": "Auth bypass leads to session fixation and admin access",
            },
            ChainType.SQLI_TO_RCE: {
                "required": ["sqli"],
                "optional": ["rce", "file_upload", "deserialization"],
                "severity": "P1",
                "description": "SQL injection enables file write leading to RCE",
            },
        }

    async def find_chains(self, program_name: str) -> List[ExploitChain]:
        """Find all possible chains for a program"""
        # Get all findings for program
        bugs = await self.bug_db.get_bugs(BugFilters(program_name=program_name, limit=1000))

        # Group findings by vulnerability type
        findings_by_type = {}
        for bug in bugs:
            if bug.vuln_type not in findings_by_type:
                findings_by_type[bug.vuln_type] = []
            findings_by_type[bug.vuln_type].append(bug)

        chains = []

        # Check each chain pattern
        for chain_type, pattern in self.chain_patterns.items():
            chain = await self._build_chain(chain_type, pattern, findings_by_type)
            if chain and len(chain.links) >= 2:
                chains.append(chain)

        # Also use AI to find novel chains
        ai_chains = await self.ai_hunter.chain_vulns([
            {
                "id": b.id,
                "vuln_type": b.vuln_type,
                "severity": b.severity,
                "title": b.title,
                "description": b.description,
                "evidence": b.evidence_paths,
            }
            for b in bugs
        ])

        for ai_chain in ai_chains:
            chain = self._convert_ai_chain(ai_chain, bugs)
            if chain:
                chains.append(chain)

        return chains

    async def _build_chain(self, chain_type: ChainType, pattern: Dict,
                           findings_by_type: Dict[str, List[BugRecord]]) -> Optional[ExploitChain]:
        """Build a chain from findings"""
        links = []
        step = 1

        # Check required vuln types
        for req_type in pattern["required"]:
            if req_type in findings_by_type and findings_by_type[req_type]:
                # Use highest severity finding
                finding = max(findings_by_type[req_type], key=lambda f: self._severity_score(f.severity))
                links.append(ChainLink(
                    step=step,
                    vuln_type=req_type,
                    finding_id=finding.id,
                    description=finding.description or finding.title,
                    provides=self._get_provides(req_type),
                ))
                step += 1

        # Check optional vuln types
        for opt_type in pattern["optional"]:
            if opt_type in findings_by_type and findings_by_type[opt_type]:
                finding = max(findings_by_type[opt_type], key=lambda f: self._severity_score(f.severity))
                links.append(ChainLink(
                    step=step,
                    vuln_type=opt_type,
                    finding_id=finding.id,
                    description=finding.description or finding.title,
                    prerequisites=self._get_prerequisites(opt_type, links),
                    provides=self._get_provides(opt_type),
                ))
                step += 1

        if len(links) < 2:
            return None

        # Calculate confidence
        confidence = sum(l.confidence for l in links) / len(links)

        # Generate POC steps
        poc_steps = self._generate_poc_steps(links, chain_type)

        return ExploitChain(
            chain_id=f"{chain_type.value}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            chain_type=chain_type,
            name=pattern.get("name", chain_type.value.replace("_", " ").title()),
            description=pattern["description"],
            links=links,
            overall_severity=pattern["severity"],
            impact=self._assess_impact(links),
            poc_steps=poc_steps,
            confidence=confidence,
        )

    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score"""
        scores = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
        return scores.get(severity, 0)

    def _get_provides(self, vuln_type: str) -> List[str]:
        """What does this vuln type provide/enable?"""
        provides_map = {
            "xss": ["javascript_execution", "dom_access", "cookie_theft", "csrf_bypass"],
            "csrf": ["state_change", "account_modification", "password_change"],
            "ssrf": ["internal_access", "cloud_metadata", "port_scan", "protocol_smuggling"],
            "idor": ["data_access", "privilege_escalation", "info_disclosure"],
            "auth_bypass": ["authentication_bypass", "session_access", "privilege_escalation"],
            "sqli": ["data_extraction", "data_manipulation", "file_read", "file_write", "rce"],
            "rce": ["full_control", "persistence", "lateral_movement"],
            "race_condition": ["limit_bypass", "state_corruption", "financial_impact"],
            "logic": ["workflow_bypass", "price_manipulation", "coupon_abuse"],
            "session_fixation": ["session_hijacking", "account_takeover"],
            "deserialization": ["rce", "object_manipulation"],
            "ssti": ["rce", "file_read", "file_write"],
        }
        return provides_map.get(vuln_type, [])

    def _get_prerequisites(self, vuln_type: str, existing_links: List[ChainLink]) -> List[str]:
        """What prerequisites does this vuln type need?"""
        prereq_map = {
            "csrf": ["xss", "auth_bypass"],
            "auth_bypass": ["idor", "sqli", "logic"],
            "rce": ["file_upload", "deserialization", "ssti", "sqli"],
            "privilege_escalation": ["idor", "auth_bypass", "info_disclosure"],
        }
        return prereq_map.get(vuln_type, [])

    def _assess_impact(self, links: List[ChainLink]) -> str:
        """Assess overall impact of chain"""
        provides = set()
        for link in links:
            provides.update(link.provides)

        impacts = []
        if "full_control" in provides:
            impacts.append("Full server compromise")
        if "account_takeover" in provides:
            impacts.append("Account takeover for any user")
        if "financial_impact" in provides:
            impacts.append("Direct financial loss")
        if "data_extraction" in provides:
            impacts.append("Mass data exfiltration")
        if "persistence" in provides:
            impacts.append("Persistent access")

        return "; ".join(impacts) if impacts else "Significant security impact"

    def _generate_poc_steps(self, links: List[ChainLink], chain_type: ChainType) -> List[str]:
        """Generate proof-of-concept steps for chain"""
        steps = []

        for i, link in enumerate(links):
            if link.vuln_type == "xss":
                steps.append(f"Step {i+1}: Exploit XSS in {link.description[:50]}... to steal session cookies")
            elif link.vuln_type == "csrf":
                steps.append(f"Step {i+1}: Use stolen session to forge CSRF request for {link.description[:50]}...")
            elif link.vuln_type == "ssrf":
                steps.append(f"Step {i+1}: Use SSRF in {link.description[:50]}... to access internal services")
            elif link.vuln_type == "idor":
                steps.append(f"Step {i+1}: Exploit IDOR in {link.description[:50]}... to access unauthorized data")
            elif link.vuln_type == "auth_bypass":
                steps.append(f"Step {i+1}: Bypass authentication via {link.description[:50]}...")
            elif link.vuln_type == "sqli":
                steps.append(f"Step {i+1}: Extract data via SQL injection in {link.description[:50]}...")
            elif link.vuln_type == "race_condition":
                steps.append(f"Step {i+1}: Trigger race condition in {link.description[:50]}... to bypass limits")
            else:
                steps.append(f"Step {i+1}: Exploit {link.vuln_type} in {link.description[:50]}...")

        # Add chain-specific final steps
        if chain_type == ChainType.XSS_TO_CSRF_TO_ATO:
            steps.append("Final: Use CSRF to change victim's email/password and take over account")
        elif chain_type == ChainType.SSRF_TO_METADATA_TO_RCE:
            steps.append("Final: Use cloud credentials from metadata to deploy malicious code")
        elif chain_type == ChainType.IDOR_TO_INFO_TO_PRIVESC:
            steps.append("Final: Use leaked info to escalate privileges to admin")

        return steps

    def _convert_ai_chain(self, ai_chain: ChainedExploit, bugs: List[BugRecord]) -> Optional[ExploitChain]:
        """Convert AI chain to ExploitChain"""
        # Map AI findings to our bugs
        links = []
        for i, vuln_id in enumerate(ai_chain.vulnerabilities):
            bug = next((b for b in bugs if str(b.id) == str(vuln_id)), None)
            if bug:
                links.append(ChainLink(
                    step=i+1,
                    vuln_type=bug.vuln_type,
                    finding_id=bug.id,
                    description=bug.description or bug.title,
                ))

        if len(links) < 2:
            return None

        return ExploitChain(
            chain_id=f"ai_chain_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            chain_type=ChainType(ai_chain.chain_name.lower().replace(" ", "_")),
            name=ai_chain.chain_name,
            description=ai_chain.description,
            links=links,
            overall_severity=ai_chain.severity,
            impact=ai_chain.impact,
            poc_steps=ai_chain.poc_steps,
            confidence=0.7,
        )


class ChainExecutor:
    """Executes vulnerability chains for validation"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()

    async def execute_chain(self, chain: ExploitChain) -> Dict[str, Any]:
        """Execute and validate an exploit chain"""
        results = {
            "chain_id": chain.chain_id,
            "executed": True,
            "steps": [],
            "overall_success": False,
            "evidence": [],
        }

        for link in chain.links:
            # This would execute each step in the chain
            # For now, return simulated results
            step_result = {
                "step": link.step,
                "vuln_type": link.vuln_type,
                "finding_id": link.finding_id,
                "success": True,
                "evidence": f"Simulated execution of {link.vuln_type}",
            }
            results["steps"].append(step_result)

        results["overall_success"] = all(s["success"] for s in results["steps"])
        return results


import datetime
from reporting.bug_database import BugFilters