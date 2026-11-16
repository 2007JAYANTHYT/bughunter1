"""
HackerOne Export Format
Generates reports compatible with HackerOne submission format
"""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from reporting.bug_database import BugRecord
from reporting.report_generator import ReportGenerator


@dataclass
class HackerOneReport:
    """HackerOne submission format"""
    title: str
    vulnerability_information: str
    severity_rating: Optional[str] = None  # Will be calculated from CVSS
    weakness_id: Optional[int] = None  # CWE ID
    structured_scope_id: Optional[int] = None
    asset_identifier: str = ""
    asset_type: str = "URL"


class HackerOneExporter:
    """Exports bugs to HackerOne format"""

    CWE_MAPPING = {
        "xss": 79,
        "sqli": 89,
        "ssrf": 918,
        "rce": 94,
        "idor": 639,
        "auth_bypass": 287,
        "csrf": 352,
        "xxe": 611,
        "ssti": 1336,
        "nosqli": 564,
        "ldap_injection": 90,
        "xpath_injection": 643,
        "command_injection": 78,
        "path_traversal": 22,
        "file_upload": 434,
        "deserialization": 502,
        "race_condition": 362,
        "logic": 840,
        "cors": 346,
        "clickjacking": 1021,
        "open_redirect": 601,
        "information_disclosure": 200,
        "rate_limiting": 770,
        "mass_assignment": 915,
        "bola": 639,
        "graphql_introspection": 200,
        "graphql_depth": 400,
        "graphql_batching": 400,
        "graphql_csrf": 352,
        "method_override": 400,
        "version_bypass": 200,
        "debug_endpoint": 200,
        "jwt": 345,
        "oauth": 287,
        "session_fixation": 384,
        "host_header_injection": 170,
        "price_manipulation": 840,
        "workflow_bypass": 840,
        "quantity_manipulation": 840,
        "coupon_abuse": 840,
        "reward_abuse": 840,
        "s3_public_listing": 200,
        "k8s_api_access": 200,
        "package_json_exposure": 200,
        "lockfile_exposure": 200,
        "dependency_confusion": 502,
        "typosquatting": 502,
    }

    SEVERITY_MAPPING = {
        "P1": "critical",
        "P2": "high",
        "P3": "medium",
        "P4": "low",
    }

    def __init__(self, config_manager=None):
        self.report_generator = ReportGenerator(config_manager)

    def map_severity(self, severity: str) -> str:
        """Map internal severity to HackerOne severity"""
        return self.SEVERITY_MAPPING.get(severity, "medium")

    def map_cwe(self, vuln_type: str) -> int:
        """Map vulnerability type to CWE ID"""
        return self.CWE_MAPPING.get(vuln_type.lower(), 200)  # Default: CWE-200

    def generate_submission(self, bug: BugRecord) -> Dict[str, Any]:
        """Generate HackerOne submission data"""
        # Generate full report
        report_content = self._generate_hackerone_markdown(bug)

        submission = {
            "report": {
                "title": bug.title,
                "vulnerability_information": report_content,
                "severity_rating": self.map_severity(bug.severity),
                "weakness_id": self.map_cwe(bug.vuln_type),
                "structured_scope_id": None,  # Would need program-specific mapping
                "asset_identifier": bug.evidence_paths[0] if bug.evidence_paths else "",
                "asset_type": "URL",
            }
        }

        return submission

    def _generate_hackerone_markdown(self, bug: BugRecord) -> str:
        """Generate HackerOne-style markdown report"""
        lines = []

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(bug.description or "No description provided.")
        lines.append("")

        # Steps to Reproduce
        lines.append("## Steps To Reproduce")
        lines.append("")
        if bug.poc:
            # Extract steps from POC
            lines.append(bug.poc)
        else:
            lines.append("1. Navigate to the vulnerable endpoint")
            lines.append("2. Inject the payload in the vulnerable parameter")
            lines.append("3. Observe the vulnerability trigger")
        lines.append("")

        # Impact
        lines.append("## Impact")
        lines.append("")
        lines.append(bug.impact or f"This vulnerability allows an attacker to {bug.vuln_type}.")
        lines.append("")

        # Remediation
        lines.append("## Remediation")
        lines.append("")
        lines.append(bug.remediation or "Implement proper input validation and output encoding.")
        lines.append("")

        # Proof of Concept
        if bug.poc:
            lines.append("## Proof of Concept")
            lines.append("")
            lines.append(bug.poc)
            lines.append("")

        # Evidence
        if bug.evidence_paths:
            lines.append("## Supporting Material/References")
            lines.append("")
            for path in bug.evidence_paths:
                lines.append(f"- {path}")
            lines.append("")

        # CVSS
        if bug.cvss_score or bug.cvss_vector:
            lines.append("## CVSS Score")
            lines.append("")
            lines.append(f"**Score:** {bug.cvss_score or 'N/A'}")
            lines.append(f"**Vector:** {bug.cvss_vector or 'N/A'}")
            lines.append("")

        return "\n".join(lines)

    def export_to_file(self, bug: BugRecord, output_dir: str = "exports/hackerone") -> str:
        """Export submission to file"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        submission = self.generate_submission(bug)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"hackerone_{bug.id}_{bug.program_name}_{timestamp}.json"
        filepath = Path(output_dir) / filename

        with open(filepath, 'w') as f:
            json.dump(submission, f, indent=2)

        # Also save markdown version
        md_filepath = filepath.with_suffix('.md')
        md_filepath.write_text(submission['report']['vulnerability_information'])

        return str(filepath)

    def export_bulk(self, bugs: List[BugRecord], output_dir: str = "exports/hackerone") -> List[str]:
        """Export multiple bugs"""
        files = []
        for bug in bugs:
            if bug.status in ["validated", "reported"]:
                files.append(self.export_to_file(bug, output_dir))
        return files


class HackerOneAPI:
    """HackerOne API integration for direct submission"""

    def __init__(self, api_token: str, api_user: str):
        self.api_token = api_token
        self.api_user = api_user
        self.base_url = "https://api.hackerone.com/v1"

    async def submit_report(self, program_handle: str, submission: Dict) -> Dict:
        """Submit report to HackerOne"""
        import httpx

        url = f"{self.base_url}/hackers/programs/{program_handle}/reports"

        auth = (self.api_user, self.api_token)
        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=60.0, auth=auth) as client:
            response = await client.post(url, json=submission, headers=headers)
            return response.json()

    async def get_program_scopes(self, program_handle: str) -> List[Dict]:
        """Get program scopes"""
        import httpx

        url = f"{self.base_url}/hackers/programs/{program_handle}/structured_scopes"
        auth = (self.api_user, self.api_token)

        async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
            response = await client.get(url)
            return response.json()

    async def get_report(self, report_id: str) -> Dict:
        """Get report details"""
        import httpx

        url = f"{self.base_url}/hackers/reports/{report_id}"
        auth = (self.api_user, self.api_token)

        async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
            response = await client.get(url)
            return response.json()


async def export_to_hackerone(bug: BugRecord, config_manager=None) -> str:
    """Export bug to HackerOne format file"""
    exporter = HackerOneExporter(config_manager)
    return exporter.export_to_file(bug)


async def bulk_export_hackerone(bugs: List[BugRecord], config_manager=None) -> List[str]:
    """Export multiple bugs to HackerOne format"""
    exporter = HackerOneExporter(config_manager)
    return exporter.export_bulk(bugs)