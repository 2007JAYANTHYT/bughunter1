"""
Bugcrowd Export Format
Generates reports compatible with Bugcrowd submission format
"""

import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from reporting.bug_database import BugRecord
from reporting.report_generator import ReportGenerator


class BugcrowdExporter:
    """Exports bugs to Bugcrowd format"""

    CWE_MAPPING = {
        "xss": "CWE-79",
        "sqli": "CWE-89",
        "ssrf": "CWE-918",
        "rce": "CWE-94",
        "idor": "CWE-639",
        "auth_bypass": "CWE-287",
        "csrf": "CWE-352",
        "xxe": "CWE-611",
        "ssti": "CWE-1336",
        "nosqli": "CWE-564",
        "command_injection": "CWE-78",
        "path_traversal": "CWE-22",
        "file_upload": "CWE-434",
        "deserialization": "CWE-502",
        "race_condition": "CWE-362",
        "logic": "CWE-840",
        "cors": "CWE-346",
        "clickjacking": "CWE-1021",
        "open_redirect": "CWE-601",
        "jwt": "CWE-345",
        "oauth": "CWE-287",
        "session_fixation": "CWE-384",
        "host_header_injection": "CWE-170",
    }

    SEVERITY_MAPPING = {
        "P1": "Critical",
        "P2": "High",
        "P3": "Medium",
        "P4": "Low",
    }

    VRT_MAPPING = {
        "xss": "Cross-Site Scripting (XSS)",
        "sqli": "SQL Injection",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "rce": "Remote Code Execution (RCE)",
        "idor": "Insecure Direct Object Reference (IDOR)",
        "auth_bypass": "Authentication Bypass",
        "csrf": "Cross-Site Request Forgery (CSRF)",
        "xxe": "XML External Entity (XXE) Injection",
        "ssti": "Server-Side Template Injection (SSTI)",
        "nosqli": "NoSQL Injection",
        "command_injection": "Command Injection",
        "path_traversal": "Path Traversal",
        "file_upload": "Unrestricted File Upload",
        "deserialization": "Insecure Deserialization",
        "race_condition": "Race Condition",
        "logic": "Business Logic Error",
        "cors": "CORS Misconfiguration",
        "clickjacking": "Clickjacking",
        "open_redirect": "Open Redirect",
        "jwt": "JWT Vulnerability",
        "oauth": "OAuth Vulnerability",
        "session_fixation": "Session Fixation",
        "host_header_injection": "Host Header Injection",
    }

    def __init__(self, config_manager=None):
        self.report_generator = ReportGenerator(config_manager)

    def map_severity(self, severity: str) -> str:
        """Map internal severity to Bugcrowd severity"""
        return self.SEVERITY_MAPPING.get(severity, "Medium")

    def map_vrt(self, vuln_type: str) -> str:
        """Map vulnerability type to Bugcrowd VRT"""
        return self.VRT_MAPPING.get(vuln_type.lower(), "Other")

    def generate_submission(self, bug: BugRecord) -> Dict[str, Any]:
        """Generate Bugcrowd submission data"""
        report_content = self._generate_bugcrowd_markdown(bug)

        submission = {
            "title": bug.title,
            "description": report_content,
            "severity": self.map_severity(bug.severity),
            "vrt": self.map_vrt(bug.vuln_type),
            "target": bug.evidence_paths[0] if bug.evidence_paths else "",
            "steps_to_reproduce": self._extract_steps(bug),
            "impact": bug.impact or f"This vulnerability allows an attacker to {bug.vuln_type}.",
            "remediation": bug.remediation or "Implement proper input validation and output encoding.",
            "proof_of_concept": bug.poc,
            "attachments": bug.evidence_paths,
        }

        return {"submission": submission}

    def _generate_bugcrowd_markdown(self, bug: BugRecord) -> str:
        """Generate Bugcrowd-style markdown report"""
        lines = []

        lines.append("## Description")
        lines.append("")
        lines.append(bug.description or "No description provided.")
        lines.append("")

        lines.append("## Steps to Reproduce")
        lines.append("")
        if bug.poc:
            lines.append(bug.poc)
        else:
            lines.append("1. Navigate to the vulnerable endpoint")
            lines.append("2. Inject the payload in the vulnerable parameter")
            lines.append("3. Observe the vulnerability trigger")
        lines.append("")

        lines.append("## Impact")
        lines.append("")
        lines.append(bug.impact or f"This vulnerability allows an attacker to {bug.vuln_type}.")
        lines.append("")

        lines.append("## Remediation")
        lines.append("")
        lines.append(bug.remediation or "Implement proper input validation and output encoding.")
        lines.append("")

        if bug.poc:
            lines.append("## Proof of Concept")
            lines.append("")
            lines.append(bug.poc)
            lines.append("")

        if bug.evidence_paths:
            lines.append("## Attachments")
            lines.append("")
            for path in bug.evidence_paths:
                lines.append(f"- {path}")
            lines.append("")

        return "\n".join(lines)

    def _extract_steps(self, bug: BugRecord) -> List[str]:
        """Extract reproduction steps from POC"""
        if bug.poc:
            # Try to extract numbered steps
            import re
            steps = re.findall(r'^\d+\.\s*(.+)$', bug.poc, re.MULTILINE)
            if steps:
                return steps

        return [
            "Navigate to the vulnerable endpoint",
            "Inject the payload in the vulnerable parameter",
            "Observe the vulnerability trigger"
        ]

    def export_to_file(self, bug: BugRecord, output_dir: str = "exports/bugcrowd") -> str:
        """Export submission to file"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        submission = self.generate_submission(bug)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"bugcrowd_{bug.id}_{bug.program_name}_{timestamp}.json"
        filepath = Path(output_dir) / filename

        with open(filepath, 'w') as f:
            json.dump(submission, f, indent=2)

        # Also save markdown version
        md_filepath = filepath.with_suffix('.md')
        md_filepath.write_text(submission['submission']['description'])

        return str(filepath)

    def export_bulk(self, bugs: List[BugRecord], output_dir: str = "exports/bugcrowd") -> List[str]:
        """Export multiple bugs"""
        files = []
        for bug in bugs:
            if bug.status in ["validated", "reported"]:
                files.append(self.export_to_file(bug, output_dir))
        return files


class BugcrowdAPI:
    """Bugcrowd API integration"""

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.bugcrowd.com"

    async def submit_report(self, program_id: str, submission: Dict) -> Dict:
        """Submit report to Bugcrowd"""
        import httpx

        url = f"{self.base_url}/programs/{program_id}/submissions"
        headers = {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=submission, headers=headers)
            return response.json()

    async def get_programs(self) -> List[Dict]:
        """Get accessible programs"""
        import httpx

        url = f"{self.base_url}/programs"
        headers = {"Authorization": f"Token {self.api_token}"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            return response.json()


async def export_to_bugcrowd(bug: BugRecord, config_manager=None) -> str:
    """Export bug to Bugcrowd format file"""
    exporter = BugcrowdExporter(config_manager)
    return exporter.export_to_file(bug)


async def bulk_export_bugcrowd(bugs: List[BugRecord], config_manager=None) -> List[str]:
    """Export multiple bugs to Bugcrowd format"""
    exporter = BugcrowdExporter(config_manager)
    return exporter.export_bulk(bugs)