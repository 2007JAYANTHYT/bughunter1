"""
Intigriti Export Format
Generates reports compatible with Intigriti submission format
"""

import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from reporting.bug_database import BugRecord
from reporting.report_generator import ReportGenerator


class IntigritiExporter:
    """Exports bugs to Intigriti format"""

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
        "command_injection": 78,
        "path_traversal": 22,
        "file_upload": 434,
        "deserialization": 502,
        "race_condition": 362,
        "logic": 840,
        "cors": 346,
        "clickjacking": 1021,
        "open_redirect": 601,
        "jwt": 345,
        "oauth": 287,
        "session_fixation": 384,
        "host_header_injection": 170,
    }

    SEVERITY_MAPPING = {
        "P1": "Critical",
        "P2": "High",
        "P3": "Medium",
        "P4": "Low",
    }

    def __init__(self, config_manager=None):
        self.report_generator = ReportGenerator(config_manager)

    def map_severity(self, severity: str) -> str:
        """Map internal severity to Intigriti severity"""
        return self.SEVERITY_MAPPING.get(severity, "Medium")

    def map_cwe(self, vuln_type: str) -> int:
        """Map vulnerability type to CWE ID"""
        return self.CWE_MAPPING.get(vuln_type.lower(), 200)

    def generate_submission(self, bug: BugRecord) -> Dict[str, Any]:
        """Generate Intigriti submission data"""
        report_content = self._generate_intigriti_markdown(bug)

        submission = {
            "title": bug.title,
            "description": report_content,
            "severity": self.map_severity(bug.severity),
            "cwe": self.map_cwe(bug.vuln_type),
            "endpoint": bug.evidence_paths[0] if bug.evidence_paths else "",
            "steps_to_reproduce": self._extract_steps(bug),
            "impact": bug.impact or f"This vulnerability allows an attacker to {bug.vuln_type}.",
            "recommendation": bug.remediation or "Implement proper input validation and output encoding.",
            "proof_of_concept": bug.poc,
            "attachments": bug.evidence_paths,
        }

        return {"submission": submission}

    def _generate_intigriti_markdown(self, bug: BugRecord) -> str:
        """Generate Intigriti-style markdown report"""
        lines = []

        lines.append("## Summary")
        lines.append("")
        lines.append(bug.description or "No description provided.")
        lines.append("")

        lines.append("## Technical Details")
        lines.append("")
        lines.append(f"- **Vulnerability Type**: {bug.vuln_type}")
        lines.append(f"- **Severity**: {bug.severity}")
        if bug.cvss_score:
            lines.append(f"- **CVSS Score**: {bug.cvss_score} ({bug.cvss_vector or 'N/A'})")
        lines.append("")

        lines.append("## Reproduction Steps")
        lines.append("")
        if bug.poc:
            lines.append(bug.poc)
        else:
            lines.append("1. Navigate to the vulnerable endpoint")
            lines.append("2. Inject the payload in the vulnerable parameter")
            lines.append("3. Observe the vulnerability trigger")
        lines.append("")

        lines.append("## Proof of Concept")
        lines.append("")
        if bug.poc:
            lines.append(bug.poc)
        lines.append("")

        lines.append("## Impact")
        lines.append("")
        lines.append(bug.impact or f"This vulnerability allows an attacker to {bug.vuln_type}.")
        lines.append("")

        lines.append("## Recommendation")
        lines.append("")
        lines.append(bug.remediation or "Implement proper input validation and output encoding.")
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
            import re
            steps = re.findall(r'^\d+\.\s*(.+)$', bug.poc, re.MULTILINE)
            if steps:
                return steps

        return [
            "Navigate to the vulnerable endpoint",
            "Inject the payload in the vulnerable parameter",
            "Observe the vulnerability trigger"
        ]

    def export_to_file(self, bug: BugRecord, output_dir: str = "exports/intigriti") -> str:
        """Export submission to file"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        submission = self.generate_submission(bug)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"intigriti_{bug.id}_{bug.program_name}_{timestamp}.json"
        filepath = Path(output_dir) / filename

        with open(filepath, 'w') as f:
            json.dump(submission, f, indent=2)

        # Also save markdown version
        md_filepath = filepath.with_suffix('.md')
        md_filepath.write_text(submission['submission']['description'])

        return str(filepath)

    def export_bulk(self, bugs: List[BugRecord], output_dir: str = "exports/intigriti") -> List[str]:
        """Export multiple bugs"""
        files = []
        for bug in bugs:
            if bug.status in ["validated", "reported"]:
                files.append(self.export_to_file(bug, output_dir))
        return files


class IntigritiAPI:
    """Intigriti API integration"""

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.intigriti.com/external/researcher/v1"

    async def submit_report(self, program_id: str, submission: Dict) -> Dict:
        """Submit report to Intigriti"""
        import httpx

        url = f"{self.base_url}/programs/{program_id}/submissions"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=submission, headers=headers)
            return response.json()

    async def get_programs(self) -> List[Dict]:
        """Get accessible programs"""
        import httpx

        url = f"{self.base_url}/programs"
        headers = {"Authorization": f"Bearer {self.api_token}"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            return response.json()


async def export_to_intigriti(bug: BugRecord, config_manager=None) -> str:
    """Export bug to Intigriti format file"""
    exporter = IntigritiExporter(config_manager)
    return exporter.export_to_file(bug)


async def bulk_export_intigriti(bugs: List[BugRecord], config_manager=None) -> List[str]:
    """Export multiple bugs to Intigriti format"""
    exporter = IntigritiExporter(config_manager)
    return exporter.export_bulk(bugs)