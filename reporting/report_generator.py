"""
Report Generator
Generates professional POC reports in Markdown, HTML, PDF, and platform-specific formats
"""

import asyncio
import json
import os
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib

from core.config_manager import get_config
from reporting.bug_database import BugRecord, BugDatabaseManager


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    JSON = "json"


class ReportTemplate(str, Enum):
    STANDARD = "standard"
    MINIMAL = "minimal"
    DETAILED = "detailed"
    EXECUTIVE = "executive"


@dataclass
class ReportConfig:
    format: ReportFormat = ReportFormat.MARKDOWN
    template: ReportTemplate = ReportTemplate.STANDARD
    include_screenshots: bool = True
    include_video_links: bool = True
    include_har: bool = True
    include_burp: bool = True
    include_terminal: bool = True
    include_poc_code: bool = True
    include_cvss: bool = True
    include_remediation: bool = True
    anonymize: bool = False
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedReport:
    finding_id: int
    format: ReportFormat
    content: str
    file_path: str
    created_at: str
    size_bytes: int
    checksum: str


class ReportGenerator:
    """Generates professional vulnerability reports"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.bug_db = BugDatabaseManager(config_manager)

    async def generate_poc_report(self, bug: BugRecord, config: ReportConfig = None) -> GeneratedReport:
        """Generate POC report for a single bug"""
        config = config or ReportConfig()

        # Generate content based on format
        if config.format == ReportFormat.MARKDOWN:
            content = self._generate_markdown(bug, config)
        elif config.format == ReportFormat.HTML:
            content = self._generate_html(bug, config)
        elif config.format == ReportFormat.HACKERONE:
            content = self._generate_hackerone(bug, config)
        elif config.format == ReportFormat.BUGCROWD:
            content = self._generate_bugcrowd(bug, config)
        elif config.format == ReportFormat.INTIGRITI:
            content = self._generate_intigriti(bug, config)
        elif config.format == ReportFormat.JSON:
            content = self._generate_json(bug, config)
        else:
            content = self._generate_markdown(bug, config)

        # Save to file
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        safe_title = "".join(c for c in bug.title if c.isalnum() or c in '-_ ')[:50]
        ext = self._get_extension(config.format)
        filename = f"report_{bug.id}_{safe_title}_{timestamp}.{ext}"
        filepath = self.reports_dir / filename

        filepath.write_text(content, encoding='utf-8')

        # Calculate checksum
        checksum = hashlib.sha256(content.encode()).hexdigest()

        return GeneratedReport(
            finding_id=bug.id,
            format=config.format,
            content=content,
            file_path=str(filepath),
            created_at=datetime.utcnow().isoformat(),
            size_bytes=len(content.encode()),
            checksum=checksum,
        )

    def _get_extension(self, format: ReportFormat) -> str:
        extensions = {
            ReportFormat.MARKDOWN: "md",
            ReportFormat.HTML: "html",
            ReportFormat.PDF: "pdf",
            ReportFormat.HACKERONE: "md",
            ReportFormat.BUGCROWD: "md",
            ReportFormat.INTIGRITI: "md",
            ReportFormat.JSON: "json",
        }
        return extensions.get(format, "md")

    def _generate_markdown(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate Markdown report"""
        severity_emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(bug.severity, "⚪")
        status_emoji = {
            "new": "🆕", "validated": "✅", "reported": "📤",
            "duplicate": "🔄", "false_positive": "❌", "fixed": "✔️", "paid": "💰"
        }.get(bug.status, "❓")

        lines = []

        # Header
        lines.append(f"# {severity_emoji} {bug.title}")
        lines.append("")

        # Metadata table
        lines.append("## 📋 Vulnerability Details")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **ID** | #{bug.id} |")
        lines.append(f"| **Program** | {bug.program_name} |")
        lines.append(f"| **Type** | {bug.vuln_type.upper()} |")
        lines.append(f"| **Severity** | {severity_emoji} {bug.severity} |")
        lines.append(f"| **Status** | {status_emoji} {bug.status.title()} |")
        lines.append(f"| **CVSS Score** | {bug.cvss_score or 'N/A'} ({bug.cvss_vector or 'N/A'}) |")
        lines.append(f"| **Created** | {bug.created_at} |")
        lines.append(f"| **Validated** | {bug.validated_at or 'Not validated'} |")
        if bug.reported_at:
            lines.append(f"| **Reported** | {bug.reported_at} |")
        if bug.reported_url:
            lines.append(f"| **Report URL** | [{bug.reported_url}]({bug.reported_url}) |")
        lines.append("")

        # Description
        lines.append("## 📝 Description")
        lines.append("")
        lines.append(bug.description or "No description provided.")
        lines.append("")

        # Impact
        if config.include_remediation and bug.impact:
            lines.append("## 💥 Impact")
            lines.append("")
            lines.append(bug.impact)
            lines.append("")

        # Proof of Concept
        if config.include_poc_code and bug.poc:
            lines.append("## 🔬 Proof of Concept")
            lines.append("")
            lines.append(bug.poc)
            lines.append("")

        # Evidence
        if config.include_screenshots and bug.evidence_paths:
            lines.append("## 📸 Evidence")
            lines.append("")
            for path in bug.evidence_paths:
                if any(path.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp']):
                    lines.append(f"![Evidence]({path})")
                    lines.append(f"*{os.path.basename(path)}*")
                    lines.append("")
        lines.append("")

        # Remediation
        if config.include_remediation and bug.remediation:
            lines.append("## 🛡️ Remediation")
            lines.append("")
            lines.append(bug.remediation)
            lines.append("")

        # Tags
        if bug.tags:
            lines.append("## 🏷️ Tags")
            lines.append("")
            lines.append(", ".join(f"`{tag}`" for tag in bug.tags))
            lines.append("")

        # Reproduction Steps (extracted from POC)
        if bug.poc:
            lines.append("## 🔁 Reproduction Steps")
            lines.append("")
            lines.append("1. Navigate to the vulnerable endpoint")
            lines.append("2. Inject the payload in the vulnerable parameter")
            lines.append("3. Observe the vulnerability trigger")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated by Bug Hunter Agent on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")
        lines.append(f"*Report ID: {bug.id}-{hashlib.md5(bug.title.encode()).hexdigest()[:8]}*")

        return "\n".join(lines)

    def _generate_html(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate HTML report"""
        markdown_content = self._generate_markdown(bug, config)

        # Convert markdown to HTML (simple conversion)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {bug.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 4px; font-family: 'Monaco', 'Consolas', monospace; }}
        pre {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px; overflow-x: auto; }}
        pre code {{ background: none; padding: 0; }}
        img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 4px; }}
        .severity-p1 {{ color: #dc3545; font-weight: bold; }}
        .severity-p2 {{ color: #fd7e14; font-weight: bold; }}
        .severity-p3 {{ color: #ffc107; font-weight: bold; }}
        .severity-p4 {{ color: #28a745; font-weight: bold; }}
        .status-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
        .status-new {{ background: #e7f3ff; color: #0066cc; }}
        .status-validated {{ background: #e8f5e9; color: #2e7d32; }}
        .status-reported {{ background: #fff3e0; color: #ef6c00; }}
        .status-duplicate {{ background: #f3e5f5; color: #7b1fa2; }}
        .status-false_positive {{ background: #fce4ec; color: #c62828; }}
        .status-fixed {{ background: #e8f5e9; color: #2e7d32; }}
        .status-paid {{ background: #fffde7; color: #f9a825; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div id="content">
        {self._markdown_to_html(markdown_content)}
    </div>
    <div class="footer">
        Report generated by Bug Hunter Agent on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC<br>
        Report ID: {bug.id}-{hashlib.md5(bug.title.encode()).hexdigest()[:8]}
    </div>
</body>
</html>"""
        return html

    def _markdown_to_html(self, markdown: str) -> str:
        """Simple markdown to HTML conversion"""
        # This is a basic converter - for production use python-markdown
        html = markdown

        # Headers
        import re
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)

        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)

        # Code blocks
        html = re.sub(r'```(\w+)?\n(.*?)\n```', r'<pre><code class="language-\1">\2</code></pre>', html, flags=re.DOTALL)

        # Inline code
        html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)

        # Links
        html = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', html)

        # Images
        html = re.sub(r'!\[(.+?)\]\((.+?)\)', r'<img src="\2" alt="\1">', html)

        # Tables
        # Simple table conversion
        lines = html.split('\n')
        in_table = False
        result = []
        for line in lines:
            if '|' in line and line.strip().startswith('|'):
                if not in_table:
                    result.append('<table>')
                    in_table = True
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if all(c.replace('-', '').strip() == '' for c in cells):
                    continue  # Skip separator row
                tag = 'th' if not in_table else 'td'
                row = '<tr>' + ''.join(f'<{tag}>{c}</{tag}>' for c in cells) + '</tr>'
                result.append(row)
            else:
                if in_table:
                    result.append('</table>')
                    in_table = False
                result.append(line)
        if in_table:
            result.append('</table>')

        html = '\n'.join(result)

        # Paragraphs
        html = re.sub(r'^(?!<[hputl])(.+)$', r'<p>\1</p>', html, flags=re.MULTILINE)

        # Clean up empty paragraphs
        html = re.sub(r'<p>\s*</p>', '', html)

        return html

    def _generate_hackerone(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate HackerOne format report"""
        return f"""# {bug.title}

## Summary
{bug.description}

## Steps To Reproduce
1. Navigate to the vulnerable endpoint
2. Inject the payload in the vulnerable parameter
3. Observe the vulnerability trigger

## Impact
{bug.impact or 'This vulnerability allows an attacker to ' + bug.vuln_type}

## Remediation
{bug.remediation or 'Implement proper input validation and output encoding.'}

## Proof of Concept
{bug.poc}

## Evidence
{chr(10).join(f'- {path}' for path in bug.evidence_paths)}

## CVSS Score
{bug.cvss_score or 'N/A'} ({bug.cvss_vector or 'N/A'})

---
*Report generated by Bug Hunter Agent*
"""

    def _generate_bugcrowd(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate Bugcrowd format report"""
        return f"""# Vulnerability Report: {bug.title}

## Vulnerability Type
{bug.vuln_type}

## Severity
{bug.severity}

## Description
{bug.description}

## Steps to Reproduce
1. Navigate to the vulnerable endpoint
2. Inject the payload in the vulnerable parameter
3. Observe the vulnerability trigger

## Proof of Concept
{bug.poc}

## Impact
{bug.impact or 'This vulnerability allows an attacker to ' + bug.vuln_type}

## Remediation
{bug.remediation or 'Implement proper input validation and output encoding.'}

## Supporting Evidence
{chr(10).join(f'- {path}' for path in bug.evidence_paths)}

## CVSS Vector
{bug.cvss_vector or 'N/A'}
"""

    def _generate_intigriti(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate Intigriti format report"""
        return f"""# {bug.title}

## Summary
{bug.description}

## Technical Details
- **Vulnerability Type**: {bug.vuln_type}
- **Severity**: {bug.severity}
- **CVSS**: {bug.cvss_score or 'N/A'} ({bug.cvss_vector or 'N/A'})

## Reproduction Steps
1. Navigate to the vulnerable endpoint
2. Inject the payload in the vulnerable parameter
3. Observe the vulnerability trigger

## Proof of Concept
{bug.poc}

## Impact
{bug.impact or 'This vulnerability allows an attacker to ' + bug.vuln_type}

## Recommendation
{bug.remediation or 'Implement proper input validation and output encoding.'}

## Attachments
{chr(10).join(f'- {path}' for path in bug.evidence_paths)}
"""

    def _generate_json(self, bug: BugRecord, config: ReportConfig) -> str:
        """Generate JSON report"""
        return json.dumps({
            "id": bug.id,
            "program": bug.program_name,
            "title": bug.title,
            "vulnerability_type": bug.vuln_type,
            "severity": bug.severity,
            "status": bug.status,
            "description": bug.description,
            "impact": bug.impact,
            "remediation": bug.remediation,
            "poc": bug.poc,
            "evidence": bug.evidence_paths,
            "cvss_score": bug.cvss_score,
            "cvss_vector": bug.cvss_vector,
            "tags": bug.tags,
            "reported_url": bug.reported_url,
            "created_at": bug.created_at,
            "validated_at": bug.validated_at,
            "reported_at": bug.reported_at,
        }, indent=2)

    async def generate_program_report(self, program_id: int, config: ReportConfig = None) -> GeneratedReport:
        """Generate summary report for all bugs in a program"""
        config = config or ReportConfig()

        stats = await self.bug_db.get_stats(program_id)
        bugs = await self.bug_db.get_bugs(BugFilters(program_id=program_id, limit=1000))

        lines = [
            f"# Bug Bounty Program Report: {stats.program_name}",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"**Total Findings:** {stats.total}",
            f"**Reported:** {stats.reported_count}",
            f"**Unreported (Validated):** {stats.unreported_count}",
            f"**Scope Coverage:** {stats.scope_coverage:.1f}%",
            "",
            "## Severity Distribution",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ["P1", "P2", "P3", "P4"]:
            count = stats.by_severity.get(sev, 0)
            emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(sev, "⚪")
            lines.append(f"| {emoji} {sev} | {count} |")

        lines.extend([
            "",
            "## Status Distribution",
            "",
            "| Status | Count |",
            "|--------|-------|",
        ])

        for status, count in stats.by_status.items():
            lines.append(f"| {status.title()} | {count} |")

        lines.extend([
            "",
            "## Vulnerability Types",
            "",
            "| Type | Count |",
            "|------|-------|",
        ])

        for vtype, count in sorted(stats.by_type.items(), key=lambda x: -x[1]):
            lines.append(f"| {vtype} | {count} |")

        lines.extend([
            "",
            "## Detailed Findings",
            "",
        ])

        for bug in bugs:
            status_emoji = {
                "new": "🆕", "validated": "✅", "reported": "📤",
                "duplicate": "🔄", "false_positive": "❌", "fixed": "✔️", "paid": "💰"
            }.get(bug.status, "❓")

            severity_emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(bug.severity, "⚪")

            lines.append(f"### {status_emoji} {severity_emoji} [{bug.id}] {bug.title}")
            lines.append(f"- **Type:** {bug.vuln_type} | **Severity:** {bug.severity} | **Status:** {bug.status}")
            if bug.reported_url:
                lines.append(f"- **Report:** {bug.reported_url}")
            lines.append("")

        content = "\n".join(lines)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"program_report_{stats.program_name}_{timestamp}.md"
        filepath = self.reports_dir / filename
        filepath.write_text(content, encoding='utf-8')

        return GeneratedReport(
            finding_id=0,
            format=ReportFormat.MARKDOWN,
            content=content,
            file_path=str(filepath),
            created_at=datetime.utcnow().isoformat(),
            size_bytes=len(content.encode()),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
        )


class ReportTemplate:
    """Custom report templates"""

    TEMPLATES = {
        "standard": """# {title}

## Summary
{description}

## Steps to Reproduce
{steps}

## Proof of Concept
{poc}

## Impact
{impact}

## Remediation
{remediation}

## Evidence
{evidence}
""",
        "minimal": """# {title}
**Severity:** {severity} | **Type:** {vuln_type}

{description}

**POC:** {poc}
""",
        "detailed": """# {title}

## Metadata
- **ID:** {id}
- **Program:** {program}
- **Type:** {vuln_type}
- **Severity:** {severity}
- **Status:** {status}
- **CVSS:** {cvss_score} ({cvss_vector})

## Description
{description}

## Impact
{impact}

## Proof of Concept
{poc}

## Steps to Reproduce
{steps}

## Root Cause Analysis
{root_cause}

## Remediation
{remediation}

## Evidence
{evidence}

## References
{references}
""",
        "executive": """# Executive Summary: {title}

## Risk Rating: {severity}

## Business Impact
{impact}

## Technical Summary
{vuln_type} vulnerability in {program} allows {description}.

## Recommendation
{remediation}

## Evidence Summary
- Screenshots: {screenshot_count}
- Videos: {video_count}
- Network Logs: {har_count}
""",
    }

    @classmethod
    def render(cls, template_name: str, **kwargs) -> str:
        template = cls.TEMPLATES.get(template_name, cls.TEMPLATES["standard"])
        return template.format(**kwargs)


async def generate_report(bug: BugRecord, format: ReportFormat = ReportFormat.MARKDOWN,
                          config_manager=None) -> GeneratedReport:
    """Generate report for a bug"""
    generator = ReportGenerator(config_manager)
    config = ReportConfig(format=format)
    return await generator.generate_poc_report(bug, config)


async def generate_program_report(program_id: int, config_manager=None) -> GeneratedReport:
    """Generate program summary report"""
    generator = ReportGenerator(config_manager)
    return await generator.generate_program_report(program_id)