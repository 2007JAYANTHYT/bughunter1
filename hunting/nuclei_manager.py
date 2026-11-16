"""
Nuclei Template Manager
Manages Nuclei templates, updates, and custom template development
"""

import os
import yaml
import json
import subprocess
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NucleiTemplate:
    id: str
    name: str
    description: str
    severity: str
    tags: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    path: str = ""
    content: str = ""


class NucleiManager:
    """Manages Nuclei templates"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.hunting_config = config_manager.load_hunting()
        self.templates_dir = Path(os.path.expanduser(
            self.hunting_config.scanners.nuclei.templates_path
        ))
        self.custom_templates_dir = self.templates_dir / "custom"
        self._template_cache: Dict[str, NucleiTemplate] = {}

    def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            subprocess.run(["nuclei", "-update-templates"], check=True, capture_output=True)
            subprocess.run(["nuclei", "-update"], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def get_templates_for_target(self, technologies: List[str]) -> List[NucleiTemplate]:
        """Get relevant templates based on detected technologies"""
        templates = []

        # Map technologies to template tags
        tech_tag_map = {
            "wordpress": ["wordpress", "wp-"],
            "drupal": ["drupal"],
            "joomla": ["joomla"],
            "php": ["php"],
            "asp.net": ["aspnet", "aspx"],
            "java": ["java", "spring", "struts"],
            "python": ["python", "django", "flask"],
            "node.js": ["nodejs", "express"],
            "ruby": ["ruby", "rails"],
            "go": ["golang"],
            "react": ["react"],
            "angular": ["angular"],
            "vue": ["vuejs"],
            "jquery": ["jquery"],
            "bootstrap": ["bootstrap"],
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "iis": ["iis"],
            "tomcat": ["tomcat"],
            "jenkins": ["jenkins"],
            "gitlab": ["gitlab"],
            "github": ["github"],
            "jira": ["jira"],
            "confluence": ["confluence"],
            "jenkins": ["jenkins"],
            "docker": ["docker"],
            "kubernetes": ["kubernetes", "k8s"],
            "aws": ["aws", "s3", "ec2"],
            "azure": ["azure"],
            "gcp": ["gcp", "google-cloud"],
        }

        # Collect relevant tags
        relevant_tags = set()
        for tech in technologies:
            tech_lower = tech.lower()
            for key, tags in tech_tag_map.items():
                if key in tech_lower:
                    relevant_tags.update(tags)

        # Always include critical tags
        relevant_tags.update(["cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "idor",
                             "auth-bypass", "privilege-escalation", "takeover", "exposure"])

        # Load templates matching tags
        templates = self._load_templates_by_tags(relevant_tags)

        return templates

    def _load_templates_by_tags(self, tags: set) -> List[NucleiTemplate]:
        """Load templates matching given tags"""
        templates = []

        for template_file in self.templates_dir.rglob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    data = yaml.safe_load(f)

                if not data or 'id' not in data:
                    continue

                template_tags = set(data.get('info', {}).get('tags', []))

                # Check if any relevant tag matches
                if tags & template_tags:
                    template = NucleiTemplate(
                        id=data['id'],
                        name=data.get('info', {}).get('name', ''),
                        description=data.get('info', {}).get('description', ''),
                        severity=data.get('info', {}).get('severity', 'info'),
                        tags=list(template_tags),
                        authors=data.get('info', {}).get('authors', []),
                        references=data.get('info', {}).get('references', []),
                        metadata=data.get('info', {}).get('metadata', {}),
                        path=str(template_file),
                    )
                    templates.append(template)
            except Exception:
                continue

        return templates

    def load_all_templates(self) -> List[NucleiTemplate]:
        """Load all available templates"""
        templates = []

        for template_file in self.templates_dir.rglob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    data = yaml.safe_load(f)

                if not data or 'id' not in data:
                    continue

                template = NucleiTemplate(
                    id=data['id'],
                    name=data.get('info', {}).get('name', ''),
                    description=data.get('info', {}).get('description', ''),
                    severity=data.get('info', {}).get('severity', 'info'),
                    tags=data.get('info', {}).get('tags', []),
                    authors=data.get('info', {}).get('authors', []),
                    references=data.get('info', {}).get('references', []),
                    metadata=data.get('info', {}).get('metadata', {}),
                    path=str(template_file),
                )
                templates.append(template)
            except Exception:
                continue

        return templates

    def search_templates(self, query: str) -> List[NucleiTemplate]:
        """Search templates by query"""
        query_lower = query.lower()
        results = []

        for template in self.load_all_templates():
            if (query_lower in template.id.lower() or
                query_lower in template.name.lower() or
                query_lower in template.description.lower() or
                any(query_lower in tag.lower() for tag in template.tags)):
                results.append(template)

        return results

    def add_custom_template(self, template: NucleiTemplate) -> bool:
        """Add a custom template"""
        try:
            self.custom_templates_dir.mkdir(parents=True, exist_ok=True)

            # Generate template content
            content = self._generate_template_yaml(template)
            template_file = self.custom_templates_dir / f"{template.id}.yaml"

            with open(template_file, 'w') as f:
                f.write(content)

            template.path = str(template_file)
            self._template_cache[template.id] = template

            return True
        except Exception as e:
            print(f"Error adding custom template: {e}")
            return False

    def _generate_template_yaml(self, template: NucleiTemplate) -> str:
        """Generate YAML content for a template"""
        data = {
            'id': template.id,
            'info': {
                'name': template.name,
                'description': template.description,
                'severity': template.severity,
                'tags': template.tags,
                'authors': template.authors,
                'references': template.references,
                'metadata': template.metadata,
            },
            'requests': template.metadata.get('requests', []),
        }
        return yaml.dump(data, sort_keys=False)

    def create_template_from_finding(self, finding_data: Dict[str, Any]) -> NucleiTemplate:
        """Create a Nuclei template from a validated finding"""
        template = NucleiTemplate(
            id=f"custom-{finding_data.get('vuln_type', 'vuln')}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=finding_data.get('title', 'Custom Finding'),
            description=finding_data.get('description', ''),
            severity=finding_data.get('severity', 'medium').lower(),
            tags=[finding_data.get('vuln_type', ''), 'custom'],
            authors=['bug-hunter-agent'],
            references=[],
            metadata={
                'original_finding': finding_data,
                'requests': finding_data.get('poc_requests', []),
            },
        )
        return template

    def validate_template(self, template_path: str) -> Dict[str, Any]:
        """Validate a Nuclei template"""
        try:
            result = subprocess.run(
                ["nuclei", "-t", template_path, "-validate"],
                capture_output=True, text=True, timeout=30
            )
            return {
                "valid": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_template_stats(self) -> Dict[str, Any]:
        """Get template statistics"""
        all_templates = self.load_all_templates()

        severity_counts = {}
        tag_counts = {}

        for template in all_templates:
            severity_counts[template.severity] = severity_counts.get(template.severity, 0) + 1
            for tag in template.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total": len(all_templates),
            "by_severity": severity_counts,
            "top_tags": dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:20]),
            "custom_templates": len(list(self.custom_templates_dir.glob("*.yaml"))) if self.custom_templates_dir.exists() else 0,
        }


# Template development helpers
class TemplateBuilder:
    """Helper to build Nuclei templates programmatically"""

    def __init__(self, template_id: str, name: str, severity: str = "medium"):
        self.template = {
            'id': template_id,
            'info': {
                'name': name,
                'description': '',
                'severity': severity,
                'tags': [],
                'authors': ['bug-hunter-agent'],
                'references': [],
            },
            'requests': [],
        }

    def set_description(self, description: str):
        self.template['info']['description'] = description
        return self

    def add_tag(self, tag: str):
        self.template['info']['tags'].append(tag)
        return self

    def add_tags(self, tags: List[str]):
        self.template['info']['tags'].extend(tags)
        return self

    def add_reference(self, url: str):
        self.template['info']['references'].append(url)
        return self

    def add_request(self, request: Dict[str, Any]):
        self.template['requests'].append(request)
        return self

    def add_get_request(self, path: str, matchers: List[Dict] = None, extractors: List[Dict] = None):
        req = {
            'method': 'GET',
            'path': [path],
        }
        if matchers:
            req['matchers'] = matchers
        if extractors:
            req['extractors'] = extractors
        self.template['requests'].append(req)
        return self

    def add_post_request(self, path: str, body: str, headers: Dict = None,
                         matchers: List[Dict] = None, extractors: List[Dict] = None):
        req = {
            'method': 'POST',
            'path': [path],
            'body': body,
        }
        if headers:
            req['headers'] = headers
        if matchers:
            req['matchers'] = matchers
        if extractors:
            req['extractors'] = extractors
        self.template['requests'].append(req)
        return self

    def add_matcher_word(self, words: List[str], condition: str = "or", part: str = "body"):
        return {
            'type': 'word',
            'words': words,
            'condition': condition,
            'part': part,
        }

    def add_matcher_regex(self, regex: List[str], condition: str = "or", part: str = "body"):
        return {
            'type': 'regex',
            'regex': regex,
            'condition': condition,
            'part': part,
        }

    def add_matcher_status(self, status_codes: List[int]):
        return {
            'type': 'status',
            'status': status_codes,
        }

    def add_matcher_dsl(self, dsl: List[str]):
        return {
            'type': 'dsl',
            'dsl': dsl,
        }

    def add_extractor_regex(self, regex: List[str], name: str = "extract"):
        return {
            'type': 'regex',
            'name': name,
            'regex': regex,
        }

    def add_extractor_dsl(self, dsl: List[str], name: str = "extract"):
        return {
            'type': 'dsl',
            'name': name,
            'dsl': dsl,
        }

    def build(self) -> str:
        return yaml.dump(self.template, sort_keys=False)

    def save(self, path: str):
        with open(path, 'w') as f:
            f.write(self.build())