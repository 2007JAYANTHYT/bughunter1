"""
GitHub Skills Fetcher
Fetches and integrates bug hunting skills from GitHub repositories
"""

import asyncio
import json
import os
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GitHubSkill:
    """Skill fetched from GitHub"""
    name: str
    description: str
    category: str
    repo_url: str
    file_path: str
    content: str
    tags: List[str] = field(default_factory=list)
    stars: int = 0
    last_updated: str = ""


@dataclass
class PayloadRepo:
    """Payload repository from GitHub"""
    name: str
    url: str
    description: str
    categories: List[str] = field(default_factory=list)
    stars: int = 0
    last_updated: str = ""


@dataclass
class WriteupPattern:
    """Bug bounty writeup pattern"""
    title: str
    url: str
    platform: str
    vuln_type: str
    severity: str
    bounty: float = 0
    techniques: List[str] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)


class GitHubSkillsFetcher:
    """Fetches skills, payloads, and methodologies from GitHub"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.skills_dir = Path("skills")
        self.payloads_dir = Path("payloads")
        self.methodology_dir = Path("skills/methodology")

    async def fetch_methodology_skills(self) -> List[GitHubSkill]:
        """Fetch methodology skills from key repositories"""
        skills = []

        # Key methodology repos
        repos = [
            {
                "url": "https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters",
                "category": "methodology",
                "tags": ["beginner", "resources", "methodology"],
            },
            {
                "url": "https://github.com/EdOverflow/bugbounty-cheatsheet",
                "category": "methodology",
                "tags": ["cheatsheet", "methodology", "checklist"],
            },
            {
                "url": "https://github.com/0xRadi/OWASP-Web-Checklist",
                "category": "checklist",
                "tags": ["owasp", "checklist", "web"],
            },
            {
                "url": "https://github.com/six2dez/reconftw",
                "category": "recon",
                "tags": ["recon", "automation", "subdomain"],
            },
            {
                "url": "https://github.com/Dheerajmadhukar/karma_V2",
                "category": "recon",
                "tags": ["recon", "automation", "passive"],
            },
            {
                "url": "https://github.com/mazen160/Gospider",
                "category": "crawling",
                "tags": ["crawling", "spider", "content-discovery"],
            },
        ]

        for repo in repos:
            try:
                repo_skills = await self._fetch_repo_skills(repo)
                skills.extend(repo_skills)
            except Exception as e:
                print(f"Failed to fetch {repo['url']}: {e}")

        return skills

    async def _fetch_repo_skills(self, repo_info: Dict) -> List[GitHubSkill]:
        """Fetch skills from a single repository"""
        skills = []

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Shallow clone
                result = subprocess.run([
                    "git", "clone", "--depth", "1", repo_info["url"], tmpdir + "/repo"
                ], capture_output=True, text=True, timeout=60)

                if result.returncode != 0:
                    return skills

                repo_path = Path(tmpdir) / "repo"

                # Find markdown files
                for md_file in repo_path.rglob("*.md"):
                    try:
                        skill = self._parse_markdown_skill(md_file, repo_info)
                        if skill:
                            skills.append(skill)
                    except Exception:
                        pass

            except Exception as e:
                print(f"Error fetching repo {repo_info['url']}: {e}")

        return skills

    def _parse_markdown_skill(self, file_path: Path, repo_info: Dict) -> Optional[GitHubSkill]:
        """Parse a markdown file as a skill"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Extract title from first heading
            title = file_path.stem
            for line in content.split('\n'):
                if line.startswith('# '):
                    title = line[2:].strip()
                    break

            # Extract description
            description = ""
            for line in content.split('\n'):
                if line.startswith('## ') and 'description' in line.lower():
                    idx = content.split('\n').index(line)
                    for next_line in content.split('\n')[idx+1:]:
                        if next_line.strip() and not next_line.startswith('#'):
                            description = next_line.strip()
                            break
                    break

            if not description and len(content) > 100:
                description = content[:200] + "..."

            return GitHubSkill(
                name=title,
                description=description,
                category=repo_info.get("category", "general"),
                repo_url=repo_info["url"],
                file_path=str(file_path.relative_to(Path(tmpdir) / "repo")),
                content=content[:5000],  # Limit content size
                tags=repo_info.get("tags", []),
            )
        except Exception:
            return None

    async def fetch_payload_repos(self) -> List[PayloadRepo]:
        """Fetch payload repositories"""
        repos = [
            {
                "name": "PayloadsAllTheThings",
                "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
                "description": "Comprehensive payload collection for web app security",
                "categories": ["xss", "sqli", "ssrf", "rce", "ssti", "xxe", "idor", "auth", "logic"],
            },
            {
                "name": "SecLists",
                "url": "https://github.com/danielmiessler/SecLists",
                "description": "Collection of security testing wordlists",
                "categories": ["fuzzing", "passwords", "usernames", "urls", "subdomains"],
            },
            {
                "name": "FuzzDB",
                "url": "https://github.com/fuzzdb-project/fuzzdb",
                "description": "Comprehensive fuzzing database",
                "categories": ["fuzzing", "attack-patterns", "discovery"],
            },
            {
                "name": "HackVault",
                "url": "https://github.com/0xsobky/HackVault",
                "description": "Nuclei templates and payloads",
                "categories": ["nuclei", "templates", "cve"],
            },
        ]

        payload_repos = []
        for repo in repos:
            # Get repo info via GitHub API
            repo_info = await self._get_github_repo_info(repo["url"])
            if repo_info:
                payload_repos.append(PayloadRepo(
                    name=repo["name"],
                    url=repo["url"],
                    description=repo["description"],
                    categories=repo["categories"],
                    stars=repo_info.get("stargazers_count", 0),
                    last_updated=repo_info.get("pushed_at", ""),
                ))

        return payload_repos

    async def _get_github_repo_info(self, url: str) -> Optional[Dict]:
        """Get repository info from GitHub API"""
        try:
            # Extract owner/repo from URL
            import re
            match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
            if not match:
                return None

            owner, repo = match.groups()
            repo = repo.replace('.git', '')

            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"

            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return None

    async def fetch_writeup_patterns(self) -> List[WriteupPattern]:
        """Analyze public writeups for hunting patterns"""
        patterns = []

        # This would fetch from bug bounty writeup repos
        writeup_repos = [
            "https://github.com/bugbountywriteups/bug-bounty-writeups",
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
        ]

        for repo_url in writeup_repos:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = subprocess.run([
                        "git", "clone", "--depth", "1", repo_url, tmpdir + "/repo"
                    ], capture_output=True, text=True, timeout=60)

                    if result.returncode == 0:
                        repo_path = Path(tmpdir) / "repo"
                        for md_file in repo_path.rglob("*.md"):
                            pattern = self._analyze_writeup(md_file)
                            if pattern:
                                patterns.append(pattern)
            except Exception:
                pass

        return patterns

    def _analyze_writeup(self, file_path: Path) -> Optional[WriteupPattern]:
        """Analyze a writeup for patterns"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Extract key info
            title = file_path.stem
            for line in content.split('\n'):
                if line.startswith('# '):
                    title = line[2:].strip()
                    break

            # Detect vulnerability type
            vuln_types = ["xss", "sqli", "ssrf", "rce", "idor", "auth bypass", "csrf", "xxe", "ssti", "race condition"]
            found_type = "unknown"
            for vt in vuln_types:
                if vt.lower() in content.lower():
                    found_type = vt
                    break

            # Detect platform
            platforms = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "synack"]
            found_platform = "unknown"
            for p in platforms:
                if p.lower() in content.lower():
                    found_platform = p
                    break

            # Extract bounty amount
            bounty = 0
            import re
            bounty_match = re.search(r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)', content)
            if bounty_match:
                bounty = float(bounty_match.group(1).replace(',', ''))

            return WriteupPattern(
                title=title,
                url=str(file_path),
                platform=found_platform,
                vuln_type=found_type,
                severity="P1",  # Would need more analysis
                bounty=bounty,
                techniques=self._extract_techniques(content),
                key_findings=self._extract_key_findings(content),
            )
        except Exception:
            return None

    def _extract_techniques(self, content: str) -> List[str]:
        """Extract techniques from writeup"""
        techniques = []
        tech_keywords = [
            "bypass", "filter", "encoding", "polyglot", "mutation", "prototype pollution",
            "dom clobbering", "cache poisoning", "deserialization", "template injection",
            "race condition", "idors", "mass assignment", "jwt", "oauth", "sso",
        ]
        content_lower = content.lower()
        for tech in tech_keywords:
            if tech in content_lower:
                techniques.append(tech)
        return techniques

    def _extract_key_findings(self, content: str) -> List[str]:
        """Extract key findings from writeup"""
        findings = []
        # Look for common finding patterns
        lines = content.split('\n')
        for line in lines:
            if any(kw in line.lower() for kw in ['found', 'discovered', 'vulnerable', 'exploit', 'bypass']):
                if len(line.strip()) > 20 and len(line.strip()) < 200:
                    findings.append(line.strip())
        return findings[:5]

    async def save_skills_locally(self, skills: List[GitHubSkill], output_dir: str = "skills/github"):
        """Save fetched skills locally as markdown files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for skill in skills:
            # Create category directory
            cat_dir = output_path / skill.category
            cat_dir.mkdir(parents=True, exist_ok=True)

            # Create skill file
            safe_name = "".join(c for c in skill.name if c.isalnum() or c in '-_ ')[:100]
            file_path = cat_dir / f"{safe_name}.md"

            content = f"""---
name: {skill.name}
description: {skill.description}
category: {skill.category}
tags: {skill.tags}
repo_url: {skill.repo_url}
file_path: {skill.file_path}
---

# {skill.name}

{skill.description}

## Source
- Repository: {skill.repo_url}
- File: {skill.file_path}

## Content
{skill.content}
"""
            file_path.write_text(content, encoding='utf-8')


# Convenience functions
async def fetch_all_github_skills(config_manager=None) -> Dict[str, Any]:
    """Fetch all skills from GitHub"""
    fetcher = GitHubSkillsFetcher(config_manager)

    results = {
        "methodology_skills": await fetcher.fetch_methodology_skills(),
        "payload_repos": await fetcher.fetch_payload_repos(),
        "writeup_patterns": await fetcher.fetch_writeup_patterns(),
    }

    return results


async def update_local_skills(config_manager=None):
    """Update local skills from GitHub"""
    fetcher = GitHubSkillsFetcher(config_manager)

    # Fetch methodology skills
    skills = await fetcher.fetch_methodology_skills()

    # Save locally
    await fetcher.save_skills_locally(skills)

    # Fetch payload repos
    payload_repos = await fetcher.fetch_payload_repos()

    return {
        "skills_fetched": len(skills),
        "payload_repos": len(payload_repos),
    }


import os