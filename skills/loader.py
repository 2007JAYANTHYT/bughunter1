"""
Skills Loader
Loads and manages bug hunting skills from markdown files
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class Skill:
    """Bug hunting skill"""
    name: str
    description: str
    category: str
    tags: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    steps: List[Dict] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    detection: Dict = field(default_factory=dict)
    mitigation: str = ""
    content: str = ""
    file_path: str = ""


class SkillsLoader:
    """Loads and manages skills"""

    def __init__(self, skills_dir: str = "skills"):
        self.skills_dir = Path(skills_dir)
        self.skills: Dict[str, Skill] = {}
        self.categories: Dict[str, List[str]] = {}

    def load_all(self) -> Dict[str, Skill]:
        """Load all skills from directory"""
        if not self.skills_dir.exists():
            return {}

        for skill_file in self.skills_dir.rglob("SKILL.md"):
            try:
                skill = self._load_skill(skill_file)
                if skill:
                    self.skills[skill.name] = skill
                    cat = skill.category
                    if cat not in self.categories:
                        self.categories[cat] = []
                    self.categories[cat].append(skill.name)
            except Exception as e:
                print(f"Failed to load skill from {skill_file}: {e}")

        return self.skills

    def _load_skill(self, file_path: Path) -> Optional[Skill]:
        """Load a single skill from markdown file"""
        content = file_path.read_text(encoding='utf-8')

        # Parse frontmatter
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                frontmatter = yaml.safe_load(parts[1])
                body = parts[2].strip()
            else:
                frontmatter = {}
                body = content
        else:
            frontmatter = {}
            body = content

        # Extract skill info
        name = frontmatter.get('name', file_path.parent.name)
        description = frontmatter.get('description', '')
        category = frontmatter.get('category', 'general')
        tags = frontmatter.get('tags', [])
        prerequisites = frontmatter.get('prerequisites', [])
        steps = frontmatter.get('steps', [])
        references = frontmatter.get('references', [])
        tools = frontmatter.get('tools', [])
        payloads = frontmatter.get('payloads', [])
        detection = frontmatter.get('detection', {})
        mitigation = frontmatter.get('mitigation', '')

        # If no frontmatter, parse from markdown
        if not frontmatter:
            name, description, category, tags = self._parse_markdown(body, file_path.parent.name)

        skill = Skill(
            name=name,
            description=description,
            category=category,
            tags=tags,
            prerequisites=prerequisites,
            steps=steps,
            references=references,
            tools=tools,
            payloads=payloads,
            detection=detection,
            mitigation=mitigation,
            content=body,
            file_path=str(file_path),
        )

        return skill

    def _parse_markdown(self, content: str, default_name: str) -> tuple:
        """Parse skill info from markdown content"""
        lines = content.split('\n')
        name = default_name
        description = ""
        category = "general"
        tags = []

        for line in lines:
            if line.startswith('# '):
                name = line[2:].strip()
            elif line.startswith('## Description'):
                # Get next non-empty line
                idx = lines.index(line)
                for next_line in lines[idx+1:]:
                    if next_line.strip() and not next_line.startswith('#'):
                        description = next_line.strip()
                        break
            elif line.startswith('**Category**:') or line.startswith('Category:'):
                category = line.split(':', 1)[1].strip()
            elif line.startswith('**Tags**:') or line.startswith('Tags:'):
                tags_str = line.split(':', 1)[1].strip()
                tags = [t.strip() for t in tags_str.split(',')]

        return name, description, category, tags

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get skill by name"""
        return self.skills.get(name)

    def get_skills_by_category(self, category: str) -> List[Skill]:
        """Get all skills in a category"""
        names = self.categories.get(category, [])
        return [self.skills[n] for n in names if n in self.skills]

    def get_skills_by_tag(self, tag: str) -> List[Skill]:
        """Get all skills with a tag"""
        return [s for s in self.skills.values() if tag in s.tags]

    def search_skills(self, query: str) -> List[Skill]:
        """Search skills by query"""
        query = query.lower()
        results = []
        for skill in self.skills.values():
            if (query in skill.name.lower() or
                query in skill.description.lower() or
                query in skill.category.lower() or
                any(query in tag.lower() for tag in skill.tags)):
                results.append(skill)
        return results

    def get_categories(self) -> List[str]:
        """Get all categories"""
        return list(self.categories.keys())

    def get_skill_summary(self, name: str) -> Optional[Dict]:
        """Get skill summary for quick reference"""
        skill = self.get_skill(name)
        if not skill:
            return None

        return {
            "name": skill.name,
            "description": skill.description,
            "category": skill.category,
            "tags": skill.tags,
            "prerequisites": skill.prerequisites,
            "tools": skill.tools,
            "payloads_count": len(skill.payloads),
            "steps_count": len(skill.steps),
        }

    def export_skills_index(self, output_file: str = "skills_index.json"):
        """Export skills index as JSON"""
        index = {}
        for name, skill in self.skills.items():
            index[name] = {
                "name": skill.name,
                "description": skill.description,
                "category": skill.category,
                "tags": skill.tags,
                "prerequisites": skill.prerequisites,
                "tools": skill.tools,
                "file_path": skill.file_path,
            }

        with open(output_file, 'w') as f:
            json.dump(index, f, indent=2)

        return index


# Global skills loader
skills_loader = SkillsLoader()


def load_skills(skills_dir: str = "skills") -> Dict[str, Skill]:
    """Load all skills"""
    global skills_loader
    skills_loader = SkillsLoader(skills_dir)
    return skills_loader.load_all()


def get_skill(name: str) -> Optional[Skill]:
    """Get skill by name"""
    return skills_loader.get_skill(name)


def search_skills(query: str) -> List[Skill]:
    """Search skills"""
    return skills_loader.search_skills(query)


def get_skills_by_category(category: str) -> List[Skill]:
    """Get skills by category"""
    return skills_loader.get_skills_by_category(category)


def get_skills_by_tag(tag: str) -> List[Skill]:
    """Get skills by tag"""
    return skills_loader.get_skills_by_tag(tag)