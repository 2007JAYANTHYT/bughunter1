"""
Scope Checklist Manager
Interactive scope tracking with coverage metrics, testing status, and visual progress
"""

import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from core.config_manager import get_config
from core.database import db_manager, ScopeChecklistCRUD, ScopeStatus, ScopeChecklist
from core.scope_fetcher import ScopeFetcher, ProgramScope, ScopeType, ScopeRule


class ChecklistItemType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    CIDR = "cidr"
    WILDCARD = "wildcard"
    REGEX = "regex"
    API_ENDPOINT = "api_endpoint"
    MOBILE_APP = "mobile_app"
    CLOUD_RESOURCE = "cloud_resource"


@dataclass
class ScopeChecklistItem:
    """Enhanced scope checklist item"""
    id: int
    program_id: int
    item_type: str  # in_scope, out_of_scope
    pattern: str
    pattern_type: ChecklistItemType
    description: str
    status: str  # pending, testing, tested, skipped
    tested_at: Optional[str] = None
    tested_by: str = ""
    notes: str = ""
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    last_scan: Optional[str] = None


@dataclass
class CoverageMetrics:
    """Scope coverage metrics"""
    program_id: int
    total_in_scope: int
    total_out_of_scope: int
    tested_in_scope: int
    tested_out_of_scope: int
    skipped_in_scope: int
    skipped_out_of_scope: int
    pending_in_scope: int
    pending_out_of_scope: int
    coverage_percentage: float
    findings_total: int
    critical_high_findings: int
    last_updated: str


@dataclass
class ChecklistProgress:
    """Progress tracking for scope testing"""
    item_id: int
    status: str
    progress_percentage: float
    sub_items: List[Dict] = field(default_factory=list)
    estimated_completion: Optional[str] = None


class ScopeChecklistManager:
    """Manages scope checklists with interactive tracking"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.scope_fetcher = ScopeFetcher(config_manager)

    async def generate_checklist(self, program_name: str) -> List[ScopeChecklistItem]:
        """Generate scope checklist from program scope"""
        async with self.scope_fetcher as fetcher:
            scope = await fetcher.fetch_program_scope(program_name)

        # Get program ID
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            program = await ProgramCRUD.get_by_name(session, program_name)
            if not program:
                raise ValueError(f"Program not found: {program_name}")

            # Clear existing checklist
            await self._clear_checklist(session, program.id)

            # Create checklist items
            items = []

            # In-scope items
            for rule in scope.in_scope:
                item = await self._create_checklist_item(
                    session, program.id, rule, ScopeType.IN_SCOPE
                )
                items.append(item)

            # Out-of-scope items
            for rule in scope.out_of_scope:
                item = await self._create_checklist_item(
                    session, program.id, rule, ScopeType.OUT_OF_SCOPE
                )
                items.append(item)

            await session.commit()

        return items

    async def _clear_checklist(self, session, program_id: int):
        """Clear existing checklist for program"""
        from sqlalchemy import delete
        await session.execute(
            delete(ScopeChecklist).where(ScopeChecklist.program_id == program_id)
        )

    async def _create_checklist_item(self, session, program_id: int,
                                      rule: ScopeRule, scope_type: ScopeType) -> ScopeChecklistItem:
        """Create a checklist item from scope rule"""
        pattern_type = self._determine_pattern_type(rule)

        item = ScopeChecklist(
            program_id=program_id,
            item_type=scope_type.value,
            pattern=rule.pattern,
            description=rule.description,
            status=ScopeStatus.PENDING.value,
        )

        created = await ScopeChecklistCRUD.create(session, item)

        return ScopeChecklistItem(
            id=created.id,
            program_id=program_id,
            item_type=scope_type.value,
            pattern=rule.pattern,
            pattern_type=pattern_type,
            description=rule.description,
            status=ScopeStatus.PENDING.value,
        )

    def _determine_pattern_type(self, rule: ScopeRule) -> ChecklistItemType:
        """Determine pattern type from rule"""
        if rule.is_cidr:
            return ChecklistItemType.CIDR
        elif rule.is_regex:
            return ChecklistItemType.REGEX
        elif rule.is_wildcard:
            return ChecklistItemType.WILDCARD
        elif '.' in rule.pattern and not rule.pattern.startswith('*.'):
            return ChecklistItemType.DOMAIN
        elif rule.pattern.startswith('*.'):
            return ChecklistItemType.SUBDOMAIN
        return ChecklistItemType.DOMAIN

    async def get_checklist(self, program_name: str) -> List[ScopeChecklistItem]:
        """Get checklist for a program"""
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            program = await ProgramCRUD.get_by_name(session, program_name)
            if not program:
                raise ValueError(f"Program not found: {program_name}")

            items = await ScopeChecklistCRUD.get_by_program(session, program.id)

            return [self._to_checklist_item(item) for item in items]

    def _to_checklist_item(self, item: ScopeChecklist) -> ScopeChecklistItem:
        """Convert DB item to checklist item"""
        # Determine pattern type
        rule = ScopeRule(pattern=item.pattern, scope_type=ScopeType(item.item_type))
        pattern_type = self._determine_pattern_type(rule)

        return ScopeChecklistItem(
            id=item.id,
            program_id=item.program_id,
            item_type=item.item_type,
            pattern=item.pattern,
            pattern_type=pattern_type,
            description=item.description,
            status=item.status,
            tested_at=item.tested_at.isoformat() if item.tested_at else None,
            notes=item.notes or "",
        )

    async def update_item_status(self, item_id: int, status: str,
                                  notes: str = "", tested_by: str = "") -> bool:
        """Update checklist item status"""
        async with db_manager.get_session() as session:
            item = await ScopeChecklistCRUD.update_status(session, item_id, status, notes)
            if item:
                # Update tested_by in notes
                if tested_by:
                    item.notes = f"Tested by: {tested_by}\n{item.notes or ''}"
                    await session.commit()
                return True
            return False

    async def mark_tested(self, item_id: int, findings_count: int = 0,
                          critical: int = 0, high: int = 0,
                          notes: str = "", tested_by: str = "") -> bool:
        """Mark item as tested with findings summary"""
        async with db_manager.get_session() as session:
            from core.database import ScopeChecklist
            from sqlalchemy import select

            result = await session.execute(
                select(ScopeChecklist).where(ScopeChecklist.id == item_id)
            )
            item = result.scalar_one_or_none()

            if item:
                item.status = ScopeStatus.TESTED.value
                item.tested_at = datetime.utcnow()
                if notes:
                    item.notes = f"{notes}\nTested by: {tested_by}\nFindings: {findings_count} (Critical: {critical}, High: {high})"
                await session.commit()
                return True
            return False

    async def skip_item(self, item_id: int, reason: str = "") -> bool:
        """Skip an item (out of scope, not applicable, etc.)"""
        return await self.update_item_status(item_id, ScopeStatus.SKIPPED.value,
                                            notes=f"Skipped: {reason}")

    async def start_testing(self, item_id: int, tested_by: str = "") -> bool:
        """Mark item as currently being tested"""
        return await self.update_item_status(item_id, ScopeStatus.TESTING.value,
                                            notes=f"Testing started by: {tested_by}")

    async def get_coverage_metrics(self, program_name: str) -> CoverageMetrics:
        """Calculate scope coverage metrics"""
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD, FindingCRUD, FindingSeverity
            from sqlalchemy import select, func

            program = await ProgramCRUD.get_by_name(session, program_name)
            if not program:
                raise ValueError(f"Program not found: {program_name}")

            # Get checklist items
            items = await ScopeChecklistCRUD.get_by_program(session, program.id)

            # Count by status and type
            in_scope_items = [i for i in items if i.item_type == "in_scope"]
            out_scope_items = [i for i in items if i.item_type == "out_of_scope"]

            tested_in = sum(1 for i in in_scope_items if i.status == ScopeStatus.TESTED.value)
            tested_out = sum(1 for i in out_scope_items if i.status == ScopeStatus.TESTED.value)
            skipped_in = sum(1 for i in in_scope_items if i.status == ScopeStatus.SKIPPED.value)
            skipped_out = sum(1 for i in out_scope_items if i.status == ScopeStatus.SKIPPED.value)
            pending_in = sum(1 for i in in_scope_items if i.status == ScopeStatus.PENDING.value)
            pending_out = sum(1 for i in out_scope_items if i.status == ScopeStatus.PENDING.value)

            total_in = len(in_scope_items)
            total_out = len(out_scope_items)

            coverage = (tested_in + skipped_in) / max(total_in, 1) * 100

            # Get findings stats
            stats = await FindingCRUD.count_by_program(session, program.id)
            findings_by_sev = {}
            for sev in ["P1", "P2", "P3", "P4"]:
                findings_by_sev[sev] = await FindingCRUD.count_by_program(
                    session, program.id, severity=sev
                )

            return CoverageMetrics(
                program_id=program.id,
                total_in_scope=total_in,
                total_out_of_scope=total_out,
                tested_in_scope=tested_in,
                tested_out_of_scope=tested_out,
                skipped_in_scope=skipped_in,
                skipped_out_of_scope=skipped_out,
                pending_in_scope=pending_in,
                pending_out_of_scope=pending_out,
                coverage_percentage=coverage,
                findings_total=stats,
                critical_high_findings=findings_by_sev.get("P1", 0) + findings_by_sev.get("P2", 0),
                last_updated=datetime.utcnow().isoformat(),
            )

    async def get_progress(self, program_name: str) -> Dict[str, Any]:
        """Get detailed progress for checklist"""
        items = await self.get_checklist(program_name)
        metrics = await self.get_coverage_metrics(program_name)

        # Group by pattern type
        by_type = {}
        for item in items:
            type_key = item.pattern_type.value
            if type_key not in by_type:
                by_type[type_key] = {"total": 0, "tested": 0, "pending": 0, "skipped": 0}
            by_type[type_key]["total"] += 1
            if item.status == ScopeStatus.TESTED.value:
                by_type[type_key]["tested"] += 1
            elif item.status == ScopeStatus.PENDING.value:
                by_type[type_key]["pending"] += 1
            elif item.status == ScopeStatus.SKIPPED.value:
                by_type[type_key]["skipped"] += 1

        # Calculate progress per type
        for type_key, stats in by_type.items():
            tested = stats["tested"] + stats["skipped"]
            stats["progress"] = (tested / max(stats["total"], 1)) * 100

        return {
            "metrics": metrics.__dict__,
            "by_type": by_type,
            "items": [self._item_to_dict(item) for item in items],
        }

    def _item_to_dict(self, item: ScopeChecklistItem) -> Dict:
        return {
            "id": item.id,
            "type": item.item_type,
            "pattern_type": item.pattern_type.value,
            "pattern": item.pattern,
            "description": item.description,
            "status": item.status,
            "tested_at": item.tested_at,
            "findings_count": item.findings_count,
            "critical_findings": item.critical_findings,
            "high_findings": item.high_findings,
            "notes": item.notes,
        }

    async def export_checklist(self, program_name: str, format: str = "json") -> str:
        """Export checklist"""
        progress = await self.get_progress(program_name)

        if format == "json":
            return json.dumps(progress, indent=2)

        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Type", "Pattern Type", "Pattern", "Description", "Status", "Tested At", "Notes"])
            for item in progress["items"]:
                writer.writerow([
                    item["id"], item["type"], item["pattern_type"],
                    item["pattern"], item["description"], item["status"],
                    item["tested_at"] or "", item["notes"]
                ])
            return output.getvalue()

        elif format == "markdown":
            lines = [f"# Scope Checklist: {program_name}", ""]
            lines.append(f"**Coverage:** {progress['metrics']['coverage_percentage']:.1f}%")
            lines.append(f"**Total In-Scope:** {progress['metrics']['total_in_scope']}")
            lines.append(f"**Tested:** {progress['metrics']['tested_in_scope']}")
            lines.append(f"**Pending:** {progress['metrics']['pending_in_scope']}")
            lines.append("")

            for type_key, stats in progress["by_type"].items():
                lines.append(f"## {type_key.title()} ({stats['progress']:.1f}% complete)")
                lines.append("")
                lines.append("| Pattern | Status | Tested | Notes |")
                lines.append("|---------|--------|--------|-------|")
                for item in progress["items"]:
                    if item["pattern_type"] == type_key:
                        lines.append(f"| {item['pattern']} | {item['status']} | {item['tested_at'] or 'No'} | {item['notes'][:50]}... |")
                lines.append("")

            return "\n".join(lines)

        return ""

    async def auto_mark_tested_from_findings(self, program_name: str) -> Dict[str, int]:
        """Auto-mark items as tested based on existing findings"""
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD, Finding, Target
            from sqlalchemy import select, func

            program = await ProgramCRUD.get_by_name(session, program_name)
            if not program:
                raise ValueError(f"Program not found: {program_name}")

            # Get all findings with their targets
            result = await session.execute(
                select(Finding, Target)
                .join(Target, Finding.target_id == Target.id)
                .where(Finding.program_id == program.id)
            )
            findings_with_targets = result.all()

            # Map findings to scope patterns
            items = await ScopeChecklistCRUD.get_by_program(session, program.id)

            updated = 0
            for item in items:
                if item.status in [ScopeStatus.TESTED.value, ScopeStatus.SKIPPED.value]:
                    continue

                # Check if any finding matches this scope pattern
                scope_checker = self.scope_fetcher._create_scope_checker(
                    type('obj', (object,), {'in_scope': [ScopeRule(pattern=item.pattern, scope_type=ScopeType.IN_SCOPE, is_wildcard='*' in item.pattern)]}, {'out_of_scope': []})()
                )

                matched = False
                for finding, target in findings_with_targets:
                    check_result = scope_checker.check(target.subdomain or target.domain)
                    if check_result.in_scope and check_result.matched_rule and check_result.matched_rule.pattern == item.pattern:
                        matched = True
                        break

                if matched:
                    # Count findings for this pattern
                    finding_count = 0
                    critical = 0
                    high = 0
                    for finding, target in findings_with_targets:
                        check_result = scope_checker.check(target.subdomain or target.domain)
                        if check_result.in_scope and check_result.matched_rule and check_result.matched_rule.pattern == item.pattern:
                            finding_count += 1
                            if finding.severity == "P1":
                                critical += 1
                            elif finding.severity == "P2":
                                high += 1

                    await self.mark_tested(item.id, finding_count, critical, high, "Auto-marked from findings")
                    updated += 1

            return {"updated": updated, "total_items": len(items)}


async def generate_checklist(program_name: str, config_manager=None) -> List[ScopeChecklistItem]:
    manager = ScopeChecklistManager(config_manager)
    return await manager.generate_checklist(program_name)


async def get_checklist(program_name: str, config_manager=None) -> List[ScopeChecklistItem]:
    manager = ScopeChecklistManager(config_manager)
    return await manager.get_checklist(program_name)


async def get_coverage(program_name: str, config_manager=None) -> CoverageMetrics:
    manager = ScopeChecklistManager(config_manager)
    return await manager.get_coverage_metrics(program_name)