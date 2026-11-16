"""
Bug Database Manager
Manages bug lifecycle: new → validated → reported → fixed → paid
With reported/unreported separation and deduplication
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from core.config_manager import get_config
from core.database import db_manager, FindingCRUD, ProgramCRUD, FindingStatus, FindingSeverity
from core.database import Finding, Evidence, ScopeChecklist, ActivityLog
from hunting.scanner_orchestrator import VulnerabilityFinding


class BugListType(str, Enum):
    REPORTED = "reported"
    UNREPORTED = "unreported"
    ALL = "all"


@dataclass
class BugRecord:
    """Enhanced bug record with tracking info"""
    id: int
    program_id: int
    program_name: str
    vuln_type: str
    severity: str
    title: str
    description: str
    status: str
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    impact: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    evidence_paths: List[str] = field(default_factory=list)
    poc: str = ""
    reported_url: str = ""
    reported_at: Optional[str] = None
    created_at: str = ""
    validated_at: Optional[str] = None
    duplicate_of: Optional[int] = None
    is_reported: bool = False


@dataclass
class BugFilters:
    """Filters for bug queries"""
    program_id: Optional[int] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    vuln_type: Optional[str] = None
    is_reported: Optional[bool] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0


@dataclass
class BugStats:
    """Program bug statistics"""
    program_id: int
    program_name: str
    total: int = 0
    by_status: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_type: Dict[str, int] = field(default_factory=dict)
    reported_count: int = 0
    unreported_count: int = 0
    scope_coverage: float = 0.0
    avg_cvss: float = 0.0


class BugDatabaseManager:
    """Manages bug database with full lifecycle tracking"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()

    async def add_finding(self, finding: VulnerabilityFinding) -> BugRecord:
        """Add a new finding from hunting"""
        async with db_manager.get_session() as session:
            db_finding = await FindingCRUD.create(session, Finding(
                program_id=finding.program_id if hasattr(finding, 'program_id') else 0,
                target_id=finding.target.target_id if hasattr(finding.target, 'target_id') else None,
                endpoint_id=finding.target.endpoint_id if hasattr(finding.target, 'endpoint_id') else None,
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                poc=finding.poc,
                status=FindingStatus.NEW.value,
                tags=finding.tags or [],
            ))

            return await self._to_bug_record(db_finding, session)

    async def get_bugs(self, filters: BugFilters) -> List[BugRecord]:
        """Get bugs with filters"""
        async with db_manager.get_session() as session:
            from sqlalchemy import select, and_, or_, func

            query = select(Finding).join(ProgramCRUD.__table__ if hasattr(ProgramCRUD, '__table__') else Program)

            # Build filters
            conditions = []
            if filters.program_id:
                conditions.append(Finding.program_id == filters.program_id)
            if filters.status:
                conditions.append(Finding.status == filters.status)
            if filters.severity:
                conditions.append(Finding.severity == filters.severity)
            if filters.vuln_type:
                conditions.append(Finding.vuln_type == filters.vuln_type)
            if filters.is_reported is not None:
                if filters.is_reported:
                    conditions.append(Finding.status == FindingStatus.REPORTED.value)
                else:
                    conditions.append(Finding.status != FindingStatus.REPORTED.value)
            if filters.date_from:
                conditions.append(Finding.created_at >= filters.date_from)
            if filters.date_to:
                conditions.append(Finding.created_at <= filters.date_to)
            if filters.search:
                conditions.append(
                    or_(
                        Finding.title.ilike(f"%{filters.search}%"),
                        Finding.description.ilike(f"%{filters.search}%"),
                        Finding.vuln_type.ilike(f"%{filters.search}%"),
                    )
                )

            if conditions:
                query = query.where(and_(*conditions))

            query = query.order_by(Finding.created_at.desc()).limit(filters.limit).offset(filters.offset)

            result = await session.execute(query)
            findings = result.scalars().all()

            return [await self._to_bug_record(f, session) for f in findings]

    async def get_bug(self, bug_id: int) -> Optional[BugRecord]:
        """Get single bug by ID"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.get(session, bug_id)
            if finding:
                return await self._to_bug_record(finding, session)
            return None

    async def mark_reported(self, bug_id: int, report_url: str, platform: str = "") -> bool:
        """Mark bug as reported"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.get(session, bug_id)
            if not finding:
                return False

            finding.status = FindingStatus.REPORTED.value
            finding.reported_at = datetime.utcnow()
            finding.evidence = finding.evidence or {}
            finding.evidence['report_url'] = report_url
            finding.evidence['report_platform'] = platform

            await session.commit()

            # Log activity
            await self._log_activity(session, bug_id, finding.program_id, "reported", {
                "report_url": report_url,
                "platform": platform,
            })

            return True

    async def mark_duplicate(self, bug_id: int, duplicate_of: int) -> bool:
        """Mark bug as duplicate"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.mark_duplicate(session, bug_id, duplicate_of)
            if finding:
                await self._log_activity(session, bug_id, finding.program_id, "marked_duplicate", {
                    "duplicate_of": duplicate_of,
                })
                return True
            return False

    async def mark_false_positive(self, bug_id: int, reason: str = "") -> bool:
        """Mark bug as false positive"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.update_status(session, bug_id, FindingStatus.FALSE_POSITIVE.value)
            if finding:
                await self._log_activity(session, bug_id, finding.program_id, "false_positive", {
                    "reason": reason,
                })
                return True
            return False

    async def mark_fixed(self, bug_id: int, bounty_amount: float = 0, bounty_currency: str = "USD") -> bool:
        """Mark bug as fixed with bounty info"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.get(session, bug_id)
            if not finding:
                return False

            finding.status = FindingStatus.FIXED.value
            finding.evidence = finding.evidence or {}
            finding.evidence['bounty_amount'] = bounty_amount
            finding.evidence['bounty_currency'] = bounty_currency
            finding.evidence['fixed_at'] = datetime.utcnow().isoformat()

            await session.commit()

            await self._log_activity(session, bug_id, finding.program_id, "fixed", {
                "bounty_amount": bounty_amount,
                "bounty_currency": bounty_currency,
            })

            return True

    async def mark_paid(self, bug_id: int, amount: float, currency: str = "USD") -> bool:
        """Mark bug as paid (bounty received)"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.get(session, bug_id)
            if not finding:
                return False

            finding.status = FindingStatus.PAID.value
            finding.evidence = finding.evidence or {}
            finding.evidence['paid_amount'] = amount
            finding.evidence['paid_currency'] = currency
            finding.evidence['paid_at'] = datetime.utcnow().isoformat()

            await session.commit()

            await self._log_activity(session, bug_id, finding.program_id, "paid", {
                "amount": amount,
                "currency": currency,
            })

            return True

    async def update_bug(self, bug_id: int, **kwargs) -> Optional[BugRecord]:
        """Update bug fields"""
        async with db_manager.get_session() as session:
            finding = await FindingCRUD.get(session, bug_id)
            if not finding:
                return None

            for key, value in kwargs.items():
                if hasattr(finding, key):
                    setattr(finding, key, value)

            finding.updated_at = datetime.utcnow()
            await session.commit()
            await session.refresh(finding)

            await self._log_activity(session, bug_id, finding.program_id, "updated", kwargs)

            return await self._to_bug_record(finding, session)

    async def get_reported_bugs(self, program_id: int = None) -> List[BugRecord]:
        """Get all reported bugs"""
        filters = BugFilters(
            program_id=program_id,
            status=FindingStatus.REPORTED.value,
        )
        return await self.get_bugs(filters)

    async def get_unreported_bugs(self, program_id: int = None) -> List[BugRecord]:
        """Get all unreported bugs (validated but not reported)"""
        filters = BugFilters(
            program_id=program_id,
            is_reported=False,
        )
        return await self.get_bugs(filters)

    async def get_stats(self, program_id: int) -> BugStats:
        """Get program bug statistics"""
        async with db_manager.get_session() as session:
            from core.database import StatsCRUD
            stats = await StatsCRUD.get_program_stats(session, program_id)

            # Get program name
            program = await ProgramCRUD.get(session, program_id)
            program_name = program.name if program else "Unknown"

            # Count reported vs unreported
            reported = stats['by_status'].get('reported', 0)
            validated = stats['by_status'].get('validated', 0)
            unreported = validated + stats['by_status'].get('new', 0)

            return BugStats(
                program_id=program_id,
                program_name=program_name,
                total=stats['total_findings'],
                by_status=stats['by_status'],
                by_severity=stats['by_severity'],
                by_type=stats['by_type'],
                reported_count=reported,
                unreported_count=unreported,
                scope_coverage=stats['scope_coverage']['percentage'],
                avg_cvss=sum(
                    sev * count for sev, count in zip([9.0, 7.0, 5.0, 3.0], [
                        stats['by_severity'].get('P1', 0),
                        stats['by_severity'].get('P2', 0),
                        stats['by_severity'].get('P3', 0),
                        stats['by_severity'].get('P4', 0),
                    ])
                ) / max(stats['total_findings'], 1) if stats['total_findings'] > 0 else 0,
            )

    async def deduplicate(self, program_id: int) -> Dict[str, Any]:
        """Find and mark duplicate bugs"""
        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from core.database import Finding

            # Get all findings for program
            result = await session.execute(
                select(Finding).where(
                    Finding.program_id == program_id,
                    Finding.status.in_([FindingStatus.NEW.value, FindingStatus.VALIDATED.value])
                )
            )
            findings = result.scalars().all()

            # Group by vuln_type + target + parameter
            groups = {}
            for f in findings:
                key = (
                    f.vuln_type,
                    f.target_id,
                    f.endpoint_id,
                    json.dumps(f.evidence.get('parameter', ''), sort_keys=True) if f.evidence else '',
                )
                if key not in groups:
                    groups[key] = []
                groups[key].append(f)

            # Find duplicates
            duplicates_found = 0
            for key, group in groups.items():
                if len(group) > 1:
                    # Keep first, mark rest as duplicates
                    original = group[0]
                    for dup in group[1:]:
                        dup.status = FindingStatus.DUPLICATE.value
                        dup.duplicate_of = original.id
                        duplicates_found += 1

            await session.commit()

            return {
                "total_findings": len(findings),
                "duplicate_groups": len([g for g in groups.values() if len(g) > 1]),
                "duplicates_marked": duplicates_found,
            }

    async def export_bugs(self, program_id: int, format: str = "json") -> str:
        """Export bugs for platform submission"""
        filters = BugFilters(program_id=program_id, limit=10000)
        bugs = await self.get_bugs(filters)

        if format == "json":
            return json.dumps([{
                'id': b.id,
                'title': b.title,
                'vuln_type': b.vuln_type,
                'severity': b.severity,
                'description': b.description,
                'poc': b.poc,
                'evidence': b.evidence_paths,
                'cvss_score': b.cvss_score,
                'cvss_vector': b.cvss_vector,
                'impact': b.impact,
                'remediation': b.remediation,
                'status': b.status,
                'reported_url': b.reported_url,
            } for b in bugs], indent=2)

        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Title', 'Type', 'Severity', 'Status', 'CVSS', 'Reported URL'])
            for b in bugs:
                writer.writerow([b.id, b.title, b.vuln_type, b.severity, b.status,
                               b.cvss_score or '', b.reported_url])
            return output.getvalue()

        return ""

    async def _to_bug_record(self, finding: Finding, session) -> BugRecord:
        """Convert DB finding to BugRecord"""
        # Get program name
        program = await ProgramCRUD.get(session, finding.program_id)
        program_name = program.name if program else "Unknown"

        # Get evidence paths
        evidence_result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding.id)
        )
        evidence_items = evidence_result.scalars().all()
        evidence_paths = [e.path for e in evidence_items]

        # Get reported URL
        reported_url = finding.evidence.get('report_url', '') if finding.evidence else ''

        return BugRecord(
            id=finding.id,
            program_id=finding.program_id,
            program_name=program_name,
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            title=finding.title,
            description=finding.description or "",
            status=finding.status,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector or "",
            impact=finding.impact or "",
            remediation=finding.remediation or "",
            tags=finding.tags or [],
            evidence_paths=evidence_paths,
            poc=finding.poc or "",
            reported_url=reported_url,
            reported_at=finding.reported_at.isoformat() if finding.reported_at else None,
            created_at=finding.created_at.isoformat() if finding.created_at else "",
            validated_at=finding.validated_at.isoformat() if finding.validated_at else None,
            duplicate_of=finding.duplicate_of,
            is_reported=finding.status == FindingStatus.REPORTED.value,
        )

    async def _log_activity(self, session, finding_id: int, program_id: int, action: str, details: Dict):
        """Log activity"""
        await session.add(ActivityLog(
            program_id=program_id,
            finding_id=finding_id,
            action=action,
            details=details,
            user="system",
        ))
        await session.commit()


# Convenience functions
async def add_finding(finding: VulnerabilityFinding, config_manager=None) -> BugRecord:
    manager = BugDatabaseManager(config_manager)
    return await manager.add_finding(finding)


async def get_bugs(filters: BugFilters, config_manager=None) -> List[BugRecord]:
    manager = BugDatabaseManager(config_manager)
    return await manager.get_bugs(filters)


async def mark_reported(bug_id: int, report_url: str, config_manager=None) -> bool:
    manager = BugDatabaseManager(config_manager)
    return await manager.mark_reported(bug_id, report_url)


async def get_stats(program_id: int, config_manager=None) -> BugStats:
    manager = BugDatabaseManager(config_manager)
    return await manager.get_stats(program_id)