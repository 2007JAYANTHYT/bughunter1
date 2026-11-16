"""
Database models and operations for Bug Hunter Agent
Uses SQLAlchemy 2.0 with async SQLite
"""

import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Float,
    ForeignKey, Index, Boolean, JSON, select, func, and_, or_
)
from sqlalchemy.orm import (
    declarative_base, relationship, sessionmaker, Session, joinedload
)
from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession, async_sessionmaker
)


Base = declarative_base()


class FindingStatus(str, Enum):
    NEW = "new"
    VALIDATED = "validated"
    REPORTED = "reported"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    PAID = "paid"


class FindingSeverity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    RECON = "recon"
    HUNTING = "hunting"
    VALIDATION = "validation"
    FULL = "full"


class ScopeStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    TESTED = "tested"
    SKIPPED = "skipped"


class Program(Base):
    __tablename__ = "programs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    platform = Column(String(50), nullable=False)  # hackerone, bugcrowd, intigriti, yeswehack, custom
    handle = Column(String(255))
    enabled = Column(Boolean, default=True)
    auth_type = Column(String(50))
    auth_env_var = Column(String(255))
    scope_file = Column(String(500))
    policy_file = Column(String(500))
    custom_headers = Column(JSON, default=list)
    notifications = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    targets = relationship("Target", back_populates="program", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="program", cascade="all, delete-orphan")
    scope_items = relationship("ScopeChecklist", back_populates="program", cascade="all, delete-orphan")
    scan_sessions = relationship("ScanSession", back_populates="program", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False, index=True)
    domain = Column(String(500), index=True)
    subdomain = Column(String(500), index=True)
    ip = Column(String(45), index=True)
    port = Column(Integer, index=True)
    service = Column(String(100))
    technology = Column(JSON, default=list)
    status_code = Column(Integer)
    content_length = Column(Integer)
    title = Column(String(500))
    screenshot_path = Column(String(500))
    headers = Column(JSON)
    discovered_at = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(100))

    # Relationships
    program = relationship("Program", back_populates="targets")
    endpoints = relationship("Endpoint", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    parameters = Column(JSON, default=dict)
    discovered_by = Column(String(100))
    crawled_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="endpoints")
    findings = relationship("Finding", back_populates="endpoint", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), index=True)
    vuln_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(10), nullable=False, index=True)  # P1-P4
    title = Column(String(500), nullable=False)
    description = Column(Text)
    evidence = Column(JSON, default=dict)  # screenshots, requests, responses, videos
    poc = Column(Text)
    status = Column(String(20), default=FindingStatus.NEW, index=True)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    impact = Column(Text)
    remediation = Column(Text)
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    validated_at = Column(DateTime)
    reported_at = Column(DateTime)
    duplicate_of = Column(Integer, ForeignKey("findings.id"), index=True)

    # Relationships
    program = relationship("Program", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")
    evidence_items = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    duplicate = relationship("Finding", remote_side=[id])


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # screenshot, video, har, burp, terminal, annotated
    path = Column(String(500), nullable=False)
    description = Column(Text)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding = relationship("Finding", back_populates="evidence_items")


class ScopeChecklist(Base):
    __tablename__ = "scope_checklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False, index=True)
    item_type = Column(String(20), nullable=False)  # in_scope, out_of_scope
    pattern = Column(String(500), nullable=False)
    description = Column(Text)
    status = Column(String(20), default=ScopeStatus.PENDING, index=True)
    tested_at = Column(DateTime)
    notes = Column(Text)

    # Relationships
    program = relationship("Program", back_populates="scope_items")


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False, index=True)
    scan_type = Column(String(20), nullable=False)
    status = Column(String(20), default=ScanStatus.RUNNING, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    config = Column(JSON)
    stats = Column(JSON)
    error = Column(Text)

    # Relationships
    program = relationship("Program", back_populates="scan_sessions")


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(Integer, ForeignKey("programs.id"), index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), index=True)
    action = Column(String(100), nullable=False)
    details = Column(JSON)
    user = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# Create indexes
Index("idx_findings_program_status", Finding.program_id, Finding.status)
Index("idx_findings_program_severity", Finding.program_id, Finding.severity)
Index("idx_findings_program_type", Finding.program_id, Finding.vuln_type)
Index("idx_targets_program_domain", Target.program_id, Target.domain)


class DatabaseManager:
    """Async database manager"""

    def __init__(self, database_url: str = None):
        if database_url is None:
            database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///bug_hunter.db")
        self.database_url = database_url
        self.engine = None
        self.async_session = None

    async def initialize(self):
        """Initialize database connection and create tables"""
        self.engine = create_async_engine(self.database_url, echo=False)
        self.async_session = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        await self.create_tables()

    async def create_tables(self):
        """Create all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self):
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        """Get a new async session"""
        return self.async_session()


# Global database manager
db_manager = DatabaseManager()


async def get_db() -> AsyncSession:
    """Dependency for FastAPI"""
    async with db_manager.get_session() as session:
        try:
            yield session
        finally:
            await session.close()


# =============================================================================
# CRUD Operations
# =============================================================================

class ProgramCRUD:
    @staticmethod
    async def create(session: AsyncSession, program: Program) -> Program:
        session.add(program)
        await session.commit()
        await session.refresh(program)
        return program

    @staticmethod
    async def get(session: AsyncSession, program_id: int) -> Optional[Program]:
        result = await session.execute(select(Program).where(Program.id == program_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_name(session: AsyncSession, name: str) -> Optional[Program]:
        result = await session.execute(select(Program).where(Program.name == name))
        return result.scalar_one_or_none()

    @staticmethod
    async def list(session: AsyncSession, enabled_only: bool = True) -> List[Program]:
        query = select(Program)
        if enabled_only:
            query = query.where(Program.enabled == True)
        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def update(session: AsyncSession, program_id: int, **kwargs) -> Optional[Program]:
        program = await ProgramCRUD.get(session, program_id)
        if program:
            for key, value in kwargs.items():
                setattr(program, key, value)
            program.updated_at = datetime.utcnow()
            await session.commit()
            await session.refresh(program)
        return program

    @staticmethod
    async def delete(session: AsyncSession, program_id: int) -> bool:
        program = await ProgramCRUD.get(session, program_id)
        if program:
            await session.delete(program)
            await session.commit()
            return True
        return False


class TargetCRUD:
    @staticmethod
    async def create(session: AsyncSession, target: Target) -> Target:
        session.add(target)
        await session.commit()
        await session.refresh(target)
        return target

    @staticmethod
    async def bulk_create(session: AsyncSession, targets: List[Target]) -> List[Target]:
        session.add_all(targets)
        await session.commit()
        for t in targets:
            await session.refresh(t)
        return targets

    @staticmethod
    async def get_by_program(session: AsyncSession, program_id: int) -> List[Target]:
        result = await session.execute(
            select(Target).where(Target.program_id == program_id)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_by_subdomain(session: AsyncSession, program_id: int, subdomain: str) -> Optional[Target]:
        result = await session.execute(
            select(Target).where(
                and_(Target.program_id == program_id, Target.subdomain == subdomain)
            )
        )
        return result.scalar_one_or_none()


class EndpointCRUD:
    @staticmethod
    async def create(session: AsyncSession, endpoint: Endpoint) -> Endpoint:
        session.add(endpoint)
        await session.commit()
        await session.refresh(endpoint)
        return endpoint

    @staticmethod
    async def bulk_create(session: AsyncSession, endpoints: List[Endpoint]) -> List[Endpoint]:
        session.add_all(endpoints)
        await session.commit()
        for e in endpoints:
            await session.refresh(e)
        return endpoints

    @staticmethod
    async def get_by_target(session: AsyncSession, target_id: int) -> List[Endpoint]:
        result = await session.execute(
            select(Endpoint).where(Endpoint.target_id == target_id)
        )
        return list(result.scalars().all())


class FindingCRUD:
    @staticmethod
    async def create(session: AsyncSession, finding: Finding) -> Finding:
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding

    @staticmethod
    async def get(session: AsyncSession, finding_id: int) -> Optional[Finding]:
        result = await session.execute(
            select(Finding).options(joinedload(Finding.evidence_items)).where(Finding.id == finding_id)
        )
        return result.unique().scalar_one_or_none()

    @staticmethod
    async def get_by_program(
        session: AsyncSession,
        program_id: int,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Finding]:
        query = select(Finding).where(Finding.program_id == program_id)

        if status:
            query = query.where(Finding.status == status)
        if severity:
            query = query.where(Finding.severity == severity)
        if vuln_type:
            query = query.where(Finding.vuln_type == vuln_type)

        query = query.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def count_by_program(
        session: AsyncSession,
        program_id: int,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> int:
        query = select(func.count(Finding.id)).where(Finding.program_id == program_id)
        if status:
            query = query.where(Finding.status == status)
        if severity:
            query = query.where(Finding.severity == severity)
        result = await session.execute(query)
        return result.scalar_one()

    @staticmethod
    async def update_status(session: AsyncSession, finding_id: int, status: str) -> Optional[Finding]:
        finding = await FindingCRUD.get(session, finding_id)
        if finding:
            finding.status = status
            if status == FindingStatus.VALIDATED:
                finding.validated_at = datetime.utcnow()
            elif status == FindingStatus.REPORTED:
                finding.reported_at = datetime.utcnow()
            await session.commit()
            await session.refresh(finding)
        return finding

    @staticmethod
    async def mark_duplicate(session: AsyncSession, finding_id: int, duplicate_of: int) -> Optional[Finding]:
        finding = await FindingCRUD.get(session, finding_id)
        if finding:
            finding.status = FindingStatus.DUPLICATE
            finding.duplicate_of = duplicate_of
            await session.commit()
            await session.refresh(finding)
        return finding


class EvidenceCRUD:
    @staticmethod
    async def create(session: AsyncSession, evidence: Evidence) -> Evidence:
        session.add(evidence)
        await session.commit()
        await session.refresh(evidence)
        return evidence

    @staticmethod
    async def get_by_finding(session: AsyncSession, finding_id: int) -> List[Evidence]:
        result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        return list(result.scalars().all())


class ScopeChecklistCRUD:
    @staticmethod
    async def create(session: AsyncSession, item: ScopeChecklist) -> ScopeChecklist:
        session.add(item)
        await session.commit()
        await session.refresh(item)
        return item

    @staticmethod
    async def bulk_create(session: AsyncSession, items: List[ScopeChecklist]) -> List[ScopeChecklist]:
        session.add_all(items)
        await session.commit()
        for item in items:
            await session.refresh(item)
        return items

    @staticmethod
    async def get_by_program(session: AsyncSession, program_id: int) -> List[ScopeChecklist]:
        result = await session.execute(
            select(ScopeChecklist).where(ScopeChecklist.program_id == program_id)
        )
        return list(result.scalars().all())

    @staticmethod
    async def update_status(session: AsyncSession, item_id: int, status: str, notes: str = None) -> Optional[ScopeChecklist]:
        result = await session.execute(
            select(ScopeChecklist).where(ScopeChecklist.id == item_id)
        )
        item = result.scalar_one_or_none()
        if item:
            item.status = status
            if status == ScopeStatus.TESTED:
                item.tested_at = datetime.utcnow()
            if notes:
                item.notes = notes
            await session.commit()
            await session.refresh(item)
        return item


class ScanSessionCRUD:
    @staticmethod
    async def create(session: AsyncSession, scan: ScanSession) -> ScanSession:
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan

    @staticmethod
    async def update(session: AsyncSession, scan_id: int, **kwargs) -> Optional[ScanSession]:
        result = await session.execute(select(ScanSession).where(ScanSession.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            for key, value in kwargs.items():
                setattr(scan, key, value)
            if kwargs.get("status") == ScanStatus.COMPLETED:
                scan.completed_at = datetime.utcnow()
            await session.commit()
            await session.refresh(scan)
        return scan

    @staticmethod
    async def get_latest(session: AsyncSession, program_id: int) -> Optional[ScanSession]:
        result = await session.execute(
            select(ScanSession)
            .where(ScanSession.program_id == program_id)
            .order_by(ScanSession.started_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class ActivityCRUD:
    @staticmethod
    async def log(
        session: AsyncSession,
        action: str,
        program_id: int = None,
        finding_id: int = None,
        details: Dict = None,
        user: str = "system"
    ) -> ActivityLog:
        activity = ActivityLog(
            program_id=program_id,
            finding_id=finding_id,
            action=action,
            details=details or {},
            user=user
        )
        session.add(activity)
        await session.commit()
        return activity

    @staticmethod
    async def get_by_program(session: AsyncSession, program_id: int, limit: int = 100) -> List[ActivityLog]:
        result = await session.execute(
            select(ActivityLog)
            .where(ActivityLog.program_id == program_id)
            .order_by(ActivityLog.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())


# Statistics functions
class StatsCRUD:
    @staticmethod
    async def get_program_stats(session: AsyncSession, program_id: int) -> Dict[str, Any]:
        # Total findings
        total = await FindingCRUD.count_by_program(session, program_id)

        # By status
        statuses = [s.value for s in FindingStatus]
        status_counts = {}
        for status in statuses:
            count = await FindingCRUD.count_by_program(session, program_id, status=status)
            status_counts[status] = count

        # By severity
        severities = [s.value for s in FindingSeverity]
        severity_counts = {}
        for severity in severities:
            count = await FindingCRUD.count_by_program(session, program_id, severity=severity)
            severity_counts[severity] = count

        # By type
        result = await session.execute(
            select(Finding.vuln_type, func.count(Finding.id))
            .where(Finding.program_id == program_id)
            .group_by(Finding.vuln_type)
        )
        type_counts = dict(result.all())

        # Scope coverage
        scope_total = await session.execute(
            select(func.count(ScopeChecklist.id)).where(ScopeChecklist.program_id == program_id)
        )
        scope_total = scope_total.scalar_one()

        scope_tested = await session.execute(
            select(func.count(ScopeChecklist.id)).where(
                and_(
                    ScopeChecklist.program_id == program_id,
                    ScopeChecklist.status == ScopeStatus.TESTED
                )
            )
        )
        scope_tested = scope_tested.scalar_one()

        return {
            "total_findings": total,
            "by_status": status_counts,
            "by_severity": severity_counts,
            "by_type": type_counts,
            "scope_coverage": {
                "total": scope_total,
                "tested": scope_tested,
                "percentage": (scope_tested / scope_total * 100) if scope_total > 0 else 0
            }
        }