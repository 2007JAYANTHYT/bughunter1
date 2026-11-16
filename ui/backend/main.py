"""
FastAPI Backend for Bug Hunter Web UI
Provides REST API and WebSocket for real-time updates
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.config_manager import get_config, ConfigManager
from core.database import db_manager, ProgramCRUD, FindingCRUD, ScopeChecklistCRUD, ScanSessionCRUD, ActivityCRUD
from core.database import FindingStatus, FindingSeverity, ScanType, ScanStatus, ScopeStatus
from core.scope_fetcher import ScopeFetcher, ScopeChecker
from recon.recon_orchestrator import ReconOrchestrator, run_full_recon
from hunting.scanner_orchestrator import ScannerOrchestrator, run_hunting
from validation.validator import ValidationEngine, validate_program_findings
from reporting.bug_database import BugDatabaseManager, BugFilters, BugListType
from reporting.report_generator import ReportGenerator, ReportFormat, generate_report
from reporting.scope_checklist import ScopeChecklistManager, get_coverage
from reporting.export_formats.hackerone import export_to_hackerone
from reporting.export_formats.bugcrowd import export_to_bugcrowd
from reporting.export_formats.intigriti import export_to_intigriti


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.program_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, program_id: str = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        if program_id:
            if program_id not in self.program_connections:
                self.program_connections[program_id] = []
            self.program_connections[program_id].append(websocket)

    def disconnect(self, websocket: WebSocket, program_id: str = None):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if program_id and program_id in self.program_connections:
            if websocket in self.program_connections[program_id]:
                self.program_connections[program_id].remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

    async def broadcast_to_program(self, program_id: str, message: str):
        if program_id in self.program_connections:
            for connection in self.program_connections[program_id]:
                try:
                    await connection.send_text(message)
                except Exception:
                    pass


manager = ConnectionManager()


# Background task tracker
background_tasks: Dict[str, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db_manager.initialize()
    yield
    # Shutdown
    for task in background_tasks.values():
        task.cancel()
    await db_manager.close()


app = FastAPI(
    title="Bug Hunter Agent API",
    description="Universal Bug Hunting AI Agent - Web UI Backend",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
config = get_config()


# =============================================================================
# Pydantic Models
# =============================================================================

class ProgramCreate(BaseModel):
    name: str
    platform: str = "custom"
    handle: str = ""
    auth_type: str = "api_token"
    auth_env_var: str = ""
    scope_file: str = ""
    policy_file: str = ""
    custom_headers: List[str] = []
    notifications: Dict[str, Any] = {}


class ProgramUpdate(BaseModel):
    name: Optional[str] = None
    platform: Optional[str] = None
    handle: Optional[str] = None
    enabled: Optional[bool] = None
    auth_type: Optional[str] = None
    auth_env_var: Optional[str] = None
    scope_file: Optional[str] = None
    policy_file: Optional[str] = None
    custom_headers: Optional[List[str]] = None
    notifications: Optional[Dict[str, Any]] = None


class FindingFilters(BaseModel):
    program_id: Optional[int] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    vuln_type: Optional[str] = None
    is_reported: Optional[bool] = None
    search: Optional[str] = None
    limit: int = 50
    offset: int = 0


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None
    duplicate_of: Optional[int] = None


class ReportRequest(BaseModel):
    bug_id: int
    format: str = "markdown"
    template: str = "standard"


class ScopeItemUpdate(BaseModel):
    status: str
    notes: Optional[str] = None


class HuntConfig(BaseModel):
    depth: str = "normal"
    scanners: List[str] = ["nuclei", "dalfox", "sqlmap", "custom", "ai"]
    specialized: List[str] = ["xss", "sqli", "ssrf", "rce", "auth", "logic", "api"]


# =============================================================================
# WebSocket Endpoint
# =============================================================================

@app.websocket("/ws/{program_id}")
async def websocket_endpoint(websocket: WebSocket, program_id: str):
    await manager.connect(websocket, program_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket, program_id)


# =============================================================================
# Program Endpoints
# =============================================================================

@app.get("/api/programs")
async def list_programs(enabled_only: bool = True):
    async with db_manager.get_session() as session:
        programs = await ProgramCRUD.list(session, enabled_only=enabled_only)
        return [{
            "id": p.id,
            "name": p.name,
            "platform": p.platform,
            "handle": p.handle,
            "enabled": p.enabled,
            "auth_type": p.auth_type,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        } for p in programs]


@app.post("/api/programs")
async def create_program(program: ProgramCreate):
    async with db_manager.get_session() as session:
        from core.database import Program
        db_program = Program(
            name=program.name,
            platform=program.platform,
            handle=program.handle,
            enabled=True,
            auth_type=program.auth_type,
            auth_env_var=program.auth_env_var,
            scope_file=program.scope_file,
            policy_file=program.policy_file,
            custom_headers=program.custom_headers,
            notifications=program.notifications,
        )
        created = await ProgramCRUD.create(session, db_program)
        await manager.broadcast(json.dumps({"type": "program_created", "program": {"id": created.id, "name": created.name}}))
        return {"id": created.id, "name": created.name}


@app.get("/api/programs/{program_id}")
async def get_program(program_id: int):
    async with db_manager.get_session() as session:
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")
        return {
            "id": program.id,
            "name": program.name,
            "platform": program.platform,
            "handle": program.handle,
            "enabled": program.enabled,
            "auth_type": program.auth_type,
            "auth_env_var": program.auth_env_var,
            "scope_file": program.scope_file,
            "policy_file": program.policy_file,
            "custom_headers": program.custom_headers,
            "notifications": program.notifications,
            "created_at": program.created_at.isoformat() if program.created_at else None,
        }


@app.put("/api/programs/{program_id}")
async def update_program(program_id: int, update: ProgramUpdate):
    async with db_manager.get_session() as session:
        program = await ProgramCRUD.update(session, program_id, **update.dict(exclude_unset=True))
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")
        await manager.broadcast_to_program(str(program_id), json.dumps({"type": "program_updated", "program_id": program_id}))
        return {"id": program.id, "name": program.name}


@app.delete("/api/programs/{program_id}")
async def delete_program(program_id: int):
    async with db_manager.get_session() as session:
        success = await ProgramCRUD.delete(session, program_id)
        if not success:
            raise HTTPException(status_code=404, detail="Program not found")
        await manager.broadcast(json.dumps({"type": "program_deleted", "program_id": program_id}))
        return {"success": True}


# =============================================================================
# Finding Endpoints
# =============================================================================

@app.get("/api/findings")
async def list_findings(filters: FindingFilters = Depends()):
    async with db_manager.get_session() as session:
        if filters.program_id:
            findings = await FindingCRUD.get_by_program(
                session, filters.program_id,
                status=filters.status,
                severity=filters.severity,
                vuln_type=filters.vuln_type,
                limit=filters.limit,
                offset=filters.offset
            )
        else:
            # Get all findings across programs
            from sqlalchemy import select, desc
            from core.database import Finding
            query = select(Finding).order_by(desc(Finding.created_at)).limit(filters.limit).offset(filters.offset)

            if filters.status:
                query = query.where(Finding.status == filters.status)
            if filters.severity:
                query = query.where(Finding.severity == filters.severity)
            if filters.vuln_type:
                query = query.where(Finding.vuln_type == filters.vuln_type)
            if filters.is_reported is not None:
                if filters.is_reported:
                    query = query.where(Finding.status == "reported")
                else:
                    query = query.where(Finding.status != "reported")

            result = await session.execute(query)
            findings = result.scalars().all()

        return [{
            "id": f.id,
            "program_id": f.program_id,
            "target_id": f.target_id,
            "endpoint_id": f.endpoint_id,
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "status": f.status,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "tags": f.tags,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "validated_at": f.validated_at.isoformat() if f.validated_at else None,
            "reported_at": f.reported_at.isoformat() if f.reported_at else None,
            "duplicate_of": f.duplicate_of,
        } for f in findings]


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: int):
    async with db_manager.get_session() as session:
        finding = await FindingCRUD.get(session, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        # Get evidence
        from core.database import Evidence
        from sqlalchemy import select
        evidence_result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        evidence_items = evidence_result.scalars().all()

        return {
            "id": finding.id,
            "program_id": finding.program_id,
            "target_id": finding.target_id,
            "endpoint_id": finding.endpoint_id,
            "vuln_type": finding.vuln_type,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "poc": finding.poc,
            "status": finding.status,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "tags": finding.tags,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
            "validated_at": finding.validated_at.isoformat() if finding.validated_at else None,
            "reported_at": finding.reported_at.isoformat() if finding.reported_at else None,
            "duplicate_of": finding.duplicate_of,
            "evidence_items": [{
                "id": e.id,
                "type": e.type,
                "path": e.path,
                "description": e.description,
                "metadata": e.metadata,
            } for e in evidence_items],
        }


@app.put("/api/findings/{finding_id}")
async def update_finding(finding_id: int, update: FindingUpdate):
    async with db_manager.get_session() as session:
        from core.database import Finding
        from sqlalchemy import select

        result = await session.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        for key, value in update.dict(exclude_unset=True).items():
            setattr(finding, key, value)

        finding.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(finding)

        await manager.broadcast_to_program(
            str(finding.program_id),
            json.dumps({"type": "finding_updated", "finding_id": finding_id, "update": update.dict(exclude_unset=True)})
        )

        return {"success": True, "finding_id": finding_id}


@app.post("/api/findings/{finding_id}/report")
async def mark_reported(finding_id: int, report_url: str = Query(...), platform: str = Query("")):
    async with db_manager.get_session() as session:
        finding = await FindingCRUD.update_status(session, finding_id, "reported")
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding.evidence = finding.evidence or {}
        finding.evidence['report_url'] = report_url
        finding.evidence['report_platform'] = platform
        await session.commit()

        await manager.broadcast_to_program(
            str(finding.program_id),
            json.dumps({"type": "finding_reported", "finding_id": finding_id, "report_url": report_url})
        )

        return {"success": True, "finding_id": finding_id}


@app.post("/api/findings/{finding_id}/duplicate")
async def mark_duplicate(finding_id: int, duplicate_of: int = Query(...)):
    async with db_manager.get_session() as session:
        finding = await FindingCRUD.mark_duplicate(session, finding_id, duplicate_of)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        await manager.broadcast_to_program(
            str(finding.program_id),
            json.dumps({"type": "finding_duplicate", "finding_id": finding_id, "duplicate_of": duplicate_of})
        )

        return {"success": True, "finding_id": finding_id}


@app.post("/api/findings/{finding_id}/validate")
async def validate_finding(finding_id: int):
    """Run validation on a finding"""
    task_id = str(uuid4())

    async def run_validation():
        try:
            await manager.broadcast_to_program(
                "all",
                json.dumps({"type": "validation_started", "finding_id": finding_id, "task_id": task_id})
            )

            result = await validate_program_findings("")  # Would need program name

            await manager.broadcast_to_program(
                "all",
                json.dumps({"type": "validation_completed", "finding_id": finding_id, "task_id": task_id, "result": "completed"})
            )
        except Exception as e:
            await manager.broadcast_to_program(
                "all",
                json.dumps({"type": "validation_failed", "finding_id": finding_id, "task_id": task_id, "error": str(e)})
            )

    task = asyncio.create_task(run_validation())
    background_tasks[task_id] = task

    return {"task_id": task_id, "status": "started"}


# =============================================================================
# Scope Checklist Endpoints
# =============================================================================

@app.get("/api/scope/{program_id}")
async def get_scope_checklist(program_id: int):
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

        items = await ScopeChecklistCRUD.get_by_program(session, program_id)

        return [{
            "id": item.id,
            "item_type": item.item_type,
            "pattern": item.pattern,
            "description": item.description,
            "status": item.status,
            "tested_at": item.tested_at.isoformat() if item.tested_at else None,
            "notes": item.notes,
        } for item in items]


@app.put("/api/scope/{program_id}/items/{item_id}")
async def update_scope_item(program_id: int, item_id: int, update: ScopeItemUpdate):
    async with db_manager.get_session() as session:
        from reporting.scope_checklist import ScopeStatus
        item = await ScopeChecklistCRUD.update_status(session, item_id, update.status, update.notes)
        if not item:
            raise HTTPException(status_code=404, detail="Scope item not found")

        await manager.broadcast_to_program(
            str(program_id),
            json.dumps({"type": "scope_updated", "item_id": item_id, "status": update.status})
        )

        return {"success": True, "item_id": item_id}


@app.post("/api/scope/{program_id}/generate")
async def generate_scope_checklist(program_id: int):
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

        from reporting.scope_checklist import ScopeChecklistManager
        manager = ScopeChecklistManager(config)
        items = await manager.generate_checklist(program.name)

        await manager.broadcast_to_program(
            str(program_id),
            json.dumps({"type": "scope_generated", "count": len(items)})
        )

        return {"success": True, "items_created": len(items)}


@app.get("/api/scope/{program_id}/coverage")
async def get_scope_coverage(program_id: int):
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

        from reporting.scope_checklist import get_coverage
        coverage = await get_coverage(program.name, config)

        return coverage.__dict__


# =============================================================================
# Hunt/Scan Endpoints
# =============================================================================

@app.post("/api/hunt/recon/{program_id}")
async def start_recon(program_id: int, depth: str = Query("normal")):
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

    task_id = str(uuid4())

    async def run_recon_task():
        try:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "recon_started", "program_id": program_id, "task_id": task_id})
            )

            orchestrator = ReconOrchestrator(program.name, config)
            results = await orchestrator.run(depth)

            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({
                    "type": "recon_completed",
                    "program_id": program_id,
                    "task_id": task_id,
                    "stats": results.stats,
                })
            )
        except Exception as e:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "recon_failed", "program_id": program_id, "task_id": task_id, "error": str(e)})
            )

    task = asyncio.create_task(run_recon_task())
    background_tasks[task_id] = task

    return {"task_id": task_id, "status": "started"}


@app.post("/api/hunt/scan/{program_id}")
async def start_scan(program_id: int, hunt_config: HuntConfig):
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

    task_id = str(uuid4())

    async def run_scan_task():
        try:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "scan_started", "program_id": program_id, "task_id": task_id})
            )

            orchestrator = ScannerOrchestrator(program.name, config)
            await orchestrator.initialize()
            findings = await orchestrator.run_all_scanners()

            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({
                    "type": "scan_completed",
                    "program_id": program_id,
                    "task_id": task_id,
                    "findings_count": len(findings),
                })
            )
        except Exception as e:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "scan_failed", "program_id": program_id, "task_id": task_id, "error": str(e)})
            )

    task = asyncio.create_task(run_scan_task())
    background_tasks[task_id] = task

    return {"task_id": task_id, "status": "started"}


@app.post("/api/hunt/full/{program_id}")
async def start_full_hunt(program_id: int):
    """Run full pipeline: recon -> scan -> validate"""
    async with db_manager.get_session() as session:
        from core.database import ProgramCRUD
        program = await ProgramCRUD.get(session, program_id)
        if not program:
            raise HTTPException(status_code=404, detail="Program not found")

    task_id = str(uuid4())

    async def run_full_hunt_task():
        try:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "full_hunt_started", "program_id": program_id, "task_id": task_id})
            )

            # Step 1: Recon
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "phase_started", "phase": "recon", "program_id": program_id})
            )
            orchestrator = ReconOrchestrator(program.name, config)
            recon_results = await orchestrator.run("normal")

            # Step 2: Scan
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "phase_started", "phase": "scan", "program_id": program_id})
            )
            scan_orchestrator = ScannerOrchestrator(program.name, config)
            await scan_orchestrator.initialize()
            findings = await scan_orchestrator.run_all_scanners()

            # Step 3: Validate
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "phase_started", "phase": "validate", "program_id": program_id})
            )
            validated = await validate_program_findings(program.name, config)

            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({
                    "type": "full_hunt_completed",
                    "program_id": program_id,
                    "task_id": task_id,
                    "recon_stats": recon_results.stats,
                    "findings_count": len(findings),
                    "validated_count": len(validated),
                })
            )
        except Exception as e:
            await manager.broadcast_to_program(
                str(program_id),
                json.dumps({"type": "full_hunt_failed", "program_id": program_id, "task_id": task_id, "error": str(e)})
            )

    task = asyncio.create_task(run_full_hunt_task())
    background_tasks[task_id] = task

    return {"task_id": task_id, "status": "started"}


@app.get("/api/hunt/tasks/{task_id}")
async def get_task_status(task_id: str):
    if task_id in background_tasks:
        task = background_tasks[task_id]
        if task.done():
            try:
                result = task.result()
                return {"task_id": task_id, "status": "completed", "result": result}
            except Exception as e:
                return {"task_id": task_id, "status": "failed", "error": str(e)}
        return {"task_id": task_id, "status": "running"}
    raise HTTPException(status_code=404, detail="Task not found")


# =============================================================================
# Report Endpoints
# =============================================================================

@app.post("/api/reports/generate")
async def generate_report(request: ReportRequest):
    from reporting.report_generator import ReportFormat
    try:
        format_enum = ReportFormat(request.format)
    except ValueError:
        format_enum = ReportFormat.MARKDOWN

    report = await generate_report(request.bug_id, format_enum, config)

    return {
        "success": True,
        "file_path": report.file_path,
        "format": report.format.value,
        "size_bytes": report.size_bytes,
    }


@app.get("/api/reports/download/{bug_id}")
async def download_report(bug_id: int, format: str = Query("markdown")):
    from reporting.report_generator import ReportFormat
    try:
        format_enum = ReportFormat(format)
    except ValueError:
        format_enum = ReportFormat.MARKDOWN

    report = await generate_report(bug_id, format_enum, config)

    return FileResponse(
        path=report.file_path,
        filename=Path(report.file_path).name,
        media_type="text/markdown" if format == "markdown" else "application/octet-stream"
    )


@app.post("/api/reports/export/hackerone/{bug_id}")
async def export_hackerone(bug_id: int):
    filepath = await export_to_hackerone(bug_id, config)
    return {"success": True, "file_path": filepath}


@app.post("/api/reports/export/bugcrowd/{bug_id}")
async def export_bugcrowd(bug_id: int):
    filepath = await export_to_bugcrowd(bug_id, config)
    return {"success": True, "file_path": filepath}


@app.post("/api/reports/export/intigriti/{bug_id}")
async def export_intigriti(bug_id: int):
    filepath = await export_to_intigriti(bug_id, config)
    return {"success": True, "file_path": filepath}


@app.get("/api/reports/program/{program_id}")
async def generate_program_report(program_id: int):
    report = await generate_program_report(program_id, config)
    return {
        "success": True,
        "file_path": report.file_path,
        "size_bytes": report.size_bytes,
    }


# =============================================================================
# Stats Endpoints
# =============================================================================

@app.get("/api/stats/{program_id}")
async def get_program_stats(program_id: int):
    async with db_manager.get_session() as session:
        from reporting.bug_database import BugDatabaseManager
        bug_db = BugDatabaseManager(config)
        stats = await bug_db.get_stats(program_id)
        return stats.__dict__


@app.get("/api/stats")
async def get_global_stats():
    async with db_manager.get_session() as session:
        from sqlalchemy import select, func
        from core.database import Finding, Program

        # Total programs
        programs_result = await session.execute(select(func.count(Program.id)))
        total_programs = programs_result.scalar()

        # Total findings
        findings_result = await session.execute(select(func.count(Finding.id)))
        total_findings = findings_result.scalar()

        # By severity
        severity_result = await session.execute(
            select(Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity)
        )
        by_severity = dict(severity_result.all())

        # By status
        status_result = await session.execute(
            select(Finding.status, func.count(Finding.id))
            .group_by(Finding.status)
        )
        by_status = dict(status_result.all())

        # By type
        type_result = await session.execute(
            select(Finding.vuln_type, func.count(Finding.id))
            .group_by(Finding.vuln_type)
        )
        by_type = dict(type_result.all())

        return {
            "total_programs": total_programs,
            "total_findings": total_findings,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_type": by_type,
        }


# =============================================================================
# Evidence Endpoints
# =============================================================================

@app.get("/api/evidence/{finding_id}")
async def get_evidence(finding_id: int):
    async with db_manager.get_session() as session:
        from core.database import Evidence
        from sqlalchemy import select

        result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        evidence_items = result.scalars().all()

        return [{
            "id": e.id,
            "type": e.type,
            "path": e.path,
            "description": e.description,
            "metadata": e.metadata,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in evidence_items]


@app.get("/api/evidence/file/{finding_id}/{evidence_id}")
async def get_evidence_file(finding_id: int, evidence_id: int):
    async with db_manager.get_session() as session:
        from core.database import Evidence
        from sqlalchemy import select

        result = await session.execute(
            select(Evidence).where(Evidence.id == evidence_id, Evidence.finding_id == finding_id)
        )
        evidence = result.scalar_one_or_none()

        if not evidence:
            raise HTTPException(status_code=404, detail="Evidence not found")

        file_path = Path(evidence.path)
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Evidence file not found")

        return FileResponse(path=str(file_path), filename=file_path.name)


# =============================================================================
# Activity Log Endpoints
# =============================================================================

@app.get("/api/activity/{program_id}")
async def get_activity(program_id: int, limit: int = Query(100)):
    async with db_manager.get_session() as session:
        activities = await ActivityCRUD.get_by_program(session, program_id, limit=limit)
        return [{
            "id": a.id,
            "program_id": a.program_id,
            "finding_id": a.finding_id,
            "action": a.action,
            "details": a.details,
            "user": a.user,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        } for a in activities]


# =============================================================================
# Config Endpoints
# =============================================================================

@app.get("/api/config/hunting")
async def get_hunting_config():
    hunting = config.load_hunting()
    return hunting.__dict__


@app.get("/api/config/validation")
async def get_validation_config():
    validation = config.load_validation()
    return validation.__dict__


@app.get("/api/config/ai")
async def get_ai_config():
    ai_models = config.load_ai_models()
    return ai_models


# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }


# =============================================================================
# Serve Frontend (in production)
# =============================================================================

# Mount static files for production
frontend_build = Path("ui/frontend/dist")
if frontend_build.exists():
    app.mount("/", StaticFiles(directory=frontend_build, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)