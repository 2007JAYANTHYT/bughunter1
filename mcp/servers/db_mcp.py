"""
Database MCP Server
Provides MCP tools for database operations
"""

import asyncio
import json
from typing import Dict, Any, List, Optional

from core.config_manager import get_config
from core.database import db_manager, ProgramCRUD, FindingCRUD, ScopeChecklistCRUD, ScanSessionCRUD, ActivityCRUD
from core.database import FindingStatus, FindingSeverity, ScanType, ScanStatus, ScopeStatus
from reporting.bug_database import BugDatabaseManager, BugFilters, BugListType


class DatabaseMCPServer:
    """MCP Server for database operations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.bug_db = BugDatabaseManager(self.config)

    # Program operations
    async def create_program(self, name: str, platform: str = "custom", handle: str = "",
                             auth_type: str = "api_token", auth_env_var: str = "",
                             scope_file: str = "", policy_file: str = "",
                             custom_headers: List[str] = None,
                             notifications: Dict = None) -> Dict[str, Any]:
        """Create a new program"""
        try:
            async with db_manager.get_session() as session:
                from core.database import Program
                program = Program(
                    name=name,
                    platform=platform,
                    handle=handle,
                    enabled=True,
                    auth_type=auth_type,
                    auth_env_var=auth_env_var,
                    scope_file=scope_file,
                    policy_file=policy_file,
                    custom_headers=custom_headers or [],
                    notifications=notifications or {},
                )
                created = await ProgramCRUD.create(session, program)
                return {"success": True, "program": {"id": created.id, "name": created.name}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_programs(self, enabled_only: bool = True) -> Dict[str, Any]:
        """List all programs"""
        try:
            async with db_manager.get_session() as session:
                programs = await ProgramCRUD.list(session, enabled_only)
                return {
                    "success": True,
                    "count": len(programs),
                    "programs": [
                        {
                            "id": p.id,
                            "name": p.name,
                            "platform": p.platform,
                            "handle": p.handle,
                            "enabled": p.enabled,
                            "created_at": p.created_at.isoformat() if p.created_at else None,
                        }
                        for p in programs
                    ],
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_program(self, program_id: int) -> Dict[str, Any]:
        """Get program by ID"""
        try:
            async with db_manager.get_session() as session:
                program = await ProgramCRUD.get(session, program_id)
                if not program:
                    return {"success": False, "error": "Program not found"}
                return {
                    "success": True,
                    "program": {
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
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_program(self, program_id: int, **kwargs) -> Dict[str, Any]:
        """Update program"""
        try:
            async with db_manager.get_session() as session:
                program = await ProgramCRUD.update(session, program_id, **kwargs)
                if not program:
                    return {"success": False, "error": "Program not found"}
                return {"success": True, "program": {"id": program.id, "name": program.name}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def delete_program(self, program_id: int) -> Dict[str, Any]:
        """Delete program"""
        try:
            async with db_manager.get_session() as session:
                success = await ProgramCRUD.delete(session, program_id)
                return {"success": success}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Finding operations
    async def list_findings(self, filters: Dict = None) -> Dict[str, Any]:
        """List findings with filters"""
        try:
            filters = filters or {}
            bug_filters = BugFilters(
                program_id=filters.get('program_id'),
                status=filters.get('status'),
                severity=filters.get('severity'),
                vuln_type=filters.get('vuln_type'),
                is_reported=filters.get('is_reported'),
                search=filters.get('search'),
                limit=filters.get('limit', 100),
                offset=filters.get('offset', 0),
            )
            bugs = await self.bug_db.get_bugs(bug_filters)
            return {
                "success": True,
                "count": len(bugs),
                "findings": [
                    {
                        "id": b.id,
                        "program_id": b.program_id,
                        "program_name": b.program_name,
                        "vuln_type": b.vuln_type,
                        "severity": b.severity,
                        "title": b.title,
                        "status": b.status,
                        "cvss_score": b.cvss_score,
                        "created_at": b.created_at,
                        "reported_at": b.reported_at,
                        "is_reported": b.is_reported,
                    }
                    for b in bugs
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_finding(self, finding_id: int) -> Dict[str, Any]:
        """Get finding by ID"""
        try:
            bug = await self.bug_db.get_bug(finding_id)
            if not bug:
                return {"success": False, "error": "Finding not found"}
            return {"success": True, "finding": bug.__dict__}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_finding(self, finding_id: int, **kwargs) -> Dict[str, Any]:
        """Update finding"""
        try:
            bug = await self.bug_db.update_bug(finding_id, **kwargs)
            if not bug:
                return {"success": False, "error": "Finding not found"}
            return {"success": True, "finding": bug.__dict__}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def mark_reported(self, finding_id: int, report_url: str, platform: str = "") -> Dict[str, Any]:
        """Mark finding as reported"""
        try:
            success = await self.bug_db.mark_reported(finding_id, report_url, platform)
            return {"success": success}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def mark_duplicate(self, finding_id: int, duplicate_of: int) -> Dict[str, Any]:
        """Mark finding as duplicate"""
        try:
            success = await self.bug_db.mark_duplicate(finding_id, duplicate_of)
            return {"success": success}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def mark_false_positive(self, finding_id: int, reason: str = "") -> Dict[str, Any]:
        """Mark finding as false positive"""
        try:
            success = await self.bug_db.mark_false_positive(finding_id, reason)
            return {"success": success}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_stats(self, program_id: int) -> Dict[str, Any]:
        """Get program statistics"""
        try:
            stats = await self.bug_db.get_stats(program_id)
            return {"success": True, "stats": stats.__dict__}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_reported_bugs(self, program_id: int = None) -> Dict[str, Any]:
        """Get reported bugs"""
        try:
            bugs = await self.bug_db.get_reported_bugs(program_id)
            return {"success": True, "count": len(bugs), "bugs": [b.__dict__ for b in bugs]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_unreported_bugs(self, program_id: int = None) -> Dict[str, Any]:
        """Get unreported bugs"""
        try:
            bugs = await self.bug_db.get_unreported_bugs(program_id)
            return {"success": True, "count": len(bugs), "bugs": [b.__dict__ for b in bugs]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def deduplicate(self, program_id: int) -> Dict[str, Any]:
        """Find and mark duplicates"""
        try:
            result = await self.bug_db.deduplicate(program_id)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def export_bugs(self, program_id: int, format: str = "json") -> Dict[str, Any]:
        """Export bugs"""
        try:
            data = await self.bug_db.export_bugs(program_id, format)
            return {"success": True, "data": data, "format": format}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Scope checklist operations
    async def get_scope_checklist(self, program_id: int) -> Dict[str, Any]:
        """Get scope checklist"""
        try:
            async with db_manager.get_session() as session:
                items = await ScopeChecklistCRUD.get_by_program(session, program_id)
                return {
                    "success": True,
                    "count": len(items),
                    "items": [
                        {
                            "id": i.id,
                            "item_type": i.item_type,
                            "pattern": i.pattern,
                            "description": i.description,
                            "status": i.status,
                            "tested_at": i.tested_at.isoformat() if i.tested_at else None,
                            "notes": i.notes,
                        }
                        for i in items
                    ],
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_scope_item(self, item_id: int, status: str, notes: str = None) -> Dict[str, Any]:
        """Update scope item status"""
        try:
            async with db_manager.get_session() as session:
                item = await ScopeChecklistCRUD.update_status(session, item_id, status, notes)
                if not item:
                    return {"success": False, "error": "Item not found"}
                return {"success": True, "item": {"id": item.id, "status": item.status}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Scan session operations
    async def create_scan_session(self, program_id: int, scan_type: str, config: Dict = None) -> Dict[str, Any]:
        """Create scan session"""
        try:
            async with db_manager.get_session() as session:
                from core.database import ScanSession
                scan = ScanSession(
                    program_id=program_id,
                    scan_type=scan_type,
                    status=ScanStatus.RUNNING.value,
                    config=config or {},
                )
                created = await ScanSessionCRUD.create(session, scan)
                return {"success": True, "scan": {"id": created.id, "scan_type": created.scan_type}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_scan_session(self, scan_id: int, **kwargs) -> Dict[str, Any]:
        """Update scan session"""
        try:
            async with db_manager.get_session() as session:
                scan = await ScanSessionCRUD.update(session, scan_id, **kwargs)
                if not scan:
                    return {"success": False, "error": "Scan not found"}
                return {"success": True, "scan": {"id": scan.id, "status": scan.status}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Activity log
    async def log_activity(self, action: str, program_id: int = None, finding_id: int = None,
                           details: Dict = None, user: str = "system") -> Dict[str, Any]:
        """Log activity"""
        try:
            async with db_manager.get_session() as session:
                activity = await ActivityCRUD.log(session, action, program_id, finding_id, details, user)
                return {"success": True, "activity": {"id": activity.id, "action": activity.action}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_activity(self, program_id: int, limit: int = 100) -> Dict[str, Any]:
        """Get activity log"""
        try:
            async with db_manager.get_session() as session:
                activities = await ActivityCRUD.get_by_program(session, program_id, limit)
                return {
                    "success": True,
                    "count": len(activities),
                    "activities": [
                        {
                            "id": a.id,
                            "action": a.action,
                            "details": a.details,
                            "user": a.user,
                            "created_at": a.created_at.isoformat() if a.created_at else None,
                        }
                        for a in activities
                    ],
                }
        except Exception as e:
            return {"success": False, "error": str(e)}


# MCP Tool definitions
DB_MCP_TOOLS = [
    # Programs
    {
        "name": "db_create_program",
        "description": "Create a new bug bounty program",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "platform": {"type": "string", "default": "custom"},
                "handle": {"type": "string", "default": ""},
                "auth_type": {"type": "string", "default": "api_token"},
                "auth_env_var": {"type": "string", "default": ""},
                "scope_file": {"type": "string", "default": ""},
                "policy_file": {"type": "string", "default": ""},
                "custom_headers": {"type": "array", "items": {"type": "string"}},
                "notifications": {"type": "object"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "db_list_programs",
        "description": "List all programs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "enabled_only": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "db_get_program",
        "description": "Get program by ID",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "db_update_program",
        "description": "Update program",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "db_delete_program",
        "description": "Delete program",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    # Findings
    {
        "name": "db_list_findings",
        "description": "List findings with filters",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filters": {"type": "object"},
            },
        },
    },
    {
        "name": "db_get_finding",
        "description": "Get finding by ID",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "db_update_finding",
        "description": "Update finding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "db_mark_reported",
        "description": "Mark finding as reported",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "report_url": {"type": "string"},
                "platform": {"type": "string", "default": ""},
            },
            "required": ["finding_id", "report_url"],
        },
    },
    {
        "name": "db_mark_duplicate",
        "description": "Mark finding as duplicate",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "duplicate_of": {"type": "integer"},
            },
            "required": ["finding_id", "duplicate_of"],
        },
    },
    {
        "name": "db_mark_false_positive",
        "description": "Mark finding as false positive",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "reason": {"type": "string", "default": ""},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "db_get_stats",
        "description": "Get program statistics",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "db_get_reported_bugs",
        "description": "Get reported bugs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
        },
    },
    {
        "name": "db_get_unreported_bugs",
        "description": "Get unreported bugs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
        },
    },
    {
        "name": "db_deduplicate",
        "description": "Find and mark duplicates",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "db_export_bugs",
        "description": "Export bugs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
                "format": {"type": "string", "default": "json"},
            },
            "required": ["program_id"],
        },
    },
    # Scope
    {
        "name": "db_get_scope_checklist",
        "description": "Get scope checklist",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "db_update_scope_item",
        "description": "Update scope item status",
        "inputSchema": {
            "type": "object",
            "properties": {
                "item_id": {"type": "integer"},
                "status": {"type": "string"},
                "notes": {"type": "string"},
            },
            "required": ["item_id", "status"],
        },
    },
    # Scans
    {
        "name": "db_create_scan_session",
        "description": "Create scan session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
                "scan_type": {"type": "string"},
                "config": {"type": "object"},
            },
            "required": ["program_id", "scan_type"],
        },
    },
    {
        "name": "db_update_scan_session",
        "description": "Update scan session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "integer"},
            },
            "required": ["scan_id"],
        },
    },
    # Activity
    {
        "name": "db_log_activity",
        "description": "Log activity",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "program_id": {"type": "integer"},
                "finding_id": {"type": "integer"},
                "details": {"type": "object"},
                "user": {"type": "string", "default": "system"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "db_get_activity",
        "description": "Get activity log",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "integer"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["program_id"],
        },
    },
]


async def handle_db_mcp_call(server: DatabaseMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Database"""
    method_map = {
        "db_create_program": server.create_program,
        "db_list_programs": server.list_programs,
        "db_get_program": server.get_program,
        "db_update_program": server.update_program,
        "db_delete_program": server.delete_program,
        "db_list_findings": server.list_findings,
        "db_get_finding": server.get_finding,
        "db_update_finding": server.update_finding,
        "db_mark_reported": server.mark_reported,
        "db_mark_duplicate": server.mark_duplicate,
        "db_mark_false_positive": server.mark_false_positive,
        "db_get_stats": server.get_stats,
        "db_get_reported_bugs": server.get_reported_bugs,
        "db_get_unreported_bugs": server.get_unreported_bugs,
        "db_deduplicate": server.deduplicate,
        "db_export_bugs": server.export_bugs,
        "db_get_scope_checklist": server.get_scope_checklist,
        "db_update_scope_item": server.update_scope_item,
        "db_create_scan_session": server.create_scan_session,
        "db_update_scan_session": server.update_scan_session,
        "db_log_activity": server.log_activity,
        "db_get_activity": server.get_activity,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)