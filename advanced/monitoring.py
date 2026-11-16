"""
Continuous Monitoring Engine
Automated scheduled recon, change detection, and alerting
"""

import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from core.config_manager import get_config
from core.database import db_manager, ProgramCRUD, TargetCRUD, FindingCRUD, ScanSessionCRUD
from core.database import ScanType, ScanStatus
from recon.recon_orchestrator import ReconOrchestrator, run_full_recon
from hunting.scanner_orchestrator import ScannerOrchestrator, run_hunting
from validation.validator import ValidationEngine, validate_program_findings
from reporting.bug_database import BugDatabaseManager, BugFilters


class AlertType(str, Enum):
    NEW_SUBDOMAIN = "new_subdomain"
    SUBDOMAIN_REMOVED = "subdomain_removed"
    NEW_SERVICE = "new_service"
    SERVICE_CHANGED = "service_changed"
    NEW_TECHNOLOGY = "new_technology"
    TECHNOLOGY_CHANGED = "technology_changed"
    NEW_FINDING = "new_finding"
    FINDING_FIXED = "finding_fixed"
    CERT_EXPIRING = "cert_expiring"
    CERT_EXPIRED = "cert_expired"
    SCOPE_CHANGED = "scope_changed"
    RATE_LIMIT_CHANGED = "rate_limit_changed"


class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Monitoring alert"""
    id: str
    program_id: int
    program_name: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None


@dataclass
class Change:
    """Detected change"""
    target_id: int
    change_type: str
    field: str
    old_value: Any
    new_value: Any
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class MonitorConfig:
    """Monitoring configuration for a program"""
    program_id: int
    enabled: bool = True
    schedule_cron: str = "0 2 * * *"  # Daily at 2 AM
    recon_depth: str = "normal"
    scan_enabled: bool = True
    validation_enabled: bool = True
    alert_on_new_subdomain: bool = True
    alert_on_new_service: bool = True
    alert_on_new_finding: bool = True
    alert_on_cert_changes: bool = True
    webhook_url: str = ""
    email: str = ""


class ContinuousMonitor:
    """Continuous monitoring engine"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.bug_db = BugDatabaseManager(self.config)
        self.monitors: Dict[int, MonitorConfig] = {}
        self.alerts: List[Alert] = []
        self.running = False
        self._tasks: Dict[int, asyncio.Task] = {}

    async def initialize(self):
        """Load monitor configurations"""
        # In production, load from database
        pass

    async def add_monitor(self, config: MonitorConfig):
        """Add or update a monitor"""
        self.monitors[config.program_id] = config

    async def remove_monitor(self, program_id: int):
        """Remove a monitor"""
        if program_id in self.monitors:
            del self.monitors[program_id]
        if program_id in self._tasks:
            self._tasks[program_id].cancel()
            del self._tasks[program_id]

    async def start_all(self):
        """Start all monitors"""
        self.running = True
        for program_id, config in self.monitors.items():
            if config.enabled:
                await self.start_monitor(program_id)

    async def stop_all(self):
        """Stop all monitors"""
        self.running = False
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()

    async def start_monitor(self, program_id: int):
        """Start monitoring for a program"""
        if program_id in self._tasks:
            self._tasks[program_id].cancel()

        config = self.monitors.get(program_id)
        if not config or not config.enabled:
            return

        async def monitor_loop():
            while self.running and self.monitors.get(program_id, MonitorConfig(program_id=0)).enabled:
                try:
                    await self.run_monitor_check(program_id)
                except Exception as e:
                    print(f"Monitor error for program {program_id}: {e}")

                # Wait for next scheduled run
                # For simplicity, run daily - in production use cron scheduler
                await asyncio.sleep(24 * 3600)  # 24 hours

        task = asyncio.create_task(monitor_loop())
        self._tasks[program_id] = task

    async def run_monitor_check(self, program_id: int) -> List[Alert]:
        """Run a single monitoring check"""
        alerts = []

        async with db_manager.get_session() as session:
            program = await ProgramCRUD.get(session, program_id)
            if not program:
                return alerts

            config = self.monitors.get(program_id)
            if not config or not config.enabled:
                return alerts

            # 1. Run recon to detect changes
            print(f"[MONITOR] Running recon for {program.name}")
            orchestrator = ReconOrchestrator(program.name, self.config)
            recon_results = await orchestrator.run(config.recon_depth)

            # Compare with previous state
            changes = await self._detect_changes(program_id, recon_results)

            # Generate alerts for changes
            for change in changes:
                alert = self._create_alert_from_change(program, change, config)
                if alert:
                    alerts.append(alert)

            # 2. Run scan if enabled
            if config.scan_enabled:
                print(f"[MONITOR] Running scan for {program.name}")
                scan_orchestrator = ScannerOrchestrator(program.name, self.config)
                await scan_orchestrator.initialize()
                findings = await scan_orchestrator.run_all_scanners()

                # Validate findings
                if config.validation_enabled:
                    validated = await validate_program_findings(program.name, self.config)
                else:
                    validated = []

                # Alert on new findings
                new_findings = await self._detect_new_findings(program_id, findings)
                for finding in new_findings:
                    alert = self._create_finding_alert(program, finding, config)
                    if alert:
                        alerts.append(alert)

            # 3. Check certificate expiration
            if config.alert_on_cert_changes:
                cert_alerts = await self._check_certificates(program_id, recon_results)
                alerts.extend(cert_alerts)

            # 4. Check scope changes
            scope_alerts = await self._check_scope_changes(program_id)
            alerts.extend(scope_alerts)

        # Send notifications
        for alert in alerts:
            await self._send_alert(alert, config)

        return alerts

    async def _detect_changes(self, program_id: int, recon_results) -> List[Change]:
        """Detect changes from previous recon"""
        changes = []

        async with db_manager.get_session() as session:
            # Get previous targets
            previous_targets = await TargetCRUD.get_by_program(session, program_id)
            previous_map = {t.subdomain: t for t in previous_targets if t.subdomain}

            # Get current targets from recon results
            current_subdomains = {s.subdomain: s for s in recon_results.subdomains}

            # New subdomains
            for subdomain, current in current_subdomains.items():
                if subdomain not in previous_map:
                    changes.append(Change(
                        target_id=0,
                        change_type="new_subdomain",
                        field="subdomain",
                        old_value=None,
                        new_value={
                            "subdomain": subdomain,
                            "ip": current.ip,
                            "verified": current.verified,
                            "status_code": current.status_code,
                        }
                    ))

            # Removed subdomains
            for subdomain, previous in previous_map.items():
                if subdomain not in current_subdomains:
                    changes.append(Change(
                        target_id=previous.id,
                        change_type="subdomain_removed",
                        field="subdomain",
                        old_value={"subdomain": subdomain},
                        new_value=None,
                    ))

            # Changed subdomains (IP, technology, status)
            for subdomain, current in current_subdomains.items():
                if subdomain in previous_map:
                    previous = previous_map[subdomain]
                    if previous.ip != current.ip:
                        changes.append(Change(
                            target_id=previous.id,
                            change_type="ip_changed",
                            field="ip",
                            old_value=previous.ip,
                            new_value=current.ip,
                        ))
                    if previous.technology != current.technology:
                        changes.append(Change(
                            target_id=previous.id,
                            change_type="technology_changed",
                            field="technology",
                            old_value=previous.technology,
                            new_value=current.technology,
                        ))
                    if previous.status_code != current.status_code:
                        changes.append(Change(
                            target_id=previous.id,
                            change_type="status_changed",
                            field="status_code",
                            old_value=previous.status_code,
                            new_value=current.status_code,
                        ))

        return changes

    def _create_alert_from_change(self, program, change: Change, config: MonitorConfig) -> Optional[Alert]:
        """Create alert from detected change"""
        if change.change_type == "new_subdomain" and config.alert_on_new_subdomain:
            return Alert(
                id=f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{hash(str(change))}",
                program_id=0,  # Will be set by caller
                program_name="",
                alert_type=AlertType.NEW_SUBDOMAIN,
                severity=AlertSeverity.MEDIUM,
                title=f"New Subdomain Discovered: {change.new_value.get('subdomain')}",
                description=f"New subdomain discovered during scheduled recon: {change.new_value.get('subdomain')}",
                details=change.new_value,
            )
        elif change.change_type == "subdomain_removed":
            return Alert(
                id=f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{hash(str(change))}",
                program_id=0,
                program_name="",
                alert_type=AlertType.SUBDOMAIN_REMOVED,
                severity=AlertSeverity.LOW,
                title=f"Subdomain No Longer Resolves: {change.old_value.get('subdomain')}",
                description=f"Previously discovered subdomain no longer resolves: {change.old_value.get('subdomain')}",
                details=change.old_value,
            )
        elif change.change_type == "technology_changed" and config.alert_on_new_service:
            return Alert(
                id=f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{hash(str(change))}",
                program_id=0,
                program_name="",
                alert_type=AlertType.TECHNOLOGY_CHANGED,
                severity=AlertSeverity.LOW,
                title=f"Technology Stack Changed",
                description=f"Technology stack changed for target",
                details={"old": change.old_value, "new": change.new_value},
            )

        return None

    async def _detect_new_findings(self, program_id: int, current_findings) -> List:
        """Detect new findings compared to previous scan"""
        new_findings = []

        async with db_manager.get_session() as session:
            # Get previous findings
            previous = await FindingCRUD.get_by_program(session, program_id)
            previous_keys = set()
            for f in previous:
                key = f"{f.vuln_type}:{f.target_id}:{f.endpoint_id}"
                previous_keys.add(key)

            # Check current findings
            for finding in current_findings:
                key = f"{finding.vuln_type}:{finding.target.target_id}:{finding.target.endpoint_id}"
                if key not in previous_keys:
                    new_findings.append(finding)

        return new_findings

    def _create_finding_alert(self, program, finding, config: MonitorConfig) -> Optional[Alert]:
        """Create alert for new finding"""
        if not config.alert_on_new_finding:
            return None

        severity_map = {"P1": AlertSeverity.CRITICAL, "P2": AlertSeverity.HIGH,
                       "P3": AlertSeverity.MEDIUM, "P4": AlertSeverity.LOW}

        return Alert(
            id=f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{hash(str(finding))}",
            program_id=0,
            program_name="",
            alert_type=AlertType.NEW_FINDING,
            severity=severity_map.get(finding.severity, AlertSeverity.MEDIUM),
            title=f"New {finding.severity} Finding: {finding.vuln_type.upper()}",
            description=f"New {finding.severity} vulnerability found: {finding.title}",
            details={
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "title": finding.title,
                "target_url": finding.target.url,
            },
        )

    async def _check_certificates(self, program_id: int, recon_results) -> List[Alert]:
        """Check for certificate expiration"""
        alerts = []
        # This would use tlsx results from recon
        # For now, return empty
        return alerts

    async def _check_scope_changes(self, program_id: int) -> List[Alert]:
        """Check for scope changes"""
        alerts = []
        # Compare current scope with stored scope
        return alerts

    async def _send_alert(self, alert: Alert, config: MonitorConfig):
        """Send alert notification"""
        alert.program_id = config.program_id
        alert.program_name = ""  # Would be set from program

        # Store alert
        self.alerts.append(alert)

        # Send webhook
        if config.webhook_url:
            await self._send_webhook(config.webhook_url, alert)

        # Send email
        if config.email:
            await self._send_email(config.email, alert)

        print(f"[ALERT] {alert.severity.value.upper()}: {alert.title}")

    async def _send_webhook(self, url: str, alert: Alert):
        """Send alert to webhook"""
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(url, json={
                    "alert_id": alert.id,
                    "program": alert.program_name,
                    "type": alert.alert_type.value,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "description": alert.description,
                    "details": alert.details,
                    "created_at": alert.created_at,
                })
        except Exception as e:
            print(f"Webhook failed: {e}")

    async def _send_email(self, email: str, alert: Alert):
        """Send alert email"""
        # Would integrate with email service
        pass

    def get_alerts(self, program_id: int = None, unacknowledged_only: bool = False) -> List[Alert]:
        """Get alerts"""
        alerts = self.alerts
        if program_id:
            alerts = [a for a in alerts if a.program_id == program_id]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        return sorted(alerts, key=lambda a: a.created_at, reverse=True)

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_at = datetime.utcnow().isoformat()
                return True
        return False


# Scheduled task runner
class ScheduledMonitor:
    """Runs monitors on a cron schedule"""

    def __init__(self, monitor: ContinuousMonitor):
        self.monitor = monitor
        self.running = False

    async def start(self):
        """Start scheduled monitoring"""
        self.running = True
        await self.monitor.start_all()

        # Keep running
        while self.running:
            await asyncio.sleep(3600)  # Check every hour

    async def stop(self):
        """Stop scheduled monitoring"""
        self.running = False
        await self.monitor.stop_all()


# Convenience functions
async def start_monitoring(program_name: str, config: MonitorConfig = None):
    """Start monitoring for a program"""
    monitor = ContinuousMonitor()
    if config is None:
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            program = await ProgramCRUD.get_by_name(session, program_name)
            if program:
                config = MonitorConfig(program_id=program.id)

    if config:
        await monitor.add_monitor(config)
        await monitor.start_monitor(config.program_id)

    return monitor


async def run_scheduled_monitors():
    """Run all scheduled monitors"""
    monitor = ContinuousMonitor()
    await monitor.initialize()
    await monitor.start_all()

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await monitor.stop_all()


import datetime
from reporting.bug_database import BugFilters