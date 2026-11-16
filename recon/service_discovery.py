"""
Service Discovery Engine
Port scanning, service detection, TLS analysis, CDN detection
"""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from core.config_manager import get_config
from core.database import db_manager, TargetCRUD, ScanSessionCRUD, ScanType, ScanStatus
from core.scope_fetcher import ScopeChecker


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    DATABASE = "database"
    CLOUD = "cloud"
    VPN = "vpn"
    MAIL = "mail"
    OTHER = "other"


@dataclass
class ServiceInfo:
    target_id: int
    ip: str
    port: int
    service: str
    service_type: ServiceType
    version: str = ""
    banner: str = ""
    tls_info: Dict[str, Any] = field(default_factory=dict)
    is_cdn: bool = False
    cdn_provider: str = ""
    asn: str = ""
    asn_name: str = ""


class ServiceDiscovery:
    """Service discovery and fingerprinting"""

    def __init__(self, program_name: str, config_manager=None):
        self.program_name = program_name
        self.config = config_manager or get_config()
        self.program = None
        self.targets = []
        self.results: List[ServiceInfo] = []

    async def discover(self, target_ids: List[int] = None) -> List[ServiceInfo]:
        """Run service discovery on targets"""
        await self._load_program_and_targets(target_ids)

        if not self.targets:
            print("No targets to scan")
            return []

        # Run port scanning with naabu
        await self._run_port_scan()

        # Run service detection with httpx
        await self._run_service_detection()

        # Run TLS analysis with tlsx
        await self._run_tls_analysis()

        # Run CDN detection with ipcdn
        await self._run_cdn_detection()

        # Run ASN mapping with asnmap
        await self._run_asn_mapping()

        # Save results
        await self._save_results()

        return self.results

    async def _load_program_and_targets(self, target_ids: List[int] = None):
        """Load program and targets from database"""
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD, TargetCRUD
            self.program = await ProgramCRUD.get_by_name(session, self.program_name)
            if not self.program:
                raise ValueError(f"Program not found: {self.program_name}")

            if target_ids:
                # Get specific targets
                for tid in target_ids:
                    from core.database import Target
                    from sqlalchemy import select
                    result = await session.execute(select(Target).where(Target.id == tid))
                    target = result.scalar_one_or_none()
                    if target:
                        self.targets.append(target)
            else:
                # Get all targets for program
                self.targets = await TargetCRUD.get_by_program(session, self.program.id)

    async def _run_port_scan(self):
        """Run naabu port scan on target IPs"""
        ips = list(set(t.ip for t in self.targets if t.ip))
        if not ips:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(ips))
            temp_file = f.name

        try:
            # Top 1000 ports by default, full scan for deep
            config = self.config.load_hunting()
            ports = "top-1000"  # Could be configurable

            cmd = [
                "naabu", "-l", temp_file,
                "-p", ports,
                "-silent", "-json",
                "-rate", "1000",
                "-retries", "2",
                "-timeout", "5"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        ip = data.get('ip')
                        port = data.get('port')
                        if ip and port:
                            # Find target with this IP
                            for target in self.targets:
                                if target.ip == ip:
                                    self.results.append(ServiceInfo(
                                        target_id=target.id,
                                        ip=ip,
                                        port=port,
                                        service="unknown",
                                        service_type=ServiceType.OTHER,
                                    ))
                                    break
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _run_service_detection(self):
        """Run httpx for HTTP service detection"""
        # Build URLs from targets with open ports
        urls = []
        for result in self.results:
            if result.port in [80, 443, 8080, 8443, 8000, 8001, 8888, 9000, 9001, 9443]:
                scheme = "https" if result.port in [443, 8443, 9443] else "http"
                urls.append(f"{scheme}://{result.ip}:{result.port}")

        if not urls:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(urls))
            temp_file = f.name

        try:
            cmd = [
                "httpx", "-l", temp_file,
                "-silent", "-status-code", "-title", "-tech-detect",
                "-web-server", "-cdn", "-ip", "-cname",
                "-json", "-follow-redirects", "-random-agent",
                "-timeout", "10", "-retries", "2"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        ip = data.get('ip') or parsed.hostname
                        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

                        # Match with existing result
                        for result in self.results:
                            if result.ip == ip and result.port == port:
                                result.service = "http" if parsed.scheme == 'http' else "https"
                                result.service_type = ServiceType.HTTP if parsed.scheme == 'http' else ServiceType.HTTPS
                                result.version = data.get('webserver', '')
                                result.title = data.get('title', '')
                                result.tls_info = {
                                    'cdn': data.get('cdn', ''),
                                    'cname': data.get('cname', ''),
                                }
                                break
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _run_tls_analysis(self):
        """Run tlsx for TLS certificate analysis"""
        https_targets = [r for r in self.results if r.service_type == ServiceType.HTTPS]
        if not https_targets:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for r in https_targets:
                f.write(f"{r.ip}:{r.port}\n")
            temp_file = f.name

        try:
            cmd = [
                "tlsx", "-l", temp_file,
                "-silent", "-json",
                "-san", "-cn", "-exp", "-issuer",
                "-wildcard", "-expired", "-revoked",
                "-self-signed", "-sig-alg", "-key-alg"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        host = data.get('host', '')
                        port = data.get('port', 443)

                        for result in self.results:
                            if result.ip == host and result.port == port:
                                result.tls_info.update({
                                    'san': data.get('san', []),
                                    'cn': data.get('cn', ''),
                                    'expires': data.get('expired', False),
                                    'issuer': data.get('issuer', ''),
                                    'wildcard': data.get('wildcard', False),
                                    'self_signed': data.get('self_signed', False),
                                    'sig_alg': data.get('sig_alg', ''),
                                    'key_alg': data.get('key_alg', ''),
                                })
                                break
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _run_cdn_detection(self):
        """Run ipcdn for CDN detection"""
        ips = list(set(r.ip for r in self.results))
        if not ips:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(ips))
            temp_file = f.name

        try:
            cmd = ["ipcdn", "-l", temp_file, "-silent", "-json"]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        ip = data.get('ip', '')
                        cdn = data.get('cdn', '')
                        provider = data.get('provider', '')

                        for result in self.results:
                            if result.ip == ip:
                                result.is_cdn = bool(cdn)
                                result.cdn_provider = provider
                                break
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _run_asn_mapping(self):
        """Run asnmap for ASN information"""
        ips = list(set(r.ip for r in self.results))
        if not ips:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(ips))
            temp_file = f.name

        try:
            cmd = ["asnmap", "-l", temp_file, "-silent", "-json"]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        ip = data.get('ip', '')
                        asn = data.get('asn', '')
                        asn_name = data.get('asn_name', '')

                        for result in self.results:
                            if result.ip == ip:
                                result.asn = asn
                                result.asn_name = asn_name
                                break
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _save_results(self):
        """Update targets with service information"""
        async with db_manager.get_session() as session:
            from core.database import Target
            from sqlalchemy import select

            for result in self.results:
                stmt = select(Target).where(Target.id == result.target_id)
                db_target = await session.execute(stmt)
                target = db_target.scalar_one_or_none()

                if target:
                    # Update target with service info
                    if not target.port or result.port not in [80, 443]:
                        target.port = result.port
                    if not target.service:
                        target.service = result.service
                    if result.technology:
                        target.technology = list(set(target.technology + result.technology))

            await session.commit()


async def run_service_discovery(program_name: str, target_ids: List[int] = None) -> List[ServiceInfo]:
    """Run service discovery for a program"""
    discovery = ServiceDiscovery(program_name)
    return await discovery.discover(target_ids)