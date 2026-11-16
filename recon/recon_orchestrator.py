"""
Recon Orchestrator
Coordinates all recon phases: subdomain enum, service discovery, content discovery
"""

import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config_manager import get_config
from core.database import db_manager, ScanSessionCRUD, ScanType, ScanStatus, ProgramCRUD
from core.scope_fetcher import ScopeFetcher
from recon.subdomain_enum import SubdomainEnumerator, SubdomainResult
from recon.service_discovery import ServiceDiscovery, ServiceInfo
from recon.content_discovery import ContentDiscovery, DiscoveredEndpoint


@dataclass
class ReconResults:
    subdomains: List[SubdomainResult] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class ReconOrchestrator:
    """Orchestrates the complete reconnaissance pipeline"""

    def __init__(self, program_name: str, config_manager=None):
        self.program_name = program_name
        self.config = config_manager or get_config()
        self.program = None
        self.results = ReconResults()

    async def run(self, depth: str = "normal") -> ReconResults:
        """Run complete reconnaissance pipeline"""
        await self._load_program()

        # Create scan session
        scan_session = await self._create_scan_session(ScanType.RECON)

        try:
            print(f"[RECON] Starting reconnaissance for {self.program_name} (depth: {depth})")

            # Phase 1: Subdomain Enumeration
            print("[RECON] Phase 1/3: Subdomain Enumeration")
            async with SubdomainEnumerator(self.program_name, self.config) as enumerator:
                self.results.subdomains = await enumerator.enumerate(depth)
            print(f"[RECON] Found {len(self.results.subdomains)} subdomains")

            # Phase 2: Service Discovery
            print("[RECON] Phase 2/3: Service Discovery")
            service_discovery = ServiceDiscovery(self.program_name, self.config)
            self.results.services = await service_discovery.discover()
            print(f"[RECON] Discovered {len(self.results.services)} services")

            # Phase 3: Content Discovery
            print("[RECON] Phase 3/3: Content Discovery")
            async with ContentDiscovery(self.program_name, self.config) as content_discovery:
                self.results.endpoints = await content_discovery.discover(depth)
            print(f"[RECON] Discovered {len(self.results.endpoints)} endpoints")

            # Calculate stats
            self.results.stats = self._calculate_stats()

            # Complete scan session
            await self._complete_scan_session(scan_session, ScanStatus.COMPLETED)

        except Exception as e:
            self.results.errors.append(str(e))
            await self._complete_scan_session(scan_session, ScanStatus.FAILED, str(e))
            raise

        return self.results

    async def _load_program(self):
        """Load program from database"""
        async with db_manager.get_session() as session:
            self.program = await ProgramCRUD.get_by_name(session, self.program_name)
            if not self.program:
                raise ValueError(f"Program not found: {self.program_name}")

    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate reconnaissance statistics"""
        verified_subs = [s for s in self.results.subdomains if s.verified]
        wildcard_subs = [s for s in self.results.subdomains if s.is_wildcard]

        http_services = [s for s in self.results.services if s.service_type.value in ['http', 'https']]
        https_services = [s for s in self.results.services if s.service_type.value == 'https']

        cdn_services = [s for s in self.results.services if s.is_cdn]

        return {
            "total_subdomains": len(self.results.subdomains),
            "verified_subdomains": len(verified_subs),
            "wildcard_subdomains": len(wildcard_subs),
            "total_services": len(self.results.services),
            "http_services": len(http_services),
            "https_services": len(https_services),
            "cdn_services": len(cdn_services),
            "total_endpoints": len(self.results.endpoints),
            "endpoints_with_params": len([e for e in self.results.endpoints if e.parameters]),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _create_scan_session(self, scan_type: ScanType):
        """Create a new scan session"""
        async with db_manager.get_session() as session:
            from core.database import ScanSession
            scan = ScanSession(
                program_id=self.program.id,
                scan_type=scan_type.value,
                status=ScanStatus.RUNNING.value,
                config={"depth": "normal"}  # Will be updated
            )
            return await ScanSessionCRUD.create(session, scan)

    async def _complete_scan_session(self, scan_session, status: ScanStatus, error: str = None):
        """Complete scan session"""
        async with db_manager.get_session() as session:
            await ScanSessionCRUD.update(
                session, scan_session.id,
                status=status.value,
                stats=self.results.stats,
                error=error
            )

    def get_summary(self) -> str:
        """Get human-readable summary"""
        stats = self.results.stats
        return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        RECONNAISSANCE SUMMARY                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Subdomains:     {stats.get('total_subdomains', 0):>4}  (Verified: {stats.get('verified_subdomains', 0):>4}, Wildcard: {stats.get('wildcard_subdomains', 0):>4})  ║
║  Services:       {stats.get('total_services', 0):>4}  (HTTP: {stats.get('http_services', 0):>4}, HTTPS: {stats.get('https_services', 0):>4}, CDN: {stats.get('cdn_services', 0):>4})  ║
║  Endpoints:      {stats.get('total_endpoints', 0):>4}  (With params: {stats.get('endpoints_with_params', 0):>4})                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Errors:         {len(self.results.errors):>4}                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


async def run_full_recon(program_name: str, depth: str = "normal") -> ReconResults:
    """Run full reconnaissance pipeline"""
    orchestrator = ReconOrchestrator(program_name)
    return await orchestrator.run(depth)