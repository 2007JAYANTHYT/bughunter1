"""
Content Discovery Engine
Crawling, directory brute forcing, parameter discovery, JS analysis
"""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import aiohttp

from core.config_manager import get_config
from core.database import db_manager, TargetCRUD, EndpointCRUD
from core.scope_fetcher import ScopeChecker


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    parameters: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    title: str = ""
    technology: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)


class ContentDiscovery:
    """Content discovery and crawling"""

    def __init__(self, program_name: str, config_manager=None):
        self.program_name = program_name
        self.config = config_manager or get_config()
        self.program = None
        self.targets = []
        self.scope_checker: Optional[ScopeChecker] = None
        self.results: List[DiscoveredEndpoint] = []
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        await self._load_program()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _load_program(self):
        """Load program and targets"""
        from core.scope_fetcher import ScopeFetcher
        async with ScopeFetcher(self.config) as fetcher:
            scope = await fetcher.fetch_program_scope(self.program_name)
        self.scope_checker = ScopeChecker(scope)

        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            self.program = await ProgramCRUD.get_by_name(session, self.program_name)
            if not self.program:
                raise ValueError(f"Program not found: {self.program_name}")

            self.targets = await TargetCRUD.get_by_program(session, self.program.id)

    async def discover(self, depth: str = "normal") -> List[DiscoveredEndpoint]:
        """Run full content discovery"""
        config = self.config.load_hunting()

        # Create scan session
        # await self._create_scan_session(ScanType.RECON)

        try:
            # Build base URLs from targets
            base_urls = self._build_base_urls()

            # Run crawling with Katana
            await self._run_katana(base_urls)

            # Run Gospider for fast spidering
            await self._run_gospider(base_urls)

            # Run Hakrawler
            await self._run_hakrawler(base_urls)

            # Run directory brute force with ffuf
            if depth in ["deep", "full"]:
                await self._run_ffuf(base_urls)

            # Run parameter discovery with arjun
            if depth in ["deep", "full"]:
                await self._run_arjun()

            # Run JS analysis with LinkFinder/SecretFinder/JSFScan
            await self._run_js_analysis()

            # Deduplicate
            await self._deduplicate()

            # Save to database
            await self._save_results()

        except Exception as e:
            print(f"Content discovery error: {e}")
            raise

        return self.results

    def _build_base_urls(self) -> List[str]:
        """Build base URLs from targets"""
        urls = []
        for target in self.targets:
            if target.status_code and target.subdomain:
                scheme = "https" if target.port == 443 else "http"
                if target.port not in [80, 443]:
                    urls.append(f"{scheme}://{target.subdomain}:{target.port}")
                else:
                    urls.append(f"{scheme}://{target.subdomain}")
        return urls

    async def _run_katana(self, urls: List[str]):
        """Run Katana for headless crawling"""
        if not urls:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(urls))
            temp_file = f.name

        try:
            config = self.config.load_hunting()
            cmd = [
                "katana", "-list", temp_file,
                "-silent", "-jc", "-kf", "-fx", "-ef", "woff,woff2,ttf,eot,svg,png,jpg,jpeg,gif,css,ico",
                "-timeout", "10", "-retry", "2", "-depth", "3",
                "-concurrency", "10", "-parallelism", "10",
                "-o", "/dev/stdout"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line:
                    endpoint = self._parse_katana_output(line)
                    if endpoint and self._check_scope(endpoint.url):
                        self.results.append(endpoint)

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def _parse_katana_output(self, line: str) -> Optional[DiscoveredEndpoint]:
        """Parse Katana output line"""
        try:
            # Katana outputs JSON when -json flag used
            data = json.loads(line)
            url = data.get('url', '')
            if not url:
                return None

            parsed = urlparse(url)
            params = {}
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        params[k] = v

            return DiscoveredEndpoint(
                url=url,
                method=data.get('method', 'GET'),
                parameters=params,
                source="katana",
                status_code=data.get('status_code'),
                content_length=data.get('content_length'),
                title=data.get('title', ''),
                technology=data.get('technology', []),
            )
        except Exception:
            # Try plain URL
            if line.startswith('http'):
                return DiscoveredEndpoint(url=line.strip(), source="katana")
        return None

    async def _run_gospider(self, urls: List[str]):
        """Run Gospider for fast spidering"""
        if not urls:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(urls))
            temp_file = f.name

        try:
            cmd = [
                "gospider", "-S", temp_file,
                "-c", "10", "-d", "3", "-t", "10",
                "--other-source", "--include-subs",
                "--js", "--sitemap", "--robots"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line and ('[url]' in line or '[javascript]' in line or '[form]' in line):
                    endpoint = self._parse_gospider_output(line)
                    if endpoint and self._check_scope(endpoint.url):
                        self.results.append(endpoint)

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def _parse_gospider_output(self, line: str) -> Optional[DiscoveredEndpoint]:
        """Parse Gospider output"""
        try:
            # Format: [url] - http://example.com - code-200
            parts = line.split(' - ')
            if len(parts) >= 2:
                url = parts[1].strip()
                if url.startswith('http'):
                    status_code = None
                    for part in parts:
                        if part.startswith('code-'):
                            try:
                                status_code = int(part.split('-')[1])
                            except Exception:
                                pass
                    return DiscoveredEndpoint(url=url, source="gospider", status_code=status_code)
        except Exception:
            pass
        return None

    async def _run_hakrawler(self, urls: List[str]):
        """Run Hakrawler for simple crawling"""
        if not urls:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(urls))
            temp_file = f.name

        try:
            cmd = [
                "hakrawler", "-d", "3", "-t", "10",
                "-insecure", "-subs", "-plain"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate(input=Path(temp_file).read_bytes())

            for line in stdout.decode().strip().split('\n'):
                if line and line.startswith('http'):
                    if self._check_scope(line.strip()):
                        self.results.append(DiscoveredEndpoint(url=line.strip(), source="hakrawler"))
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _run_ffuf(self, urls: List[str]):
        """Run ffuf for directory brute forcing"""
        if not urls:
            return

        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"

        for url in urls[:10]:  # Limit to prevent too many scans
            try:
                cmd = [
                    "ffuf", "-u", f"{url}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,204,301,302,307,401,403,405,500",
                    "-fc", "404", "-fs", "0",
                    "-t", "50", "-timeout", "10",
                    "-o", "/dev/stdout", "-of", "json"
                ]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                try:
                    data = json.loads(stdout.decode())
                    for result in data.get('results', []):
                        found_url = result.get('url', '')
                        if found_url and self._check_scope(found_url):
                            self.results.append(DiscoveredEndpoint(
                                url=found_url,
                                source="ffuf",
                                status_code=result.get('status'),
                                content_length=result.get('length'),
                            ))
                except Exception:
                    pass
            except Exception as e:
                print(f"ffuf error for {url}: {e}")

    async def _run_arjun(self):
        """Run arjun for parameter discovery"""
        if not self.results:
            return

        # Get unique base URLs
        base_urls = list(set(urlparse(r.url)._replace(query='', fragment='').geturl() for r in self.results))

        for url in base_urls[:20]:  # Limit
            try:
                cmd = [
                    "arjun", "-u", url,
                    "-m", "GET", "POST",
                    "-t", "10", "--rate-limit", "50",
                    "-o", "/dev/stdout", "-oJ"
                ]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                try:
                    data = json.loads(stdout.decode())
                    for endpoint, params in data.items():
                        for param in params:
                            if self._check_scope(endpoint):
                                self.results.append(DiscoveredEndpoint(
                                    url=endpoint,
                                    method="GET",
                                    parameters={param: ""},
                                    source="arjun",
                                ))
                except Exception:
                    pass
            except Exception as e:
                print(f"arjun error for {url}: {e}")

    async def _run_js_analysis(self):
        """Run JavaScript analysis tools"""
        # Collect JS URLs
        js_urls = []
        for result in self.results:
            if result.url.endswith('.js') or '.js?' in result.url:
                js_urls.append(result.url)

        # Also extract from HTML responses
        # This would need HTML parsing - simplified for now

        if not js_urls:
            return

        # Run LinkFinder
        await self._run_linkfinder(js_urls)

        # Run SecretFinder
        await self._run_secretfinder(js_urls)

        # Run JSFScan
        await self._run_jsfscan(js_urls)

    async def _run_linkfinder(self, js_urls: List[str]):
        """Run LinkFinder on JS files"""
        for url in js_urls[:50]:  # Limit
            try:
                cmd = ["python3", "~/tools/LinkFinder/linkfinder.py", "-i", url, "-o", "cli"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                # Parse output for endpoints
                for line in stdout.decode().strip().split('\n'):
                    if line.startswith('http') and self._check_scope(line.strip()):
                        self.results.append(DiscoveredEndpoint(url=line.strip(), source="linkfinder"))
            except Exception:
                pass

    async def _run_secretfinder(self, js_urls: List[str]):
        """Run SecretFinder on JS files"""
        for url in js_urls[:50]:
            try:
                cmd = ["python3", "~/tools/SecretFinder/SecretFinder.py", "-i", url, "-o", "cli"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                # Parse output for secrets/endpoints
                for line in stdout.decode().strip().split('\n'):
                    if line.startswith('http') and self._check_scope(line.strip()):
                        self.results.append(DiscoveredEndpoint(url=line.strip(), source="secretfinder"))
            except Exception:
                pass

    async def _run_jsfscan(self, js_urls: List[str]):
        """Run JSFScan on JS files"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(js_urls[:100]))
                temp_file = f.name

            cmd = ["bash", "~/tools/JSFScan/JSFScan.sh", "-f", temp_file, "-o", "/dev/stdout"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            for line in stdout.decode().strip().split('\n'):
                if line.startswith('http') and self._check_scope(line.strip()):
                    self.results.append(DiscoveredEndpoint(url=line.strip(), source="jsfscan"))

            Path(temp_file).unlink(missing_ok=True)
        except Exception:
            pass

    def _check_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        if not self.scope_checker:
            return True
        try:
            result = self.scope_checker.check_url(url)
            return result.in_scope
        except Exception:
            return True

    async def _deduplicate(self):
        """Deduplicate results by URL"""
        seen = set()
        unique = []
        for result in self.results:
            # Normalize URL
            parsed = urlparse(result.url)
            normalized = parsed._replace(query='', fragment='').geturl()
            if normalized not in seen:
                seen.add(normalized)
                unique.append(result)
        self.results = unique

    async def _save_results(self):
        """Save discovered endpoints to database"""
        if not self.program:
            return

        async with db_manager.get_session() as session:
            from core.database import Target
            from sqlalchemy import select

            for endpoint in self.results:
                # Find target by URL
                parsed = urlparse(endpoint.url)
                hostname = parsed.hostname

                stmt = select(Target).where(
                    Target.program_id == self.program.id,
                    Target.subdomain == hostname
                )
                db_target = await session.execute(stmt)
                target = db_target.scalar_one_or_none()

                if target:
                    ep = Endpoint(
                        target_id=target.id,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameters=endpoint.parameters,
                        discovered_by=endpoint.source,
                    )
                    await EndpointCRUD.create(session, ep)


async def run_content_discovery(program_name: str, depth: str = "normal") -> List[DiscoveredEndpoint]:
    """Run content discovery for a program"""
    async with ContentDiscovery(program_name) as discovery:
        return await discovery.discover(depth)