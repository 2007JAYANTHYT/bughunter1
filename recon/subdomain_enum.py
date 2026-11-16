"""
Subdomain Enumeration Engine
Multi-source subdomain discovery with deduplication and verification
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
import aiofiles

from core.config_manager import get_config
from core.database import db_manager, TargetCRUD, ScanSessionCRUD, ScanType, ScanStatus
from core.scope_fetcher import ScopeChecker, ProgramScope, ScopeType, ScopeRule


class SubdomainSource(str, Enum):
    SUBFINDER = "subfinder"
    AMASS = "amass"
    ASSETFINDER = "assetfinder"
    FINDOMAIN = "findomain"
    CRT_SH = "crt.sh"
    CERTSPOTTER = "certspotter"
    GAU = "gau"
    WAYBACKURLS = "waybackurls"
    DNS_BRUTE = "dns_brute"
    ALTDNS = "altdns"
    VIRUSTOTAL = "virustotal"
    SECURITYTRAILS = "securitytrails"
    SHODAN = "shodan"
    CENSYS = "censys"
    RECURSIVE = "recursive"


@dataclass
class SubdomainResult:
    subdomain: str
    source: SubdomainSource
    ip: Optional[str] = None
    cname: Optional[str] = None
    is_wildcard: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    technology: List[str] = field(default_factory=list)
    verified: bool = False


class SubdomainEnumerator:
    """Multi-source subdomain enumeration with verification"""

    def __init__(self, program_name: str, config_manager=None):
        self.program_name = program_name
        self.config = config_manager or get_config()
        self.program = None
        self.scope: Optional[ProgramScope] = None
        self.scope_checker: Optional[ScopeChecker] = None
        self.results: Dict[str, SubdomainResult] = {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        await self._load_program()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _load_program(self):
        """Load program and scope"""
        from core.scope_fetcher import ScopeFetcher
        async with ScopeFetcher(self.config) as fetcher:
            self.scope = await fetcher.fetch_program_scope(self.program_name)
        self.scope_checker = ScopeChecker(self.scope)

        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD
            self.program = await ProgramCRUD.get_by_name(session, self.program_name)

    async def enumerate(self, depth: str = "normal") -> List[SubdomainResult]:
        """Run full subdomain enumeration"""
        config = self.config.load_hunting()
        hunting_config = config

        # Create scan session
        scan_session = await self._create_scan_session(ScanType.RECON)

        try:
            # Run all enumeration sources in parallel
            tasks = [
                self._run_subfinder(),
                self._run_assetfinder(),
                self._run_findomain(),
                self._run_crt_sh(),
                self._run_gau(),
                self._run_waybackurls(),
            ]

            if depth in ["deep", "full"]:
                tasks.extend([
                    self._run_amass(),
                    self._run_dns_brute(),
                    self._run_altdns(),
                    self._run_virustotal(),
                    self._run_securitytrails(),
                    self._run_shodan(),
                    self._run_censys(),
                ])

            if depth == "full":
                tasks.append(self._run_recursive())

            await asyncio.gather(*tasks, return_exceptions=True)

            # Deduplicate results
            await self._deduplicate()

            # Verify subdomains with httpx
            await self._verify_with_httpx()

            # Check for wildcard DNS
            await self._check_wildcards()

            # Save to database
            await self._save_results()

            # Update scan session
            await self._complete_scan_session(scan_session, ScanStatus.COMPLETED)

        except Exception as e:
            await self._complete_scan_session(scan_session, ScanStatus.FAILED, str(e))
            raise

        return list(self.results.values())

    async def _create_scan_session(self, scan_type: ScanType):
        async with db_manager.get_session() as session:
            return await ScanSessionCRUD.create(session, session=session, scan=...)

    async def _run_subfinder(self) -> List[str]:
        """Run subfinder for passive subdomain enumeration"""
        try:
            cmd = [
                "subfinder", "-d", self._get_main_domain(),
                "-silent", "-all", "-recursive",
                "-config", os.path.expanduser("~/.config/subfinder/config.yaml")
            ]
            result = await self._run_command(cmd)
            subdomains = result.stdout.strip().split('\n') if result.stdout else []
            await self._add_results(subdomains, SubdomainSource.SUBFINDER)
            return subdomains
        except Exception as e:
            print(f"Subfinder error: {e}")
            return []

    async def _run_amass(self) -> List[str]:
        """Run amass for comprehensive enumeration"""
        try:
            cmd = [
                "amass", "enum", "-passive", "-d", self._get_main_domain(),
                "-config", os.path.expanduser("~/.config/amass/config.ini")
            ]
            result = await self._run_command(cmd, timeout=300)
            subdomains = result.stdout.strip().split('\n') if result.stdout else []
            await self._add_results(subdomains, SubdomainSource.AMASS)
            return subdomains
        except Exception as e:
            print(f"Amass error: {e}")
            return []

    async def _run_assetfinder(self) -> List[str]:
        """Run assetfinder"""
        try:
            cmd = ["assetfinder", "--subs-only", self._get_main_domain()]
            result = await self._run_command(cmd)
            subdomains = result.stdout.strip().split('\n') if result.stdout else []
            await self._add_results(subdomains, SubdomainSource.ASSETFINDER)
            return subdomains
        except Exception as e:
            print(f"Assetfinder error: {e}")
            return []

    async def _run_findomain(self) -> List[str]:
        """Run findomain"""
        try:
            cmd = ["findomain", "-t", self._get_main_domain(), "-q"]
            result = await self._run_command(cmd)
            subdomains = result.stdout.strip().split('\n') if result.stdout else []
            await self._add_results(subdomains, SubdomainSource.FINDOMAIN)
            return subdomains
        except Exception as e:
            print(f"Findomain error: {e}")
            return []

    async def _run_crt_sh(self) -> List[str]:
        """Query crt.sh for certificate transparency logs"""
        try:
            domain = self._get_main_domain()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with self.session.get(url) as resp:
                data = await resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f'.{domain}') or sub == domain:
                            subdomains.add(sub)
                await self._add_results(list(subdomains), SubdomainSource.CRT_SH)
                return list(subdomains)
        except Exception as e:
            print(f"crt.sh error: {e}")
            return []

    async def _run_certspotter(self) -> List[str]:
        """Query certspotter API"""
        try:
            domain = self._get_main_domain()
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with self.session.get(url) as resp:
                data = await resp.json()
                subdomains = set()
                for entry in data:
                    for name in entry.get('dns_names', []):
                        name = name.strip().lower()
                        if name.endswith(f'.{domain}') or name == domain:
                            subdomains.add(name)
                await self._add_results(list(subdomains), SubdomainSource.CERTSPOTTER)
                return list(subdomains)
        except Exception as e:
            print(f"Certspotter error: {e}")
            return []

    async def _run_gau(self) -> List[str]:
        """Run gau for URL discovery"""
        try:
            cmd = ["gau", "--subs", self._get_main_domain()]
            result = await self._run_command(cmd, timeout=120)
            urls = result.stdout.strip().split('\n') if result.stdout else []
            subdomains = set()
            for url in urls:
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(url).hostname
                    if hostname and (hostname.endswith(f'.{self._get_main_domain()}') or hostname == self._get_main_domain()):
                        subdomains.add(hostname.lower())
                except Exception:
                    pass
            await self._add_results(list(subdomains), SubdomainSource.GAU)
            return list(subdomains)
        except Exception as e:
            print(f"GAU error: {e}")
            return []

    async def _run_waybackurls(self) -> List[str]:
        """Run waybackurls"""
        try:
            cmd = ["waybackurls", self._get_main_domain()]
            result = await self._run_command(cmd, timeout=120)
            urls = result.stdout.strip().split('\n') if result.stdout else []
            subdomains = set()
            for url in urls:
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(url).hostname
                    if hostname and (hostname.endswith(f'.{self._get_main_domain()}') or hostname == self._get_main_domain()):
                        subdomains.add(hostname.lower())
                except Exception:
                    pass
            await self._add_results(list(subdomains), SubdomainSource.WAYBACKURLS)
            return list(subdomains)
        except Exception as e:
            print(f"Waybackurls error: {e}")
            return []

    async def _run_dns_brute(self) -> List[str]:
        """Run DNS brute force with alterx + dnsx"""
        try:
            # Generate permutations with alterx
            wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

            # Use alterx to generate permutations
            cmd = [
                "alterx", "-l", wordlist, "-d", self._get_main_domain(),
                "-silent", "-enrich"
            ]
            result = await self._run_command(cmd, timeout=180)
            permutations = result.stdout.strip().split('\n') if result.stdout else []

            # Resolve with dnsx
            if permutations:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write('\n'.join(permutations))
                    temp_file = f.name

                try:
                    cmd = [
                        "dnsx", "-l", temp_file, "-silent",
                        "-a", "-cname", "-resp", "-json"
                    ]
                    result = await self._run_command(cmd, timeout=180)
                    subdomains = []
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            try:
                                data = json.loads(line)
                                subdomains.append(data['host'])
                            except Exception:
                                pass
                    await self._add_results(subdomains, SubdomainSource.DNS_BRUTE)
                    return subdomains
                finally:
                    Path(temp_file).unlink(missing_ok=True)
            return []
        except Exception as e:
            print(f"DNS brute force error: {e}")
            return []

    async def _run_altdns(self) -> List[str]:
        """Run altdns for permutation scanning"""
        try:
            # Get already found subdomains
            existing = list(self.results.keys())
            if not existing:
                return []

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(existing))
                input_file = f.name

            output_file = input_file + '.altdns.txt'
            cmd = ["altdns", "-i", input_file, "-o", output_file, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-r", "-s", "results.txt"]

            result = await self._run_command(cmd, timeout=180)

            if Path(output_file).exists():
                subdomains = Path(output_file).read_text().strip().split('\n')
                await self._add_results(subdomains, SubdomainSource.ALTDNS)

                # Resolve new subdomains
                await self._resolve_subdomains(subdomains)

            Path(input_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)
            return []
        except Exception as e:
            print(f"Altdns error: {e}")
            return []

    async def _run_virustotal(self) -> List[str]:
        """Query VirusTotal API"""
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return []

        try:
            domain = self._get_main_domain()
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
            headers = {"x-apikey": api_key}

            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = [item['id'] for item in data.get('data', [])]
                    await self._add_results(subdomains, SubdomainSource.VIRUSTOTAL)
                    return subdomains
        except Exception as e:
            print(f"VirusTotal error: {e}")
        return []

    async def _run_securitytrails(self) -> List[str]:
        """Query SecurityTrails API"""
        api_key = os.getenv("SECURITYTRAILS_API_KEY")
        if not api_key:
            return []

        try:
            domain = self._get_main_domain()
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"apikey": api_key}

            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
                    await self._add_results(subdomains, SubdomainSource.SECURITYTRAILS)
                    return subdomains
        except Exception as e:
            print(f"SecurityTrails error: {e}")
        return []

    async def _run_shodan(self) -> List[str]:
        """Query Shodan API"""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return []

        try:
            domain = self._get_main_domain()
            url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"

            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = [item['hostname'] for item in data.get('subdomains', [])]
                    subdomains = [f"{sub}.{domain}" for sub in subdomains]
                    await self._add_results(subdomains, SubdomainSource.SHODAN)
                    return subdomains
        except Exception as e:
            print(f"Shodan error: {e}")
        return []

    async def _run_censys(self) -> List[str]:
        """Query Censys API"""
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            return []

        try:
            # Censys requires authentication - simplified
            return []
        except Exception as e:
            print(f"Censys error: {e}")
        return []

    async def _run_recursive(self) -> List[str]:
        """Recursive subdomain enumeration on discovered subdomains"""
        # Get subdomains that have subdomains themselves
        base_domain = self._get_main_domain()
        discovered = [s for s in self.results.keys() if s.count('.') == base_domain.count('.') + 1]

        new_subdomains = set()
        for sub in discovered[:20]:  # Limit to prevent explosion
            try:
                cmd = ["subfinder", "-d", sub, "-silent"]
                result = await self._run_command(cmd, timeout=60)
                subs = result.stdout.strip().split('\n') if result.stdout else []
                for s in subs:
                    if s.endswith(f'.{base_domain}'):
                        new_subdomains.add(s)
            except Exception:
                pass

        if new_subdomains:
            await self._add_results(list(new_subdomains), SubdomainSource.RECURSIVE)
            await self._resolve_subdomains(list(new_subdomains))

        return list(new_subdomains)

    async def _add_results(self, subdomains: List[str], source: SubdomainSource):
        """Add subdomain results with scope checking"""
        for sub in subdomains:
            sub = sub.strip().lower()
            if not sub:
                continue

            # Check scope
            if self.scope_checker:
                result = self.scope_checker.check(sub)
                if not result.in_scope:
                    continue

            if sub not in self.results:
                self.results[sub] = SubdomainResult(subdomain=sub, source=source)
            else:
                # Track multiple sources
                pass

    async def _resolve_subdomains(self, subdomains: List[str]):
        """Resolve subdomains to IPs using dnsx"""
        if not subdomains:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            temp_file = f.name

        try:
            cmd = ["dnsx", "-l", temp_file, "-silent", "-a", "-cname", "-resp", "-json"]
            result = await self._run_command(cmd, timeout=120)

            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        host = data['host']
                        if host in self.results:
                            self.results[host].ip = data.get('a', [None])[0]
                            self.results[host].cname = data.get('cname', [None])[0]
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _verify_with_httpx(self):
        """Verify subdomains with httpx and gather tech info"""
        subdomains = list(self.results.keys())
        if not subdomains:
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            temp_file = f.name

        try:
            cmd = [
                "httpx", "-l", temp_file,
                "-silent", "-status-code", "-title", "-tech-detect",
                "-json", "-follow-redirects", "-random-agent",
                "-timeout", "10", "-retries", "2"
            ]
            result = await self._run_command(cmd, timeout=300)

            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        from urllib.parse import urlparse
                        hostname = urlparse(url).hostname
                        if hostname and hostname in self.results:
                            self.results[hostname].verified = True
                            self.results[hostname].status_code = data.get('status_code')
                            self.results[hostname].title = data.get('title')
                            self.results[hostname].technology = data.get('tech', [])
                    except Exception:
                        pass
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _check_wildcards(self):
        """Check for wildcard DNS"""
        base_domain = self._get_main_domain()
        test_sub = f"nonexistent-wildcard-test-{os.urandom(4).hex()}.{base_domain}"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_sub)
            temp_file = f.name

        try:
            cmd = ["dnsx", "-l", temp_file, "-silent", "-a"]
            result = await self._run_command(cmd)
            has_wildcard = bool(result.stdout.strip())

            if has_wildcard:
                # Mark all unverified subdomains as potential wildcard
                for sub, data in self.results.items():
                    if not data.verified and not data.ip:
                        data.is_wildcard = True
        finally:
            Path(temp_file).unlink(missing_ok=True)

    async def _deduplicate(self):
        """Deduplicate results - already handled by dict"""
        pass

    async def _save_results(self):
        """Save results to database"""
        if not self.program:
            return

        async with db_manager.get_session() as session:
            targets = []
            for sub, data in self.results.items():
                if data.verified or data.ip:
                    target = TargetCRUD.create(
                        session=session,
                        target=Target(
                            program_id=self.program.id,
                            domain=self._get_main_domain(),
                            subdomain=sub,
                            ip=data.ip,
                            service="http/https" if data.verified else "dns",
                            technology=data.technology,
                            status_code=data.status_code,
                            title=data.title,
                            source=data.source.value,
                        )
                    )
                    targets.append(target)

            await TargetCRUD.bulk_create(session, targets)

    async def _complete_scan_session(self, scan_session, status: ScanStatus, error: str = None):
        """Complete scan session"""
        pass

    def _get_main_domain(self) -> str:
        """Extract main domain from scope"""
        for rule in self.scope.in_scope:
            if not rule.is_wildcard and not rule.is_cidr and not rule.is_regex:
                return rule.pattern
        return self.program_name

    async def _run_command(self, cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
        """Run command asynchronously"""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return subprocess.CompletedProcess(cmd, proc.returncode, stdout.decode(), stderr.decode())
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise


# Convenience function
async def run_subdomain_enum(program_name: str, depth: str = "normal") -> List[SubdomainResult]:
    """Run subdomain enumeration for a program"""
    async with SubdomainEnumerator(program_name) as enumerator:
        return await enumerator.enumerate(depth)