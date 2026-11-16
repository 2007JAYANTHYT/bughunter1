"""
Specialized Supply Chain Hunter
Dependency confusion, typosquatting, malicious packages
"""

import asyncio
import re
import json
from typing import List, Dict, Any, Optional

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


class SupplyChainHunter:
    """Specialized supply chain vulnerability hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for supply chain vulnerabilities"""
        for target in targets[:20]:
            await self._test_dependency_confusion(target)
            await self._test_typosquatting(target)
            await self._test_package_json(target)
            await self._test_lockfile(target)

        return self.findings

    async def _test_dependency_confusion(self, target: ScanTarget):
        """Test dependency confusion"""
        # Check for package.json, requirements.txt, pom.xml, etc.
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 'composer.json', 'cargo.toml', 'go.mod']):
            return

        # Try to fetch dependency file
        import httpx

        dep_files = [
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'requirements-dev.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
            'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
            'composer.json', 'composer.lock',
            'cargo.toml', 'cargo.lock',
            'go.mod', 'go.sum',
        ]

        for dep_file in dep_files:
            test_url = target.url.rstrip('/') + '/' + dep_file
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(test_url)

                if response.status_code == 200:
                    await self._analyze_dependencies(target, dep_file, response.text)
            except Exception:
                pass

    async def _analyze_dependencies(self, target: ScanTarget, dep_file: str, content: str):
        """Analyze dependencies for confusion/typosquatting"""
        # Parse dependencies based on file type
        if dep_file in ['package.json', 'package-lock.json']:
            await self._analyze_npm_deps(target, content)
        elif 'requirements' in dep_file or dep_file in ['Pipfile', 'Pipfile.lock', 'poetry.lock']:
            await self._analyze_python_deps(target, content)
        elif dep_file == 'pom.xml':
            await self._analyze_maven_deps(target, content)
        elif 'gradle' in dep_file:
            await self._analyze_gradle_deps(target, content)

    async def _analyze_npm_deps(self, target: ScanTarget, content: str):
        """Analyze NPM dependencies"""
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get('dependencies', {}))
            deps.update(data.get('devDependencies', {}))
            deps.update(data.get('peerDependencies', {}))
            deps.update(data.get('optionalDependencies', {}))

            for pkg, version in deps.items():
                # Check for typosquatting candidates
                await self._check_typosquatting(target, 'npm', pkg, version)
        except Exception:
            pass

    async def _analyze_python_deps(self, target: ScanTarget, content: str):
        """Analyze Python dependencies"""
        # Parse requirements.txt format
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse package name
                pkg = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].split('!=')[0].strip()
                if pkg:
                    version = line.split('==')[1] if '==' in line else ''
                    await self._check_typosquatting(target, 'pypi', pkg, version)

    async def _analyze_maven_deps(self, target: ScanTarget, content: str):
        """Analyze Maven dependencies"""
        # Simple regex for pom.xml
        import re
        deps = re.findall(r'<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', content)
        for pkg, version in deps:
            await self._check_typosquatting(target, 'maven', pkg, version)

    async def _analyze_gradle_deps(self, target: ScanTarget, content: str):
        """Analyze Gradle dependencies"""
        import re
        # implementation 'group:artifact:version'
        deps = re.findall(r"['\"]([\w\-.]+):([\w\-.]+):([\w\-.]+)['\"]", content)
        for group, artifact, version in deps:
            await self._check_typosquatting(target, 'maven', f"{group}:{artifact}", version)

    async def _check_typosquatting(self, target: ScanTarget, ecosystem: str, package: str, version: str):
        """Check for typosquatting"""
        # Generate typosquatting variants
        variants = self._generate_typosquatting_variants(package)

        # Check if any variant exists in public registry
        # This would need registry API access
        # For now, just flag internal packages that look like public ones
        if self._looks_like_public_package(package):
            finding = VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="dependency_confusion",
                severity="P3",
                title=f"Potential Dependency Confusion: {package}",
                description=f"Internal package '{package}' resembles a public package name. Could be vulnerable to dependency confusion attacks.",
                target=target,
                evidence={
                    "technique": "dependency_confusion",
                    "ecosystem": ecosystem,
                    "package": package,
                    "version": version,
                },
                poc="",
                confidence=0.5,
                tags=["supply-chain", "dependency-confusion", ecosystem],
            )
            self.findings.append(finding)

    def _generate_typosquatting_variants(self, package: str) -> List[str]:
        """Generate typosquatting variants"""
        variants = []
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789-_'

        # Deletion
        for i in range(len(package)):
            variants.append(package[:i] + package[i+1:])

        # Insertion
        for i in range(len(package) + 1):
            for c in chars:
                variants.append(package[:i] + c + package[i:])

        # Substitution
        for i in range(len(package)):
            for c in chars:
                if c != package[i]:
                    variants.append(package[:i] + c + package[i+1:])

        # Transposition
        for i in range(len(package) - 1):
            variants.append(package[:i] + package[i+1] + package[i] + package[i+2:])

        return list(set(variants))

    def _looks_like_public_package(self, package: str) -> bool:
        """Check if package name looks like it could be public"""
        # Common public package patterns
        public_patterns = [
            'utils', 'helper', 'common', 'core', 'base', 'lib', 'library',
            'client', 'server', 'api', 'sdk', 'tool', 'tools', 'cli',
            'auth', 'security', 'crypto', 'hash', 'encrypt', 'decrypt',
            'config', 'configuration', 'settings', 'env', 'environment',
            'logger', 'logging', 'log', 'debug', 'trace',
            'http', 'request', 'response', 'fetch', 'axios',
            'db', 'database', 'orm', 'sql', 'nosql', 'redis', 'mongo',
            'cache', 'caching', 'memory', 'session', 'cookie',
            'validate', 'validation', 'schema', 'joi', 'yup',
            'test', 'testing', 'mock', 'stub', 'fixture',
            'build', 'compile', 'bundle', 'minify', 'uglify',
            'lint', 'eslint', 'prettier', 'format', 'style',
        ]

        pkg_lower = package.lower().replace('-', '').replace('_', '').replace('.', '')
        for pattern in public_patterns:
            if pattern in pkg_lower:
                return True

        return False

    async def _test_typosquatting(self, target: ScanTarget):
        """Test for typosquatting in URL parameters"""
        # Check if URL parameters contain package names
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['package', 'dependency', 'lib', 'module', 'import']):
                await self._check_typosquatting(target, 'unknown', param_value, '')

    async def _test_package_json(self, target: ScanTarget):
        """Test package.json exposure"""
        import httpx

        test_url = target.url.rstrip('/') + '/package.json'
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(test_url)

            if response.status_code == 200:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="package_json_exposure",
                    severity="P4",
                    title="package.json Exposed",
                    description="package.json file is publicly accessible, revealing project dependencies and metadata.",
                    target=target,
                    evidence={
                        "technique": "file_exposure",
                        "file": "package.json",
                    },
                    poc="",
                    confidence=0.9,
                    tags=["supply-chain", "information-disclosure", "npm"],
                )
                self.findings.append(finding)
        except Exception:
            pass

    async def _test_lockfile(self, target: ScanTarget):
        """Test lockfile exposure"""
        lockfiles = [
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'Pipfile.lock', 'poetry.lock',
            'composer.lock', 'cargo.lock', 'go.sum',
        ]

        import httpx
        for lockfile in lockfiles:
            test_url = target.url.rstrip('/') + '/' + lockfile
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(test_url)

                if response.status_code == 200:
                    finding = VulnerabilityFinding(
                        scanner=ScannerType.CUSTOM,
                        vuln_type="lockfile_exposure",
                        severity="P4",
                        title=f"{lockfile} Exposed",
                        description=f"{lockfile} is publicly accessible, revealing exact dependency versions.",
                        target=target,
                        evidence={
                            "technique": "file_exposure",
                            "file": lockfile,
                        },
                        poc="",
                        confidence=0.9,
                        tags=["supply-chain", "information-disclosure"],
                    )
                    self.findings.append(finding)
            except Exception:
                pass


async def hunt_supply_chain(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for supply chain vulnerabilities"""
    hunter = SupplyChainHunter(config_manager or get_config())
    return await hunter.hunt(targets)