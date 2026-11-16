"""
Evidence Collector
Packages all evidence: screenshots, videos, HAR, Burp exports, terminal recordings, annotations
"""

import asyncio
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import hashlib

from core.config_manager import get_config
from validation.browser_repro import ReproductionResult
from validation.burp_integration import BurpCapture
from validation.terminal_capture import TerminalEvidence
from hunting.scanner_orchestrator import VulnerabilityFinding


@dataclass
class EvidencePackage:
    """Complete evidence package for a finding"""
    finding_id: int
    vuln_type: str
    target_url: str
    package_path: str
    created_at: str

    # Evidence files
    screenshots: List[str] = field(default_factory=list)
    videos: List[str] = field(default_factory=list)
    har_files: List[str] = field(default_factory=list)
    burp_exports: List[str] = field(default_factory=list)
    terminal_recordings: List[str] = field(default_factory=list)
    annotated_screenshots: List[str] = field(default_factory=list)
    poc_files: List[str] = field(default_factory=list)

    # Metadata
    reproduction_result: Optional[Dict] = None
    burp_capture: Optional[Dict] = None
    terminal_evidence: Optional[Dict] = None
    ai_validation: Optional[Dict] = None

    # Integrity
    file_hashes: Dict[str, str] = field(default_factory=dict)


class EvidenceCollector:
    """Collects and packages all evidence for a finding"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.evidence_dir = Path(self.val_config.evidence.package_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def create_package(self, finding: VulnerabilityFinding,
                             reproduction: ReproductionResult = None,
                             burp_capture: BurpCapture = None,
                             terminal_evidence: TerminalEvidence = None,
                             ai_validation: Dict = None) -> EvidencePackage:
        """Create complete evidence package"""

        package_id = f"finding_{finding.id}_{finding.vuln_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        package_dir = self.evidence_dir / package_id
        package_dir.mkdir(parents=True, exist_ok=True)

        package = EvidencePackage(
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            vuln_type=finding.vuln_type,
            target_url=finding.target.url,
            package_path=str(package_dir),
            created_at=datetime.utcnow().isoformat(),
        )

        # Copy screenshots
        if reproduction and reproduction.screenshots:
            for screenshot in reproduction.screenshots:
                dest = await self._copy_evidence(screenshot, package_dir, "screenshots")
                package.screenshots.append(dest)
                package.file_hashes[dest] = self._hash_file(dest)

        # Copy videos
        if reproduction and reproduction.video_path:
            dest = await self._copy_evidence(reproduction.video_path, package_dir, "videos")
            package.videos.append(dest)
            package.file_hashes[dest] = self._hash_file(dest)

        # Copy HAR files
        if reproduction and reproduction.har_path:
            dest = await self._copy_evidence(reproduction.har_path, package_dir, "har")
            package.har_files.append(dest)
            package.file_hashes[dest] = self._hash_file(dest)

        # Copy Burp exports
        if burp_capture and burp_capture.export_path:
            dest = await self._copy_evidence(burp_capture.export_path, package_dir, "burp")
            package.burp_exports.append(dest)
            package.file_hashes[dest] = self._hash_file(dest)

        # Copy terminal recordings
        if terminal_evidence and terminal_evidence.recording_path:
            dest = await self._copy_evidence(terminal_evidence.recording_path, package_dir, "terminal")
            package.terminal_recordings.append(dest)
            package.file_hashes[dest] = self._hash_file(dest)

        # Copy annotated screenshots
        if self.val_config.evidence.annotate_screenshots and reproduction and reproduction.screenshots:
            for screenshot in reproduction.screenshots:
                if 'annotated' in screenshot or '_success_' in screenshot or '_failure_' in screenshot:
                    dest = await self._copy_evidence(screenshot, package_dir, "annotated")
                    package.annotated_screenshots.append(dest)
                    package.file_hashes[dest] = self._hash_file(dest)

        # Save POC files
        if finding.poc:
            poc_path = package_dir / "poc" / "poc.md"
            poc_path.parent.mkdir(parents=True, exist_ok=True)
            poc_path.write_text(finding.poc)
            package.poc_files.append(str(poc_path))
            package.file_hashes[str(poc_path)] = self._hash_file(str(poc_path))

        # Save reproduction result
        if reproduction:
            package.reproduction_result = {
                'success': reproduction.success,
                'vulnerability_type': reproduction.vulnerability_type,
                'payload_used': reproduction.payload_used,
                'payload_executed': reproduction.payload_executed,
                'execution_evidence': reproduction.execution_evidence,
                'false_positive_indicators': reproduction.false_positive_indicators,
                'reproduction_time': reproduction.reproduction_time,
                'console_logs_count': len(reproduction.console_logs),
                'network_logs_count': len(reproduction.network_logs),
            }

        # Save Burp capture summary
        if burp_capture:
            package.burp_capture = {
                'target_url': burp_capture.target_url,
                'requests_count': len(burp_capture.requests),
                'responses_count': len(burp_capture.responses),
                'proxy_history_count': len(burp_capture.proxy_history),
                'capture_time': burp_capture.capture_time,
            }

        # Save terminal evidence summary
        if terminal_evidence:
            package.terminal_evidence = {
                'session_name': terminal_evidence.session_name,
                'start_time': terminal_evidence.start_time,
                'end_time': terminal_evidence.end_time,
                'duration_seconds': terminal_evidence.duration_seconds,
                'commands_count': len(terminal_evidence.commands),
                'output_size': terminal_evidence.output_size,
            }

        # Save AI validation
        if ai_validation:
            package.ai_validation = ai_validation

        # Create manifest
        manifest = {
            'package_id': package_id,
            'finding_id': package.finding_id,
            'vuln_type': package.vuln_type,
            'target_url': package.target_url,
            'created_at': package.created_at,
            'evidence': {
                'screenshots': package.screenshots,
                'videos': package.videos,
                'har_files': package.har_files,
                'burp_exports': package.burp_exports,
                'terminal_recordings': package.terminal_recordings,
                'annotated_screenshots': package.annotated_screenshots,
                'poc_files': package.poc_files,
            },
            'metadata': {
                'reproduction': package.reproduction_result,
                'burp_capture': package.burp_capture,
                'terminal_evidence': package.terminal_evidence,
                'ai_validation': package.ai_validation,
            },
            'integrity': {
                'file_hashes': package.file_hashes,
            },
        }

        manifest_path = package_dir / "manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        # Create ZIP archive
        zip_path = await self._create_zip(package_dir)
        package.package_path = zip_path

        return package

    async def _copy_evidence(self, src: str, dest_dir: Path, category: str) -> str:
        """Copy evidence file to package directory"""
        src_path = Path(src)
        if not src_path.exists():
            return ""

        category_dir = dest_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)

        dest_path = category_dir / src_path.name
        shutil.copy2(src_path, dest_path)

        return str(dest_path)

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    async def _create_zip(self, package_dir: Path) -> str:
        """Create ZIP archive of evidence package"""
        zip_path = package_dir.with_suffix('.zip')

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in package_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(package_dir)
                    zf.write(file_path, arcname)

        return str(zip_path)

    def verify_package(self, package_path: str) -> Dict[str, Any]:
        """Verify evidence package integrity"""
        if package_path.endswith('.zip'):
            # Extract and verify
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(package_path, 'r') as zf:
                    zf.extractall(tmpdir)

                manifest_path = Path(tmpdir) / "manifest.json"
                if manifest_path.exists():
                    with open(manifest_path) as f:
                        manifest = json.load(f)

                    return self._verify_manifest(manifest, Path(tmpdir))
        else:
            # Directory package
            manifest_path = Path(package_path) / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)

                return self._verify_manifest(manifest, Path(package_path))

        return {'valid': False, 'error': 'No manifest found'}

    def _verify_manifest(self, manifest: Dict, package_dir: Path) -> Dict[str, Any]:
        """Verify manifest against actual files"""
        results = {
            'valid': True,
            'missing_files': [],
            'hash_mismatches': [],
            'total_files': 0,
            'verified_files': 0,
        }

        file_hashes = manifest.get('integrity', {}).get('file_hashes', {})
        results['total_files'] = len(file_hashes)

        for rel_path, expected_hash in file_hashes.items():
            full_path = package_dir / rel_path
            if full_path.exists():
                actual_hash = self._hash_file(str(full_path))
                if actual_hash == expected_hash:
                    results['verified_files'] += 1
                else:
                    results['hash_mismatches'].append({
                        'file': rel_path,
                        'expected': expected_hash,
                        'actual': actual_hash,
                    })
                    results['valid'] = False
            else:
                results['missing_files'].append(rel_path)
                results['valid'] = False

        return results


class EvidenceViewer:
    """View and analyze evidence packages"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.evidence_dir = Path(self.config.load_validation().evidence.package_dir)

    def list_packages(self, finding_id: int = None, vuln_type: str = None) -> List[Dict]:
        """List available evidence packages"""
        packages = []

        for item in self.evidence_dir.iterdir():
            if item.is_dir() or item.suffix == '.zip':
                manifest_path = item / "manifest.json" if item.is_dir() else None

                if item.suffix == '.zip':
                    # Read manifest from zip
                    import zipfile
                    try:
                        with zipfile.ZipFile(item, 'r') as zf:
                            if 'manifest.json' in zf.namelist():
                                with zf.open('manifest.json') as f:
                                    manifest = json.load(f)
                    except Exception:
                        continue
                elif manifest_path and manifest_path.exists():
                    with open(manifest_path) as f:
                        manifest = json.load(f)
                else:
                    continue

                # Filter
                if finding_id and manifest.get('finding_id') != finding_id:
                    continue
                if vuln_type and manifest.get('vuln_type') != vuln_type:
                    continue

                packages.append({
                    'package_id': manifest.get('package_id'),
                    'finding_id': manifest.get('finding_id'),
                    'vuln_type': manifest.get('vuln_type'),
                    'target_url': manifest.get('target_url'),
                    'created_at': manifest.get('created_at'),
                    'path': str(item),
                    'has_screenshots': len(manifest.get('evidence', {}).get('screenshots', [])) > 0,
                    'has_video': len(manifest.get('evidence', {}).get('videos', [])) > 0,
                    'has_har': len(manifest.get('evidence', {}).get('har_files', [])) > 0,
                    'has_burp': len(manifest.get('evidence', {}).get('burp_exports', [])) > 0,
                    'has_terminal': len(manifest.get('evidence', {}).get('terminal_recordings', [])) > 0,
                })

        return sorted(packages, key=lambda p: p['created_at'], reverse=True)

    def get_package_details(self, package_path: str) -> Optional[Dict]:
        """Get full package details"""
        path = Path(package_path)

        if path.suffix == '.zip':
            import zipfile
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    if 'manifest.json' not in zf.namelist():
                        return None
                    with zf.open('manifest.json') as f:
                        manifest = json.load(f)
            except Exception:
                return None
        else:
            manifest_path = path / "manifest.json"
            if not manifest_path.exists():
                return None
            with open(manifest_path) as f:
                manifest = json.load(f)

        return manifest

    def extract_package(self, package_path: str, output_dir: str) -> bool:
        """Extract package to directory"""
        path = Path(package_path)
        out_path = Path(output_dir)

        if path.suffix == '.zip':
            import zipfile
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    zf.extractall(out_path)
                return True
            except Exception:
                return False
        else:
            # Copy directory
            try:
                shutil.copytree(path, out_path / path.name, dirs_exist_ok=True)
                return True
            except Exception:
                return False


class ScreenshotAnnotator:
    """Annotate screenshots with vulnerability highlights"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.annotation_color = self.config.load_validation().evidence.annotation_color
        self.annotation_width = self.config.load_validation().evidence.annotation_width

    def annotate(self, screenshot_path: str, finding: VulnerabilityFinding,
                 annotations: List[Dict] = None) -> str:
        """Annotate screenshot with vulnerability info"""
        try:
            from PIL import Image, ImageDraw, ImageFont

            img = Image.open(screenshot_path)
            draw = ImageDraw.Draw(img)

            width, height = img.size

            # Draw border
            draw.rectangle([0, 0, width-1, height-1],
                         outline=self.annotation_color, width=self.annotation_width)

            # Add finding info
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
                font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
            except Exception:
                font = ImageFont.load_default()
                font_small = ImageFont.load_default()

            # Title bar
            title = f"{finding.vuln_type.upper()} - {finding.title[:80]}"
            draw.rectangle([0, 0, width, 50], fill=self.annotation_color)
            draw.text((10, 10), title, fill="white", font=font)

            # Severity badge
            severity_colors = {'P1': 'red', 'P2': 'orange', 'P3': 'yellow', 'P4': 'green'}
            sev_color = severity_colors.get(finding.severity, 'white')
            draw.text((width - 100, 10), finding.severity, fill=sev_color, font=font)

            # Custom annotations
            if annotations:
                for ann in annotations:
                    x = ann.get('x', 10)
                    y = ann.get('y', 70)
                    text = ann.get('text', '')
                    color = ann.get('color', self.annotation_color)
                    draw.text((x, y), text, fill=color, font=font_small)

            # Save annotated version
            annotated_path = str(Path(screenshot_path).with_stem(
                Path(screenshot_path).stem + '_annotated'
            ))
            img.save(annotated_path)

            return annotated_path
        except Exception as e:
            print(f"Annotation failed: {e}")
            return screenshot_path


import tempfile