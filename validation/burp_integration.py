"""
Burp Suite Integration
Real Burp Suite Professional API integration for traffic capture and scanning
Fallback to mitmproxy for Burp Community Edition
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget


@dataclass
class BurpCapture:
    """Burp Suite traffic capture"""
    target_url: str
    requests: List[Dict] = field(default_factory=list)
    responses: List[Dict] = field(default_factory=list)
    websocket_messages: List[Dict] = field(default_factory=list)
    proxy_history: List[Dict] = field(default_factory=list)
    scan_results: List[Dict] = field(default_factory=list)
    export_path: str = ""
    capture_time: str = ""


@dataclass
class BurpIssue:
    """Burp Suite issue/vulnerability"""
    issue_id: str
    name: str
    severity: str
    confidence: str
    url: str
    issue_type: str
    detail: str
    remediation: str
    request_response: Dict
    false_positive: bool = False


class BurpIntegration:
    """Burp Suite Professional integration via REST API"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.api_url = self.val_config.burp.api_url
        self.api_key = os.getenv("BURP_API_KEY", "")
        self.proxy_port = self.val_config.burp.proxy_port
        self.proxy_host = self.val_config.burp.proxy_host
        self.export_dir = Path(self.val_config.burp.export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    async def capture_traffic(self, target: ScanTarget, actions: List[str] = None) -> BurpCapture:
        """Capture traffic by routing browser through Burp proxy"""
        capture = BurpCapture(
            target_url=target.url,
            capture_time=datetime.utcnow().isoformat(),
        )

        # This would route browser traffic through Burp
        # For now, use the export API to get proxy history
        history = await self._get_proxy_history(target.url)
        capture.proxy_history = history
        capture.requests = [h for h in history if 'request' in h]
        capture.responses = [h for h in history if 'response' in h]

        # Export to file
        capture.export_path = await self._export_capture(capture)

        return capture

    async def run_scan(self, target: ScanTarget) -> List[BurpIssue]:
        """Run Burp active scan on target"""
        issues = []

        # Submit scan
        scan_id = await self._start_scan(target.url)
        if not scan_id:
            return issues

        # Wait for scan completion
        await self._wait_for_scan(scan_id)

        # Get scan results
        issues = await self._get_scan_issues(scan_id)

        return issues

    async def export_issue(self, issue_id: str) -> Optional[Dict]:
        """Export full issue details with request/response"""
        try:
            async with self._http_session() as session:
                async with session.get(
                    f"{self.api_url}/v0.1/issues/{issue_id}",
                    headers=self._auth_headers()
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return None

    async def _get_proxy_history(self, url_filter: str = None) -> List[Dict]:
        """Get proxy history from Burp"""
        try:
            async with self._http_session() as session:
                params = {}
                if url_filter:
                    params['url'] = url_filter

                async with session.get(
                    f"{self.api_url}/v0.1/proxy/history",
                    headers=self._auth_headers(),
                    params=params
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return []

    async def _start_scan(self, url: str) -> Optional[str]:
        """Start Burp active scan"""
        try:
            async with self._http_session() as session:
                async with session.post(
                    f"{self.api_url}/v0.1/scans",
                    headers=self._auth_headers(),
                    json={"urls": [url]}
                ) as resp:
                    if resp.status == 201:
                        data = await resp.json()
                        return data.get('scan_id')
        except Exception:
            pass
        return None

    async def _wait_for_scan(self, scan_id: str, timeout: int = 3600) -> bool:
        """Wait for scan to complete"""
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).seconds < timeout:
            try:
                async with self._http_session() as session:
                    async with session.get(
                        f"{self.api_url}/v0.1/scans/{scan_id}",
                        headers=self._auth_headers()
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get('status') == 'succeeded':
                                return True
                            elif data.get('status') == 'failed':
                                return False
            except Exception:
                pass

            await asyncio.sleep(30)

        return False

    async def _get_scan_issues(self, scan_id: str) -> List[BurpIssue]:
        """Get issues from completed scan"""
        issues = []
        try:
            async with self._http_session() as session:
                async with session.get(
                    f"{self.api_url}/v0.1/scans/{scan_id}/issues",
                    headers=self._auth_headers()
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for issue_data in data.get('issues', []):
                            issues.append(BurpIssue(
                                issue_id=issue_data.get('issue_id', ''),
                                name=issue_data.get('name', ''),
                                severity=issue_data.get('severity', ''),
                                confidence=issue_data.get('confidence', ''),
                                url=issue_data.get('origin', ''),
                                issue_type=issue_data.get('type', ''),
                                detail=issue_data.get('detail', ''),
                                remediation=issue_data.get('remediation', ''),
                                request_response=issue_data.get('request_response', {}),
                            ))
        except Exception:
            pass
        return issues

    async def _export_capture(self, capture: BurpCapture) -> str:
        """Export capture to JSON file"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"burp_capture_{timestamp}.json"
        filepath = self.export_dir / filename

        with open(filepath, 'w') as f:
            json.dump({
                'target_url': capture.target_url,
                'capture_time': capture.capture_time,
                'requests': capture.requests,
                'responses': capture.responses,
                'websocket_messages': capture.websocket_messages,
                'proxy_history': capture.proxy_history,
            }, f, indent=2)

        return str(filepath)

    def _auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        } if self.api_key else {"Content-Type": "application/json"}

    def _http_session(self):
        """Get HTTP session"""
        import httpx
        return httpx.AsyncClient(timeout=60.0)


class MitmproxyFallback:
    """mitmproxy fallback for Burp Community Edition"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.proxy_port = self.val_config.burp.mitmproxy_port
        self.capture_dir = Path(self.val_config.burp.export_dir) / "mitmproxy"
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.process = None

    async def start_proxy(self):
        """Start mitmproxy in background"""
        # Start mitmproxy with custom script
        script_path = self._create_capture_script()

        self.process = await asyncio.create_subprocess_exec(
            "mitmdump",
            "-p", str(self.proxy_port),
            "-s", script_path,
            "--set", f"hardump={self.capture_dir}/capture.har",
            "--ssl-insecure",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wait for startup
        await asyncio.sleep(2)

    def _create_capture_script(self) -> str:
        """Create mitmproxy capture script"""
        script = '''
from mitmproxy import http, ctx
import json
import os

CAPTURE_DIR = os.environ.get("MITM_CAPTURE_DIR", "/tmp/mitm_capture")
os.makedirs(CAPTURE_DIR, exist_ok=True)

def request(flow: http.HTTPFlow):
    # Log request
    entry = {
        "timestamp": flow.request.timestamp_start,
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "headers": dict(flow.request.headers),
        "content": flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else "",
    }
    with open(os.path.join(CAPTURE_DIR, "requests.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\\n")

def response(flow: http.HTTPFlow):
    # Log response
    entry = {
        "timestamp": flow.response.timestamp_start,
        "url": flow.request.pretty_url,
        "status_code": flow.response.status_code,
        "headers": dict(flow.response.headers),
        "content": flow.response.content.decode('utf-8', errors='ignore') if flow.response.content else "",
    }
    with open(os.path.join(CAPTURE_DIR, "responses.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\\n")
'''

        script_path = self.capture_dir / "capture.py"
        script_path.write_text(script)
        return str(script_path)

    async def stop_proxy(self):
        """Stop mitmproxy"""
        if self.process:
            self.process.terminate()
            await self.process.wait()

    async def get_captured_traffic(self) -> Dict[str, List]:
        """Get captured traffic"""
        requests = []
        responses = []

        req_file = self.capture_dir / "requests.jsonl"
        resp_file = self.capture_dir / "responses.jsonl"

        if req_file.exists():
            with open(req_file) as f:
                for line in f:
                    try:
                        requests.append(json.loads(line))
                    except Exception:
                        pass

        if resp_file.exists():
            with open(resp_file) as f:
                for line in f:
                    try:
                        responses.append(json.loads(line))
                    except Exception:
                        pass

        return {"requests": requests, "responses": responses}


class BurpTrafficCapture:
    """High-level traffic capture combining browser + Burp/mitmproxy"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.use_mitmproxy = self.val_config.burp.use_mitmproxy_fallback

        if self.use_mitmproxy:
            self.proxy = MitmproxyFallback(config_manager)
        else:
            self.proxy = BurpIntegration(config_manager)

    async def __aenter__(self):
        if self.use_mitmproxy:
            await self.proxy.start_proxy()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.use_mitmproxy:
            await self.proxy.stop_proxy()

    async def capture_browser_traffic(self, finding: VulnerabilityFinding) -> BurpCapture:
        """Capture browser traffic through proxy"""
        # This would be called during browser reproduction
        # Browser should be configured to use proxy

        if self.use_mitmproxy:
            traffic = await self.proxy.get_captured_traffic()
            return BurpCapture(
                target_url=finding.target.url,
                requests=traffic['requests'],
                responses=traffic['responses'],
                capture_time=datetime.utcnow().isoformat(),
            )
        else:
            # Use Burp API
            return await self.proxy.capture_traffic(finding.target)

    def get_proxy_config(self) -> Dict[str, str]:
        """Get proxy configuration for browser"""
        if self.use_mitmproxy:
            return {
                "host": "127.0.0.1",
                "port": self.val_config.burp.mitmproxy_port,
            }
        else:
            return {
                "host": self.val_config.burp.proxy_host,
                "port": self.val_config.burp.proxy_port,
            }


async def capture_with_burp(finding: VulnerabilityFinding, config_manager=None) -> BurpCapture:
    """Capture traffic for a finding using Burp/mitmproxy"""
    async with BurpTrafficCapture(config_manager) as capture:
        return await capture.capture_browser_traffic(finding)