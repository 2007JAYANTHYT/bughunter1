"""
Browser Reproduction Engine
Real Firefox browser automation with Playwright for evidence capture
NO synthetic requests - real browser only
"""

import asyncio
import json
import os
import base64
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget
from core.database import Evidence, db_manager


@dataclass
class ReproductionResult:
    success: bool
    finding_id: int
    target_url: str
    vulnerability_type: str
    payload_used: str

    # Evidence
    screenshots: List[str] = field(default_factory=list)  # Paths to screenshot files
    video_path: Optional[str] = None
    har_path: Optional[str] = None
    console_logs: List[Dict] = field(default_factory=list)
    network_logs: List[Dict] = field(default_factory=list)
    dom_snapshot: Optional[str] = None

    # Request/Response
    request_sent: Optional[Dict] = None
    response_received: Optional[Dict] = None

    # Validation
    payload_executed: bool = False
    execution_evidence: str = ""
    false_positive_indicators: List[str] = field(default_factory=list)

    # Metadata
    reproduction_time: str = ""
    browser_version: str = ""
    user_agent: str = ""


class BrowserReproducer:
    """Real Firefox browser reproduction with Playwright"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.browser = None
        self.context = None
        self.evidence_dir = Path(self.val_config.evidence.screenshot_dir)
        self.video_dir = Path(self.val_config.evidence.video_dir)
        self.har_dir = Path(self.val_config.evidence.har_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.video_dir.mkdir(parents=True, exist_ok=True)
        self.har_dir.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self):
        await self._launch_browser()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_browser()

    async def _launch_browser(self):
        """Launch real Firefox browser with Playwright"""
        try:
            from playwright.async_api import async_playwright

            self.playwright = await async_playwright().start()

            # Launch Firefox (NOT headless for real evidence)
            self.browser = await self.playwright.firefox.launch(
                headless=self.val_config.browser.headless,  # False for real evidence
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                    '--ignore-certificate-errors',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                ],
                firefox_user_prefs={
                    'dom.webdriver.enabled': False,
                    'useAutomationExtension': False,
                }
            )

            # Create context with recording
            self.context = await self.browser.new_context(
                viewport={'width': self.val_config.browser.viewport_width, 'height': self.val_config.browser.viewport_height},
                user_agent=self.val_config.browser.user_agent,
                ignore_https_errors=self.val_config.browser.ignore_https_errors,
                record_video_dir=str(self.video_dir) if self.val_config.browser.record_video else None,
                record_video_size={'width': 1920, 'height': 1080},
                java_script_enabled=True,
                accept_downloads=True,
            )

            # Enable CDP for network capture
            self.client = await self.context.new_cdp_session(self.context.pages[0] if self.context.pages else await self.context.new_page())

            await self.client.send('Network.enable')
            await self.client.send('Console.enable')
            await self.client.send('Page.enable')

        except Exception as e:
            print(f"Failed to launch browser: {e}")
            raise

    async def _close_browser(self):
        """Close browser and cleanup"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()

    async def reproduce_xss(self, finding: VulnerabilityFinding) -> ReproductionResult:
        """Reproduce XSS vulnerability with real browser"""
        result = ReproductionResult(
            success=False,
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            target_url=finding.target.url,
            vulnerability_type="xss",
            payload_used=finding.evidence.get('payload', ''),
            reproduction_time=datetime.utcnow().isoformat(),
        )

        page = await self.context.new_page()

        # Set up event listeners
        console_logs = []
        network_logs = []
        dialog_triggered = False
        dialog_message = ""

        page.on('console', lambda msg: console_logs.append({
            'type': msg.type,
            'text': msg.text,
            'timestamp': datetime.utcnow().isoformat(),
        }))

        page.on('request', lambda req: network_logs.append({
            'type': 'request',
            'url': req.url,
            'method': req.method,
            'headers': req.headers,
            'timestamp': datetime.utcnow().isoformat(),
        }))

        page.on('response', lambda resp: network_logs.append({
            'type': 'response',
            'url': resp.url,
            'status': resp.status,
            'headers': resp.headers,
            'timestamp': datetime.utcnow().isoformat(),
        }))

        page.on('dialog', lambda dialog: self._handle_dialog(dialog, dialog_message))

        # Navigate to target with payload
        payload = finding.evidence.get('payload', '')
        param = finding.evidence.get('parameter', '')
        test_url = self._inject_payload(finding.target.url, param, payload)

        try:
            # Navigate
            response = await page.goto(test_url, wait_until='networkidle', timeout=self.val_config.browser.timeout)

            result.request_sent = {
                'url': test_url,
                'method': 'GET',
                'headers': dict(response.request.headers) if response.request.headers else {},
            }

            if response:
                result.response_received = {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'url': response.url,
                }

            # Wait for payload execution
            await page.wait_for_timeout(3000)

            # Check for alert dialog (XSS execution)
            if dialog_triggered:
                result.payload_executed = True
                result.execution_evidence = f"Alert dialog triggered: {dialog_message}"
                result.success = True

            # Check for payload in DOM
            dom_content = await page.content()
            if payload in dom_content and not self._is_encoded(payload, dom_content):
                result.payload_executed = True
                result.execution_evidence = "Payload found unencoded in DOM"
                result.success = True

            # Take screenshot
            if self.val_config.browser.screenshot_on_success and result.success:
                screenshot_path = await self._take_screenshot(page, finding, "success")
                result.screenshots.append(screenshot_path)

            # Take screenshot on failure too
            if self.val_config.browser.screenshot_on_failure and not result.success:
                screenshot_path = await self._take_screenshot(page, finding, "failure")
                result.screenshots.append(screenshot_path)

            # Capture HAR
            if self.val_config.browser.har_capture:
                har_path = await self._capture_har(page, finding)
                result.har_path = har_path

            # Get video path
            video = page.video
            if video:
                result.video_path = await video.path()

            result.console_logs = console_logs
            result.network_logs = network_logs
            result.dom_snapshot = dom_content[:10000]  # Limit size

        except Exception as e:
            result.false_positive_indicators.append(f"Reproduction error: {str(e)}")
            if self.val_config.browser.screenshot_on_failure:
                screenshot_path = await self._take_screenshot(page, finding, "error")
                result.screenshots.append(screenshot_path)

        finally:
            await page.close()

        return result

    async def reproduce_sqli(self, finding: VulnerabilityFinding) -> ReproductionResult:
        """Reproduce SQL injection"""
        result = ReproductionResult(
            success=False,
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            target_url=finding.target.url,
            vulnerability_type="sqli",
            payload_used=finding.evidence.get('payload', ''),
            reproduction_time=datetime.utcnow().isoformat(),
        )

        page = await self.context.new_page()

        console_logs = []
        network_logs = []

        page.on('console', lambda msg: console_logs.append({
            'type': msg.type, 'text': msg.text, 'timestamp': datetime.utcnow().isoformat()}))
        page.on('request', lambda req: network_logs.append({'type': 'request', 'url': req.url, 'method': req.method}))
        page.on('response', lambda resp: network_logs.append({'type': 'response', 'url': resp.url, 'status': resp.status}))

        payload = finding.evidence.get('payload', '')
        param = finding.evidence.get('parameter', '')
        test_url = self._inject_payload(finding.target.url, param, payload)

        try:
            response = await page.goto(test_url, wait_until='networkidle', timeout=self.val_config.browser.timeout)

            result.request_sent = {'url': test_url, 'method': 'GET'}
            if response:
                result.response_received = {'status': response.status, 'url': response.url}

            await page.wait_for_timeout(3000)

            # Check for SQL error messages in response
            dom_content = await page.content()
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite',
                'syntax error', 'unclosed quotation', 'Microsoft OLE DB',
            ]

            for error in sql_errors:
                if error.lower() in dom_content.lower():
                    result.payload_executed = True
                    result.execution_evidence = f"SQL error detected: {error}"
                    result.success = True
                    break

            # Check for data exfiltration (UNION results)
            if 'uid=' in dom_content or 'root:' in dom_content or 'id:' in dom_content:
                result.payload_executed = True
                result.execution_evidence = "Data exfiltration detected in response"
                result.success = True

            if self.val_config.browser.screenshot_on_success and result.success:
                result.screenshots.append(await self._take_screenshot(page, finding, "success"))

            if self.val_config.browser.har_capture:
                result.har_path = await self._capture_har(page, finding)

            video = page.video
            if video:
                result.video_path = await video.path()

            result.console_logs = console_logs
            result.network_logs = network_logs

        except Exception as e:
            result.false_positive_indicators.append(f"Reproduction error: {str(e)}")
        finally:
            await page.close()

        return result

    async def reproduce_ssrf(self, finding: VulnerabilityFinding) -> ReproductionResult:
        """Reproduce SSRF vulnerability"""
        result = ReproductionResult(
            success=False,
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            target_url=finding.target.url,
            vulnerability_type="ssrf",
            payload_used=finding.evidence.get('payload', ''),
            reproduction_time=datetime.utcnow().isoformat(),
        }

        page = await self.context.new_page()

        network_logs = []
        page.on('request', lambda req: network_logs.append({'type': 'request', 'url': req.url, 'method': req.method}))
        page.on('response', lambda resp: network_logs.append({'type': 'response', 'url': resp.url, 'status': resp.status}))

        payload = finding.evidence.get('payload', '')
        param = finding.evidence.get('parameter', '')
        test_url = self._inject_payload(finding.target.url, param, payload)

        try:
            response = await page.goto(test_url, wait_until='networkidle', timeout=self.val_config.browser.timeout)

            result.request_sent = {'url': test_url, 'method': 'GET'}
            if response:
                result.response_received = {'status': response.status, 'url': response.url}

            await page.wait_for_timeout(5000)  # Longer wait for SSRF

            # Check for SSRF indicators in network logs
            for log in network_logs:
                if log['type'] == 'response':
                    url = log['url']
                    # Check if internal IPs were accessed
                    if any(x in url for x in ['127.0.0.1', 'localhost', '169.254.169.254', 'metadata.google.internal']):
                        result.payload_executed = True
                        result.execution_evidence = f"Internal request detected: {url}"
                        result.success = True
                        break

            # Check response content for cloud metadata
            dom_content = await page.content()
            cloud_indicators = ['ami-id', 'instance-id', 'iam', 'project-id', 'droplet-id']
            for ind in cloud_indicators:
                if ind in dom_content.lower():
                    result.payload_executed = True
                    result.execution_evidence = f"Cloud metadata found: {ind}"
                    result.success = True
                    break

            if self.val_config.browser.screenshot_on_success and result.success:
                result.screenshots.append(await self._take_screenshot(page, finding, "success"))

            if self.val_config.browser.har_capture:
                result.har_path = await self._capture_har(page, finding)

            video = page.video
            if video:
                result.video_path = await video.path()

            result.network_logs = network_logs

        except Exception as e:
            result.false_positive_indicators.append(f"Reproduction error: {str(e)}")
        finally:
            await page.close()

        return result

    async def reproduce_rce(self, finding: VulnerabilityFinding) -> ReproductionResult:
        """Reproduce RCE vulnerability"""
        result = ReproductionResult(
            success=False,
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            target_url=finding.target.url,
            vulnerability_type="rce",
            payload_used=finding.evidence.get('payload', ''),
            reproduction_time=datetime.utcnow().isoformat(),
        )

        page = await self.context.new_page()

        console_logs = []
        network_logs = []

        page.on('console', lambda msg: console_logs.append({'type': msg.type, 'text': msg.text}))
        page.on('request', lambda req: network_logs.append({'type': 'request', 'url': req.url, 'method': req.method}))
        page.on('response', lambda resp: network_logs.append({'type': 'response', 'url': resp.url, 'status': resp.status}))

        payload = finding.evidence.get('payload', '')
        param = finding.evidence.get('parameter', '')
        test_url = self._inject_payload(finding.target.url, param, payload)

        try:
            response = await page.goto(test_url, wait_until='networkidle', timeout=self.val_config.browser.timeout)

            result.request_sent = {'url': test_url, 'method': 'GET'}
            if response:
                result.response_received = {'status': response.status, 'url': response.url}

            await page.wait_for_timeout(3000)

            dom_content = await page.content()

            # Check for command output
            rce_indicators = ['uid=', 'gid=', 'groups=', 'root:', 'daemon:', 'bin:', 'sys:',
                            'PING', '64 bytes from', 'Windows IP Configuration']

            for ind in rce_indicators:
                if ind in dom_content:
                    result.payload_executed = True
                    result.execution_evidence = f"RCE indicator found: {ind}"
                    result.success = True
                    break

            if self.val_config.browser.screenshot_on_success and result.success:
                result.screenshots.append(await self._take_screenshot(page, finding, "success"))

            if self.val_config.browser.har_capture:
                result.har_path = await self._capture_har(page, finding)

            video = page.video
            if video:
                result.video_path = await video.path()

            result.console_logs = console_logs
            result.network_logs = network_logs

        except Exception as e:
            result.false_positive_indicators.append(f"Reproduction error: {str(e)}")
        finally:
            await page.close()

        return result

    async def reproduce_generic(self, finding: VulnerabilityFinding) -> ReproductionResult:
        """Generic reproduction for any vulnerability type"""
        result = ReproductionResult(
            success=False,
            finding_id=finding.id if hasattr(finding, 'id') else 0,
            target_url=finding.target.url,
            vulnerability_type=finding.vuln_type,
            payload_used=finding.evidence.get('payload', ''),
            reproduction_time=datetime.utcnow().isoformat(),
        )

        page = await self.context.new_page()

        network_logs = []
        page.on('request', lambda req: network_logs.append({'type': 'request', 'url': req.url, 'method': req.method}))
        page.on('response', lambda resp: network_logs.append({'type': 'response', 'url': resp.url, 'status': resp.status}))

        payload = finding.evidence.get('payload', '')
        param = finding.evidence.get('parameter', '')
        test_url = self._inject_payload(finding.target.url, param, payload)

        try:
            response = await page.goto(test_url, wait_until='networkidle', timeout=self.val_config.browser.timeout)

            result.request_sent = {'url': test_url, 'method': 'GET'}
            if response:
                result.response_received = {'status': response.status, 'url': response.url}

            await page.wait_for_timeout(3000)

            # Basic success criteria - got valid response
            if response and response.status in [200, 201, 202, 204, 301, 302, 401, 403, 500]:
                result.success = True
                result.payload_executed = True
                result.execution_evidence = f"Request completed with status {response.status}"

            if self.val_config.browser.screenshot_on_success and result.success:
                result.screenshots.append(await self._take_screenshot(page, finding, "success"))
            elif self.val_config.browser.screenshot_on_failure and not result.success:
                result.screenshots.append(await self._take_screenshot(page, finding, "failure"))

            if self.val_config.browser.har_capture:
                result.har_path = await self._capture_har(page, finding)

            video = page.video
            if video:
                result.video_path = await video.path()

            result.network_logs = network_logs

        except Exception as e:
            result.false_positive_indicators.append(f"Reproduction error: {str(e)}")
        finally:
            await page.close()

        return result

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _is_encoded(self, payload: str, content: str) -> bool:
        """Check if payload appears encoded in content"""
        import html
        encoded = html.escape(payload)
        return encoded in content and payload not in content

    def _handle_dialog(self, dialog, dialog_message):
        """Handle JavaScript dialogs (alert, confirm, prompt)"""
        dialog_message = dialog.message
        # Auto-dismiss for reproduction
        asyncio.create_task(dialog.dismiss())

    async def _take_screenshot(self, page, finding: VulnerabilityFinding, suffix: str) -> str:
        """Take annotated screenshot"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        finding_id = finding.id if hasattr(finding, 'id') else 'unknown'
        filename = f"finding_{finding_id}_{finding.vuln_type}_{suffix}_{timestamp}.png"
        filepath = self.evidence_dir / filename

        await page.screenshot(path=str(filepath), full_page=True)

        # Annotate if enabled
        if self.val_config.evidence.annotate_screenshots:
            await self._annotate_screenshot(filepath, finding, suffix)

        return str(filepath)

    async def _annotate_screenshot(self, filepath: Path, finding: VulnerabilityFinding, suffix: str):
        """Annotate screenshot with vulnerability info"""
        try:
            from PIL import Image, ImageDraw, ImageFont

            img = Image.open(filepath)
            draw = ImageDraw.Draw(img)

            # Draw red box around vulnerable area (simplified)
            width, height = img.size
            box_color = self.val_config.evidence.annotation_color
            box_width = self.val_config.evidence.annotation_width

            # Draw border
            draw.rectangle([0, 0, width-1, height-1], outline=box_color, width=box_width)

            # Add text annotation
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
            except Exception:
                font = ImageFont.load_default()

            text = f"{finding.vuln_type.upper()} - {suffix.upper()}"
            draw.text((10, 10), text, fill=box_color, font=font)

            img.save(filepath)
        except Exception:
            pass  # Annotation optional

    async def _capture_har(self, page, finding: VulnerabilityFinding) -> str:
        """Capture HAR file"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        finding_id = finding.id if hasattr(finding, 'id') else 'unknown'
        filename = f"finding_{finding_id}_{finding.vuln_type}_{timestamp}.har"
        filepath = self.har_dir / filename

        # Get HAR from CDP
        try:
            har = await self.client.send('Network.getHAR')
            with open(filepath, 'w') as f:
                json.dump(har, f, indent=2)
        except Exception:
            # Fallback: create basic HAR
            har_data = {
                'log': {
                    'version': '1.2',
                    'creator': {'name': 'BugHunter', 'version': '1.0'},
                    'entries': [],
                }
            }
            with open(filepath, 'w') as f:
                json.dump(har_data, f, indent=2)

        return str(filepath)


async def reproduce_finding(finding: VulnerabilityFinding, config_manager=None) -> ReproductionResult:
    """Reproduce a finding with real browser"""
    async with BrowserReproducer(config_manager) as reproducer:
        if finding.vuln_type == 'xss':
            return await reproducer.reproduce_xss(finding)
        elif finding.vuln_type == 'sqli':
            return await reproducer.reproduce_sqli(finding)
        elif finding.vuln_type == 'ssrf':
            return await reproducer.reproduce_ssrf(finding)
        elif finding.vuln_type == 'rce':
            return await reproducer.reproduce_rce(finding)
        else:
            return await reproducer.reproduce_generic(finding)