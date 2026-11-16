"""
Playwright MCP Server
Provides MCP tools for browser automation with real Firefox
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from core.config_manager import get_config


@dataclass
class BrowserSession:
    """Browser session state"""
    context_id: str
    page_id: str
    url: str = ""


class PlaywrightMCPServer:
    """MCP Server for Playwright browser automation"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.playwright = None
        self.browser = None
        self.contexts: Dict[str, Any] = {}
        self.pages: Dict[str, Any] = {}
        self.evidence_dir = Path(self.val_config.evidence.screenshot_dir)
        self.video_dir = Path(self.val_config.evidence.video_dir)
        self.har_dir = Path(self.val_config.evidence.har_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.video_dir.mkdir(parents=True, exist_ok=True)
        self.har_dir.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self):
        await self._launch()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close()

    async def _launch(self):
        """Launch Playwright with Firefox"""
        from playwright.async_api import async_playwright

        self.playwright = await async_playwright().start()

        self.browser = await self.playwright.firefox.launch(
            headless=self.val_config.browser.headless,
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

    async def _close(self):
        """Close browser and cleanup"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def new_context(self, context_id: str = None, viewport: Dict = None,
                          record_video: bool = None, user_agent: str = None) -> Dict[str, Any]:
        """Create new browser context"""
        try:
            context_id = context_id or f"ctx_{len(self.contexts)}"

            context = await self.browser.new_context(
                viewport=viewport or {
                    'width': self.val_config.browser.viewport_width,
                    'height': self.val_config.browser.viewport_height
                },
                user_agent=user_agent or self.val_config.browser.user_agent,
                ignore_https_errors=self.val_config.browser.ignore_https_errors,
                record_video_dir=str(self.video_dir) if (record_video or self.val_config.browser.record_video) else None,
                record_video_size={'width': 1920, 'height': 1080},
                java_script_enabled=True,
                accept_downloads=True,
            )

            # Enable CDP for network capture
            page = await context.new_page()
            client = await context.new_cdp_session(page)
            await client.send('Network.enable')
            await client.send('Console.enable')
            await client.send('Page.enable')

            self.contexts[context_id] = {
                'context': context,
                'page': page,
                'cdp_client': client,
                'console_logs': [],
                'network_logs': [],
            }

            # Set up event listeners
            page.on('console', lambda msg: self.contexts[context_id]['console_logs'].append({
                'type': msg.type,
                'text': msg.text,
                'timestamp': asyncio.get_event_loop().time(),
            }))
            page.on('request', lambda req: self.contexts[context_id]['network_logs'].append({
                'type': 'request',
                'url': req.url,
                'method': req.method,
                'headers': req.headers,
            }))
            page.on('response', lambda resp: self.contexts[context_id]['network_logs'].append({
                'type': 'response',
                'url': resp.url,
                'status': resp.status,
                'headers': resp.headers,
            }))

            return {"success": True, "context_id": context_id}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def navigate(self, context_id: str, url: str, wait_until: str = "networkidle",
                       timeout: int = None) -> Dict[str, Any]:
        """Navigate to URL"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            ctx = self.contexts[context_id]
            page = ctx['page']

            response = await page.goto(
                url,
                wait_until=wait_until,
                timeout=timeout or self.val_config.browser.timeout
            )

            return {
                "success": True,
                "url": page.url,
                "status": response.status if response else None,
                "title": await page.title(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def click(self, context_id: str, selector: str, options: Dict = None) -> Dict[str, Any]:
        """Click element"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            await page.click(selector, **(options or {}))
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def fill(self, context_id: str, selector: str, value: str) -> Dict[str, Any]:
        """Fill input field"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            await page.fill(selector, value)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def evaluate(self, context_id: str, script: str) -> Dict[str, Any]:
        """Execute JavaScript in page context"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            result = await page.evaluate(script)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def screenshot(self, context_id: str, full_page: bool = True,
                         annotated: bool = False, finding_info: Dict = None) -> Dict[str, Any]:
        """Take screenshot"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']

            timestamp = asyncio.get_event_loop().time()
            filename = f"screenshot_{context_id}_{int(timestamp)}.png"
            filepath = self.evidence_dir / filename

            await page.screenshot(path=str(filepath), full_page=full_page)

            # Annotate if requested
            if annotated and finding_info:
                await self._annotate_screenshot(filepath, finding_info)

            return {"success": True, "path": str(filepath)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _annotate_screenshot(self, filepath: Path, finding_info: Dict):
        """Annotate screenshot with vulnerability info"""
        try:
            from PIL import Image, ImageDraw, ImageFont

            img = Image.open(filepath)
            draw = ImageDraw.Draw(img)
            width, height = img.size

            # Draw border
            draw.rectangle([0, 0, width-1, height-1], outline="red", width=3)

            # Add text
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
            except Exception:
                font = ImageFont.load_default()

            text = f"{finding_info.get('vuln_type', 'VULN').upper()} - {finding_info.get('title', '')[:80]}"
            draw.rectangle([0, 0, width, 50], fill="red")
            draw.text((10, 10), text, fill="white", font=font)

            img.save(filepath)
        except Exception:
            pass

    async def get_har(self, context_id: str) -> Dict[str, Any]:
        """Get HAR file from context"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            client = self.contexts[context_id]['cdp_client']
            har = await client.send('Network.getHAR')

            timestamp = asyncio.get_event_loop().time()
            filename = f"har_{context_id}_{int(timestamp)}.har"
            filepath = self.har_dir / filename

            with open(filepath, 'w') as f:
                json.dump(har, f, indent=2)

            return {"success": True, "path": str(filepath), "har": har}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_console_logs(self, context_id: str) -> Dict[str, Any]:
        """Get console logs"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            return {"success": True, "logs": self.contexts[context_id]['console_logs']}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_network_logs(self, context_id: str) -> Dict[str, Any]:
        """Get network logs"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            return {"success": True, "logs": self.contexts[context_id]['network_logs']}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def wait_for_selector(self, context_id: str, selector: str, timeout: int = 30000) -> Dict[str, Any]:
        """Wait for element to appear"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            await page.wait_for_selector(selector, timeout=timeout)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_content(self, context_id: str) -> Dict[str, Any]:
        """Get page HTML content"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            content = await page.content()
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def close_context(self, context_id: str) -> Dict[str, Any]:
        """Close browser context"""
        try:
            if context_id in self.contexts:
                ctx = self.contexts[context_id]
                await ctx['context'].close()
                del self.contexts[context_id]
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_video(self, context_id: str) -> Dict[str, Any]:
        """Get recorded video path"""
        try:
            if context_id not in self.contexts:
                return {"success": False, "error": "Context not found"}

            page = self.contexts[context_id]['page']
            video = page.video
            if video:
                path = await video.path()
                return {"success": True, "path": path}
            return {"success": False, "error": "No video recorded"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# MCP Tool definitions
PLAYWRIGHT_MCP_TOOLS = [
    {
        "name": "playwright_new_context",
        "description": "Create new browser context",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string", "description": "Custom context ID"},
                "viewport": {"type": "object", "properties": {"width": {"type": "integer"}, "height": {"type": "integer"}}},
                "record_video": {"type": "boolean"},
                "user_agent": {"type": "string"},
            },
        },
    },
    {
        "name": "playwright_navigate",
        "description": "Navigate to URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string", "description": "Context ID"},
                "url": {"type": "string", "description": "URL to navigate to"},
                "wait_until": {"type": "string", "description": "Wait condition", "default": "networkidle"},
                "timeout": {"type": "integer", "description": "Timeout in ms"},
            },
            "required": ["context_id", "url"],
        },
    },
    {
        "name": "playwright_click",
        "description": "Click element",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
                "selector": {"type": "string"},
                "options": {"type": "object"},
            },
            "required": ["context_id", "selector"],
        },
    },
    {
        "name": "playwright_fill",
        "description": "Fill input field",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
                "selector": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["context_id", "selector", "value"],
        },
    },
    {
        "name": "playwright_evaluate",
        "description": "Execute JavaScript in page",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
                "script": {"type": "string"},
            },
            "required": ["context_id", "script"],
        },
    },
    {
        "name": "playwright_screenshot",
        "description": "Take screenshot",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
                "full_page": {"type": "boolean", "default": True},
                "annotated": {"type": "boolean", "default": False},
                "finding_info": {"type": "object"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_get_har",
        "description": "Get HAR file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_get_console_logs",
        "description": "Get console logs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_get_network_logs",
        "description": "Get network logs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_wait_for_selector",
        "description": "Wait for element",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
                "selector": {"type": "string"},
                "timeout": {"type": "integer", "default": 30000},
            },
            "required": ["context_id", "selector"],
        },
    },
    {
        "name": "playwright_get_content",
        "description": "Get page HTML",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_close_context",
        "description": "Close browser context",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
    {
        "name": "playwright_get_video",
        "description": "Get recorded video",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {"type": "string"},
            },
            "required": ["context_id"],
        },
    },
]


async def handle_playwright_mcp_call(server: PlaywrightMCPServer, tool_name: str, arguments: Dict) -> Dict:
    """Handle MCP tool call for Playwright"""
    method_map = {
        "playwright_new_context": server.new_context,
        "playwright_navigate": server.navigate,
        "playwright_click": server.click,
        "playwright_fill": server.fill,
        "playwright_evaluate": server.evaluate,
        "playwright_screenshot": server.screenshot,
        "playwright_get_har": server.get_har,
        "playwright_get_console_logs": server.get_console_logs,
        "playwright_get_network_logs": server.get_network_logs,
        "playwright_wait_for_selector": server.wait_for_selector,
        "playwright_get_content": server.get_content,
        "playwright_close_context": server.close_context,
        "playwright_get_video": server.get_video,
    }

    if tool_name not in method_map:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    method = method_map[tool_name]
    return await method(**arguments)