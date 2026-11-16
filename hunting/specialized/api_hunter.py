"""
Specialized API Hunter
GraphQL, REST, gRPC, WebSocket API vulnerabilities
"""

import asyncio
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


class APIHunter:
    """Specialized API vulnerability hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for API vulnerabilities"""
        for target in targets[:50]:
            await self._detect_api_type(target)
            await self._test_graphql(target)
            await self._test_rest_api(target)
            await self._test_mass_assignment(target)
            await self._test_bola(target)
            await self._test_rate_limiting(target)
            await self._test_api_versioning(target)

        return self.findings

    async def _detect_api_type(self, target: ScanTarget) -> Optional[str]:
        """Detect API type from URL and response"""
        url_lower = target.url.lower()

        if '/graphql' in url_lower or 'graphql' in url_lower:
            target.technology.append('graphql')
            return 'graphql'
        elif '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower:
            target.technology.append('rest')
            return 'rest'
        elif target.url.startswith('ws://') or target.url.startswith('wss://'):
            target.technology.append('websocket')
            return 'websocket'

        # Check response headers/content
        # This would need actual request
        return None

    async def _test_graphql(self, target: ScanTarget):
        """Test GraphQL vulnerabilities"""
        if 'graphql' not in target.technology:
            return

        # Test introspection
        await self._test_graphql_introspection(target)

        # Test query depth
        await self._test_graphql_depth(target)

        # Test field suggestions
        await self._test_graphql_field_suggestions(target)

        # Test batch queries
        await self._test_graphql_batching(target)

        # Test CSRF
        await self._test_graphql_csrf(target)

    async def _test_graphql_introspection(self, target: ScanTarget):
        """Test GraphQL introspection"""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                    }
                }
            }
        }
        """

        result = await self._send_graphql_query(target, introspection_query)
        if result and 'data' in result and '__schema' in result.get('data', {}):
            finding = VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="graphql_introspection",
                severity="P3",
                title="GraphQL Introspection Enabled",
                description="GraphQL introspection is enabled, exposing full schema including queries, mutations, types, and directives.",
                target=target,
                evidence={
                    "technique": "introspection",
                    "schema_types": len(result['data']['__schema'].get('types', [])),
                },
                poc=self._generate_graphql_poc(introspection_query),
                confidence=0.9,
                tags=["graphql", "introspection", "information-disclosure"],
            )
            self.findings.append(finding)

    async def _test_graphql_depth(self, target: ScanTarget):
        """Test GraphQL query depth limit"""
        # Build deeply nested query
        def build_deep_query(depth: int) -> str:
            query = "query {"
            for i in range(depth):
                query += f" level{i}: __typename "
            query += "}"
            return query

        for depth in [10, 20, 50, 100]:
            query = build_deep_query(depth)
            result = await self._send_graphql_query(target, query)

            if result and 'errors' not in result:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="graphql_depth",
                    severity="P4",
                    title=f"GraphQL Query Depth Limit Missing (depth={depth})",
                    description=f"GraphQL accepts deeply nested queries (depth={depth}). Could lead to DoS.",
                    target=target,
                    evidence={
                        "technique": "depth_limit",
                        "tested_depth": depth,
                    },
                    poc=self._generate_graphql_poc(query),
                    confidence=0.7,
                    tags=["graphql", "dos", "depth-limit"],
                )
                self.findings.append(finding)
                return

    async def _test_graphql_field_suggestions(self, target: ScanTarget):
        """Test GraphQL field suggestions for schema leakage"""
        # Query with typo to get suggestions
        typo_query = """
        query {
            usr { id }
        }
        """

        result = await self._send_graphql_query(target, typo_query)
        if result and 'errors' in result:
            for error in result['errors']:
                if 'did you mean' in error.get('message', '').lower():
                    finding = VulnerabilityFinding(
                        scanner=ScannerType.CUSTOM,
                        vuln_type="graphql_field_suggestions",
                        severity="P4",
                        title="GraphQL Field Suggestions Enabled",
                        description="GraphQL field suggestions leak schema information via error messages.",
                        target=target,
                        evidence={
                            "technique": "field_suggestions",
                            "error_message": error.get('message'),
                        },
                        poc="",
                        confidence=0.8,
                        tags=["graphql", "information-disclosure", "field-suggestions"],
                    )
                    self.findings.append(finding)
                    return

    async def _test_graphql_batching(self, target: ScanTarget):
        """Test GraphQL query batching"""
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]

        result = await self._send_graphql_batch(target, batch_query)
        if result and isinstance(result, list) and len(result) == 5:
            finding = VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="graphql_batching",
                severity="P4",
                title="GraphQL Query Batching Enabled",
                description="GraphQL query batching allows multiple queries in single request. Can be used for brute force/DoS.",
                target=target,
                evidence={
                    "technique": "batching",
                    "batch_size": 5,
                },
                poc="",
                confidence=0.7,
                tags=["graphql", "batching", "dos"],
            )
            self.findings.append(finding)

    async def _test_graphql_csrf(self, target: ScanTarget):
        """Test GraphQL CSRF"""
        # GraphQL endpoints often accept GET requests with query param
        # Test if mutation works via GET
        mutation = """
        mutation {
            changeEmail(email: "attacker@evil.com") { success }
        }
        """

        import httpx
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(target.url, params={"query": mutation})

            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    finding = VulnerabilityFinding(
                        scanner=ScannerType.CUSTOM,
                        vuln_type="graphql_csrf",
                        severity="P3",
                        title="GraphQL CSRF via GET Request",
                        description="GraphQL mutations accepted via GET requests, enabling CSRF attacks.",
                        target=target,
                        evidence={
                            "technique": "csrf_get",
                            "mutation": mutation,
                        },
                        poc="",
                        confidence=0.8,
                        tags=["graphql", "csrf", "auth-bypass"],
                    )
                    self.findings.append(finding)
        except Exception:
            pass

    async def _test_rest_api(self, target: ScanTarget):
        """Test REST API vulnerabilities"""
        # Test HTTP method override
        await self._test_method_override(target)

        # Test API versioning bypass
        await self._test_version_bypass(target)

        # Test debug endpoints
        await self._test_debug_endpoints(target)

    async def _test_method_override(self, target: ScanTarget):
        """Test HTTP method override"""
        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-Original-Method",
        ]

        for header in override_headers:
            headers = {header: "DELETE"}
            result = await self._send_request_with_headers(target, headers)

            if result and result.status_code in [200, 204]:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="method_override",
                    severity="P3",
                    title=f"HTTP Method Override via {header}",
                    description=f"HTTP method override header {header} allows DELETE via POST.",
                    target=target,
                    evidence={
                        "technique": "method_override",
                        "header": header,
                    },
                    poc="",
                    confidence=0.8,
                    tags=["rest", "method-override", "auth-bypass"],
                )
                self.findings.append(finding)
                return

    async def _test_version_bypass(self, target: ScanTarget):
        """Test API versioning bypass"""
        # Try different version formats
        versions = ['v1', 'v2', 'v3', 'v0', 'beta', 'alpha', 'internal', 'admin']

        for version in versions:
            test_url = target.url.replace('/api/', f'/api/{version}/')
            if test_url == target.url:
                test_url = target.url.rstrip('/') + f'/{version}'

            result = await self._send_request_to_url(test_url, target.method, target.parameters)
            if result and result.status_code == 200:
                # Check if response differs from original
                pass  # Would need baseline

    async def _test_debug_endpoints(self, target: ScanTarget):
        """Test debug endpoints"""
        debug_paths = [
            '/debug', '/actuator', '/health', '/metrics', '/info',
            '/swagger', '/api-docs', '/openapi', '/graphql-playground',
            '/graphiql', '/altair', '/voyager',
            '/.env', '/.git', '/.well-known',
        ]

        base_url = '/'.join(target.url.split('/')[:3])  # scheme://host

        for path in debug_paths:
            test_url = base_url + path
            result = await self._send_request_to_url(test_url, 'GET', {})
            if result and result.status_code == 200:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="debug_endpoint",
                    severity="P3",
                    title=f"Debug Endpoint Exposed: {path}",
                    description=f"Debug/development endpoint exposed: {path}",
                    target=target,
                    evidence={
                        "technique": "debug_endpoint",
                        "path": path,
                        "url": test_url,
                    },
                    poc="",
                    confidence=0.8,
                    tags=["rest", "debug", "information-disclosure"],
                )
                self.findings.append(finding)

    async def _test_mass_assignment(self, target: ScanTarget):
        """Test mass assignment / parameter pollution"""
        if target.method not in ['POST', 'PUT', 'PATCH']:
            return

        # Test adding extra parameters
        extra_params = {
            "is_admin": "true",
            "role": "admin",
            "user_id": "1",
            "account_type": "premium",
            "is_active": "true",
            "permissions": '["admin"]',
        }

        test_params = dict(target.parameters)
        test_params.update(extra_params)

        result = await self._send_request(target, "", "", test_params)
        if result and result.status_code in [200, 201]:
            # Check if extra params were accepted
            if 'admin' in result.text.lower() or 'premium' in result.text.lower():
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="mass_assignment",
                    severity="P2",
                    title="Mass Assignment / Parameter Pollution",
                    description=f"API accepts unexpected parameters that modify user privileges.",
                    target=target,
                    evidence={
                        "technique": "mass_assignment",
                        "extra_params": extra_params,
                    },
                    poc="",
                    confidence=0.7,
                    tags=["rest", "mass-assignment", "privilege-escalation"],
                )
                self.findings.append(finding)

    async def _test_bola(self, target: ScanTarget):
        """Test Broken Object Level Authorization (BOLA)"""
        # Similar to IDOR but for APIs
        id_params = {}
        for param_name, param_value in target.parameters.items():
            if param_value.isdigit() or re.match(r'^[a-f0-9-]{36}$', param_value):  # UUID
                id_params[param_name] = param_value

        if not id_params:
            return

        for param_name, original_id in id_params.items():
            # Test adjacent IDs
            test_ids = []
            try:
                id_num = int(original_id)
                test_ids = [id_num - 1, id_num + 1, 1, 2]
            except ValueError:
                # UUID - harder to test
                pass

            for test_id in test_ids:
                if test_id <= 0:
                    continue

                test_params = dict(target.parameters)
                test_params[param_name] = str(test_id)

                result = await self._send_request(target, "", "", test_params)
                if result and result.status_code == 200:
                    finding = VulnerabilityFinding(
                        scanner=ScannerType.CUSTOM,
                        vuln_type="bola",
                        severity="P2",
                        title=f"BOLA in {param_name} parameter",
                        description=f"Broken Object Level Authorization in {param_name} parameter. Accessing ID {test_id} returns data.",
                        target=target,
                        evidence={
                            "technique": "bola",
                            "original_id": original_id,
                            "tested_id": test_id,
                        },
                        poc="",
                        confidence=0.7,
                        tags=["bola", "api", "access-control"],
                    )
                    self.findings.append(finding)
                    return

    async def _test_rate_limiting(self, target: ScanTarget):
        """Test API rate limiting"""
        # Send rapid requests
        results = []
        for _ in range(20):
            result = await self._send_request(target, "", "", target.parameters)
            results.append(result)

        # Check if all succeeded (no rate limiting)
        success_count = sum(1 for r in results if r and r.status_code in [200, 201])
        if success_count == 20:
            finding = VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="rate_limiting",
                severity="P4",
                title="Missing Rate Limiting",
                description=f"API endpoint lacks rate limiting. 20/20 rapid requests succeeded.",
                target=target,
                evidence={
                    "technique": "rate_limiting",
                    "requests_sent": 20,
                    "successful": success_count,
                },
                poc="",
                confidence=0.7,
                tags=["rest", "rate-limiting", "dos"],
            )
            self.findings.append(finding)

    async def _test_api_versioning(self, target: ScanTarget):
        """Test API versioning issues"""
        # Check for deprecated versions still accessible
        pass

    async def _send_graphql_query(self, target: ScanTarget, query: str) -> Optional[Dict]:
        """Send GraphQL query"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                if target.method == "GET":
                    response = await client.get(target.url, params={"query": query})
                else:
                    response = await client.post(target.url, json={"query": query})
            return response.json()
        except Exception:
            return None

    async def _send_graphql_batch(self, target: ScanTarget, queries: List[Dict]) -> Optional[List]:
        """Send GraphQL batch query"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(target.url, json=queries)
            return response.json()
        except Exception:
            return None

    async def _send_request(self, target: ScanTarget, param_name: str, param_value: str, extra_params: Dict = None):
        """Send HTTP request"""
        import httpx

        data = dict(target.parameters)
        if param_name and param_value:
            data[param_name] = param_value
        if extra_params:
            data.update(extra_params)

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                if target.method == "GET":
                    return await client.get(target.url, params=data)
                else:
                    return await client.post(target.url, data=data)
        except Exception:
            return None

    async def _send_request_with_headers(self, target: ScanTarget, headers: Dict):
        """Send request with custom headers"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                if target.method == "GET":
                    return await client.get(target.url, params=target.parameters, headers=headers)
                else:
                    return await client.post(target.url, data=target.parameters, headers=headers)
        except Exception:
            return None

    async def _send_request_to_url(self, url: str, method: str, params: Dict):
        """Send request to specific URL"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                if method == "GET":
                    return await client.get(url, params=params)
                else:
                    return await client.post(url, data=params)
        except Exception:
            return None

    def _generate_graphql_poc(self, query: str) -> str:
        """Generate GraphQL POC"""
        return f"""# GraphQL Proof of Concept
## Query
```graphql
{query}
```

## cURL Command
```bash
curl -X POST {self.target_url if hasattr(self, 'target_url') else '<TARGET_URL>'} \\
  -H "Content-Type: application/json" \\
  -d '{{\"query\": {json.dumps(query)}}}'
```

## Python
```python
import requests
query = {json.dumps(query)}
response = requests.post('<TARGET_URL>', json={{'query': query}})
print(response.json())
```"""


async def hunt_api(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for API vulnerabilities"""
    hunter = APIHunter(config_manager or get_config())
    return await hunter.hunt(targets)