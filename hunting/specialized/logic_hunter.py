"""
Specialized Logic Hunter
Business logic vulnerabilities, race conditions, IDOR, price manipulation
"""

import asyncio
import json
import random
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config_manager import get_config
from hunting.scanner_orchestrator import VulnerabilityFinding, ScanTarget, ScannerType


class LogicHunter:
    """Specialized business logic vulnerability hunting module"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.findings: List[VulnerabilityFinding] = []

    async def hunt(self, targets: List[ScanTarget]) -> List[VulnerabilityFinding]:
        """Hunt for business logic vulnerabilities"""
        for target in targets[:50]:
            await self._test_idor(target)
            await self._test_race_conditions(target)
            await self._test_price_manipulation(target)
            await self._test_workflow_bypass(target)
            await self._test_quantity_manipulation(target)
            await self._test_coupon_abuse(target)
            await self._test_reward_abuse(target)

        return self.findings

    async def _test_idor(self, target: ScanTarget):
        """Test Insecure Direct Object References"""
        # Look for numeric IDs in parameters
        id_params = {}
        for param_name, param_value in target.parameters.items():
            if param_value.isdigit() or (param_value.startswith('id=') and param_value[3:].isdigit()):
                id_params[param_name] = param_value

        if not id_params:
            return

        # Test IDOR by incrementing/decrementing IDs
        for param_name, original_id in id_params.items():
            try:
                id_num = int(original_id)
            except ValueError:
                continue

            # Test adjacent IDs
            test_ids = [id_num - 1, id_num + 1, id_num + 10, id_num - 10, 1, 2, 999999]

            baseline = await self._send_request(target, param_name, original_id)
            if not baseline:
                continue

            baseline_length = len(baseline.text)
            baseline_status = baseline.status_code

            for test_id in test_ids:
                if test_id <= 0:
                    continue

                response = await self._send_request(target, param_name, str(test_id))
                if not response:
                    continue

                # Check if we got different data (not just error)
                if response.status_code == baseline_status:
                    # Compare content - if similar length but different content, might be IDOR
                    if abs(len(response.text) - baseline_length) < baseline_length * 0.1:
                        # Similar length - could be different user's data
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="idor",
                            severity="P2",
                            title=f"IDOR in {param_name} parameter",
                            description=f"Insecure Direct Object Reference in {param_name} parameter. Accessing ID {test_id} returns similar response structure as ID {original_id}.",
                            target=target,
                            evidence={
                                "technique": "idor",
                                "original_id": original_id,
                                "tested_id": test_id,
                                "baseline_status": baseline_status,
                                "test_status": response.status_code,
                                "baseline_length": baseline_length,
                                "test_length": len(response.text),
                            },
                            poc=self._generate_idor_poc(target.url, param_name, original_id, test_id),
                            confidence=0.7,
                            tags=["idor", "access-control"],
                        )
                        self.findings.append(finding)
                        return

    async def _test_race_conditions(self, target: ScanTarget):
        """Test race conditions"""
        # Look for endpoints that modify state
        state_changing_methods = ['POST', 'PUT', 'PATCH', 'DELETE']
        if target.method not in state_changing_methods:
            return

        # Common race condition targets
        race_endpoints = [
            'coupon', 'voucher', 'promo', 'gift',
            'reward', 'points', 'credit', 'balance',
            'withdraw', 'deposit', 'transfer',
            'vote', 'like', 'follow', 'subscribe',
            'register', 'signup', 'claim',
        ]

        url_lower = target.url.lower()
        if not any(x in url_lower for x in race_endpoints):
            return

        # Send concurrent requests
        results = await self._send_concurrent_requests(target, 10)

        # Analyze for race condition
        success_count = sum(1 for r in results if r and r.status_code in [200, 201])
        if success_count > 1:
            finding = VulnerabilityFinding(
                scanner=ScannerType.CUSTOM,
                vuln_type="race_condition",
                severity="P2",
                title=f"Race Condition in {target.url}",
                description=f"Race condition detected. {success_count}/10 concurrent requests succeeded where only 1 should.",
                target=target,
                evidence={
                    "technique": "race_condition",
                    "concurrent_requests": 10,
                    "successful_requests": success_count,
                    "status_codes": [r.status_code for r in results if r],
                },
                poc=self._generate_race_poc(target.url, target.method, target.parameters),
                confidence=0.75,
                tags=["race-condition", "concurrency"],
            )
            self.findings.append(finding)

    async def _test_price_manipulation(self, target: ScanTarget):
        """Test price manipulation"""
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['cart', 'checkout', 'order', 'purchase', 'payment', 'buy']):
            return

        # Look for price/quantity parameters
        price_params = {}
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['price', 'amount', 'cost', 'total', 'value']):
                try:
                    price_params[param_name] = float(param_value)
                except ValueError:
                    pass

        if not price_params:
            return

        for param_name, original_price in price_params.items():
            # Test negative price
            for test_price in [-original_price, 0, 0.01, original_price * 0.001, -1]:
                response = await self._send_request(target, param_name, str(test_price))
                if response and response.status_code in [200, 201]:
                    # Check if order was created with manipulated price
                    if 'success' in response.text.lower() or 'order' in response.text.lower() or 'confirm' in response.text.lower():
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="price_manipulation",
                            severity="P1",
                            title=f"Price Manipulation in {param_name} parameter",
                            description=f"Price manipulation in {param_name} parameter. Original: {original_price}, Tested: {test_price}. Order processed successfully.",
                            target=target,
                            evidence={
                                "technique": "price_manipulation",
                                "original_price": original_price,
                                "manipulated_price": test_price,
                                "response_snippet": response.text[:500],
                            },
                            poc=self._generate_price_poc(target.url, param_name, original_price, test_price),
                            confidence=0.85,
                            tags=["price-manipulation", "business-logic"],
                        )
                        self.findings.append(finding)
                        return

    async def _test_workflow_bypass(self, target: ScanTarget):
        """Test workflow/step bypass"""
        # Look for multi-step processes
        step_params = {}
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['step', 'stage', 'phase', 'flow', 'wizard']):
                step_params[param_name] = param_value

        if not step_params:
            return

        # Try to skip steps
        for param_name, current_step in step_params.items():
            try:
                step_num = int(current_step)
            except ValueError:
                continue

            # Try to jump to final step
            for test_step in [step_num + 1, step_num + 2, 99, 'complete', 'finish', 'final']:
                response = await self._send_request(target, param_name, str(test_step))
                if response and response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'complete' in response.text.lower():
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="workflow_bypass",
                            severity="P3",
                            title=f"Workflow Bypass in {param_name} parameter",
                            description=f"Workflow step bypass in {param_name} parameter. Jumped from step {current_step} to {test_step}.",
                            target=target,
                            evidence={
                                "technique": "workflow_bypass",
                                "original_step": current_step,
                                "bypassed_step": test_step,
                            },
                            poc="",
                            confidence=0.7,
                            tags=["workflow-bypass", "business-logic"],
                        )
                        self.findings.append(finding)
                        return

    async def _test_quantity_manipulation(self, target: ScanTarget):
        """Test quantity manipulation"""
        qty_params = {}
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['qty', 'quantity', 'count', 'number', 'amount']):
                try:
                    qty_params[param_name] = int(param_value)
                except ValueError:
                    pass

        if not qty_params:
            return

        for param_name, original_qty in qty_params.items():
            # Test negative/zero/large quantities
            test_quantities = [-1, 0, 999999, 2147483647, -2147483648]

            for test_qty in test_quantities:
                response = await self._send_request(target, param_name, str(test_qty))
                if response and response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'added' in response.text.lower() or 'cart' in response.text.lower():
                        finding = VulnerabilityFinding(
                            scanner=ScannerType.CUSTOM,
                            vuln_type="quantity_manipulation",
                            severity="P3",
                            title=f"Quantity Manipulation in {param_name} parameter",
                            description=f"Quantity manipulation in {param_name} parameter. Original: {original_qty}, Tested: {test_qty}. Request processed.",
                            target=target,
                            evidence={
                                "technique": "quantity_manipulation",
                                "original_qty": original_qty,
                                "tested_qty": test_qty,
                            },
                            poc="",
                            confidence=0.7,
                            tags=["quantity-manipulation", "business-logic"],
                        )
                        self.findings.append(finding)
                        return

    async def _test_coupon_abuse(self, target: ScanTarget):
        """Test coupon/voucher abuse"""
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['coupon', 'voucher', 'promo', 'discount', 'gift']):
            return

        # Test coupon reuse
        coupon_params = {}
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['coupon', 'voucher', 'promo', 'code', 'discount']):
                coupon_params[param_name] = param_value

        if not coupon_params:
            return

        # Try to apply same coupon multiple times
        for param_name, coupon_code in coupon_params.items():
            results = await self._send_concurrent_requests(target, 5, {param_name: coupon_code})
            success_count = sum(1 for r in results if r and r.status_code in [200, 201])

            if success_count > 1:
                finding = VulnerabilityFinding(
                    scanner=ScannerType.CUSTOM,
                    vuln_type="coupon_abuse",
                    severity="P2",
                    title=f"Coupon Reuse in {param_name} parameter",
                    description=f"Coupon code can be used multiple times. {success_count}/5 concurrent applications succeeded.",
                    target=target,
                    evidence={
                        "technique": "coupon_reuse",
                        "coupon_code": coupon_code,
                        "successful_uses": success_count,
                    },
                    poc="",
                    confidence=0.8,
                    tags=["coupon-abuse", "business-logic"],
                )
                self.findings.append(finding)

    async def _test_reward_abuse(self, target: ScanTarget):
        """Test reward/points abuse"""
        url_lower = target.url.lower()
        if not any(x in url_lower for x in ['reward', 'point', 'loyalty', 'referral', 'bonus']):
            return

        # Test referral abuse
        ref_params = {}
        for param_name, param_value in target.parameters.items():
            if any(x in param_name.lower() for x in ['ref', 'referral', 'invite', 'affiliate']):
                ref_params[param_name] = param_value

        if ref_params:
            # Test self-referral or multiple referrals
            for param_name, ref_code in ref_params.items():
                results = await self._send_concurrent_requests(target, 5, {param_name: ref_code})
                success_count = sum(1 for r in results if r and r.status_code in [200, 201])

                if success_count > 1:
                    finding = VulnerabilityFinding(
                        scanner=ScannerType.CUSTOM,
                        vuln_type="reward_abuse",
                        severity="P3",
                        title=f"Referral Abuse in {param_name} parameter",
                        description=f"Referral code can be used multiple times. {success_count}/5 concurrent uses succeeded.",
                        target=target,
                        evidence={
                            "technique": "referral_abuse",
                            "referral_code": ref_code,
                            "successful_uses": success_count,
                        },
                        poc="",
                        confidence=0.7,
                        tags=["referral-abuse", "business-logic"],
                    )
                    self.findings.append(finding)

    async def _send_request(self, target: ScanTarget, param_name: str, param_value: str):
        """Send HTTP request with modified parameter"""
        import httpx

        if target.method == "GET":
            url = self._inject_parameter(target.url, param_name, param_value)
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    return await client.get(url)
            except Exception:
                return None
        else:
            data = dict(target.parameters)
            data[param_name] = param_value
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    return await client.post(target.url, data=data)
            except Exception:
                return None

    async def _send_concurrent_requests(self, target: ScanTarget, count: int, extra_params: Dict = None) -> List:
        """Send concurrent requests"""
        import httpx

        async def send_one():
            if target.method == "GET":
                url = target.url
                if extra_params:
                    for k, v in extra_params.items():
                        url = self._inject_parameter(url, k, v)
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    return await client.get(url)
            else:
                data = dict(target.parameters)
                if extra_params:
                    data.update(extra_params)
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    return await client.post(target.url, data=data)

        tasks = [send_one() for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if not isinstance(r, Exception)]

    def _inject_parameter(self, url: str, param_name: str, value: str) -> str:
        """Inject parameter into URL"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _generate_idor_poc(self, url: str, param: str, original_id: str, test_id: str) -> str:
        """Generate IDOR POC"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        return f"""# IDOR Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Original ID**: {original_id}
- **Tested ID**: {test_id}

## Reproduction Steps
1. Access own resource: {base_url}?{param}={original_id}
2. Modify parameter to: {base_url}?{param}={test_id}
3. Observe access to another user's resource

## cURL Command
```bash
curl -X GET "{base_url}?{param}={test_id}"
```"""

    def _generate_race_poc(self, url: str, method: str, params: Dict) -> str:
        """Generate Race Condition POC"""
        import urllib.parse

        if method == "GET":
            query = urllib.parse.urlencode(params)
            full_url = f"{url}?{query}" if query else url
            return f"""# Race Condition Proof of Concept
## Vulnerability Details
- **URL**: {full_url}
- **Method**: {method}

## Reproduction (Python)
```python
import asyncio
import httpx

async def make_request():
    async with httpx.AsyncClient() as client:
        return await client.get("{full_url}")

async def main():
    tasks = [make_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    for i, r in enumerate(results):
        print(f"Request {{i}}: {{r.status_code}} - {{len(r.text)}} bytes")

asyncio.run(main())
```"""
        else:
            return f"""# Race Condition Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Method**: {method}
- **Parameters**: {params}

## Reproduction (Python)
```python
import asyncio
import httpx

async def make_request():
    async with httpx.AsyncClient() as client:
        return await client.post("{url}", data={params})

async def main():
    tasks = [make_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    for i, r in enumerate(results):
        print(f"Request {{i}}: {{r.status_code}} - {{len(r.text)}} bytes")

asyncio.run(main())
```"""

    def _generate_price_poc(self, url: str, param: str, original: float, test: float) -> str:
        """Generate Price Manipulation POC"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query=''))

        return f"""# Price Manipulation Proof of Concept
## Vulnerability Details
- **URL**: {url}
- **Parameter**: {param}
- **Original Price**: {original}
- **Manipulated Price**: {test}

## Reproduction Steps
1. Add item to cart
2. Intercept checkout request
3. Modify {param} from {original} to {test}
4. Submit order

## cURL Command
```bash
curl -X POST "{base_url}" -d "{param}={test}"
```"""


async def hunt_logic(targets: List[ScanTarget], config_manager=None) -> List[VulnerabilityFinding]:
    """Hunt for business logic vulnerabilities"""
    hunter = LogicHunter(config_manager or get_config())
    return await hunter.hunt(targets)