"""
Validation Orchestrator
Coordinates browser reproduction, Burp capture, AI validation, and evidence collection
"""

import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config_manager import get_config
from core.database import db_manager, FindingCRUD, EvidenceCRUD, FindingStatus
from validation.browser_repro import BrowserReproducer, ReproductionResult, reproduce_finding
from validation.burp_integration import BurpTrafficCapture, BurpCapture
from validation.terminal_capture import TerminalCapture, TerminalEvidence
from validation.evidence_collector import EvidenceCollector, EvidencePackage
from hunting.scanner_orchestrator import VulnerabilityFinding, FindingStatus
from hunting.ai_hunter import AIHunter, ValidationResult


@dataclass
class ValidatedFinding:
    """Fully validated finding with all evidence"""
    original_finding: VulnerabilityFinding
    reproduction: Optional[ReproductionResult] = None
    burp_capture: Optional[BurpCapture] = None
    terminal_evidence: Optional[TerminalEvidence] = None
    ai_validation: Optional[ValidationResult] = None
    evidence_package: Optional[EvidencePackage] = None
    final_status: str = "validated"
    validation_confidence: float = 0.0
    validated_at: str = ""


class ValidationEngine:
    """Orchestrates the complete validation pipeline"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.val_config = self.config.load_validation()
        self.ai_hunter = AIHunter(config_manager)
        self.evidence_collector = EvidenceCollector(config_manager)

    async def validate(self, finding: VulnerabilityFinding) -> ValidatedFinding:
        """Run complete validation pipeline for a finding"""
        validated = ValidatedFinding(original_finding=finding)
        validated.validated_at = datetime.utcnow().isoformat()

        try:
            # Step 1: Browser reproduction (REAL browser - no synthetic)
            print(f"[VALIDATION] Reproducing {finding.vuln_type} in real browser...")
            validated.reproduction = await reproduce_finding(finding, self.config)

            # Step 2: Burp/mitmproxy traffic capture
            if self.val_config.burp.enabled:
                print(f"[VALIDATION] Capturing traffic with Burp/mitmproxy...")
                async with BurpTrafficCapture(self.config) as capture:
                    validated.burp_capture = await capture.capture_browser_traffic(finding)

            # Step 3: AI validation (false positive check)
            if self.val_config.ai_validation.enabled:
                print(f"[VALIDATION] Running AI false positive check...")
                validated.ai_validation = await self.ai_hunter.validate_finding({
                    'vuln_type': finding.vuln_type,
                    'target_url': finding.target.url,
                    'parameter': finding.evidence.get('parameter', ''),
                    'payload': finding.evidence.get('payload', ''),
                    'response': finding.evidence.get('response_snippet', ''),
                    'evidence': finding.evidence,
                })

            # Step 4: Determine final status
            validated = self._determine_status(validated)

            # Step 5: Create evidence package
            print(f"[VALIDATION] Creating evidence package...")
            validated.evidence_package = await self.evidence_collector.create_package(
                finding,
                reproduction=validated.reproduction,
                burp_capture=validated.burp_capture,
                terminal_evidence=validated.terminal_evidence,
                ai_validation=validated.ai_validation.__dict__ if validated.ai_validation else None,
            )

            # Step 6: Save to database
            await self._save_validation(validated)

        except Exception as e:
            print(f"[VALIDATION] Error: {e}")
            validated.final_status = "validation_failed"
            validated.validation_confidence = 0.0

        return validated

    def _determine_status(self, validated: ValidatedFinding) -> ValidatedFinding:
        """Determine final validation status"""
        confidence_factors = []

        # Browser reproduction confidence
        if validated.reproduction:
            if validated.reproduction.success:
                confidence_factors.append(0.9)
            else:
                confidence_factors.append(0.1)

            if validated.reproduction.payload_executed:
                confidence_factors.append(0.9)
            else:
                confidence_factors.append(0.2)

        # AI validation confidence
        if validated.ai_validation:
            confidence_factors.append(validated.ai_validation.confidence)

        # Burp capture confidence
        if validated.burp_capture and validated.burp_capture.requests:
            confidence_factors.append(0.8)

        # Calculate overall confidence
        if confidence_factors:
            validated.validation_confidence = sum(confidence_factors) / len(confidence_factors)
        else:
            validated.validation_confidence = 0.0

        # Determine status based on confidence threshold
        threshold = self.val_config.ai_validation.confidence_threshold

        if validated.validation_confidence >= threshold:
            validated.final_status = FindingStatus.VALIDATED.value
        elif validated.validation_confidence >= 0.5:
            validated.final_status = "needs_review"
        else:
            validated.final_status = FindingStatus.FALSE_POSITIVE.value

        return validated

    async def _save_validation(self, validated: ValidatedFinding):
        """Save validation results to database"""
        async with db_manager.get_session() as session:
            # Update finding status
            await FindingCRUD.update_status(
                session,
                validated.original_finding.id if hasattr(validated.original_finding, 'id') else 0,
                validated.final_status
            )

            # Save evidence package metadata
            if validated.evidence_package:
                for evidence_path in validated.evidence_package.screenshots:
                    await EvidenceCRUD.create(session, session=session, evidence=...)

    async def validate_batch(self, findings: List[VulnerabilityFinding],
                             max_concurrent: int = 3) -> List[ValidatedFinding]:
        """Validate multiple findings with concurrency control"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def validate_one(finding):
            async with semaphore:
                return await self.validate(finding)

        tasks = [validate_one(f) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        validated_findings = []
        for result in results:
            if isinstance(result, ValidatedFinding):
                validated_findings.append(result)
            elif isinstance(result, Exception):
                print(f"Validation error: {result}")

        return validated_findings

    async def validate_from_database(self, program_name: str,
                                     status: str = "new",
                                     max_findings: int = 50) -> List[ValidatedFinding]:
        """Validate findings from database"""
        async with db_manager.get_session() as session:
            from core.database import ProgramCRUD, FindingCRUD

            program = await ProgramCRUD.get_by_name(session, program_name)
            if not program:
                raise ValueError(f"Program not found: {program_name}")

            findings = await FindingCRUD.get_by_program(
                session, program.id, status=status, limit=max_findings
            )

            # Convert to VulnerabilityFinding objects
            vuln_findings = []
            for f in findings:
                vuln_findings.append(VulnerabilityFinding(
                    id=f.id,
                    vuln_type=f.vuln_type,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    evidence=f.evidence or {},
                    poc=f.poc or "",
                    target=f.target,
                ))

        return await self.validate_batch(vuln_findings)


class ValidationScheduler:
    """Schedule and manage validations"""

    def __init__(self, config_manager=None):
        self.config = config_manager or get_config()
        self.engine = ValidationEngine(config_manager)
        self.pending: List[VulnerabilityFinding] = []
        self.running: Dict[int, asyncio.Task] = {}
        self.completed: List[ValidatedFinding] = []

    async def add_finding(self, finding: VulnerabilityFinding):
        """Add finding to validation queue"""
        self.pending.append(finding)

    async def process_queue(self, max_concurrent: int = 3):
        """Process validation queue"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_one(finding):
            async with semaphore:
                result = await self.engine.validate(finding)
                self.completed.append(result)
                return result

        tasks = [process_one(f) for f in self.pending]
        self.pending.clear()

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                print(f"Validation failed: {result}")

    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        total = len(self.completed)
        validated = sum(1 for v in self.completed if v.final_status == "validated")
        needs_review = sum(1 for v in self.completed if v.final_status == "needs_review")
        false_positive = sum(1 for v in self.completed if v.final_status == "false_positive")

        avg_confidence = 0
        if self.completed:
            avg_confidence = sum(v.validation_confidence for v in self.completed) / total

        return {
            "total_processed": total,
            "validated": validated,
            "needs_review": needs_review,
            "false_positive": false_positive,
            "average_confidence": avg_confidence,
            "pending": len(self.pending),
        }


async def validate_finding(finding: VulnerabilityFinding, config_manager=None) -> ValidatedFinding:
    """Validate a single finding"""
    engine = ValidationEngine(config_manager)
    return await engine.validate(finding)


async def validate_program_findings(program_name: str, config_manager=None) -> List[ValidatedFinding]:
    """Validate all findings for a program"""
    engine = ValidationEngine(config_manager)
    return await engine.validate_from_database(program_name)