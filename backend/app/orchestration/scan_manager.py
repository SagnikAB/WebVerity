"""High-level scan manager coordinating validation, orchestration, and persistence."""

import uuid
from datetime import UTC, datetime

from backend.app.analyzers.url_analyzer.normalizer import normalize_url
from backend.app.analyzers.url_analyzer.validator import validate_url
from backend.app.core.security import SSRFSecurityException, is_safe_hostname
from backend.app.orchestration.pipeline import execute_scan_pipeline
from backend.app.schemas.scan import (
    ModuleResults,
    ScanResponse,
    ScanStatus,
)
from backend.app.services.result_service import ResultService
from sqlalchemy.orm import Session


class ScanManager:
    """Manager for full scan lifecycle execution."""

    @staticmethod
    async def process_scan(raw_url: str, db: Session) -> ScanResponse:
        """Execute complete scan lifecycle.

        Args:
            raw_url: Submitted URL.
            db: Database session.

        Returns:
            ScanResponse populated with scan results.

        Raises:
            URLValidationError: If URL structure is invalid.
            SSRFSecurityException: If target hostname violates SSRF policy.
        """
        # Step 1: URL validation
        validate_url(raw_url)

        # Step 2: URL normalization
        normalized = normalize_url(raw_url)

        # Step 3: SSRF pre-check on target hostname
        safe_host, reason = is_safe_hostname(normalized.hostname)
        if not safe_host:
            raise SSRFSecurityException(
                message=f"SSRF Security Violation: {reason}",
                target=normalized.hostname,
            )

        # Step 4: Generate unique scan identifier
        scan_id = str(uuid.uuid4())
        created_at_dt = datetime.now(UTC)
        created_at_str = created_at_dt.isoformat()

        # Step 5: Initialize scan record in database
        ResultService.create_scan_record(
            db=db,
            scan_id=scan_id,
            submitted_url_redacted=normalized.redacted_url,
            normalized_url=normalized.normalized_url,
            domain=normalized.hostname,
        )

        # Step 6: Asynchronously execute analysis pipeline
        aggregated = await execute_scan_pipeline(normalized=normalized, raw_url=raw_url)

        completed_at_dt = datetime.now(UTC)
        completed_at_str = completed_at_dt.isoformat()

        # Step 7: Serialize modules and findings for storage
        results_data = {
            "modules": aggregated.modules,
            "findings": [f.model_dump() for f in aggregated.findings],
            "threat_assessment": aggregated.threat_assessment.model_dump(),
        }

        # Step 8: Update database record
        ResultService.save_scan_result(
            db=db,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED.value,
            risk_score=aggregated.threat_assessment.risk_score,
            risk_level=aggregated.threat_assessment.classification.value,
            confidence=aggregated.threat_assessment.confidence.value,
            results_json=results_data,
        )

        # Step 9: Build and return ScanResponse contract
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            target=normalized.hostname,
            threat_assessment=aggregated.threat_assessment,
            modules=ModuleResults(
                url_analysis=aggregated.modules.get("url_analysis", {}),
                dns_analysis=aggregated.modules.get("dns_analysis", {}),
                tls_analysis=aggregated.modules.get("tls_analysis", {}),
            ),
            findings=aggregated.findings,
            created_at=created_at_str,
            completed_at=completed_at_str,
        )
