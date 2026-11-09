"""High-level scan manager coordinating validation, orchestration, and persistence."""

import uuid
from datetime import UTC, datetime

from backend.app.analyzers.url_analyzer.normalizer import normalize_url
from backend.app.analyzers.url_analyzer.validator import validate_url
from backend.app.core.security import SSRFSecurityException, is_safe_hostname
from backend.app.intelligence.intelligence_manager import collect_community_matches
from backend.app.orchestration.pipeline import execute_scan_pipeline
from backend.app.schemas.scan import (
    ConfidenceLevel,
    ModuleResults,
    RiskClassification,
    ScanResponse,
    ScanStatus,
    SecurityPosture,
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
        dns_records = (aggregated.modules.get("dns_analysis") or {}).get("records", {})
        resolved_ips = [
            address
            for record_type in ("A", "AAAA")
            for address in dns_records.get(record_type, [])
            if isinstance(address, str)
        ]
        community_matches = collect_community_matches(normalized, db, resolved_ips)
        if community_matches:
            aggregated.modules["threat_intelligence"]["community_matches"] = [
                match.model_dump() for match in community_matches
            ]

        completed_at_dt = datetime.now(UTC)
        completed_at_str = completed_at_dt.isoformat()

        # Phase 3: unified detection result (risk + confidence + evidence)
        from backend.app.detection.detection_orchestrator import run_detection
        from backend.app.detection.risk_scoring import POSTURE_WEIGHTS, calculate_security_posture

        detection = await run_detection(
            aggregated,
            dict(aggregated.statuses),
            community_matches=community_matches,
        )
        posture_findings = [f for f in aggregated.findings if f.id in POSTURE_WEIGHTS]
        posture_score = calculate_security_posture(aggregated.findings)
        threat_assessment = aggregated.threat_assessment.model_copy(
            update={
                "risk_score": detection.risk.risk_score,
                "classification": RiskClassification(detection.risk.classification.value),
                "confidence": ConfidenceLevel(detection.confidence.confidence_level.value),
                "is_probability": False,
                "explanation": detection.explanation,
                "security_posture_score": posture_score,
            }
        )
        aggregated.threat_assessment = threat_assessment

        from backend.app.detection.recommendations import generate_recommendations

        recommendations = generate_recommendations(aggregated)
        scan_metadata = {
            "modules_completed": sum(
                1 for s in aggregated.statuses.values() if s in ("COMPLETED", "RESOLVED")
            ),
            "modules_total": len(aggregated.statuses),
            "module_statuses": aggregated.statuses,
        }
        results_data = {
            "modules": aggregated.modules,
            "findings": [f.model_dump() for f in aggregated.findings],
            "threat_assessment": threat_assessment.model_dump(),
            "security_posture": {
                "score": posture_score,
                "findings": [f.model_dump() for f in posture_findings],
            },
            "recommendations": recommendations,
            "scan_metadata": scan_metadata,
        }
        results_data["detection"] = detection.to_dict()

        # Step 8: Update database record (after detection so it is persisted)
        ResultService.save_scan_result(
            db=db,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED.value,
            risk_score=threat_assessment.risk_score,
            risk_level=threat_assessment.classification.value,
            confidence=threat_assessment.confidence.value,
            security_posture_score=posture_score,
            results_json=results_data,
        )

        # Phase 3: persist threat indicators / matches / evidence / detection
        from backend.app.models.threat import (
            DetectionResult as DetectionRow,
        )
        from backend.app.models.threat import (
            IntelligenceMatch,
            ScanEvidence,
            ThreatIndicator,
        )

        for m in detection.intelligence_matches:
            if not m.get("matched"):
                continue
            provider = m.get("provider", "unknown")
            ind = None
            if provider.startswith("community:"):
                ind = (
                    db.query(ThreatIndicator)
                    .filter(
                        ThreatIndicator.source == provider,
                        ThreatIndicator.indicator_type == m.get("indicator_type", "url"),
                        ThreatIndicator.indicator_value == m.get("indicator_value", "")[:2048],
                    )
                    .first()
                )
            if ind is None:
                ind = ThreatIndicator(
                    indicator_type=m.get("indicator_type", "url"),
                    indicator_value=m.get("indicator_value", "")[:2048],
                    source=provider,
                    threat_category=m.get("threat_category"),
                    verification_status=str(m.get("verification_status", "unknown")),
                    last_seen=m.get("last_observed"),
                )
                db.add(ind)
                db.flush()
            db.add(
                IntelligenceMatch(
                    scan_id=scan_id,
                    indicator_id=ind.id,
                    provider=provider,
                    match_type=str(m.get("match_type", "none")),
                    verification_status=str(m.get("verification_status", "unknown")),
                )
            )
        for e in detection.evidence.items:
            db.add(
                ScanEvidence(
                    scan_id=scan_id,
                    evidence_id=e.id,
                    category=e.category.value,
                    description=e.description[:2048],
                    severity=e.severity.value,
                    source=e.source,
                    confidence=e.confidence,
                )
            )
        db.add(
            DetectionRow(
                scan_id=scan_id,
                risk_score=detection.risk.risk_score,
                risk_level=detection.risk.risk_level.value,
                classification=detection.risk.classification.value,
                confidence_score=detection.confidence.confidence_score,
                explanation=detection.explanation[:4096],
            )
        )
        db.commit()

        # Step 9: Build and return ScanResponse contract
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            target=normalized.hostname,
            threat_assessment=threat_assessment,
            security_posture=SecurityPosture(
                score=posture_score,
                findings=posture_findings,
            ),
            detection=detection.to_dict(),
            modules=ModuleResults(
                url_analysis=aggregated.modules.get("url_analysis", {}),
                dns_analysis=aggregated.modules.get("dns_analysis", {}),
                tls_analysis=aggregated.modules.get("tls_analysis", {}),
                http_security=aggregated.modules.get("http_security", {}),
                redirect_analysis=aggregated.modules.get("redirect_analysis", {}),
                content_analysis=aggregated.modules.get("content_analysis", {}),
                domain_intelligence=aggregated.modules.get("domain_intelligence", {}),
                threat_intelligence=aggregated.modules.get("threat_intelligence", {}),
            ),
            findings=aggregated.findings,
            recommendations=recommendations,
            scan_metadata=scan_metadata,
            created_at=created_at_str,
            completed_at=completed_at_str,
        )
