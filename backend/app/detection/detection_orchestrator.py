"""Final detection orchestrator (Phase 3).

Receives Phase 2 scan results, gathers normalized intelligence, correlates
evidence, and produces one unified detection result with risk, confidence,
and explanations. Provider failures never block the scan.
"""

from typing import Any

from backend.app.core.logging import logger
from backend.app.detection.confidence_engine import (
    ConfidenceAssessment,
    calculate_confidence,
)
from backend.app.detection.evidence_correlator import (
    CorrelatedEvidence,
    correlate_evidence,
)
from backend.app.detection.risk_engine import RiskAssessment, calculate_risk
from backend.app.detection.risk_scoring import LOW_RISK_DISCLAIMER
from backend.app.intelligence.base import ThreatIntelligenceResult
from backend.app.intelligence.intelligence_manager import normalize_provider_results
from backend.app.intelligence.models import IndicatorType, NormalizedIndicatorMatch


class DetectionResult:
    """Unified detection output combining Phase 2 assessment with Phase 3
    correlation, scoring, and confidence."""

    def __init__(
        self,
        risk: RiskAssessment,
        confidence: ConfidenceAssessment,
        evidence: CorrelatedEvidence,
        intelligence_matches: list[dict[str, Any]],
        explanation: str,
    ):
        self.risk = risk
        self.confidence = confidence
        self.evidence = evidence
        self.intelligence_matches = intelligence_matches
        self.explanation = explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk.risk_score,
            "risk_level": self.risk.risk_level.value,
            "classification": self.risk.classification.value,
            "score_breakdown": self.risk.score_breakdown.model_dump(),
            "reasons": self.risk.reasons,
            "confidence_score": self.confidence.confidence_score,
            "confidence_level": self.confidence.confidence_level.value,
            "confidence_explanation": self.confidence.explanation,
            "successful_checks": self.confidence.successful_checks,
            "failed_checks": self.confidence.failed_checks,
            "unavailable_providers": self.confidence.unavailable_providers,
            "evidence": [e.model_dump() for e in self.evidence.items],
            "duplicates_removed": self.evidence.duplicates_removed,
            "intelligence_matches": self.intelligence_matches,
            "explanation": self.explanation,
            "is_probability": False,
        }


async def run_detection(
    aggregated,
    module_statuses: dict[str, str],
    community_matches: list[NormalizedIndicatorMatch] | None = None,
) -> DetectionResult:
    """Run the Phase 3 detection pipeline over completed Phase 2 results.

    Args:
        aggregated: ``AggregatedScanResult`` from the Phase 2 pipeline.
        module_statuses: Module name -> status map.
    """
    provider_results = (aggregated.modules.get("threat_intelligence") or {}).get("results", [])
    normalized_results: list[tuple[ThreatIntelligenceResult, IndicatorType, str]] = []
    for raw_result in provider_results:
        try:
            result = ThreatIntelligenceResult.model_validate(raw_result)
        except (TypeError, ValueError) as e:
            logger.error(f"Invalid Phase 2 threat-intelligence result: {e}")
            continue
        indicator_type = (
            IndicatorType.URL
            if result.query.lower().startswith(("http://", "https://"))
            else IndicatorType.DOMAIN
        )
        normalized_results.append((result, indicator_type, result.query))

    matches = [match.model_dump() for match in normalize_provider_results(normalized_results)] + [
        match.model_dump() for match in (community_matches or [])
    ]

    evidence = correlate_evidence(
        findings=aggregated.findings,
        module_statuses=module_statuses,
        intelligence_matches=matches,
    )

    completed = sum(1 for s in module_statuses.values() if s in ("COMPLETED", "RESOLVED", "OK"))
    risk = calculate_risk(
        evidence=evidence,
        completed_modules=completed,
        total_modules=len(module_statuses),
    )
    confidence = calculate_confidence(module_statuses, evidence, matches)

    explanation_parts = list(risk.reasons[:5])
    explanation = " ".join(explanation_parts)
    if evidence.duplicates_removed:
        explanation += (
            f" ({evidence.duplicates_removed} duplicate finding(s) removed before scoring.)"
        )
    if any(e.category.value == "unavailable" for e in evidence.items):
        explanation += (
            " Some checks did not complete; missing evidence is not interpreted as a clean result."
        )
    explanation += " Scores are heuristic and explicitly not calibrated probabilities."
    if risk.risk_score < 25:
        explanation += f" {LOW_RISK_DISCLAIMER}"

    return DetectionResult(
        risk=risk,
        confidence=confidence,
        evidence=evidence,
        intelligence_matches=matches,
        explanation=explanation,
    )
