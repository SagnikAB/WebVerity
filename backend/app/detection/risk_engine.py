"""Intelligent risk scoring engine (Phase 3).

Transparent, configurable, deterministic scoring: converts correlated
evidence into a 0-100 integer risk score with breakdown, reasons, and
precedence rules for confirmed threat-intelligence matches.

This is a heuristic scoring model — explicitly NOT a probability.
"""

from enum import StrEnum

from backend.app.detection.evidence_correlator import (
    CorrelatedEvidence,
    EvidenceCategory,
    EvidenceItem,
)
from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Configurable initial weights (not validated probabilities).
DEFAULT_WEIGHTS: dict[str, int] = {
    "confirmed_phishing_match": 90,
    "confirmed_malware_match": 90,
    "unverified_threat_match": 25,
    "strong_brand_impersonation": 35,
    "suspicious_url_characteristics": 15,
    "suspicious_redirect_behaviour": 20,
    "high_risk_page_behaviour": 25,
    "suspicious_dns_domain_evidence": 10,
    "weak_tls_configuration": 5,
    "expired_certificate": 5,
    "missing_security_headers": 2,
}


class ScoreBreakdown(BaseModel):
    """Per-source contribution to the final score."""

    threat_intelligence: int = 0
    url_analysis: int = 0
    dns_analysis: int = 0
    tls_analysis: int = 0
    http_security: int = 0
    redirect_analysis: int = 0
    content_analysis: int = 0
    domain_intelligence: int = 0


class RiskAssessment(BaseModel):
    """Explainable risk output of the risk engine."""

    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    classification: RiskLevel
    score_breakdown: ScoreBreakdown
    reasons: list[str] = Field(default_factory=list)
    is_probability: bool = Field(
        False, description="Heuristic score — explicitly not a probability"
    )


# Evidence id prefixes/substrings mapped to reason phrasing.
_REASON_PHRASES = {
    "confirmed_phishing": "Confirmed phishing match from threat intelligence",
    "confirmed_malware": "Confirmed malware URL match from threat intelligence",
    "TI_": "Known threat indicator matched",
    "URL_": "Suspicious URL characteristics detected",
    "DNS_": "Suspicious DNS or domain evidence",
    "TLS_": "TLS configuration weakness observed",
    "HTTP_": "HTTP security configuration weakness",
    "REDIRECT_": "Suspicious redirect behaviour",
    "CONTENT_": "High-risk page/form behaviour",
    "BRAND_": "Strong brand impersonation indicators",
}


def _reason_for(item: EvidenceItem) -> str:
    for prefix, phrase in _REASON_PHRASES.items():
        if item.id.startswith(prefix):
            return phrase
    return item.description[:120]


def classify_level(score: int) -> RiskLevel:
    """Map a 0-100 score to the project's fixed classification bands."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def _scale_breakdown(breakdown: ScoreBreakdown, maximum: int) -> ScoreBreakdown:
    """Scale source contributions proportionally so they sum to a score cap."""
    total = sum(getattr(breakdown, name) for name in ScoreBreakdown.model_fields)
    if total <= maximum or total == 0:
        return breakdown
    scaled = {
        name: int(getattr(breakdown, name) * maximum / total)
        for name in ScoreBreakdown.model_fields
    }
    remainder = maximum - sum(scaled.values())
    for name in ScoreBreakdown.model_fields:
        if remainder == 0:
            break
        if getattr(breakdown, name) > 0:
            scaled[name] += 1
            remainder -= 1
    return breakdown.model_copy(update=scaled)


def calculate_risk(
    evidence: CorrelatedEvidence,
    weights: dict[str, int] | None = None,
    completed_modules: int = 0,
    total_modules: int = 0,
) -> RiskAssessment:
    """Deterministically score correlated evidence into 0-100 risk.

    Precedence rule: a confirmed threat-intelligence match (verified by the
    provider) forces a CRITICAL classification regardless of other evidence,
    because provider verification dominates all heuristics.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    breakdown = ScoreBreakdown()
    reasons: list[str] = []

    confirmed_match = False
    unverified_match_score = 0
    for item in evidence.malicious:
        is_confirmed = (
            item.confidence >= 0.9
            and item.severity.value == "CRITICAL"
            and ("threat_intelligence" in item.origin or item.id.startswith("TI_"))
        )
        confirmed_match = confirmed_match or is_confirmed
        if "threat_intelligence" in item.origin or item.id.startswith("TI_"):
            if is_confirmed:
                breakdown.threat_intelligence = 100
            else:
                unverified_match_score = min(
                    unverified_match_score + w.get("unverified_threat_match", 25), 50
                )
        reasons.append(_reason_for(item))
    breakdown.threat_intelligence = max(breakdown.threat_intelligence, unverified_match_score)

    source_map = {
        "url_analysis": "url_analysis",
        "dns_analysis": "dns_analysis",
        "tls_analysis": "tls_analysis",
        "http_security": "http_security",
        "redirect_analysis": "redirect_analysis",
        "content_analysis": "content_analysis",
        "domain_intelligence": "domain_intelligence",
    }
    for item in evidence.items:
        if item.category != EvidenceCategory.SUSPICIOUS:
            continue
        weight = w.get("suspicious_url_characteristics", 15)
        field = source_map.get(item.origin)
        if field:
            current = getattr(breakdown, field)
            setattr(breakdown, field, min(current + weight, 60))
        if len(reasons) < 12 and not any(r == _reason_for(item) for r in reasons):
            reasons.append(_reason_for(item))

    total = sum(
        [
            breakdown.threat_intelligence,
            breakdown.url_analysis,
            breakdown.dns_analysis,
            breakdown.tls_analysis,
            breakdown.http_security,
            breakdown.redirect_analysis,
            breakdown.content_analysis,
            breakdown.domain_intelligence,
        ]
    )
    total = min(total, 100)

    # Precedence: verified threat intelligence dominates heuristics.
    if confirmed_match:
        total = max(total, 90)
        reasons.insert(0, "Confirmed threat-intelligence match — MALICIOUS classification")

    suspicious_strong_sources = {
        item.origin
        for item in evidence.suspicious
        if item.severity.value in {"HIGH", "CRITICAL"} and item.confidence >= 0.8
    }
    if total >= 75 and not confirmed_match and len(suspicious_strong_sources) < 2:
        breakdown = _scale_breakdown(breakdown, 74)
        total = 74
        reasons.append(
            "Critical risk requires a verified threat match or strong corroboration "
            "from multiple independent modules."
        )

    # Incomplete scans cap non-confirmed escalation at MODERATE without
    # contradicting the score breakdown.
    if total_modules > 0 and completed_modules < (total_modules // 2) and not confirmed_match:
        if total > 49:
            breakdown = _scale_breakdown(breakdown, 49)
            total = sum(getattr(breakdown, name) for name in ScoreBreakdown.model_fields)
        reasons.append(
            "Insufficient completed checks — non-confirmed risk is capped at MODERATE "
            "pending further evidence."
        )

    risk_level = classify_level(total)

    return RiskAssessment(
        risk_score=total,
        risk_level=risk_level,
        classification=risk_level,
        score_breakdown=breakdown,
        reasons=reasons or ["No strong threat indicators observed in the completed checks."],
    )


__all__ = ["DEFAULT_WEIGHTS", "RiskAssessment", "RiskLevel", "calculate_risk", "classify_level"]
