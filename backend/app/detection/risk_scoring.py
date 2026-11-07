"""Rule-based risk scoring and confidence calculation engine."""

from backend.app.detection.rules_engine import RULE_WEIGHTS
from backend.app.schemas.evidence import Finding
from backend.app.schemas.scan import ConfidenceLevel, RiskClassification, ThreatAssessment

LOW_RISK_DISCLAIMER = (
    "No strong threat indicators observed in the completed checks. "
    "This does not guarantee that the website is safe."
)


def calculate_risk_score(
    findings: list[Finding],
    module_statuses: dict[str, str],
) -> ThreatAssessment:
    """Calculate heuristic threat risk score, classification, and confidence.

    Category Weighting:
    - URL structural anomalies: max 50 points (50%)
    - DNS infrastructure indicators: max 25 points (25%)
    - TLS trust & certificate anomalies: max 25 points (25%)
    Total maximum: 100 points.

    Args:
        findings: Consolidated list of deduplicated findings.
        module_statuses: Map of module names to completion status.

    Returns:
        ThreatAssessment schema object.
    """
    url_score = 0
    dns_score = 0
    tls_score = 0

    seen_rule_ids = set()

    for finding in findings:
        rule_id = finding.id
        if rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(rule_id)

        weight = RULE_WEIGHTS.get(rule_id, 0)
        module = finding.module

        if module == "url_analysis":
            url_score += weight
        elif module == "dns_analysis":
            dns_score += weight
        elif module == "tls_analysis":
            tls_score += weight

    # Enforce category caps to respect the 50% / 25% / 25% architecture
    url_score = min(url_score, 50)
    dns_score = min(dns_score, 25)
    tls_score = min(tls_score, 25)

    total_score = min(url_score + dns_score + tls_score, 100)

    # Classify risk level
    if total_score >= 75:
        classification = RiskClassification.CRITICAL
        explanation = (
            "Critical threat indicators confirmed. Infrastructure exhibits direct IP hosting, "
            "SSRF evasions, or severe hostname/certificate forgery."
        )
    elif total_score >= 50:
        classification = RiskClassification.HIGH
        explanation = (
            "High risk indicators detected. URL characteristics, DNS status, or cryptographic "
            "anomalies strongly suggest deceptive or compromised infrastructure."
        )
    elif total_score >= 25:
        classification = RiskClassification.MODERATE
        explanation = (
            "Moderate suspicious signals or configuration weaknesses detected. "
            "Exercise caution before submitting credentials or sensitive information."
        )
    else:
        classification = RiskClassification.LOW
        explanation = LOW_RISK_DISCLAIMER

    # Confidence calculation based on evidence completeness
    # Count failed / degraded modules
    failed_modules = 0
    dns_status = module_statuses.get("dns_analysis", "UNKNOWN")
    tls_status = module_statuses.get("tls_analysis", "UNKNOWN")
    url_status = module_statuses.get("url_analysis", "UNKNOWN")

    if url_status not in ("COMPLETED", "RESOLVED"):
        failed_modules += 1

    if dns_status in ("TIMEOUT", "ERROR", "UNKNOWN"):
        failed_modules += 1

    if tls_status in ("FAILED", "UNKNOWN"):
        failed_modules += 1

    if failed_modules == 0:
        confidence = ConfidenceLevel.HIGH
    elif failed_modules == 1:
        confidence = ConfidenceLevel.MEDIUM
    else:
        confidence = ConfidenceLevel.LOW

    return ThreatAssessment(
        risk_score=total_score,
        classification=classification,
        confidence=confidence,
        is_probability=False,
        explanation=explanation,
    )
