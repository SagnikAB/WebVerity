"""Evidence correlation engine (Phase 3).

Consolidates findings from every Phase 2 analyzer module and Phase 3
intelligence provider into categorized, deduplicated evidence items with
severity, confidence, and source attribution.

Key invariants:
- The same underlying finding is never counted twice (dedup by rule id and
  finding fingerprint).
- A missing security header is a configuration weakness, not phishing proof.
- A valid TLS certificate is not proof of legitimacy.
- Failed/unavailable modules are recorded as UNAVAILABLE evidence, never as
  negative (risk-raising) evidence.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from backend.app.core.logging import sanitize_url_for_logging
from backend.app.schemas.evidence import Finding, Severity
from pydantic import BaseModel, Field


class EvidenceCategory(StrEnum):
    """Correlated evidence buckets."""

    MALICIOUS_INDICATOR = "malicious_indicator"
    SUSPICIOUS = "suspicious"
    SECURITY_WEAKNESS = "security_weakness"
    NEUTRAL = "neutral"
    UNAVAILABLE = "unavailable"


class EvidenceStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


# Finding ids that are configuration weaknesses, never phishing evidence.
_POSTURE_ONLY_IDS = {
    "HTTP_MISSING_HSTS",
    "HTTP_MISSING_CSP",
    "HTTP_MISSING_XFRAMEOPTIONS",
    "HTTP_MISSING_XCONTENTTYPE",
    "HTTP_MISSING_REFERRER_POLICY",
    "HTTP_MISSING_PERMISSIONS_POLICY",
    "HTTP_COOKIE_MISSING_SECURE",
    "HTTP_COOKIE_MISSING_HTTPONLY",
    "HTTP_COOKIE_MISSING_SAMESITE",
    "HTTP_SERVER_DISCLOSURE",
    "HTTP_OUTDATED_SERVER",
    "HTTP_UNEXPECTED_CONTENT_TYPE",
    "DNS_NO_MX_RECORDS",
}

# Severity -> reliability weight used by the confidence engine.
SEVERITY_RELIABILITY: dict[str, float] = {
    "CRITICAL": 0.95,
    "HIGH": 0.8,
    "MEDIUM": 0.6,
    "LOW": 0.4,
    "INFO": 0.3,
}


class EvidenceItem(BaseModel):
    """Single correlated, explainable evidence record."""

    id: str = Field(..., description="Stable evidence identifier (rule or indicator id)")
    category: EvidenceCategory = Field(..., description="Evidence bucket")
    description: str = Field(..., description="Human-readable explanation")
    severity: Severity = Field(..., description="Severity classification")
    source: str = Field(..., description="Originating analyzer or provider")
    observed_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(), description="ISO-8601 timestamp"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Reliability weight of this evidence"
    )
    status: EvidenceStatus = Field(EvidenceStatus.COMPLETED, description="Execution status")
    origin: str = Field(..., description="Analyzer or provider module name")


class CorrelatedEvidence(BaseModel):
    """Final deduplicated evidence set returned by the correlator."""

    items: list[EvidenceItem] = Field(default_factory=list)
    malicious: list[EvidenceItem] = Field(default_factory=list)
    suspicious: list[EvidenceItem] = Field(default_factory=list)
    weaknesses: list[EvidenceItem] = Field(default_factory=list)
    neutral: list[EvidenceItem] = Field(default_factory=list)
    unavailable: list[EvidenceItem] = Field(default_factory=list)
    duplicates_removed: int = 0


def _classify(finding: Finding, module_statuses: dict[str, str]) -> EvidenceCategory:
    """Assign an evidence bucket to a finding."""
    if finding.id.startswith("TI_"):
        return EvidenceCategory.MALICIOUS_INDICATOR
    if finding.id in _POSTURE_ONLY_IDS:
        return EvidenceCategory.SECURITY_WEAKNESS
    severity = finding.severity
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return EvidenceCategory.SUSPICIOUS
    if severity == Severity.MEDIUM:
        return EvidenceCategory.SUSPICIOUS
    if severity == Severity.LOW:
        return EvidenceCategory.NEUTRAL
    return EvidenceCategory.NEUTRAL


def _intelligence_evidence_id(provider: str, threat_category: str | None) -> str:
    category = (threat_category or "match").lower()
    if category in {"malware", "malware_download", "malware_url"}:
        category = "malware_url"
    return f"TI_{provider}_{category}"


def _fingerprint(finding: Finding) -> str:
    """Stable identity of the underlying observation, independent of which
    module happened to report it (deduplicates cross-module duplicates)."""
    host = finding.evidence.get("hostname") or finding.evidence.get("domain") or ""
    url = sanitize_url_for_logging(str(finding.evidence.get("url") or ""))
    return f"{finding.id}|{host}|{url}"


def correlate_evidence(
    findings: list[Finding],
    module_statuses: dict[str, str],
    intelligence_matches: list[dict[str, Any]] | None = None,
) -> CorrelatedEvidence:
    """Build the deduplicated, categorized evidence set.

    Args:
        findings: Merged findings from all analyzers.
        module_statuses: Module name -> execution status map.
        intelligence_matches: Normalized intelligence matches (from
            ``intelligence_manager.collect_intelligence``), included as
            MALICIOUS_INDICATOR evidence when verified.
    """
    seen_fingerprints: set[str] = set()
    seen_evidence_ids: set[str] = set()
    items: list[EvidenceItem] = []
    duplicates = 0

    for finding in findings:
        fp = _fingerprint(finding)
        if fp in seen_fingerprints:
            duplicates += 1
            continue
        seen_fingerprints.add(fp)
        evidence_id = finding.id
        if finding.id.startswith("TI_"):
            evidence_id = _intelligence_evidence_id(
                str(finding.evidence.get("source") or "unknown"),
                finding.evidence.get("threat_type"),
            )
        if evidence_id in seen_evidence_ids:
            duplicates += 1
            continue
        seen_evidence_ids.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                category=_classify(finding, module_statuses),
                description=finding.description,
                severity=finding.severity,
                source=str(finding.evidence.get("source") or finding.module),
                observed_at=finding.timestamp,
                confidence=SEVERITY_RELIABILITY.get(str(finding.severity.value), 0.3),
                status=EvidenceStatus.COMPLETED,
                origin=finding.module,
            )
        )

    # Intelligence matches become highest-confidence evidence when verified.
    for match in intelligence_matches or []:
        if not match.get("matched"):
            continue
        provider = str(match.get("provider") or "unknown")
        eid = _intelligence_evidence_id(provider, match.get("threat_category"))
        verified = match.get("verification_status") == "confirmed"
        if eid in seen_evidence_ids:
            duplicates += 1
            continue
        seen_evidence_ids.add(eid)
        items.append(
            EvidenceItem(
                id=eid,
                category=EvidenceCategory.MALICIOUS_INDICATOR,
                description=(
                    f"{match.get('provider')} reports indicator as "
                    f"'{match.get('threat_category')}' "
                    f"(verification: {match.get('verification_status')}, "
                    f"match type: {match.get('match_type')})."
                ),
                severity=Severity.CRITICAL if verified else Severity.MEDIUM,
                source=str(match.get("provider")),
                confidence=0.95 if verified else 0.6,
                status=EvidenceStatus.COMPLETED,
                origin="threat_intelligence",
            )
        )

    # Module failures -> UNAVAILABLE evidence (never negative evidence).
    for module, status_value in module_statuses.items():
        if status_value in ("FAILED", "ERROR", "TIMEOUT", "SKIPPED", "UNAVAILABLE"):
            eid = f"UNAVAILABLE_{module}"
            if eid in seen_evidence_ids:
                continue
            seen_evidence_ids.add(eid)
            items.append(
                EvidenceItem(
                    id=eid,
                    category=EvidenceCategory.UNAVAILABLE,
                    description=(
                        f"Module '{module}' did not complete (status: {status_value}); "
                        f"missing evidence must not be interpreted as a clean result."
                    ),
                    severity=Severity.INFO,
                    source=module,
                    confidence=0.0,
                    status=(
                        EvidenceStatus.TIMEOUT
                        if status_value == "TIMEOUT"
                        else EvidenceStatus.SKIPPED
                        if status_value in ("SKIPPED", "UNAVAILABLE")
                        else EvidenceStatus.FAILED
                    ),
                    origin=module,
                )
            )

    bucket_map = {
        EvidenceCategory.MALICIOUS_INDICATOR: "malicious",
        EvidenceCategory.SUSPICIOUS: "suspicious",
        EvidenceCategory.SECURITY_WEAKNESS: "weaknesses",
        EvidenceCategory.NEUTRAL: "neutral",
        EvidenceCategory.UNAVAILABLE: "unavailable",
    }
    result = CorrelatedEvidence(items=items, duplicates_removed=duplicates)
    for item in items:
        getattr(result, bucket_map[item.category]).append(item)
    return result
