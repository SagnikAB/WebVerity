"""Intelligence manager (Phase 3): fan-out, normalization, and aggregation.

Coordinates every enabled provider, converts raw provider results into
``NormalizedIndicatorMatch`` objects, applies indicator matching for
explainability, deduplicates provider responses, and never treats a failed
lookup as a clean result.
"""

from datetime import UTC, datetime

from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.intelligence.base import (
    ThreatIntelligenceResult,
    redact_url_for_external_query,
)
from backend.app.intelligence.indicator_matcher import match_indicator
from backend.app.intelligence.models import (
    IndicatorType,
    MatchType,
    NormalizedIndicatorMatch,
    ProviderHealth,
    ProviderResponseStatus,
    VerificationStatus,
)
from backend.app.intelligence.phishtank import PhishTankProvider
from backend.app.intelligence.urlhaus import URLhausProvider
from backend.app.models.threat import ThreatIndicator
from sqlalchemy import or_
from sqlalchemy.orm import Session

# Maps Phase 2 lookup statuses to normalized response statuses.
_STATUS_MAP: dict[str, ProviderResponseStatus] = {
    "COMPLETED": ProviderResponseStatus.CLEAN,  # refined below when matched
    "RATE_LIMITED": ProviderResponseStatus.RATE_LIMITED,
    "TIMEOUT": ProviderResponseStatus.TIMEOUT,
    "FAILED": ProviderResponseStatus.ERROR,
    "SKIPPED": ProviderResponseStatus.UNAVAILABLE,
    "NOT_APPLICABLE": ProviderResponseStatus.NOT_APPLICABLE,
}

_THREAT_CATEGORY_MAP: dict[str, str] = {
    "phishing": "phishing",
    "malware": "malware_url",
    "malware_download": "malware_url",
    "malware_url": "malware_url",
}


def _verification_of(result: ThreatIntelligenceResult) -> VerificationStatus:
    if result.match_found and result.verified:
        return VerificationStatus.CONFIRMED
    if result.match_found:
        return VerificationStatus.UNVERIFIED
    return VerificationStatus.UNKNOWN


def get_provider_health() -> list[ProviderHealth]:
    """Report each provider's configuration/enabled state for the status API."""
    phishtank = PhishTankProvider()
    return [
        ProviderHealth(
            provider="URLhaus",
            configured=True,
            enabled=settings.ENABLE_URLHAUS,
            status=(
                ProviderResponseStatus.UNAVAILABLE
                if not settings.ENABLE_URLHAUS
                else ProviderResponseStatus.CLEAN
            ),
            description=(
                "abuse.ch URLhaus community feed; optional auth key supported. "
                "Docs: https://urlhaus.abuse.ch/api/"
            ),
        ),
        ProviderHealth(
            provider="PhishTank",
            configured=bool(phishtank._api_key),
            enabled=settings.ENABLE_PHISHTANK,
            status=(
                ProviderResponseStatus.UNAVAILABLE
                if not (settings.ENABLE_PHISHTANK and phishtank._api_key)
                else ProviderResponseStatus.CLEAN
            ),
            description=(
                "PhishTank verified-phishing database (rate-limited free API). "
                "Without a key the provider is skipped and reported as unavailable. "
                "Docs: https://phishtank.org/api_info.php"
            ),
        ),
    ]


def collect_community_matches(
    normalized: NormalizedURL,
    db: Session,
    resolved_ips: list[str] | None = None,
) -> list[NormalizedIndicatorMatch]:
    """Match the target against active indicators approved by an analyst."""
    indicators = (
        db.query(ThreatIndicator)
        .filter(
            ThreatIndicator.source.like("community:%"),
            ThreatIndicator.verification_status == "community_approved",
            or_(
                ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > datetime.now(UTC)
            ),
        )
        .all()
    )
    targets_by_type = {
        IndicatorType.URL: [normalized.redacted_url],
        IndicatorType.DOMAIN: [normalized.hostname],
        IndicatorType.IP: [normalized.hostname, *(resolved_ips or [])],
        IndicatorType.IPV4: [normalized.hostname, *(resolved_ips or [])],
    }

    matches: list[NormalizedIndicatorMatch] = []
    for indicator in indicators:
        indicator_type = {
            "url": IndicatorType.URL,
            "domain": IndicatorType.DOMAIN,
            "ip": IndicatorType.IP,
        }.get(indicator.indicator_type)
        if indicator_type is None:
            continue

        for target in targets_by_type[indicator_type]:
            matched, match_type = match_indicator(
                target,
                indicator.indicator_value,
                indicator_type,
            )
            if not matched:
                continue

            indicator_value = indicator.indicator_value
            if indicator_type == IndicatorType.URL:
                indicator_value = redact_url_for_external_query(indicator_value)
            matches.append(
                NormalizedIndicatorMatch(
                    provider=indicator.source,
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    original_value=normalized.redacted_url,
                    matched=True,
                    match_type=match_type,
                    threat_category=indicator.threat_category,
                    verification_status=VerificationStatus.CONFIRMED,
                    expires_at=indicator.expires_at.isoformat() if indicator.expires_at else None,
                    response_status=ProviderResponseStatus.MATCH,
                )
            )
            break
    return matches


def collect_intelligence(normalized: NormalizedURL) -> list[NormalizedIndicatorMatch]:
    """Query all enabled providers and return normalized, matched results.

    Failures in any single provider never raise — they become ERROR/UNAVAILABLE
    entries so the correlation engine can distinguish missing evidence from
    clean results.
    """
    redacted = redact_url_for_external_query(normalized.normalized_url)
    url_parts = redacted.split("://", 1)
    bare_url = url_parts[1] if len(url_parts) == 2 else redacted
    domain = normalized.hostname

    providers = []
    if settings.ENABLE_URLHAUS:
        providers.append(URLhausProvider())
    if settings.ENABLE_PHISHTANK:
        providers.append(PhishTankProvider())

    results: list[tuple[ThreatIntelligenceResult, IndicatorType, str]] = []
    for provider in providers:
        for query_value, kind in ((bare_url, IndicatorType.URL), (domain, IndicatorType.DOMAIN)):
            try:
                if kind == IndicatorType.URL:
                    result = provider.check_url(query_value)
                else:
                    result = provider.check_domain(query_value)
            except Exception as e:  # never let one provider break the scan
                logger.error(f"Provider '{provider.get_source_name()}' failed: {e}", exc_info=True)
                result = ThreatIntelligenceResult(
                    source=provider.get_source_name(),
                    query=query_value,
                    error=f"Unexpected provider error: {e}",
                    status="FAILED",
                )
            results.append((result, kind, query_value))
    return normalize_provider_results(results)


def normalize_provider_results(
    results: list[tuple[ThreatIntelligenceResult, IndicatorType, str]],
) -> list[NormalizedIndicatorMatch]:
    """Normalize provider results already fetched by the Phase 2 pipeline."""
    return _deduplicate(
        [
            _normalize_result(
                result,
                provider_name=result.source,
                indicator_type=indicator_type,
                original=original,
            )
            for result, indicator_type, original in results
        ]
    )


def _normalize_result(
    result: ThreatIntelligenceResult,
    provider_name: str,
    indicator_type: IndicatorType,
    original: str,
) -> NormalizedIndicatorMatch:
    """Convert a Phase 2 provider result into the normalized Phase 3 schema."""
    matched = result.match_found
    if matched:
        matched, match_type = match_indicator(original, result.query)
        if result.source == "URLhaus" and indicator_type == IndicatorType.URL:
            match_type = MatchType.EXACT_URL if matched else MatchType.NONE
    else:
        match_type = MatchType.NONE

    response_status = _STATUS_MAP.get(result.status, ProviderResponseStatus.ERROR)
    if matched:
        response_status = ProviderResponseStatus.MATCH

    threat_category = None
    if matched and result.threat_type:
        threat_category = _THREAT_CATEGORY_MAP.get(
            str(result.threat_type).lower(), str(result.threat_type)
        )

    return NormalizedIndicatorMatch(
        provider=provider_name,
        indicator_type=indicator_type,
        indicator_value=result.query,
        original_value=original,
        matched=matched,
        match_type=match_type if matched else MatchType.NONE,
        threat_category=threat_category,
        verification_status=_verification_of(result),
        source_url=result.reference,
        last_observed=result.last_seen,
        response_status=response_status,
        error=result.error,
    )


def _deduplicate(
    matches: list[NormalizedIndicatorMatch],
) -> list[NormalizedIndicatorMatch]:
    """Drop duplicate provider responses for the same indicator+type, keeping
    the most favorable verified entry."""
    best: dict[tuple[str, str, str], NormalizedIndicatorMatch] = {}
    for m in matches:
        key = (m.provider, m.indicator_type.value, m.indicator_value)
        existing = best.get(key)
        if existing is None:
            best[key] = m
            continue
        # Prefer verified > unverified; otherwise prefer non-error status.
        if (m.verification_status == VerificationStatus.CONFIRMED) and (
            existing.verification_status != VerificationStatus.CONFIRMED
        ):
            best[key] = m
        elif m.error is None and existing.error is not None:
            best[key] = m
    return list(best.values())
