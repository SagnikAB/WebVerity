"""Asynchronous scan pipeline execution engine.

Coordinates URL, DNS, and TLS analyzers with timeout boundaries and thread pooling.
"""

import asyncio
from typing import Any

from backend.app.analyzers.dns_analyzer.analyzer import analyze_dns
from backend.app.analyzers.tls_analyzer.validator import validate_tls
from backend.app.analyzers.url_analyzer.features import extract_url_features
from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.detection.aggregator import AggregatedScanResult, aggregate_evidence
from backend.app.schemas.evidence import Finding, Severity


async def execute_scan_pipeline(
    normalized: NormalizedURL,
    raw_url: str,
) -> AggregatedScanResult:
    """Execute all security analysis modules asynchronously.

    Ensures that failures or timeouts in one module do not interrupt the broader scan.

    Args:
        normalized: Normalized URL container.
        raw_url: Submitted URL.

    Returns:
        AggregatedScanResult containing module outputs, findings, and risk scoring.
    """
    # 1. URL Structural and Feature Analysis
    url_findings: list[Finding] = []
    try:
        url_features, url_findings = extract_url_features(normalized, raw_url)
        url_result: dict[str, Any] = {
            "module": "url_analysis",
            "features": url_features,
            "findings": [f.model_dump() for f in url_findings],
            "status": "COMPLETED",
        }
    except Exception as e:
        logger.error(f"URL analysis module error: {e}", exc_info=True)
        url_result = {
            "module": "url_analysis",
            "features": {},
            "findings": [],
            "status": "FAILED",
        }

    # 2. DNS Infrastructure Analysis (run in worker thread)
    dns_findings: list[Finding] = []
    validated_ips: list[str] = []
    try:
        dns_result, dns_findings, validated_ips = await asyncio.wait_for(
            asyncio.to_thread(analyze_dns, normalized.hostname),
            timeout=settings.DNS_TIMEOUT + 2.0,
        )
    except TimeoutError:
        logger.warning(f"DNS analysis timed out for {normalized.hostname}")
        dns_findings.append(
            Finding(
                id="DNS_TIMEOUT",
                module="dns_analysis",
                severity=Severity.INFO,
                title="DNS Resolution Timeout",
                description="DNS queries timed out during pipeline execution.",
                evidence={"hostname": normalized.hostname},
            )
        )
        dns_result = {
            "module": "dns_analysis",
            "domain": normalized.hostname,
            "records": {},
            "dns_status": "TIMEOUT",
            "findings": [f.model_dump() for f in dns_findings],
        }
    except Exception as e:
        logger.error(f"DNS analysis module failure for {normalized.hostname}: {e}", exc_info=True)
        dns_result = {
            "module": "dns_analysis",
            "domain": normalized.hostname,
            "records": {},
            "dns_status": "ERROR",
            "findings": [],
        }

    # 3. TLS Certificate and Transport Inspection (run in worker thread)
    tls_findings: list[Finding] = []
    try:
        if normalized.scheme == "http":
            tls_result, tls_findings = validate_tls(
                scheme="http",
                hostname=normalized.hostname,
                port=normalized.port,
            )
        else:
            destination_ip = validated_ips[0] if validated_ips else None
            tls_result, tls_findings = await asyncio.wait_for(
                asyncio.to_thread(
                    validate_tls,
                    scheme="https",
                    hostname=normalized.hostname,
                    destination_ip=destination_ip,
                    port=normalized.port,
                    timeout=settings.TLS_TIMEOUT,
                ),
                timeout=settings.TLS_TIMEOUT + 2.0,
            )
    except TimeoutError:
        logger.warning(f"TLS analysis timed out for {normalized.hostname}")
        tls_findings.append(
            Finding(
                id="TLS_HANDSHAKE_ERROR",
                module="tls_analysis",
                severity=Severity.LOW,
                title="TLS Inspection Timeout",
                description="TLS handshake timed out before completion.",
                evidence={"hostname": normalized.hostname},
            )
        )
        tls_result = {
            "module": "tls_analysis",
            "status": "UNKNOWN",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "UNKNOWN",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [f.model_dump() for f in tls_findings],
        }
    except Exception as e:
        logger.error(f"TLS analysis module failure for {normalized.hostname}: {e}", exc_info=True)
        tls_result = {
            "module": "tls_analysis",
            "status": "FAILED",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "UNKNOWN",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [],
        }

    # 4. Evidence Aggregation & Risk Scoring
    aggregated = aggregate_evidence(
        url_result=url_result,
        url_findings=url_findings,
        dns_result=dns_result,
        dns_findings=dns_findings,
        tls_result=tls_result,
        tls_findings=tls_findings,
    )

    return aggregated
