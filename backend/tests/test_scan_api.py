"""Integration tests for Scan API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient


@patch("backend.app.orchestration.pipeline.analyze_dns")
@patch("backend.app.orchestration.pipeline.validate_tls")
def test_submit_valid_scan_success(mock_validate_tls, mock_analyze_dns, client: TestClient):
    """Verify POST /api/v1/scans creates, executes, and returns a completed scan."""
    mock_analyze_dns.return_value = (
        {
            "module": "dns_analysis",
            "domain": "example.com",
            "records": {"A": ["93.184.216.34"], "MX": []},
            "dns_status": "RESOLVED",
            "findings": [],
        },
        [],
        ["93.184.216.34"],
    )

    mock_validate_tls.return_value = (
        {
            "module": "tls_analysis",
            "status": "COMPLETED",
            "https_enabled": True,
            "hostname_match": True,
            "chain_validation": "VALID",
            "certificate_expired": False,
            "issuer": "DigiCert",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate": {},
            "findings": [],
        },
        [],
    )

    payload = {"url": "https://example.com/test-path?ref=123"}
    response = client.post("/api/v1/scans", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "COMPLETED"
    assert data["target"] == "example.com"
    assert "threat_assessment" in data
    assert data["threat_assessment"]["classification"] == "LOW"
    assert "modules" in data
    assert "url_analysis" in data["modules"]
    assert "dns_analysis" in data["modules"]
    assert "tls_analysis" in data["modules"]

    # Verify retrieval by scan ID
    scan_id = data["scan_id"]
    get_response = client.get(f"/api/v1/scans/{scan_id}")
    assert get_response.status_code == 200
    retrieved = get_response.json()
    assert retrieved["scan_id"] == scan_id
    assert retrieved["target"] == "example.com"
    assert "security_posture" in retrieved


def test_phase3_assessment_is_returned_and_persisted(client: TestClient, monkeypatch):
    from backend.app.orchestration import pipeline

    monkeypatch.setattr(
        pipeline,
        "check_threat_intelligence",
        lambda normalized: (
            {
                "module": "threat_intelligence",
                "status": "COMPLETED",
                "results": [
                    {
                        "source": "URLhaus",
                        "query": "https://example.com/",
                        "match_found": True,
                        "verified": True,
                        "threat_type": "malware_url",
                        "status": "COMPLETED",
                    }
                ],
                "findings": [],
            },
            [],
        ),
    )

    response = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    assert response.status_code == 201
    data = response.json()
    assert data["threat_assessment"]["risk_score"] == 100
    assert data["threat_assessment"]["classification"] == "CRITICAL"
    assert data["detection"]["risk_score"] == 100
    assert data["security_posture"]["score"] == data["threat_assessment"]["security_posture_score"]

    retrieved = client.get(f"/api/v1/scans/{data['scan_id']}")
    assert retrieved.status_code == 200
    assert retrieved.json()["threat_assessment"]["risk_score"] == 100
    assert retrieved.json()["detection"]["risk_score"] == 100


def test_approved_community_indicator_is_used_and_persisted(client, db_session):
    from backend.app.models.threat import IntelligenceMatch, ThreatIndicator

    indicator = ThreatIndicator(
        indicator_type="domain",
        indicator_value="example.com",
        source="community:analyst",
        threat_category="phishing",
        verification_status="community_approved",
    )
    db_session.add(indicator)
    db_session.commit()

    response = client.post("/api/v1/scans", json={"url": "https://example.com/login"})

    assert response.status_code == 201
    result = response.json()
    community_matches = [
        match
        for match in result["detection"]["intelligence_matches"]
        if match["provider"] == "community:analyst"
    ]
    assert len(community_matches) == 1
    assert community_matches[0]["matched"] is True
    assert community_matches[0]["verification_status"] == "confirmed"
    assert (
        result["modules"]["threat_intelligence"]["community_matches"][0]["indicator_value"]
        == "example.com"
    )
    assert (
        db_session.query(IntelligenceMatch)
        .filter_by(scan_id=result["scan_id"], indicator_id=indicator.id)
        .count()
        == 1
    )
    assert (
        db_session.query(ThreatIndicator)
        .filter_by(source="community:analyst", indicator_value="example.com")
        .count()
        == 1
    )


def test_expired_community_indicator_is_not_used(client, db_session):
    from datetime import UTC, datetime, timedelta

    from backend.app.models.threat import ThreatIndicator

    db_session.add(
        ThreatIndicator(
            indicator_type="domain",
            indicator_value="expired-community-test.net",
            source="community:analyst",
            threat_category="phishing",
            verification_status="community_approved",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    db_session.commit()

    response = client.post(
        "/api/v1/scans",
        json={"url": "https://expired-community-test.net/"},
    )

    assert response.status_code == 201
    assert not any(
        match["provider"] == "community:analyst"
        for match in response.json()["detection"]["intelligence_matches"]
    )


def test_submit_invalid_url_rejected(client: TestClient):
    """Verify invalid URL returns 400 Bad Request."""
    response = client.post("/api/v1/scans", json={"url": "invalid-url-without-scheme"})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_submit_unsupported_port_rejected(client: TestClient):
    """Verify unsupported port returns 400 Bad Request."""
    response = client.post("/api/v1/scans", json={"url": "http://example.com:8080"})
    assert response.status_code == 400
    assert "Port 8080 is not permitted" in response.json()["detail"]


def test_submit_ssrf_target_rejected(client: TestClient):
    """Verify submission of localhost or private IP is rejected by SSRF guard."""
    response_lh = client.post("/api/v1/scans", json={"url": "http://localhost/admin"})
    assert response_lh.status_code == 400
    assert "SSRF Security Violation" in response_lh.json()["detail"]

    response_priv = client.post("/api/v1/scans", json={"url": "http://192.168.1.1/setup"})
    assert response_priv.status_code == 400
    assert "SSRF Security Violation" in response_priv.json()["detail"]


def test_get_nonexistent_scan_returns_404(client: TestClient):
    """Verify querying an unknown scan ID returns 404."""
    response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
