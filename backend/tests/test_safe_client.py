"""SSRF-safe HTTP client tests using mocked DNS and HTTP transports."""

import httpcore
import httpx
import pytest
from backend.app.analyzers.website import safe_client
from backend.app.core.security import SSRFSecurityException


def _mock_transport(factory, handler):
    def create(address):
        factory.append(address)
        return httpx.MockTransport(handler)

    return create


def test_http_connection_uses_validated_ip(monkeypatch):
    connected_hosts = []

    def stop_connection(self, host, port, **kwargs):
        connected_hosts.append(host)
        raise httpcore.ConnectError("stop after address verification")

    monkeypatch.setattr(safe_client, "_resolve_and_validate", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", stop_connection)

    with pytest.raises(safe_client.SafeFetchError):
        safe_client.fetch_page("https://example.com/")

    assert connected_hosts == ["93.184.216.34"]


def test_response_body_is_capped_while_streaming(monkeypatch):
    addresses = []
    body = b"x" * (safe_client.MAX_RESPONSE_BYTES + 100)
    monkeypatch.setattr(safe_client, "_resolve_and_validate", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(
        safe_client,
        "_PinnedHTTPTransport",
        _mock_transport(
            addresses,
            lambda request: httpx.Response(200, content=body, request=request),
        ),
    )

    result = safe_client.fetch_page("https://example.com/")

    assert addresses == ["93.184.216.34"]
    assert len(result["body"]) == safe_client.MAX_RESPONSE_BYTES
    assert result["body_truncated"] is True


def test_private_redirect_is_blocked_before_second_connection(monkeypatch):
    addresses = []
    requests = []

    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"}, request=request)

    def resolve(hostname):
        if hostname == "example.com":
            return ["93.184.216.34"]
        raise SSRFSecurityException("Blocked private address", target=hostname)

    monkeypatch.setattr(safe_client, "_resolve_and_validate", resolve)
    monkeypatch.setattr(safe_client, "_PinnedHTTPTransport", _mock_transport(addresses, respond))

    with pytest.raises(SSRFSecurityException):
        safe_client.fetch_page("https://example.com/")

    assert requests == ["https://example.com/"]
    assert addresses == ["93.184.216.34"]


def test_redirect_to_restricted_port_is_rejected(monkeypatch):
    addresses = []
    requests = []

    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "http://redirect.example:8080/"},
            request=request,
        )

    monkeypatch.setattr(safe_client, "_resolve_and_validate", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(safe_client, "_PinnedHTTPTransport", _mock_transport(addresses, respond))

    with pytest.raises(safe_client.SafeFetchError) as error:
        safe_client.fetch_page("https://example.com/")

    assert error.value.reason == "INVALID_URL"
    assert requests == ["https://example.com/"]


def test_redirect_loop_is_detected(monkeypatch):
    addresses = []
    monkeypatch.setattr(safe_client, "_resolve_and_validate", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(
        safe_client,
        "_PinnedHTTPTransport",
        _mock_transport(
            addresses,
            lambda request: httpx.Response(
                302,
                headers={"location": str(request.url)},
                request=request,
            ),
        ),
    )

    with pytest.raises(safe_client.SafeFetchError) as error:
        safe_client.fetch_page("https://example.com/")

    assert error.value.reason == "REDIRECT_LOOP"
    assert addresses == ["93.184.216.34"]


def test_redirect_depth_stops_following(monkeypatch):
    addresses = []
    request_paths = []

    def respond(request):
        request_paths.append(request.url.path)
        return httpx.Response(
            302,
            headers={"location": f"/{len(request_paths)}"},
            request=request,
        )

    monkeypatch.setattr(safe_client, "_resolve_and_validate", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(safe_client, "_PinnedHTTPTransport", _mock_transport(addresses, respond))

    result = safe_client.fetch_page("https://example.com/", max_redirects=2)

    assert result["blocked"] is True
    assert result["block_reason"] == "TOO_MANY_REDIRECTS"
    assert len(request_paths) == 3
    assert len(addresses) == 3
