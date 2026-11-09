
"""URLhaus (abuse.ch) threat intelligence provider.

Official API:
    POST https://urlhaus-api.abuse.ch/v1/url/
        Form field: url

    POST https://urlhaus-api.abuse.ch/v1/host/
        Form field: host

Authentication:
    Auth-Key HTTP header, configured through URLHAUS_AUTH_KEY.

Documentation:
    https://urlhaus-api.abuse.ch/
"""

import os
import time
from typing import Any

import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import (
    ProviderStatus,
    ThreatIntelligenceResult,
    redact_url_for_external_query,
)

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API_URL = "https://urlhaus-api.abuse.ch/v1/host/"

REQUEST_TIMEOUT = 8.0
MIN_REQUEST_INTERVAL = 1.0


class URLhausProvider:
    """URLhaus adapter implementing the ThreatIntelligenceProvider contract."""

    def __init__(self, auth_key: str | None = None):
        configured_key = (
            auth_key
            if auth_key is not None
            else os.environ.get("URLHAUS_AUTH_KEY")
        )

        self._auth_key = configured_key.strip() if configured_key else None
        self._last_request_ts = 0.0

    def get_source_name(self) -> str:
        return "URLhaus"

    def get_provider_status(self) -> ProviderStatus:
        """Report whether the provider has the required API credentials."""
        if not self._auth_key:
            return ProviderStatus.DEGRADED

        return ProviderStatus.AVAILABLE

    def _throttle(self) -> None:
        """Enforce a minimum interval between requests."""
        elapsed = time.time() - self._last_request_ts

        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)

        self._last_request_ts = time.time()

    def _lookup(
        self,
        indicator: str,
        query_type: str,
    ) -> ThreatIntelligenceResult:
        """Perform a URL or hostname lookup against URLhaus."""

        base = ThreatIntelligenceResult(
            source=self.get_source_name(),
            query=indicator,
        )

        if query_type not in ("url", "host"):
            base.error = "Unsupported URLhaus query type"
            base.status = "FAILED"
            return base

        self._throttle()

        headers = {
            "Auth-Key": self._auth_key,
            "User-Agent": "WebVerity/0.1.0",
        } if self._auth_key else {
            "User-Agent": "WebVerity/0.1.0",
        }

        payload: dict[str, Any] = {
            query_type: indicator,
        }

        self._throttle()

        headers = {
            "Auth-Key": self._auth_key,
            "User-Agent": "WebVerity/0.1.0",
        }

        payload: dict[str, Any] = {
            query_type: indicator,
        }

        # URL and hostname lookups use different API endpoints.
        endpoint = (
            URLHAUS_HOST_API_URL
            if query_type == "host"
            else URLHAUS_API_URL
        )

        # Send the request.
        try:
            response = httpx.post(
                endpoint,
                data=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
            )

        except httpx.TimeoutException:
            base.error = "URLhaus API timeout"
            base.status = "TIMEOUT"
            return base

        except httpx.HTTPError as exc:
            base.error = f"URLhaus API unreachable: {type(exc).__name__}"
            base.status = "FAILED"
            return base

        # Handle HTTP errors.
        if response.status_code == 429:
            base.error = "URLhaus rate limit exceeded (HTTP 429)"
            base.status = "RATE_LIMITED"
            return base

        if response.status_code == 401:
            base.error = "URLhaus rejected credentials (HTTP 401)"
            base.status = "FAILED"
            return base

        if response.status_code != 200:
            base.error = (
                f"URLhaus returned HTTP {response.status_code}"
            )
            base.status = "FAILED"
            return base

        # Parse the JSON response.
        try:
            data = response.json()

        except ValueError:
            base.error = "URLhaus returned invalid JSON"
            base.status = "FAILED"
            return base

        if not isinstance(data, dict):
            base.error = "URLhaus returned an unexpected response format"
            base.status = "FAILED"
            return base

        query_status = data.get("query_status")

        # A no_results response is a successful lookup.
        if query_status == "no_results":
            base.match_found = False
            base.verified = False
            base.status = "COMPLETED"
            return base

        # Handle unsuccessful API query statuses.
        if query_status != "ok":
            if query_status == "unknown_auth_key":
                base.error = "URLhaus rejected the configured Auth-Key"
            elif query_status == "invalid_url":
                base.error = "URLhaus rejected the submitted URL"
            elif query_status == "invalid_host":
                base.error = "URLhaus rejected the submitted hostname"
            else:
                base.error = (
                    f"URLhaus query failed: {query_status or 'unknown status'}"
                )

            base.status = "FAILED"
            return base

        # ---------------------------------------------------------
        # HOSTNAME LOOKUP
        # Endpoint: POST /v1/host/
        # Request field: host
        # ---------------------------------------------------------
        if query_type == "host":
            host_urls = data.get("urls") or []

            if not isinstance(host_urls, list):
                base.error = "URLhaus returned an invalid host URL list"
                base.status = "FAILED"
                return base

            # URLhaus returns url_count as a string.
            try:
                url_count = int(data.get("url_count", 0))
            except (TypeError, ValueError):
                url_count = 0

            # A host is listed if URLhaus reports associated URLs.
            base.match_found = bool(host_urls) or url_count > 0
            base.verified = base.match_found

            if base.match_found:
                base.confidence = "HIGH"

                # Retrieve threat information from associated URLs.
                threats = [
                    item.get("threat")
                    for item in host_urls
                    if isinstance(item, dict) and item.get("threat")
                ]

                base.threat_type = (
                    str(threats[0])
                    if threats
                    else "malware_host"
                )

                # Prefer the official host reference returned by URLhaus.
                base.reference = (
                    data.get("urlhaus_reference")
                    or f"https://urlhaus.abuse.ch/host/{indicator}/"
                )

                # Get the latest date associated with observed URLs.
                dates = [
                    item.get("date_added")
                    for item in host_urls
                    if isinstance(item, dict)
                    and item.get("date_added")
                ]

                base.last_seen = (
                    max(dates)
                    if dates
                    else data.get("firstseen")
                )

            base.status = "COMPLETED"
            return base

        # ---------------------------------------------------------
        # URL LOOKUP
        # Endpoint: POST /v1/url/
        # Request field: url
        # ---------------------------------------------------------

        base.match_found = True

        base.verified = data.get("url_status") in (
            "online",
            "offline",
            "blocked",
        )

        base.threat_type = (
            "malware_url"
            if data.get("threat") is None
            else str(data.get("threat"))
        )

        base.confidence = "HIGH"

        base.last_seen = (
            data.get("last_online")
            or data.get("date_added")
        )

        base.reference = (
            data.get("urlhaus_reference")
            or "https://urlhaus.abuse.ch/browse/"
        )

        base.status = "COMPLETED"
        return base

    def check_url(self, url: str) -> ThreatIntelligenceResult:
        """Look up a redacted URL in the URLhaus database."""

        redacted = redact_url_for_external_query(url)

        logger.debug(
            f"URLhaus URL lookup for {redacted}"
        )

        return self._lookup(
            indicator=redacted,
            query_type="url",
        )

    def check_domain(self, domain: str) -> ThreatIntelligenceResult:
        """Look up a hostname in the URLhaus database."""

        logger.debug(
            f"URLhaus host lookup for {domain}"
        )

        return self._lookup(
            indicator=domain,
            query_type="host",
        )
