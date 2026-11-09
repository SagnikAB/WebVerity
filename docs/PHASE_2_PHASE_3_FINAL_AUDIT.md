# Phase 2 / Phase 3 Integration Audit

## Outcome

**Overall: PASS WITH FOLLOW-UP ITEMS.** The Phase 2 scan pipeline now feeds the Phase 3 assessment exactly once, and the final Phase 3 risk and confidence result is the one returned and persisted. Core regressions were fixed and the complete offline test suite passes. The remaining items below limit production readiness or heuristic accuracy; they are not represented as completed functionality.

## Verified behavior

| Area | Status | Evidence |
|---|---|---|
| URL validation and SSRF controls | PASS | Rejects credentials and malformed/non-standard ports; resolves and validates all target IPs before connecting; pins HTTP and TLS connections to validated addresses; applies the same checks to redirect destinations. See [safe_client.py](../backend/app/analyzers/website/safe_client.py), [validator.py](../backend/app/analyzers/url_analyzer/validator.py), and [security.py](../backend/app/core/security.py). |
| HTTP response limits | PASS, with provider caveat below | The scanned-site HTTP client reads response data incrementally and enforces the configured cap. RDAP bootstrap and registration requests now also stream under a fixed cap and do not follow redirects. See [safe_client.py](../backend/app/analyzers/website/safe_client.py) and [analyzer.py](../backend/app/analyzers/domain_intelligence/analyzer.py). |
| Phase 2 / Phase 3 integration | PASS | Phase 3 normalizes the threat-intelligence results already collected by Phase 2; it does not make a second provider fan-out. The unified risk/confidence assessment is returned and persisted alongside separate posture data. See [detection_orchestrator.py](../backend/app/detection/detection_orchestrator.py) and [scan_manager.py](../backend/app/orchestration/scan_manager.py). |
| Risk semantics | PASS | Unverified intelligence matches cannot force a critical classification; security-posture evidence is kept out of threat-risk scoring; classification boundaries are explicit; heuristic outputs set `is_probability: false`; low-risk explanations include the required disclaimer. See [risk_engine.py](../backend/app/detection/risk_engine.py) and [risk_scoring.py](../backend/app/detection/risk_scoring.py). |
| Persistence and response reconstruction | PASS | Scan history reconstructs the Phase 3 assessment, detection details, and independent posture data. The incremental migration uses SQLAlchemy inspection and preserves existing rows. SQLite migration behavior is covered by an idempotence regression test; a live PostgreSQL server was not available for runtime verification. See [connection.py](../backend/app/database/connection.py), [scans.py](../backend/app/api/routes/scans.py), and [test_database_migrations.py](../backend/tests/test_database_migrations.py). |
| Frontend API contract | PASS | Missing shared API, format, and type modules were added; frontend types include the additive detection and posture response fields. TypeScript, ESLint, and production build complete successfully. See [api.ts](../frontend/src/lib/api.ts), [types.ts](../frontend/src/lib/types.ts), and [api_documentation.md](./api_documentation.md). |
| RDAP response handling | PASS | Registration and IANA bootstrap responses are streamed with a 512 KiB ceiling; redirects are not followed. Oversize, timeout, invalid JSON, and unavailable-server cases are handled as incomplete results rather than fabricated evidence. See [analyzer.py](../backend/app/analyzers/domain_intelligence/analyzer.py). |

## Follow-up findings and limitations

| Priority | Finding | Impact / recommended follow-up |
|---|---|---|
| MEDIUM | Scan and scan-retrieval routes have no authentication or scan-specific rate limit. | An exposed deployment can be used to consume scanning/network resources and enumerate stored scan results. Put these routes behind deployment-level authentication and rate limiting, or add application controls before public exposure. The community submission rate limit does not cover scan endpoints. See [scans.py](../backend/app/api/routes/scans.py). |
| MEDIUM | Domain comparisons use a last-two-label approximation instead of the Public Suffix List. | For multi-label suffixes (for example, `co.uk`), legitimate-domain checks and link/form same-site comparisons can be wrong. Use a maintained public-suffix implementation and add tests for multi-label suffixes before relying on these comparisons. See [analyzer.py](../backend/app/analyzers/content_analyzer/analyzer.py). |
| MEDIUM | URLhaus and PhishTank response JSON is read without a streaming response-size cap. | The provider URLs are fixed HTTPS endpoints, but an unexpectedly large provider response can still consume excess memory. Add bounded streaming and an explicit oversized-response status. See [urlhaus.py](../backend/app/intelligence/urlhaus.py) and [phishtank.py](../backend/app/intelligence/phishtank.py). |
| LOW | Brand impersonation coverage is a small curated set of six brands. | This is heuristic coverage, not comprehensive brand impersonation detection. Keep the output explicitly heuristic and expand/maintain the data source only with a defined update and validation process. See [analyzer.py](../backend/app/analyzers/content_analyzer/analyzer.py). |
| LOW | The TTL cache implementation is not wired into provider lookup calls. | `THREAT_INTELLIGENCE_CACHE_TTL` currently does not prevent repeat provider requests across scans. Integrate a bounded, thread-safe cache or remove the unused configuration/claim. See [cache.py](../backend/app/intelligence/cache.py). |
| INFO | Certificate revocation is not checked. | The implementation extracts certificate metadata and validates the TLS connection, but does not perform OCSP/CRL checks. Revocation therefore remains unknown/not assessed; it must not be reported as revoked without verified revocation evidence. See [certificate.py](../backend/app/analyzers/tls_analyzer/certificate.py). |
| CONDITIONAL | PhishTank is usable only when its API key is configured; provider credentials were not verified in this audit. | The provider reports unavailable/skipped when no key is present. URLhaus supports an optional key. No live provider calls were made; see [phishtank.py](../backend/app/intelligence/phishtank.py) and [urlhaus.py](../backend/app/intelligence/urlhaus.py). |

## Validation

- Backend: `pytest -q` — **166 passed**, one Starlette/httpx deprecation warning.
- Backend lint: `ruff check backend/app backend/tests` — **passed**.
- Modified Python files: `ruff format --check` — **23 files passed**.
- Frontend: `npx tsc --noEmit`, `npm run lint`, and `npm run build` — **passed**. Next.js emitted an environment warning that it ignored a parent-directory package lock; compilation and static generation succeeded.
- Dependency audit recorded during the work: `npm audit --omit=dev` reported **0 vulnerabilities**; the complete dependency tree reported **8 moderate advisories**.
- Repository-wide Ruff checks are not fully clean due to pre-existing files outside this change: `ruff check .` reports four issues in `backend/_dbg.py`; the backend-wide format check reports four unrelated community files. These files were left unchanged.

All network-dependent tests used controlled offline fixtures. No live target sites or live intelligence providers were queried. The workspace has no Git repository metadata, so no commit or diff-based baseline could be produced.
