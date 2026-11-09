"use client";

import { useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, Loader2, ScanSearch, ShieldAlert } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { RISK_BANDS } from "@/lib/format";
import { RiskGauge } from "@/components/ui";
import type { ScanResponse } from "@/lib/types";

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function handleSubmit(e: React.SubmitEvent) {
    e.preventDefault();
    if (!url.trim() || scanning) return;
    // Basic client-side scheme validation — the backend performs authoritative
    // validation and SSRF enforcement.
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed) && !/^[\w-]+(\.[\w-]+)+/.test(trimmed)) {
      setError("Enter a valid URL, e.g. https://example.com");
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const target = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      const scan = await api.submitScan(target);
      setResult(scan);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unexpected error while scanning.");
    } finally {
      setScanning(false);
    }
  }

  const band = result ? RISK_BANDS[result.threat_assessment.classification] : null;

  return (
    <div className="cyber-page scanner-page">
      <div className="cyber-shell scanner-shell">
        <div className="scanner-heading">
          <div className="section-heading">
            <span className="section-tag">/01</span>
            <span className="section-title">LIVE WEBSITE ASSESSMENT</span>
          </div>
          <h1>ASSESS A PUBLIC URL</h1>
          <p>
            Inspect URL structure, DNS, TLS certificate trust, web configuration, redirects, page
            content, registration data, and available threat intelligence. Only scan sites you are
            authorized to assess.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="scanner-form">
          <input
            className="scanner-input"
            type="text"
            inputMode="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
            aria-label="URL to scan"
          />
          <button type="submit" className="scanner-button" disabled={scanning || !url.trim()}>
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
            {scanning ? "ASSESSING..." : "RUN SCAN"}
          </button>
        </form>

        {scanning && (
          <div className="scanner-state" role="status" aria-live="polite">
            <Loader2 className="h-5 w-5 animate-spin" />
            <div>
              <p>Running the 8-module assessment pipeline...</p>
              <span>DNS / TLS / HTTP / REDIRECTS / CONTENT / RDAP / THREAT FEEDS</span>
            </div>
          </div>
        )}

        {error && (
          <div className="scanner-error" role="alert">
            {error.toLowerCase().includes("security") ? (
              <ShieldAlert className="h-5 w-5 shrink-0" />
            ) : (
              <AlertTriangle className="h-5 w-5 shrink-0" />
            )}
            <div>
              <p>{error}</p>
              <span>
                Requests for private, loopback, or metadata addresses are rejected by the SSRF guard by design.
              </span>
            </div>
          </div>
        )}

        {result && band && (
          <div className="scanner-result">
            <div className="scanner-result-header">
              <div>
                <p className="scanner-overline">SCAN COMPLETE / {result.scan_id}</p>
                <h2>{result.target}</h2>
                <div className="scanner-badges">
                  <span className={`scanner-badge ${band.border} ${band.bg} ${band.color}`}>
                    {band.label}
                  </span>
                  <span className="scanner-badge neutral">
                    Confidence: {result.threat_assessment.confidence}
                  </span>
                  <span className="scanner-badge neutral">
                    Modules: {String(result.scan_metadata?.modules_completed ?? "—")}/
                    {String(result.scan_metadata?.modules_total ?? "8")}
                  </span>
                </div>
              </div>
              <RiskGauge score={result.threat_assessment.risk_score} />
            </div>
            {result.threat_assessment.explanation && (
              <p className="scanner-explanation">{result.threat_assessment.explanation}</p>
            )}
            <p className="scanner-disclaimer">
              Heuristic score—not a probability. No strong threat indicators observed in completed
              checks does not guarantee the website is safe.
            </p>
            <div className="scanner-actions">
              <Link href={`/scan/${result.scan_id}`} className="cyber-button primary">
                VIEW FULL REPORT
                <ArrowRight size={16} />
              </Link>
              <button
                className="cyber-button secondary"
                onClick={() => {
                  setResult(null);
                  setUrl("");
                }}
              >
                SCAN ANOTHER URL
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
