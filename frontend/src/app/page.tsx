import Link from "next/link";
import { ArrowRight, ChevronRight } from "lucide-react";

const SIGNALS = [
  {
    title: "URL + DNS",
    copy: "Inspect URL structure, hostname signals, and public DNS records.",
  },
  {
    title: "TLS CERTIFICATES",
    copy: "Check the live certificate chain, hostname match, validity dates, and crypto metadata.",
  },
  {
    title: "WEB SECURITY",
    copy: "Assess headers, cookies, redirect paths, and fetched page content.",
  },
  {
    title: "THREAT FEEDS",
    copy: "Compare against URLhaus and PhishTank when enabled and configured.",
  },
  {
    title: "COMMUNITY REPORTS",
    copy: "Review submitted indicators; approved, active reports are included in scan scoring.",
  },
];

const FEATURES = [
  {
    label: "01 / DETECT",
    sub: "URL + PAGE SIGNALS",
    detail: "Heuristics for suspicious URL structure, brand lookalikes, and credential forms.",
  },
  {
    label: "02 / VALIDATE",
    sub: "DNS + TLS TRUST",
    detail: "DNS records and the presented certificate's hostname, chain, dates, and crypto details.",
  },
  {
    label: "03 / ASSESS",
    sub: "WEB CONFIGURATION",
    detail: "Security headers, cookies, redirects, and transport posture—separate from phishing risk.",
  },
  {
    label: "04 / CORRELATE",
    sub: "FEEDS + COMMUNITY",
    detail: "Configured external feeds and analyst-approved community indicators add traceable evidence.",
  },
];

const CHECKS = [
  "Eight analysis modules report their own completion status.",
  "Threat risk, security posture, and evidence confidence stay separate.",
  "Unavailable providers are shown as unavailable—not as a clean result.",
  "Scores are heuristic, not calibrated probabilities or safety guarantees.",
];

export default function LandingPage() {
  return (
    <div className="cyber-page">
      <div className="cyber-shell">
        <section className="cyber-hero">
          <div className="cyber-copy">
            <div className="cyber-kicker">WEBVERITY / THREAT ASSESSMENT</div>
            <h1>
              TRUST
              <br />
              NEEDS
              <br />
              EVIDENCE
            </h1>
            <p className="cyber-tagline">
              PHISHING SIGNALS.
              <br />
              WEB SECURITY.
              <br />
              CERTIFICATE CHECKS.
            </p>
            <p className="cyber-description">
              Assess a public URL across URL and DNS signals, TLS certificates, web configuration,
              redirects, page content, registration data, and available threat intelligence. Get
              explainable findings—not an unsupported promise that a site is safe.
            </p>
            <div className="cyber-actions">
              <Link href="/scan" className="cyber-button primary">
                RUN A SCAN
                <ArrowRight size={16} />
              </Link>
              <Link href="/about" className="cyber-button secondary">
                HOW IT WORKS
              </Link>
            </div>
          </div>

          <div className="cyber-visual" aria-label="WebVerity assessment signal visualization">
            <div className="scan-overlay">
              <span>ASSESSMENT PIPELINE</span>
              <strong>8 MODULES</strong>
            </div>
            <div className="head-visual">
              <div className="head-core" />
              <div className="head-grid" />
              <div className="head-data" />
            </div>
            <div className="visual-metadata">
              <span>URL + DNS</span>
              <span>TLS + WEB</span>
              <span>FEEDS + REPORTS</span>
            </div>
            <div className="scan-tag">{"//EVIDENCE_FIRST"}</div>
          </div>
        </section>

        <section className="cyber-principles" aria-label="Analysis signals">
          {SIGNALS.map((item) => (
            <article key={item.title} className="cyber-card principle-card">
              <div className="mini-label">+ SIGNAL</div>
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </section>

        <section className="cyber-work-section">
          <div className="section-heading">
            <span className="section-tag">/02</span>
            <span className="section-title">FROM URL TO EXPLAINABLE FINDINGS</span>
          </div>
          <div className="cyber-work-grid">
            {FEATURES.map((feature, index) => (
              <article key={feature.label} className={`cyber-card work-card work-${index + 1}`}>
                <div className="work-figure" />
                <div className="feature-content">
                  <span>{feature.label}</span>
                  <strong>{feature.sub}</strong>
                  <p>{feature.detail}</p>
                  <ChevronRight size={18} />
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="cyber-lower-grid">
          <article className="cyber-card large-cta">
            <div className="section-heading compact">
              <span className="section-tag">/03</span>
            </div>
            <h2>HTTPS IS A START. NOT THE WHOLE STORY.</h2>
            <p>
              CA incidents, including the eMudhra incident, underline why encrypted transport
              alone cannot establish that a site is trustworthy. WebVerity validates the presented
              certificate and connection; it does not monitor Certificate Transparency logs or
              perform OCSP/CRL revocation checks.
            </p>
            <Link href="/scan" className="cyber-button primary inline-button">
              CHECK A WEBSITE
              <ArrowRight size={16} />
            </Link>
          </article>

          <article className="cyber-card status-card">
            <div className="section-heading compact">
              <span className="section-tag">/04</span>
              <span className="section-title">WHAT THE REPORT MEANS</span>
            </div>
            <ul className="signal-check-list">
              {CHECKS.map((check) => (
                <li key={check}>
                  <span>+</span>
                  {check}
                </li>
              ))}
            </ul>
            <div className="status-bottom">EVIDENCE FIRST / NO FABRICATED SIGNALS</div>
          </article>

          <article className="cyber-card subscribe-card">
            <div className="section-heading compact">
              <span className="section-tag">/05</span>
              <span className="section-title">SHARE THREAT SIGNALS</span>
            </div>
            <p>
              Submit a suspicious URL or domain for review. Reports stay separate from trusted
              indicators until an analyst approves them.
            </p>
            <Link href="/community" className="cyber-button secondary inline-button">
              OPEN COMMUNITY INTELLIGENCE
              <ArrowRight size={16} />
            </Link>
          </article>
        </section>
      </div>
    </div>
  );
}
