import type { RiskLevel, Severity } from "@/lib/types";

export const RISK_BANDS: Record<
  RiskLevel,
  { label: string; color: string; bg: string; border: string }
> = {
  LOW: {
    label: "Low",
    color: "text-emerald-300",
    bg: "bg-emerald-400/10",
    border: "border-emerald-400/30",
  },
  MODERATE: {
    label: "Moderate",
    color: "text-amber-300",
    bg: "bg-amber-400/10",
    border: "border-amber-400/30",
  },
  HIGH: {
    label: "High",
    color: "text-orange-300",
    bg: "bg-orange-400/10",
    border: "border-orange-400/30",
  },
  CRITICAL: {
    label: "Critical",
    color: "text-rose-300",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
  },
};

export const SEVERITY_STYLES: Record<Severity, string> = {
  INFO: "border-slate-500/30 bg-slate-500/10 text-slate-300",
  LOW: "border-sky-400/30 bg-sky-400/10 text-sky-300",
  MEDIUM: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  HIGH: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  CRITICAL: "border-rose-500/30 bg-rose-500/10 text-rose-300",
};

export const MODULE_LABELS: Record<string, string> = {
  url_analysis: "URL Analysis",
  dns_analysis: "DNS Analysis",
  tls_analysis: "TLS Analysis",
  http_security: "HTTP Security Headers",
  redirect_analysis: "Redirect Analysis",
  content_analysis: "HTML Content Analysis",
  domain_intelligence: "RDAP Domain Intelligence",
  threat_intelligence: "Threat Intelligence",
};

export function riskBand(score: number): RiskLevel {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MODERATE";
  return "LOW";
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
