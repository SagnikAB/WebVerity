export type RiskLevel = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ScanStatus = "PENDING" | "PROCESSING" | "COMPLETED" | "FAILED";

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  timestamp: string;
}

export interface EvidenceItem {
  id: string;
  category:
    | "malicious_indicator"
    | "suspicious"
    | "security_weakness"
    | "neutral"
    | "unavailable";
  description: string;
  severity: Severity;
  source: string;
  observed_at: string;
  confidence: number;
  status: string;
  origin: string;
}

export interface ThreatAssessment {
  risk_score: number;
  classification: RiskLevel;
  confidence: ConfidenceLevel;
  is_probability: false;
  explanation: string | null;
  security_posture_score: number;
}

export interface DetectionResult {
  risk_score: number;
  risk_level: RiskLevel;
  classification: RiskLevel;
  score_breakdown: Record<string, number>;
  reasons: string[];
  confidence_score: number;
  confidence_level: ConfidenceLevel;
  confidence_explanation: string;
  successful_checks: string[];
  failed_checks: string[];
  unavailable_providers: string[];
  evidence: EvidenceItem[];
  duplicates_removed: number;
  intelligence_matches: IntelligenceMatch[];
  explanation: string;
  is_probability: false;
}

export interface ScanResponse {
  scan_id: string;
  status: ScanStatus;
  target: string;
  threat_assessment: ThreatAssessment;
  security_posture: { score: number; findings: Finding[] };
  detection: DetectionResult;
  modules: Record<string, Record<string, unknown>>;
  findings: Finding[];
  recommendations: string[];
  scan_metadata: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
}

export interface ScanHistoryItem {
  scan_id: string;
  target: string;
  url: string;
  status: ScanStatus;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: ConfidenceLevel;
  security_posture_score: number;
  created_at: string;
  completed_at: string | null;
}

export interface ScanHistoryResponse {
  total: number;
  count: number;
  limit: number;
  offset: number;
  scans: ScanHistoryItem[];
}

export interface IntelligenceProvider {
  provider: string;
  configured: boolean;
  enabled: boolean;
  status: string;
  description: string;
}

export interface IntelligenceStatusResponse {
  providers: IntelligenceProvider[];
  credentials_exposed: false;
}

export interface IntelligenceMatch {
  provider: string;
  indicator_type: string;
  indicator_value: string;
  original_value?: string;
  matched?: boolean;
  match_type?: string;
  threat_category: string | null;
  verification_status: "confirmed" | "unverified" | "unknown";
  source_url?: string | null;
  detail?: string;
  error?: string | null;
}

export interface IntelligenceCheckResponse {
  url: string;
  providers_checked: number;
  matches_found: number;
  verified_matches: number;
  matches: IntelligenceMatch[];
  is_probability: false;
  disclaimer: string;
}

export interface ScanIntelligenceResponse {
  scan_id: string;
  threat_intelligence: Record<string, unknown>;
  domain_intelligence: Record<string, unknown>;
}

export interface CommunitySubmission {
  id: string;
  indicator_type: string;
  indicator_value: string;
  threat_category: string;
  description: string;
  evidence: string | null;
  source_name: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "INFO_REQUESTED";
  confidence: number;
  review_notes: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface CommunitySubmissionsResponse {
  total: number;
  count: number;
  limit: number;
  offset: number;
  submissions: CommunitySubmission[];
}

export interface CommunityMeta {
  indicator_types: string[];
  threat_categories: string[];
  rate_limit_per_hour: number;
}

export interface AuditLogEntry {
  id: string;
  actor_id: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string | null;
  created_at: string;
}

export interface AuditLogsResponse {
  total: number;
  count: number;
  logs: AuditLogEntry[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
}
