import type {
  AuditLogsResponse,
  CommunityMeta,
  CommunitySubmission,
  CommunitySubmissionsResponse,
  DetectionResult,
  IntelligenceCheckResponse,
  IntelligenceStatusResponse,
  ScanHistoryResponse,
  ScanResponse,
  ScanIntelligenceResponse,
} from "@/lib/types";

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function getApiBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";
  const override =
    typeof window !== "undefined" ? window.localStorage.getItem("verity_api_url") : null;
  return (override || configured).replace(/\/+$/, "");
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body !== undefined) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      ...init,
      headers,
      cache: "no-store",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The backend could not be reached.";
    throw new ApiError(message, 0);
  }

  const text = await response.text();
  let payload: unknown;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const detail =
      typeof payload === "object" && payload !== null && "detail" in payload
        ? (payload as { detail: unknown }).detail
        : payload;
    const message =
      typeof detail === "string" ? detail : `Request failed with status ${response.status}.`;
    throw new ApiError(message, response.status);
  }

  return payload as T;
}

function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export const api = {
  submitScan(url: string): Promise<ScanResponse> {
    return request("/api/v1/scans", {
      method: "POST",
      body: JSON.stringify({ url }),
    });
  },

  getScan(scanId: string): Promise<ScanResponse> {
    return request(`/api/v1/scans/${encodeURIComponent(scanId)}`);
  },

  listScans(params: {
    search?: string;
    risk_level?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<ScanHistoryResponse> {
    return request(
      `/api/v1/scans${queryString({
        search: params.search,
        risk_level: params.risk_level,
        status_filter: params.status,
        limit: params.limit,
        offset: params.offset,
      })}`,
    );
  },

  getScanDetection(scanId: string): Promise<{ scan_id: string; detection: DetectionResult }> {
    return request(`/api/v1/scans/${encodeURIComponent(scanId)}/detection`);
  },

  getScanEvidence(scanId: string): Promise<{
    scan_id: string;
    count: number;
    duplicates_removed: number;
    evidence: DetectionResult["evidence"];
  }> {
    return request(`/api/v1/scans/${encodeURIComponent(scanId)}/evidence`);
  },

  getScanIntelligence(scanId: string): Promise<ScanIntelligenceResponse> {
    return request(`/api/v1/scans/${encodeURIComponent(scanId)}/intelligence`);
  },

  intelligenceStatus(): Promise<IntelligenceStatusResponse> {
    return request("/api/v1/intelligence/status");
  },

  intelligenceCheck(url: string): Promise<IntelligenceCheckResponse> {
    return request("/api/v1/intelligence/check", {
      method: "POST",
      body: JSON.stringify({ url }),
    });
  },

  listSubmissions(params: {
    indicator_type?: string;
    threat_category?: string;
    status_filter?: string;
    limit?: number;
    offset?: number;
  }): Promise<CommunitySubmissionsResponse> {
    return request(`/api/v1/community/submissions${queryString(params)}`);
  },

  communityMeta(): Promise<CommunityMeta> {
    return request("/api/v1/community/meta");
  },

  createSubmission(payload: {
    indicator_type: string;
    indicator_value: string;
    threat_category: string;
    description: string;
    evidence?: string;
    source_name?: string;
  }): Promise<CommunitySubmission> {
    return request("/api/v1/community/submissions", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  reviewSubmission(
    submissionId: string,
    payload: { decision: string; notes?: string },
    token: string,
  ): Promise<CommunitySubmission> {
    return request(
      `/api/v1/community/submissions/${encodeURIComponent(submissionId)}/review`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      },
    );
  },

  getAuditLogs(token: string, limit = 50): Promise<AuditLogsResponse> {
    return request(`/api/v1/community/audit-logs${queryString({ limit })}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  },
};
