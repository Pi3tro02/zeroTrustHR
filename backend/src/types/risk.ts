export interface RiskEvaluateRequest {
  user: string;
  role?: string;
  department?: string;
  device?: {
    trusted?: boolean;
    status?: string;
    os?: string;
    ip?: string;
    ja3?: string;
  };
  network?: {
    ip?: string;
    zone?: string;
  };
  request: {
    resource: string;
    action: string;
  };
}

export interface RiskEvaluateResponse {
  risk_score: number;
  severity: "safe" | "warning" | "danger" | "critical";
  profit: number;
  risk_cover?: string;
  recent_denies?: number;
  recent_allows?: number;
  distinct_device_ips?: number;
  distinct_ja3?: number;
  distinct_trust_states?: number;
  source: "splunk" | "fallback";
  window: string;
}