export type NetworkZone = "internal" | "vpn" | "external" | "unknown";
export type AccessAction = "read" | "write" | "update" | "delete";
export type AccessDecision = "allow" | "deny";

export interface AccessRiskContext {
  score: number;
  reasons: string[];
  known_device: boolean;
  trusted_device: boolean;
  network_zone: NetworkZone;
  mfa_verified: boolean;
}

export interface AccessRequest {
  user_id: string;
  device_id: string;
  resource_name: string;
  action: AccessAction;
  request_time: Date;
  context: {
    ip_address?: string;
    network_zone: NetworkZone;
    mfa_verified: boolean;
    trusted_device: boolean;
    known_device: boolean;
  };
  risk: AccessRiskContext;
  decision: AccessDecision;
  decision_reason: string;
}