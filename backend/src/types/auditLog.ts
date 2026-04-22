export type AuditOutcome = "success" | "failure";

export interface AuditLog {
  timestamp: Date;
  user_id?: string;
  username?: string;
  role?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  outcome: AuditOutcome;
  ip_address?: string;
  user_agent?: string;
  details: Record<string, unknown>;
}