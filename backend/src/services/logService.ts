import { getDb } from "../config/db";
import { AuditLog, AuditOutcome } from "../types/auditLog";

interface LogEventParams {
  user_id?: string;
  username?: string;
  role?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  outcome: AuditOutcome;
  ip_address?: string;
  user_agent?: string;
  details?: Record<string, unknown>;
}

/**
 * Salva un evento nel registro di audit.
 */
export async function logEvent({
  user_id,
  username,
  role,
  action,
  resource_type,
  resource_id,
  outcome,
  ip_address,
  user_agent,
  details = {}
}: LogEventParams): Promise<void> {
  const db = getDb();

  const logDoc: AuditLog = {
    timestamp: new Date(),
    user_id,
    username,
    role,
    action,
    resource_type,
    resource_id,
    outcome,
    ip_address,
    user_agent,
    details
  };

  await db.collection("audit_logs").insertOne(logDoc);
}