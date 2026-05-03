/**
 * backend/src/services/logService.ts  (Versione Enterprise)
 *
 * Modifiche:
 *  - Rimossa la dipendenza da fetch/https verso Splunk.
 *  - Aggiunto 'pino' per il logging NDJSON (Newline Delimited JSON) su stdout.
 *  - Delega la spedizione dei log al Logging Driver nativo di Docker.
 */

import { getDb } from "../config/db";
import { AuditLog, AuditOutcome } from "../types/auditLog";
import pino from "pino";

// Inizializza Pino per produrre JSON ottimizzato sullo Standard Output
const logger = pino({
  level: 'info',
  // Usa il formato ISO8601 per i timestamp, che Splunk digerisce nativamente
  timestamp: pino.stdTimeFunctions.isoTime, 
});

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
 * Salva un evento nel registro di audit MongoDB (Local Audit Trail)
 * e lo logga su Stdout per l'inoltro a Splunk tramite Docker.
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
  details = {},
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
    details,
  };

  // 1. Salva su MongoDB (System of Record per l'applicazione)
  // L'await garantisce che l'azione sia registrata localmente
  await db.collection("audit_logs").insertOne(logDoc);

  // 2. Determina il sourcetype per Splunk
  const sourcetype = logDoc.action.startsWith("SPLUNK_")
    ? "zerotrust:splunk_internal"
    : logDoc.action === "ACCESS_REQUEST"
    ? "zerotrust:access"
    : "zerotrust:audit";

  // 3. Logga su Stdout in formato JSON strutturato
  // NIENTE PIÙ FETCH! Docker catturerà questo output e lo inoltrerà all'HEC
  logger.info({
    event: logDoc,
    sourcetype: sourcetype,
    source: "backend_node_pino"
  });
}