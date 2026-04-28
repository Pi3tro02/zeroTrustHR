/**
 * backend/src/services/logService.ts  (versione aggiornata)
 *
 * Rispetto alla versione originale aggiunge:
 *  - invio asincrono a Splunk HEC (fire-and-forget, non blocca la request)
 *  - sourcetype differenziato per tipo di evento
 *  - fallback silenzioso se Splunk non è raggiungibile
 */

import { getDb } from "../config/db";
import { AuditLog, AuditOutcome } from "../types/auditLog";
import https from "https";

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

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

// ─── Splunk HEC ───────────────────────────────────────────────────────────────

/**
 * Invia un evento a Splunk HEC in modo asincrono (fire-and-forget).
 * Non solleva eccezioni: un log drop non deve mai bloccare la business logic.
 */
async function sendToSplunk(logDoc: AuditLog): Promise<void> {
  const hecUrl = process.env.SPLUNK_HEC_URL;
  const hecToken = process.env.SPLUNK_HEC_TOKEN;

  if (!hecUrl || !hecToken) return; // Splunk non configurato — skip silenzioso

  // Scegli sourcetype in base al tipo di azione
  const sourcetype = logDoc.action.startsWith("SPLUNK_")
    ? "zerotrust:splunk_internal"
    : logDoc.action === "ACCESS_REQUEST"
    ? "zerotrust:access"
    : "zerotrust:audit";

  const hecPayload = {
    time: Math.floor(new Date(logDoc.timestamp).getTime() / 1000),
    index: "zerotrust",
    sourcetype,
    source: "backend_node",
    event: {
      ...logDoc,
      // Assicura che timestamp sia stringa ISO per Splunk
      timestamp: new Date(logDoc.timestamp).toISOString(),
    },
  };

  try {
    const res = await fetch(hecUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Splunk ${hecToken}`,
      },
      body: JSON.stringify(hecPayload),
      signal: AbortSignal.timeout(3000), // timeout 3s
      // @ts-ignore
      agent: httpsAgent,
    });

    if (!res.ok) {
      console.warn(`[logService] Splunk HEC risposta non OK: ${res.status}`);
    }
  } catch (err) {
    // Non loggare su console in produzione per evitare loop
    if (process.env.NODE_ENV !== "production") {
      console.warn("[logService] Splunk HEC non raggiungibile:", (err as Error).message);
    }
  }
}

// ─── Funzione principale ──────────────────────────────────────────────────────

/**
 * Salva un evento nel registro di audit MongoDB
 * e lo inoltra a Splunk HEC in modo asincrono.
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

  // 1. Salva su MongoDB (await — la persistenza locale è obbligatoria)
  await db.collection("audit_logs").insertOne(logDoc);

  // 2. Invia a Splunk HEC (fire-and-forget — non await intenzionale)
  sendToSplunk(logDoc).catch(() => {});
}
