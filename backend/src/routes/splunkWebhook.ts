/**
 * backend/src/routes/splunkWebhook.ts
 *
 * Endpoint ricevuto da Splunk quando BARAC_BlockUser_Webhook scatta.
 * Workflow:
 *  1. Verifica il segreto condiviso (X-Splunk-Webhook-Secret)
 *  2. Valida il payload JSON
 *  3. Aggiorna la blocklist in MongoDB (collection: blocked_users)
 *  4. Notifica OPA via PATCH /v1/data/authz/blocked_users
 *  5. Scrive un audit log dell'operazione
 *
 * Variabili d'ambiente necessarie:
 *   SPLUNK_WEBHOOK_SECRET   — segreto condiviso con Splunk
 *   OPA_URL                 — es. http://opa:8181
 */

import { Router, Request, Response } from "express";
import { getDb } from "../config/db";
import { logEvent } from "../services/logService";

const router = Router();

// ─── Tipi ────────────────────────────────────────────────────────────────────

interface SplunkWebhookPayload {
  action: "block_user" | "unblock_user";
  username: string;
  profit: number;
  total_risk: number;
  total_benefit: number;
  deny_count: number;
  block_reason: string;
  blocked_at: string;
  source: string;
}

interface BlockedUserDoc {
  username: string;
  blocked: boolean;
  profit_at_block: number;
  total_risk: number;
  total_benefit: number;
  deny_count: number;
  block_reason: string;
  blocked_at: Date;
  blocked_by: string;
  updated_at: Date;
}

// ─── Helper: aggiorna OPA data via REST API ──────────────────────────────────

async function updateOpaBlocklist(blockedUsernames: string[]): Promise<void> {
  const opaUrl = process.env.OPA_URL ?? "http://opa:8181";
  const endpoint = `${opaUrl}/v1/data/authz/blocked_users`;

  const response = await fetch(endpoint, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    //body: JSON.stringify({ data: blockedUsernames }),
    body: JSON.stringify(blockedUsernames),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`OPA update failed [${response.status}]: ${body}`);
  }
}

// ─── Helper: legge tutti gli utenti bloccati da MongoDB ─────────────────────

async function getBlockedUsernames(): Promise<string[]> {
  const db = getDb();
  const docs = await db
    .collection<BlockedUserDoc>("blocked_users")
    .find({ blocked: true })
    .project({ username: 1 })
    .toArray();
  return docs.map((d) => d.username);
}

// ─── Middleware: verifica segreto webhook ────────────────────────────────────

function verifyWebhookSecret(req: Request, res: Response, next: () => void): void {
  const secret = process.env.SPLUNK_WEBHOOK_SECRET ?? "changeme";
  const incoming = req.headers["x-splunk-webhook-secret"] as string | undefined;

  if (!incoming || incoming !== secret) {
    res.status(401).json({ error: "Unauthorized: invalid webhook secret" });
    return;
  }
  next();
}

// ─── POST /api/splunk-webhook ─────────────────────────────────────────────────

router.post("/", verifyWebhookSecret, async (req: Request, res: Response) => {
  const payload = req.body as SplunkWebhookPayload;

  // Validazione base
  if (!payload.username || !payload.action) {
    return res.status(400).json({ error: "Payload non valido: mancano username o action" });
  }

  if (payload.action !== "block_user") {
    return res.status(400).json({ error: `Azione non supportata: ${payload.action}` });
  }

  const db = getDb();

  try {
    // 1. Scrivi / aggiorna il documento in MongoDB
    await db.collection<BlockedUserDoc>("blocked_users").updateOne(
      { username: payload.username },
      {
        $set: {
          username: payload.username,
          blocked: true,
          profit_at_block: payload.profit,
          total_risk: payload.total_risk,
          total_benefit: payload.total_benefit,
          deny_count: payload.deny_count,
          block_reason: payload.block_reason,
          blocked_at: new Date(payload.blocked_at),
          blocked_by: "splunk_barac",
          updated_at: new Date(),
        },
      },
      { upsert: true }
    );

    // 2. Ricostruisci la lista completa e invia a OPA
    const allBlocked = await getBlockedUsernames();
    await updateOpaBlocklist(allBlocked);

    // 3. Audit log
    await logEvent({
      action: "SPLUNK_BLOCK_USER",
      resource_type: "user",
      resource_id: payload.username,
      outcome: "success",
      details: {
        profit: payload.profit,
        total_risk: payload.total_risk,
        deny_count: payload.deny_count,
        block_reason: payload.block_reason,
        opa_blocklist_size: allBlocked.length,
        source: payload.source,
      },
    });

    console.log(
      `[SplunkWebhook] Utente bloccato: ${payload.username} | profit=${payload.profit} | deny=${payload.deny_count}`
    );

    return res.status(200).json({
      message: "Utente bloccato con successo",
      username: payload.username,
      profit: payload.profit,
      opa_updated: true,
      blocklist_size: allBlocked.length,
    });
  } catch (err) {
    const error = err as Error;
    console.error("[SplunkWebhook] Errore:", error.message);

    await logEvent({
      action: "SPLUNK_BLOCK_USER",
      resource_type: "user",
      resource_id: payload.username,
      outcome: "failure",
      details: { error: error.message },
    }).catch(() => {});

    return res.status(500).json({ error: "Errore interno durante il blocco utente" });
  }
});

export default router;
