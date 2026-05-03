// zeroTrustHR/backend/src/server.ts

import dotenv from "dotenv";
import app from "./app";
import { connectToMongo, getDb } from "./config/db"; // Aggiunto getDb
import { initDb } from "./config/initDb";
import { seedData } from "./config/seedData";
import { seedResourceData } from "./seed";

dotenv.config();

const PORT = process.env.PORT || 3000;

/**
 * Funzione per riallineare lo stato di OPA con il Database all'avvio
 */
async function syncOpaBlocklistOnStartup(): Promise<void> {
  try {
    const db = getDb();
    // Estraiamo solo gli utenti attivamente bloccati
    const docs = await db.collection("blocked_users").find({ blocked: true }).project({ username: 1 }).toArray();
    const blockedUsernames = docs.map(d => d.username);

    const opaUrl = process.env.OPA_URL ?? "http://opa:8181";
    const response = await fetch(`${opaUrl}/v1/data/authz/blocked_users`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(blockedUsernames),
    });

    if (response.ok) {
      console.log(`[OPA Sync] Blocklist sincronizzata con successo. Utenti bloccati: ${blockedUsernames.length}`);
    } else {
      console.error(`[OPA Sync] Errore HTTP da OPA: ${response.status}`);
    }
  } catch (error) {
    console.error("[OPA Sync] Impossibile contattare OPA all'avvio:", (error as Error).message);
  }
}

async function startServer(): Promise<void> {
  try {
    await connectToMongo();
    await initDb();
    await seedData();
    await seedResourceData();
    
    // Sincronizziamo OPA prima di accettare richieste
    await syncOpaBlocklistOnStartup();

    app.listen(PORT, () => {
      console.log(`Server avviato sulla porta ${PORT}`);
    });
  } catch (error) {
    console.error("Impossibile avviare il server:", error);
    process.exit(1);
  }
}

startServer();