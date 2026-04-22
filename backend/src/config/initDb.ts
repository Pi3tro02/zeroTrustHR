import { getDb } from "./db";

/**
 * Crea gli indici principali del database.
 */
export async function initDb(): Promise<void> {
  const db = getDb();

  await db.collection("users").createIndex({ username: 1 }, { unique: true });
  await db.collection("users").createIndex({ email: 1 }, { unique: true });

  await db.collection("devices").createIndex({ user_id: 1 });
  await db.collection("devices").createIndex({ trusted: 1 });

  await db.collection("access_policies").createIndex({ policy_name: 1 }, { unique: true });
  await db.collection("access_policies").createIndex({ resource_name: 1 });

  await db.collection("audit_logs").createIndex({ timestamp: 1 });
  await db.collection("audit_logs").createIndex({ user_id: 1 });
  await db.collection("audit_logs").createIndex({ event_type: 1 });

  await db.collection("access_requests").createIndex({ user_id: 1 });
  await db.collection("access_requests").createIndex({ resource_name: 1 });
  await db.collection("access_requests").createIndex({ request_time: 1 });

  console.log("Database inizializzato correttamente");
}