import { getDb } from "./db";
import { createPolicy } from "../models/policyModel";
import { createDevice } from "../models/deviceModel";
import { registerUser } from "../services/authService";

/**
 * Popola il database con dati iniziali se mancanti.
 */
export async function seedData(): Promise<void> {
  const db = getDb();

  const existingPolicy = await db.collection("access_policies").findOne({
    policy_name: "HR records policy"
  });

  if (!existingPolicy) {
    const policyDoc = createPolicy({
      policy_name: "HR records policy",
      resource_name: "employee_records",
      resource_sensitivity: "critical",
      allowed_roles: ["hr", "admin"],
      allowed_actions: ["read", "update"],
      max_risk_score: 25,
      conditions: {
        mfa_required: true,
        trusted_device_required: true,
        require_known_device: true,
        allowed_network_zones: ["internal", "vpn"]
      },
      created_by: "system"
    });

    await db.collection("access_policies").insertOne(policyDoc);
    console.log("Policy iniziale creata");
  }

  const existingAdmin = await db.collection("users").findOne({
    username: "admin"
  });

  if (!existingAdmin) {
    const adminId = await registerUser({
      username: "admin",
      password: "admin123",
      role: "admin",
      first_name: "Pietro",
      last_name: "Salvatore",
      email: "admin@company.com",
      department: "IT",
      mfa_enabled: true,
      created_by: "system"
    });

    const existingDevice = await db.collection("devices").findOne({
      user_id: adminId.toString(),
      device_name: "Admin Laptop"
    });

    if (!existingDevice) {
      const deviceDoc = createDevice({
        user_id: adminId.toString(),
        device_name: "Admin Laptop",
        device_type: "laptop",
        os: "macOS",
        ip_address: "192.168.1.10",
        trusted: true,
        ja3_fingerprint: "sample_ja3_hash",
        status: "active"
      });

      await db.collection("devices").insertOne(deviceDoc);
      console.log("Device iniziale creato");
    }

    console.log("Utente admin iniziale creato");
  }

  console.log("Seed completato");
}