import { getDb } from "./db";
import { createPolicy } from "../models/policyModel";
import { createDevice } from "../models/deviceModel";
import { registerUser } from "../services/authService";
import { UserRole } from "../types/user";

interface SeedUser {
  username: string;
  password: string;
  role: UserRole;
  first_name: string;
  last_name: string;
  email: string;
  department: string;
}

const seedUsers: SeedUser[] = [
  {
    username: "alice_hr",
    password: "alice123",
    role: "hr",
    first_name: "Alice",
    last_name: "Rossi",
    email: "alice.hr@company.com",
    department: "HR"
  },
  {
    username: "marco_employee",
    password: "marco123",
    role: "employee",
    first_name: "Marco",
    last_name: "Bianchi",
    email: "marco.employee@company.com",
    department: "Finance"
  },
  {
    username: "demo_customer",
    password: "demo123",
    role: "customer",
    first_name: "Demo",
    last_name: "Customer",
    email: "demo.customer@company.com",
    department: "Customer"
  }
];

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

  let adminId = existingAdmin?._id.toString();

  if (!existingAdmin) {
    const insertedAdminId = await registerUser({
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

    adminId = insertedAdminId.toString();

    console.log("Utente admin iniziale creato");
  }

  if (adminId) {
    const existingDevice = await db.collection("devices").findOne({
      user_id: adminId,
      device_name: "Admin Laptop"
    });

    const hardwareBoundDevice = {
      device_id: "admin-laptop-001",
      hardware_key_type: "secure_enclave" as const,
      certificate_subject: "C=IT, ST=Italy, L=Ancona, O=ZeroTrustHR, OU=ClientDevice, CN=admin-laptop-001",
      certificate_san_uri: "urn:zerotrusthr:device:admin-laptop-001",
      trusted: true,
      status: "active" as const,
      updated_at: new Date()
    };

    if (!existingDevice) {
      const deviceDoc = createDevice({
        device_id: hardwareBoundDevice.device_id,
        user_id: adminId,
        device_name: "Admin Laptop",
        device_type: "laptop",
        os: "macOS",
        ip_address: "192.168.1.10",
        trusted: hardwareBoundDevice.trusted,
        hardware_key_type: hardwareBoundDevice.hardware_key_type,
        certificate_subject: hardwareBoundDevice.certificate_subject,
        certificate_san_uri: hardwareBoundDevice.certificate_san_uri,
        ja3_fingerprint: "sample_ja3_hash",
        status: hardwareBoundDevice.status
      });

      await db.collection("devices").insertOne(deviceDoc);
      console.log("Device iniziale creato");
    } else {
      await db.collection("devices").updateOne(
        { _id: existingDevice._id },
        { $set: hardwareBoundDevice }
      );
    }
  }

  for (const seedUser of seedUsers) {
    const existingUser = await db.collection("users").findOne({
      username: seedUser.username
    });

    if (!existingUser) {
      await registerUser({
        ...seedUser,
        mfa_enabled: true,
        created_by: "system"
      });

      console.log(`Utente seed creato: ${seedUser.username}`);
    }
  }

  console.log("Seed completato");
}
