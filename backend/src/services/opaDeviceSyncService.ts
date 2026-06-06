// Sync dinamico verso OPA
import { getDb } from "../config/db";

export async function syncTrustedDevicesToOpa(): Promise<void> {
    const db = getDb();

    const trustedDevices = await db.collection("devices").find({
        trusted: true,
        status: "active",
        hardware_key_type: { $in: ["tpm", "secure_enclave", "software"]}
    }).project({
        _id: 0,
        device_id: 1,
        certificate_san_uri: 1,
        hardware_key_type: 1,
        trusted: 1,
        status: 1,
        os: 1,
        ip_address: 1,
        ja3_fingerprint: 1
    }).toArray();

    const opaUrl = process.env.OPA_URL ?? "http://opa:8181";

    const response = await fetch(`${opaUrl}/v1/data/trusted_devices`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(trustedDevices)
    });

    if (!response.ok) {
        throw new Error(`Errore sync device verso OPA: ${response.status}`);
    }
}
