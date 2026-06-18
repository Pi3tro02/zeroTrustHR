// Registra device, approva device, firma CSR, aggiorna Mongo, sincronizza OPA
import { createVerify, randomBytes, randomUUID } from "crypto";
import { getDb } from "../config/db";
import { createDevice } from "../models/deviceModel";
import { signDeviceCsr } from "./certificateService";
import { syncTrustedDevicesToOpa } from "./opaDeviceSyncService";
import { DeviceType, HardwareKeyType } from "../types/device";

const allowedDeviceTypes: DeviceType[] = ["laptop", "desktop", "smartphone", "tablet", "server", "other"];
const allowedHardwareKeyTypes: HardwareKeyType[] = ["tpm", "secure_enclave", "software"];

function verifyHardwareChallengeSignature(params: {
    publicKeyPem: string;
    challenge: string;
    signatureBase64: string;
}) {
    const verifier = createVerify("sha256");
    verifier.update(params.challenge);
    verifier.end();

    return verifier.verify(
        params.publicKeyPem,
        Buffer.from(params.signatureBase64, "base64")
    );
}

function isHardwareBound(type: HardwareKeyType) {
    return type === "tpm" || type === "secure_enclave";
}

function isSoftwareFallback(type: HardwareKeyType) {
    return type === "software";
}

export async function createEnrollmentChallenge({
    user,
    body
}: {
    user: string;
    body: any;
}) {
    if (!body?.device_name || !body?.device_type || !body?.os || !body?.hardware_key_type) {
        throw new Error("Campi obbligatori mancanti per challenge enrollment");
    }

    if (!allowedDeviceTypes.includes(body.device_type)) {
        throw new Error("device_type non valido");
    }

    if (!allowedHardwareKeyTypes.includes(body.hardware_key_type)) {
        throw new Error("hardware_key_type non valido o non richiesto");
    }

    const db = getDb();
    const deviceId = randomUUID();
    const challenge = randomBytes(32).toString("base64url");
    const sanUri = `urn:zerotrusthr:device:${deviceId}`;

    const deviceDoc = createDevice({
        device_id: deviceId,
        user_id: user,
        device_name: body.device_name,
        device_type: body.device_type,
        os: body.os,
        ip_address: body.ip_address,
        trusted: false,
        hardware_key_type: body.hardware_key_type,
        enrollment_challenge: challenge,
        challenge_expires_at: new Date(Date.now() + 5 * 60 * 1000),
        certificate_san_uri: sanUri,
        status: "pending"
    });

    await db.collection("devices").insertOne(deviceDoc);

    return {
        device_id: deviceId,
        certificate_san_uri: sanUri,
        challenge,
        status: "pending"
    };
}

export async function enrollDevice({ body }: { body: any }) {
    if (
      !body?.device_id ||
      !body?.csr_pem ||
      !body?.public_key_pem
    ) {
      throw new Error("Campi obbligatori mancanti per enrollment device");
    }
  
    const db = getDb();
  
    const device = await db.collection("devices").findOne({
      device_id: body.device_id,
      status: "pending"
    });
  
    if (!device) {
      throw new Error("Device pending non trovato");
    }

    const hardwareKeyType = device.hardware_key_type as HardwareKeyType;
  
    if (isHardwareBound(hardwareKeyType)) {
        if (!body?.challenge_signature) {
            throw new Error("Firma challenge obbligatoria per device hardware-bound");
        }

        if (!device.enrollment_challenge || !device.challenge_expires_at) {
            throw new Error("Challenge enrollment assente");
          }
        
          if (new Date(device.challenge_expires_at).getTime() < Date.now()) {
            throw new Error("Challenge enrollment scaduta");
          }
        
          const signatureOk = verifyHardwareChallengeSignature({
            publicKeyPem: body.public_key_pem,
            challenge: device.enrollment_challenge,
            signatureBase64: body.challenge_signature
          });
        
          if (!signatureOk) {
            throw new Error("Firma challenge non valida");
          }
    }

    if (isSoftwareFallback(hardwareKeyType)) {
        if (!body?.ja3_fingerprint) {
            throw new Error("JA3 fingerprint obbligatorio per fallback software");
        }
    } 
  
    await db.collection("devices").updateOne(
        { device_id: body.device_id },
        {
            $set: {
                csr_pem: body.csr_pem,
                public_key_pem: body.public_key_pem,
                ja3_fingerprint: isSoftwareFallback(hardwareKeyType)
                    ? body.ja3_fingerprint
                    : device.ja3_fingerprint,
                challenge_verified_at: isHardwareBound(hardwareKeyType)
                    ? new Date()
                    : null,
                updated_at: new Date()
            },
            $unset: {
                enrollment_challenge: "",
                challenge_expires_at: ""
            }
        }
    );
  
    return {
      message: "Device enrollment verificato",
      device_id: body.device_id,
      status: "pending"
    };
  }

export async function approveDevice(deviceId: string) {
    const db = getDb();

    const device = await db.collection("devices").findOne({
        device_id: deviceId
    });

    if (!device) {
        throw new Error("Device non trovato");
    }

    if (device.status === "active" && device.certificate_pem) {
        return {
            message: "Device già approvato",
            device_id: deviceId,
            certificate_pem: device.certificate_pem
        };
    }

    if (device.status !== "pending") {
        throw new Error(`Device non approvabile nello stato corrente: ${device.status}`);
    }

    if (!device.csr_pem || !device.certificate_san_uri) {
        throw new Error("Device pending privo di CSR o SAN URI");
    }

    const hardwareKeyType = device.hardware_key_type as HardwareKeyType;

    if (isHardwareBound(hardwareKeyType) && !device.challenge_verified_at) {
        throw new Error("Challenge hardware non verificata");
    }

    if (isSoftwareFallback(hardwareKeyType) && !device.ja3_fingerprint) {
        throw new Error("JA3 fingerprint mancante per fallback software");
    }

    if (!device.public_key_pem) {
        throw new Error("Public key device mancante");
    }

    const certificatePem = await signDeviceCsr({
        csrPem: device.csr_pem,
        deviceId,
        sanUri: device.certificate_san_uri,
        publicKeyPem: device.public_key_pem
    });

    await db.collection("devices").updateOne(
        { device_id: deviceId },
        {
            $set: {
                trusted: true,
                status: "active",
                certificate_pem: certificatePem,
                updated_at: new Date()
            }
        }
    );

    await syncTrustedDevicesToOpa();

    return {
        message: "Device approvato",
        device_id: deviceId,
        certificate_pem: certificatePem
    };
}

export async function rejectDevice(deviceId: string) {
    const db = getDb();

    const device = await db.collection("devices").findOne({
        device_id: deviceId
    });

    if (!device) {
        throw new Error("Device non trovato");
    }

    if (device.status !== "pending") {
        throw new Error(`Device non rifiutabile nello stato corrente: ${device.status}`);
    }

    await db.collection("devices").updateOne(
        { device_id: deviceId },
        {
            $set: {
                trusted: false,
                status: "suspended",
                updated_at: new Date()
            },
            $unset: {
                enrollment_challenge: "",
                challenge_expires_at: ""
            }
        }
    );

    return {
        message: "Device rifiutato",
        device_id: deviceId,
        status: "suspended"
    };
}

export async function revokeDevice(deviceId: string) {
    const db = getDb();

    const device = await db.collection("devices").findOne({
        device_id: deviceId
    });

    if (!device) {
        throw new Error("Device non trovato");
    }

    if (device.status !== "active") {
        throw new Error(`Device non revocabile nello stato corrente: ${device.status}`);
    }

    await db.collection("devices").updateOne(
        { device_id: deviceId },
        {
            $set: {
                trusted: false,
                status: "revoked",
                updated_at: new Date()
            }
        }
    );

    await syncTrustedDevicesToOpa();

    return {
        message: "Device revocato",
        device_id: deviceId,
        status: "revoked"
    };
}
