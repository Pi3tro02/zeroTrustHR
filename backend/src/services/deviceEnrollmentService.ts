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

function normalizePemInput(value: string) {
    return value
        .trim()
        .replace(/^"|"$/g, "")
        .replace(/\\r\\n/g, "\n")
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\n")
        .replace(/\\\//g, "/")
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n")
        .trim();
}

function normalizeBase64Input(value: string) {
    return value
        .trim()
        .replace(/^"|"$/g, "")
        .replace(/\\\//g, "/")
        .replace(/\s/g, "");
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
    console.log("[Device Enrollment] enroll start", {
        device_id: body?.device_id,
        has_csr_pem: Boolean(body?.csr_pem),
        has_public_key_pem: Boolean(body?.public_key_pem),
        has_challenge_signature: Boolean(body?.challenge_signature),
        has_ja3_fingerprint: Boolean(body?.ja3_fingerprint)
    });

    if (
      !body?.device_id ||
      !body?.csr_pem ||
      !body?.public_key_pem
    ) {
      throw new Error("Campi obbligatori mancanti per enrollment device");
    }

    const normalizedCsrPem = normalizePemInput(body.csr_pem);
    const normalizedPublicKeyPem = normalizePemInput(body.public_key_pem);
    const normalizedChallengeSignature = body.challenge_signature
        ? normalizeBase64Input(body.challenge_signature)
        : undefined;
  
    const db = getDb();
  
    console.log("[Device Enrollment] looking for pending device", {
        device_id: body.device_id
    });

    const device = await db.collection("devices").findOne({
      device_id: body.device_id,
      status: "pending"
    });
  
    if (!device) {
      throw new Error("Device pending non trovato");
    }

    const hardwareKeyType = device.hardware_key_type as HardwareKeyType;
    console.log("[Device Enrollment] pending device found", {
        device_id: body.device_id,
        hardware_key_type: hardwareKeyType,
        has_challenge: Boolean(device.enrollment_challenge),
        has_challenge_expires_at: Boolean(device.challenge_expires_at),
        has_certificate_san_uri: Boolean(device.certificate_san_uri)
    });
  
    if (isHardwareBound(hardwareKeyType)) {
        if (!normalizedChallengeSignature) {
            throw new Error("Firma challenge obbligatoria per device hardware-bound");
        }

        if (!device.enrollment_challenge || !device.challenge_expires_at) {
            throw new Error("Challenge enrollment assente");
          }
        
          if (new Date(device.challenge_expires_at).getTime() < Date.now()) {
            throw new Error("Challenge enrollment scaduta");
          }
        
          console.log("[Device Enrollment] verifying hardware challenge signature", {
            device_id: body.device_id
          });

          const signatureOk = verifyHardwareChallengeSignature({
            publicKeyPem: normalizedPublicKeyPem,
            challenge: device.enrollment_challenge,
            signatureBase64: normalizedChallengeSignature
          });

          console.log("[Device Enrollment] hardware challenge signature verified", {
            device_id: body.device_id,
            signature_ok: signatureOk
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
  
    console.log("[Device Enrollment] saving CSR and public key", {
        device_id: body.device_id
    });

    await db.collection("devices").updateOne(
        { device_id: body.device_id },
        {
            $set: {
                csr_pem: normalizedCsrPem,
                public_key_pem: normalizedPublicKeyPem,
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

    console.log("[Device Enrollment] enrollment saved", {
        device_id: body.device_id
    });
  
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
