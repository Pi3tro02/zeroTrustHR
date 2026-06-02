// Registra device, approva device, firma CSR, aggiorna Mongo, sincronizza OPA
import { randomUUID } from "crypto";
import { getDb } from "../config/db";
import { createDevice } from "../models/deviceModel";
import { signDeviceCsr } from "./certificateService";
import { syncTrustedDevicesToOpa } from "./opaDeviceSyncService";
import { DeviceType, HardwareKeyType } from "../types/device";

const allowedDeviceTypes: DeviceType[] = ["laptop", "desktop", "smartphone", "tablet", "server", "other"];
const allowedHardwareKeyTypes: HardwareKeyType[] = ["tpm", "secure_enclave", "android_keystore"];

export async function enrollDevice({
    user, 
    body
}: {
    user: string;
    body: any;
}) {
    if (
        !body?.device_name ||
        !body?.device_type ||
        !body?.os ||
        !body?.csr_pem ||
        !body?.hardware_key_type
    ) {
        throw new Error("Campi obbligatori mancanti per enrollment device");
    }

    if (!allowedDeviceTypes.includes(body.device_type)) {
        throw new Error("device_type non valido");
    }

    if (!allowedHardwareKeyTypes.includes(body.hardware_key_type)) {
        throw new Error("hardware_key_type non valido o non hardware-backed");
    }

    const db = getDb();
    const deviceId = randomUUID();
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
        certificate_san_uri: sanUri,
        status: "pending"
    });

    await db.collection("devices").insertOne({
        ...deviceDoc,
        csr_pem: body.csr_pem
    });

    return {
        message: "Device enrollment richiesto",
        device_id: deviceId,
        certificate_san_uri: sanUri,
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

    const certificatePem = await signDeviceCsr({
        csrPem: device.csr_pem,
        deviceId,
        sanUri: device.certificate_san_uri
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
