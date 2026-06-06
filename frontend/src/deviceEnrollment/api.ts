export type HardwareKeyType = "tpm" | "secure_enclave" | "software";

const ENROLLMENT_BASE_URL = "https://localhost:10001";
const BACKEND_BASE_URL = "http://localhost:3000";

export async function createEnrollmentChallenge(params: {
    jwt: string;
    deviceName: string;
    deviceType: string;
    os: string;
    hardwareKeyType: HardwareKeyType;
}) {
    const response = await fetch(`${ENROLLMENT_BASE_URL}/api/devices/challenge`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${params.jwt}`,
        },
        body: JSON.stringify({
            device_name: params.deviceName,
            device_type: params.deviceType,
            os: params.os,
            hardware_key_type: params.hardwareKeyType,
        }),
    });

    const body = await response.json();

    if (!response.ok) {
        throw new Error(body.message ?? "Creazione challenge fallita");
    }

    return body as {
        message: string;
        device_id: string;
        certificate_san_uri: string;
        challenge: string;
        status: "pending";
    };
}

export async function enrollDevice(params: {
    jwt: string;
    deviceId: string;
    csrPem: string;
    publicKeyPem: string;
    challengeSignature?: string;
    ja3Fingerprint?: string;
}) {
    const response = await fetch(`${ENROLLMENT_BASE_URL}/api/devices/enroll`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${params.jwt}`,
        },
        body: JSON.stringify({
            device_id: params.deviceId,
            csr_pem: params.csrPem,
            public_key_pem: params.publicKeyPem,
            challenge_signature: params.challengeSignature,
            ja3_fingerprint: params.ja3Fingerprint
        }),
    });

    const body = await response.json();

    if (!response.ok) {
        throw new Error(body.message ?? "Enrollment fallito");
    }

    return body as {
        message: string;
        device_id: string;
        status: "pending";
    };
}

export async function approveDevice(params: {
    jwt: string;
    deviceId: string;
}) {
    const response = await fetch(
        `${BACKEND_BASE_URL}/api/devices/${params.deviceId}/approve`,
        {
            method: "POST",
            headers: {
                Authorization: `Bearer ${params.jwt}`,
            },
        },
    );

    const body = await response.json();

    if (!response.ok) {
        throw new Error(body.message ?? "Approvazione fallita");
    }

    return body as {
        message: string;
        device_id: string;
        certificate_pem: string;
    };
}
