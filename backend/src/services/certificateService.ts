export async function signDeviceCsr({
    csrPem,
    deviceId,
    sanUri,
    publicKeyPem
}: {
    csrPem: string;
    deviceId: string;
    sanUri: string;
    publicKeyPem: string;
}): Promise<string> {
    const caServiceUrl = process.env.CA_SERVICE_URL ?? "http://ca:4000";
    const caServiceToken = process.env.CA_SERVICE_TOKEN ?? "dev-ca-token";

    const response = await fetch(`${caServiceUrl}/sign`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "x-ca-service-token": caServiceToken
        },
        body: JSON.stringify({
            csr_pem: csrPem,
            device_id: deviceId,
            san_uri: sanUri,
            public_key_pem: publicKeyPem
        })
    });

    const body = await response.json().catch(() => ({}));

    if (!response.ok || typeof body.certificate_pem !== "string") {
        throw new Error(
            `Errore firma CSR dal servizio CA: ${response.status} ${body.message ?? ""}`.trim()
        );
    }

    return body.certificate_pem;
}
