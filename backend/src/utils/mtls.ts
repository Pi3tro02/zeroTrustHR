import { Request } from "express";

export interface MtlsInfo {
    enabled: boolean;
    subject?: string;
    clientCert?: string;
}

export function getMtlsInfo(req: Request): MtlsInfo {
    const subject = req.header("x-mtls-subject");
    const clientCert = req.header("x-mtls-client-cert");

    return {
        enabled: Boolean(subject || clientCert),
        subject,
        clientCert
    };
}
