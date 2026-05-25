import { Request, Response, NextFunction } from "express";
import { getDb } from "../config/db";

function extractDeviceIdFromXfcc(xfcc: string): string | null {
    const uriMatch = xfcc.match(/URI="?([^";,]+)"?/);

    if (!uriMatch || !uriMatch[1]) {
        return null;
    }

    const uri = decodeURIComponent(uriMatch[1]);
    const prefix = "urn:zerotrusthr:device:";

    if (!uri.startsWith(prefix)) {
        return null;
    }

    return uri.slice(prefix.length);
}

export async function requireTrustedDevice(req: Request, res: Response, next: NextFunction) {
    try {
        const xfcc = req.headers["x-forwarded-client-cert"];

        if (!xfcc || typeof xfcc !== "string") {
            return res.status(403).json({
                error: "Missing client certificate information"
            });
        }

        const deviceId = extractDeviceIdFromXfcc(xfcc);

        if (!deviceId) {
            return res.status(403).json({
                error: "Missing device identity"
            });
        }

        const db = getDb();

        const device = await db.collection("devices").findOneAndUpdate({
            device_id: deviceId,
            trusted: true,
            status: "active",
            hardware_key_type: { $in: ["tpm", "secure_enclave", "android_keystore"] }
        }, {
            $set: {
                last_seen: new Date(),
                updated_at: new Date()
            }
        }, {
            returnDocument: "after"
        });

        if (!device) {
            return res.status(403).json({
                error: "Untrusted, inactive, or non hardware-bound device"
            });
        }

        (req as any).device = device;

        next();
    } catch (error) {
        return res.status(500).json({
            error: "Device authentication failed"
        });
    }
}
