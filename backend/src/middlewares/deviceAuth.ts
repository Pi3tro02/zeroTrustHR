import { Request, Response, NextFunction } from "express";
import { getDb } from "../config/db";

function extractDeviceIdFromXfcc(xfcc: string): string | null {
    const uriMatch = xfcc.match(/URI="?([^";,]+)"?/);

    if (!uriMatch || !uriMatch[1]) {
        return null;
    }

    return decodeURIComponent(uriMatch[1]);
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

        const device = await db.collection("devices").findOne({
            device_id: deviceId,
            trusted: true,
            status: "active"
        });

        if (!device) {
            return res.status(403).json({
                error: "Untrusted or inactive device"
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
