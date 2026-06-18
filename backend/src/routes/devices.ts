// Endpoint HTTP
import { Router } from "express";
import { Filter, ObjectId } from "mongodb";
import { getDb } from "../config/db";
import { requireJwt } from "../middlewares/jwtMiddleware";
import { requireAdmin } from "../middlewares/adminGuard";
import { approveDevice, createEnrollmentChallenge, enrollDevice, rejectDevice, revokeDevice } from "../services/deviceEnrollmentService";
import { syncTrustedDevicesToOpa } from "../services/opaDeviceSyncService";
import { Device, DeviceStatus } from "../types/device";

const router = Router();

type DeviceDocument = Device & { _id: ObjectId };

const allowedDeviceStatuses: DeviceStatus[] = ["pending", "active", "suspended", "revoked"];

function sanitizeDevice(device: DeviceDocument) {
  return {
    id: device._id.toString(),
    device_id: device.device_id,
    user_id: device.user_id,
    device_name: device.device_name,
    device_type: device.device_type,
    os: device.os,
    ip_address: device.ip_address,
    trusted: device.trusted,
    hardware_key_type: device.hardware_key_type,
    certificate_subject: device.certificate_subject,
    certificate_san_uri: device.certificate_san_uri,
    ja3_fingerprint: device.ja3_fingerprint,
    status: device.status,
    last_seen: device.last_seen,
    created_at: device.created_at,
    updated_at: device.updated_at
  };
}

router.get("/me", requireJwt, async (req, res) => {
  const userId = req.headers["x-user"];

  if (!userId || typeof userId !== "string") {
    return res.status(401).json({
      message: "Token JWT non valido: user mancante"
    });
  }

  try {
    const db = getDb();
    const devices = await db.collection<DeviceDocument>("devices")
      .find({ user_id: userId })
      .sort({ updated_at: -1 })
      .toArray();

    return res.status(200).json({
      devices: devices.map(sanitizeDevice)
    });
  } catch (error) {
    return res.status(500).json({
      message: "Errore durante il recupero dei device dell'utente"
    });
  }
});

router.get("/", requireJwt, requireAdmin, async (req, res) => {
  const { status } = req.query;

  if (status && typeof status !== "string") {
    return res.status(400).json({
      message: "Parametro status non valido"
    });
  }

  if (status && !allowedDeviceStatuses.includes(status as DeviceStatus)) {
    return res.status(400).json({
      message: "Valore status non valido",
      allowed_values: allowedDeviceStatuses
    });
  }

  try {
    const db = getDb();
    const filter: Filter<DeviceDocument> = status
      ? { status: status as DeviceStatus }
      : {};
    const devices = await db.collection<DeviceDocument>("devices")
      .find(filter)
      .sort({ updated_at: -1 })
      .toArray();

    return res.status(200).json({
      devices: devices.map(sanitizeDevice)
    });
  } catch (error) {
    return res.status(500).json({
      message: "Errore durante il recupero dei device"
    });
  }
});

router.post("/challenge", requireJwt, async (req, res) => {
    try {
        const result = await createEnrollmentChallenge({
            user: req.headers["x-user"] as string,
            body: req.body
        });

        return res.status(201).json(result);
    } catch (error) {
        return res.status(400).json({
            message: (error as Error).message
        });
    }
});

router.post("/enroll", requireJwt, async (req, res) => {
    try {
        const result = await enrollDevice({
            body: req.body
        });

        return res.status(202).json(result);
    } catch (error) {
        return res.status(400).json({
            message: (error as Error).message
        });
    }
});

router.post("/sync-opa", requireJwt, requireAdmin, async (_req, res) => {
  try {
    await syncTrustedDevicesToOpa();

    return res.status(200).json({
      message: "Trusted devices sincronizzati verso OPA"
    });
  } catch (error) {
    return res.status(500).json({
      message: (error as Error).message
    });
  }
});

router.post("/:deviceId/approve", requireJwt, requireAdmin, async (req, res) => {
  const { deviceId } = req.params;

  if (!deviceId || Array.isArray(deviceId)) {
    return res.status(400).json({
      message: "deviceId non valido"
    });
  }

  try {
    const result = await approveDevice(deviceId);

    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json({
      message: (error as Error).message
    });
  }
});

router.post("/:deviceId/reject", requireJwt, requireAdmin, async (req, res) => {
  const { deviceId } = req.params;

  if (!deviceId || Array.isArray(deviceId)) {
    return res.status(400).json({
      message: "deviceId non valido"
    });
  }

  try {
    const result = await rejectDevice(deviceId);

    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json({
      message: (error as Error).message
    });
  }
});

router.post("/:deviceId/revoke", requireJwt, requireAdmin, async (req, res) => {
  const { deviceId } = req.params;

  if (!deviceId || Array.isArray(deviceId)) {
    return res.status(400).json({
      message: "deviceId non valido"
    });
  }

  try {
    const result = await revokeDevice(deviceId);

    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json({
      message: (error as Error).message
    });
  }
});

export default router;
