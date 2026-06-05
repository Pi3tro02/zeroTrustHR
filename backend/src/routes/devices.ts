// Endpoint HTTP
import { Router } from "express";
import { requireJwt } from "../middlewares/jwtMiddleware";
import { requireAdmin } from "../middlewares/adminGuard";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../services/deviceEnrollmentService";
import { syncTrustedDevicesToOpa } from "../services/opaDeviceSyncService";

const router = Router();

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

export default router;
