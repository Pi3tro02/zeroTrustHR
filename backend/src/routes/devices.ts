// Endpoint HTTP
import { Router } from "express";
import { requireJwt } from "../middlewares/jwtMiddleware";
import { enrollDevice, approveDevice } from "../services/deviceEnrollmentService";

const router = Router();

router.post("/enroll", requireJwt, async (req, res) => {
    try {
        const result = await enrollDevice({
            user: req.headers["x-user"] as string,
            body: req.body
        });

        return res.status(202).json(result);
    } catch (error) {
        return res.status(400).json({
            message: (error as Error).message
        });
    }
});

router.post("/:deviceId/approve", requireJwt, async (req, res) => {
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
