import { Router } from "express";
import { ObjectId } from "mongodb";
import { getDb } from "../config/db";
import { evaluateAccess } from "../services/accessService";
import { User } from "../types/user";
import { Device } from "../types/device";
import { AccessAction, NetworkZone } from "../types/accessRequest";

const router = Router();

type UserDocument = User & { _id: ObjectId };
type DeviceDocument = Device & { _id: ObjectId };

interface EvaluateAccessBody {
  username?: string;
  device_name?: string;
  resource_name?: string;
  action?: AccessAction;
  source_ip?: string;
  network_zone?: NetworkZone;
  mfa_verified?: boolean;
}

/**
 * Route di test rapido con valori fissi.
 */
router.get("/test", async (_req, res) => {
  try {
    const db = getDb();

    const user = await db.collection<UserDocument>("users").findOne({
      username: "admin"
    });

    if (!user) {
      return res.status(404).json({
        message: "Utente admin non trovato"
      });
    }

    const device = await db.collection<DeviceDocument>("devices").findOne({
      user_id: user._id.toString(),
      device_name: "Admin Laptop"
    });

    if (!device) {
      return res.status(404).json({
        message: "Device admin non trovato"
      });
    }

    const result = await evaluateAccess({
      user,
      device,
      resource_name: "employee_records",
      action: "read",
      source_ip: "192.168.1.10",
      network_zone: "internal",
      mfa_verified: true
    });

    return res.status(200).json({
      message: "Valutazione accesso completata",
      username: user.username,
      device_name: device.device_name,
      resource_name: "employee_records",
      action: "read",
      decision: result.decision,
      reason: result.reason
    });
  } catch (error) {
    console.error("Errore nella route /api/access/test:", error);

    return res.status(500).json({
      message: "Errore interno durante il test di accesso"
    });
  }
});

/**
 * Route dinamica per valutare una richiesta di accesso.
 */
router.post("/evaluate", async (req, res) => {
  try {
    const {
      username,
      device_name,
      resource_name,
      action,
      source_ip,
      network_zone = "unknown",
      mfa_verified = false
    } = req.body as EvaluateAccessBody;

    if (!username || !device_name || !resource_name || !action) {
      return res.status(400).json({
        message: "Campi obbligatori mancanti",
        required_fields: ["username", "device_name", "resource_name", "action"]
      });
    }

    const allowedActions: AccessAction[] = ["read", "write", "update", "delete"];
    if (!allowedActions.includes(action)) {
      return res.status(400).json({
        message: "Valore action non valido",
        allowed_values: allowedActions
      });
    }

    const allowedNetworkZones: NetworkZone[] = ["internal", "vpn", "external", "unknown"];
    if (!allowedNetworkZones.includes(network_zone)) {
      return res.status(400).json({
        message: "Valore network_zone non valido",
        allowed_values: allowedNetworkZones
      });
    }

    const db = getDb();

    const user = await db.collection<UserDocument>("users").findOne({
      username
    });

    if (!user) {
      return res.status(404).json({
        message: "Utente non trovato",
        username
      });
    }

    const device = await db.collection<DeviceDocument>("devices").findOne({
      user_id: user._id.toString(),
      device_name
    });

    if (!device) {
      return res.status(404).json({
        message: "Device non trovato per l'utente specificato",
        username,
        device_name
      });
    }

    const result = await evaluateAccess({
      user,
      device,
      resource_name,
      action,
      source_ip,
      network_zone,
      mfa_verified
    });

    return res.status(200).json({
      message: "Valutazione accesso completata",
      username: user.username,
      role: user.role,
      device_name: device.device_name,
      device_status: device.status,
      device_trusted: device.trusted,
      resource_name,
      action,
      network_zone,
      mfa_verified,
      decision: result.decision,
      reason: result.reason
    });
  } catch (error) {
    console.error("Errore nella route /api/access/evaluate:", error);

    return res.status(500).json({
      message: "Errore interno durante la valutazione di accesso"
    });
  }
});

export default router;