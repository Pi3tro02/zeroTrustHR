import { Router } from "express";
import { getDb } from "../config/db";

const router = Router();

/**
 * Verifica che il backend sia attivo.
 */
router.get("/", (_req, res) => {
  return res.status(200).json({ message: "Backend attivo" });
});

/**
 * Verifica che MongoDB sia raggiungibile.
 */
router.get("/db-test", async (_req, res) => {
  try {
    const db = getDb();
    const result = await db.command({ ping: 1 });

    return res.status(200).json({
      message: "Connessione a MongoDB attiva",
      mongoResponse: result
    });
  } catch (error) {
    console.error("Errore nel test MongoDB:", error);

    return res.status(500).json({
      message: "Errore nella connessione a MongoDB"
    });
  }
});

export default router;