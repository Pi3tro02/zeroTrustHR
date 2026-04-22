import express from "express";
import cors from "cors";
import { getDb } from "./config/db";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/api/health", (_req, res) => {
  res.status(200).json({ message: "Backend attivo" });
});

/**
 * Route di test per verificare la connessione a MongoDB.
 */
app.get("/api/db-test", async (_req, res) => {
  try {
    const db = getDb();
    const result = await db.command({ ping: 1 });

    res.status(200).json({
      message: "Connessione a MongoDB attiva",
      mongoResponse: result
    });
  } catch (error) {
    console.error("Errore nel test MongoDB:", error);

    res.status(500).json({
      message: "Errore nella connessione a MongoDB"
    });
  }
});

export default app;