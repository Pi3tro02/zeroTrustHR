import dotenv from "dotenv";
import app from "./app";
import { connectToMongo } from "./config/db";
import { initDb } from "./config/initDb";
import { seedData } from "./config/seedData";

dotenv.config();

const PORT = process.env.PORT || 3000;

/**
 * Avvia il server solo dopo aver stabilito la connessione al database,
 * inizializzato gli indici e popolato i dati iniziali.
 */
async function startServer(): Promise<void> {
  try {
    await connectToMongo();
    await initDb();
    await seedData();

    app.listen(PORT, () => {
      console.log(`Server avviato sulla porta ${PORT}`);
    });
  } catch (error) {
    console.error("Impossibile avviare il server:", error);
    process.exit(1);
  }
}

startServer();