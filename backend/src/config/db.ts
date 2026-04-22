import { MongoClient, Db } from "mongodb";

const mongoUri = process.env.MONGO_URI || "mongodb://localhost:27017";
const dbName = process.env.DB_NAME || "zerotrusthr";

let client: MongoClient;
let database: Db;

/**
 * Inizializza la connessione a MongoDB e salva il riferimento al database.
 */
export async function connectToMongo(): Promise<Db> {
  try {
    client = new MongoClient(mongoUri);
    await client.connect();

    database = client.db(dbName);

    await database.command({ ping: 1 });
    console.log("Connessione a MongoDB riuscita");

    return database;
  } catch (error) {
    console.error("Errore di connessione a MongoDB:", error);
    throw error;
  }
}

/**
 * Restituisce l'istanza del database già inizializzata.
 */
export function getDb(): Db {
  if (!database) {
    throw new Error("Database non inizializzato. Chiama prima connectToMongo().");
  }

  return database;
}

/**
 * Chiude la connessione al client MongoDB.
 */
export async function closeMongoConnection(): Promise<void> {
  if (client) {
    await client.close();
    console.log("Connessione a MongoDB chiusa");
  }
}