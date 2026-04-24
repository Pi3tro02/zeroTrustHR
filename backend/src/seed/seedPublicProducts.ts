import { getDb } from "../config/db";
import publicProducts from "./data/seedPublicProducts.json";

/**
 * Popola la collezione public_products con dati demo se vuota.
 */
export async function seedPublicProducts(): Promise<void> {
  const db = getDb();

  const existingProductsCount = await db.collection("public_products").countDocuments();

  if (existingProductsCount > 0) {
    console.log("public_products già popolata");
    return;
  }

  await db.collection("public_products").insertMany(publicProducts);
  console.log("Dati demo public_products inseriti");
}