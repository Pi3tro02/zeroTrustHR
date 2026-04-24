import { getDb } from "../config/db";
import companyPolicies from "./data/seedCompanyPolicies.json";

/**
 * Popola la collezione company_policies con dati demo se vuota.
 */
export async function seedCompanyPolicies(): Promise<void> {
  const db = getDb();

  const existingPoliciesCount = await db.collection("company_policies").countDocuments();

  if (existingPoliciesCount > 0) {
    console.log("company_policies già popolata");
    return;
  }

  await db.collection("company_policies").insertMany(companyPolicies);
  console.log("Dati demo company_policies inseriti");
}