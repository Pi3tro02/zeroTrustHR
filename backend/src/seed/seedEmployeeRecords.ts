import { getDb } from "../config/db";
import employeeRecords from "./data/seedEmployeeRecords.json";

/**
 * Popola la collezione employee_records con dati demo se vuota.
 */
export async function seedEmployeeRecords(): Promise<void> {
  const db = getDb();

  const existingRecordsCount = await db.collection("employee_records").countDocuments();

  if (existingRecordsCount > 0) {
    console.log("employee_records già popolata");
    return;
  }

  await db.collection("employee_records").insertMany(employeeRecords);
  console.log("Dati demo employee_records inseriti");
}