import { seedEmployeeRecords } from "./seedEmployeeRecords";
import { seedCompanyPolicies } from "./seedCompanyPolicies";
import { seedPublicProducts } from "./seedPublicProducts";

/**
 * Popola le collezioni demo delle risorse applicative.
 */
export async function seedResourceData(): Promise<void> {
  await seedEmployeeRecords();
  await seedCompanyPolicies();
  await seedPublicProducts();
}