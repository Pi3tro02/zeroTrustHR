import { Router, Request, Response } from "express";
import { getDb } from "../config/db";

const router = Router();

/**
 * Verifica che l'header x-resource-name corrisponda alla risorsa attesa
 * per la route richiesta.
 */
function validateResourceHeader(
  req: Request,
  res: Response,
  expectedResource: string
): boolean {
  const resourceName = req.header("x-resource-name");

  if (!resourceName) {
    res.status(400).json({
      message: "Header x-resource-name mancante"
    });
    return false;
  }

  if (resourceName !== expectedResource) {
    res.status(400).json({
      message: "Risorsa richiesta non coerente con la route",
      expected_resource: expectedResource,
      received_resource: resourceName
    });
    return false;
  }

  return true;
}

/**
 * Risorsa protetta di demo relativa ai record dei dipendenti.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/employee-records", async (req, res) => {
  if (!validateResourceHeader(req, res, "employee_records")) {
    return;
  }

  try {
    const db = getDb();
    const records = await db.collection("employee_records").find().toArray();

    return res.status(200).json({
      message: "Accesso consentito alla risorsa protetta employee_records",
      resource: "employee_records",
      data: records
    });
  } catch (error) {
    return res.status(500).json({
      message: "Errore durante il recupero dei record dei dipendenti"
    });
  }
});

/**
 * Risorsa protetta di demo relativa alle policy aziendali.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/company-policies", async (req, res) => {
  if (!validateResourceHeader(req, res, "company_policies")) {
    return;
  }

  try {
    const db = getDb();
    const policies = await db.collection("company_policies").find().toArray();

    return res.status(200).json({
      message: "Accesso consentito alla risorsa protetta company_policies",
      resource: "company_policies",
      data: policies
    });
  } catch (error) {
    return res.status(500).json({
      message: "Errore durante il recupero delle policy aziendali"
    });
  }
});

/**
 * Risorsa protetta di demo relativa ai prodotti pubblici.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/public-products", async (req, res) => {
  if (!validateResourceHeader(req, res, "public_products")) {
    return;
  }

  try {
    const db = getDb();
    const products = await db.collection("public_products").find().toArray();

    return res.status(200).json({
      message: "Accesso consentito alla risorsa protetta public_products",
      resource: "public_products",
      data: products
    });
  } catch (error) {
    return res.status(500).json({
      message: "Errore durante il recupero dei prodotti pubblici"
    });
  }
});

export default router;