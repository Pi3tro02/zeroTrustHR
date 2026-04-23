import { Router } from "express";

const router = Router();

/**
 * Risorsa protetta di demo relativa ai record dei dipendenti.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/employee-records", (_req, res) => {
  return res.status(200).json({
    message: "Accesso consentito alla risorsa protetta employee_records",
    resource: "employee_records",
    data: [
      { id: 1, employee: "Mario Rossi", department: "HR" },
      { id: 2, employee: "Lucia Bianchi", department: "Finance" }
    ]
  });
});

/**
 * Risorsa protetta di demo relativa alle policy aziendali.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/company-policies", (_req, res) => {
  return res.status(200).json({
    message: "Accesso consentito alla risorsa protetta company_policies",
    resource: "company_policies",
    data: [
      { id: 1, title: "Remote Work Policy", category: "HR" },
      { id: 2, title: "Password Policy", category: "Security" },
      { id: 3, title: "Acceptable Use Policy", category: "IT" }
    ]
  });
});

/**
 * Risorsa pubblica di demo relativa ai prodotti.
 * Deve essere raggiungibile solo passando da Envoy + OPA.
 */
router.get("/public-products", (_req, res) => {
  return res.status(200).json({
    message: "Accesso consentito alla risorsa protetta public_products",
    resource: "public_products",
    data: [
      { id: 1, name: "Laptop Pro 14", category: "Electronics", price: 1299 },
      { id: 2, name: "Office Chair X", category: "Furniture", price: 249 },
      { id: 3, name: "Wireless Mouse", category: "Accessories", price: 39 }
    ]
  });
});

export default router;