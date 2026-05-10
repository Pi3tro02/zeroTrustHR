import { Router } from "express";
import { RiskController } from "../controllers/riskController";

export function createRiskRoutes(controller: RiskController): Router {
  const router = Router();

  router.post("/evaluate", controller.evaluate);

  return router;
}