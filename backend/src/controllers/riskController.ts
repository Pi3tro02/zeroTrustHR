import { Request, Response } from "express";
import { RiskService } from "../services/riskService";
import { RiskEvaluateRequest } from "../types/risk";

export class RiskController {
  constructor(private readonly riskService: RiskService) {}

  evaluate = async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as RiskEvaluateRequest;

      if (!body?.user || !body?.request?.resource || !body?.request?.action) {
        res.status(400).json({
          message: "Missing required fields: user, request.resource, request.action"
        });
        return;
      }

      const result = await this.riskService.evaluate(body);
      res.status(200).json(result);
    } catch (error) {
      console.error("Risk evaluation error:", error);

      res.status(500).json({
        message: "Risk evaluation failed"
      });
    }
  };
}