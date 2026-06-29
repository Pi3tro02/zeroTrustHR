import { RiskEvaluateRequest, RiskEvaluateResponse } from "../types/risk";
import { buildSplunkQuery } from "../utils/buildSplunkQuery";
import { SplunkService } from "./splunkService";

export class RiskService {
  constructor(
    private readonly splunkService: SplunkService,
    private readonly defaultWindow: string
  ) {}

  async evaluate(payload: RiskEvaluateRequest): Promise<RiskEvaluateResponse> {
    const query = buildSplunkQuery(payload, this.defaultWindow);
    let results: any[] = [];
    try {
      results = await this.splunkService.runSearch(query);
    } catch (error: any) {
      console.warn("Splunk search failed (model might not exist yet):", error.message);
    }

    if (!results || results.length === 0) {
      return {
        risk_score: 0.1, // baseline risk se non c'è storia
        prob_attack: 0.1,
        impact: 1.0,
        severity: "safe",
        source: "splunk",
        window: this.defaultWindow
      };
    }

    const first = results[0];

    return {
      risk_score: Number(first.risk_score ?? 0.1),
      prob_attack: Number(first.prob_attack ?? 0.1),
      impact: Number(first.impact ?? 1.0),
      severity: (first.severity ?? "safe") as RiskEvaluateResponse["severity"],
      total_denies: Number(first.total_denies ?? 0),
      total_snort_alerts: Number(first.total_snort_alerts ?? 0),
      distinct_device_ips: Number(first.distinct_device_ips ?? 0),
      distinct_ja3: Number(first.distinct_ja3 ?? 0),
      distinct_trust_states: Number(first.distinct_trust_states ?? 0),
      source: "splunk",
      window: this.defaultWindow
    };
  }
}