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
    const results = await this.splunkService.runSearch(query);

    if (!results || results.length === 0) {
      return {
        risk_score: 0.9,
        severity: "danger",
        profit: -1,
        source: "fallback",
        window: this.defaultWindow
      };
    }

    const first = results[0];

    return {
      risk_score: Number(first.risk_score ?? 0.9),
      severity: (first.severity ?? "danger") as RiskEvaluateResponse["severity"],
      profit: Number(first.profit ?? -1),
      risk_cover: first.risk_cover,
      recent_denies: Number(first.recent_denies ?? 0),
      recent_allows: Number(first.recent_allows ?? 0),
      distinct_device_ips: Number(first.distinct_device_ips ?? 0),
      distinct_ja3: Number(first.distinct_ja3 ?? 0),
      distinct_trust_states: Number(first.distinct_trust_states ?? 0),
      source: "splunk",
      window: this.defaultWindow
    };
  }
}