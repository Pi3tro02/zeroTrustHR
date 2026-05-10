import axios from "axios";
import https from "https";

export class SplunkService {
  private readonly httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });

  constructor(
    private readonly baseUrl: string,
    private readonly username: string,
    private readonly password: string,
    private readonly owner: string,
    private readonly app: string
  ) {}

  async runSearch(query: string): Promise<any[]> {
    console.log("=== SPLUNK QUERY ===");
    console.log(query);

    const url = `${this.baseUrl}/servicesNS/${this.owner}/${this.app}/search/jobs/export`;

    const form = new URLSearchParams();
    form.append("search", query);
    form.append("output_mode", "json");
    form.append("exec_mode", "oneshot");

    const response = await axios.post(url, form.toString(), {
      auth: {
        username: this.username,
        password: this.password
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      httpsAgent: this.httpsAgent,
      responseType: "text",
      timeout: 15000
    });

    const raw = response.data as string;

    console.log("=== SPLUNK RAW RESPONSE START ===");
    console.log(raw);
    console.log("=== SPLUNK RAW RESPONSE END ===");

    const results: any[] = [];

    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const parsed = JSON.parse(trimmed);

        if (parsed.result) {
          results.push(parsed.result);
        }
      } catch {
        console.warn("Unable to parse Splunk line:", trimmed);
      }
    }

    console.log("=== SPLUNK PARSED RESULTS ===");
    console.log(results);

    return results;
  }

  async ping(): Promise<boolean> {
    try {
      await axios.get(
        `${this.baseUrl}/services/server/info?output_mode=json`,
        {
          auth: {
            username: this.username,
            password: this.password
          },
          httpsAgent: this.httpsAgent,
          timeout: 3000
        }
      );
      return true;
    } catch {
      return false;
    }
  }
}