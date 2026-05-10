import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import healthRouter from "./routes/health";
import accessRouter from "./routes/access";
import protectedRouter from "./routes/protected";
import splunkWebhookRouter from "./routes/splunkWebhook";

import { SplunkService } from "./services/splunkService";
import { RiskService } from "./services/riskService";
import { RiskController } from "./controllers/riskController";
import { createRiskRoutes } from "./routes/risk";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const splunkBaseUrl = process.env.SPLUNK_BASE_URL!;
const splunkUsername = process.env.SPLUNK_USERNAME!;
const splunkPassword = process.env.SPLUNK_PASSWORD!;
const splunkWindow = process.env.SPLUNK_WINDOW!;
const splunkOwner = process.env.SPLUNK_SEARCH_OWNER!;
const splunkApp = process.env.SPLUNK_SEARCH_APP!;

const splunkService = new SplunkService(
  splunkBaseUrl,
  splunkUsername,
  splunkPassword,
  splunkOwner,
  splunkApp
);

const riskService = new RiskService(
  splunkService,
  splunkWindow
);

const riskController = new RiskController(riskService);

app.use("/health", healthRouter);
app.use("/access", accessRouter);
app.use("/protected", protectedRouter);
app.use("/api/splunk-webhook", splunkWebhookRouter);
app.use("/api/risk", createRiskRoutes(riskController));

export default app;