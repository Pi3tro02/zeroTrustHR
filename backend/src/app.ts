import express from "express";
import cors from "cors";
import healthRouter from "./routes/health";
import accessRouter from "./routes/access";
import protectedRouter from "./routes/protected";
import splunkWebhookRouter from "./routes/splunkWebhook";

const app = express();

app.use(cors());
app.use(express.json());

app.use("/health", healthRouter);
app.use("/access", accessRouter);
app.use("/protected", protectedRouter);
app.use("/api/splunk-webhook", splunkWebhookRouter); 

export default app;