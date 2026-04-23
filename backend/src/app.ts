import express from "express";
import cors from "cors";
import healthRouter from "./routes/health";
import accessRouter from "./routes/access";
import protectedRouter from "./routes/protected";

const app = express();

app.use(cors());
app.use(express.json());

app.use("/health", healthRouter);
app.use("/access", accessRouter);
app.use("/protected", protectedRouter);

export default app;