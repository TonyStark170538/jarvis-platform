import cors from "cors";
import express from "express";
import { createServer } from "http";
import securityRouter from "./security/routes";

const app = express();
const server = createServer(app);

app.disable("x-powered-by");
app.use(cors({ origin: process.env.FRONTEND_ORIGIN?.split(",") ?? true }));
app.use(express.json({ limit: "256kb" }));

app.get("/api/health", (_req, res) => {
  res.json({ success: true, service: "jarvis-api", status: "online" });
});

app.use("/api/security", securityRouter);

const port = Number(process.env.PORT ?? 3001);

server.listen(port, "0.0.0.0", () => {
  console.log(`J.A.R.V.I.S. API running on port ${port}`);
});
