import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import path from "path";
import { initDb, getDb, queryAll, queryOne, run, saveDb } from "./lib/db";
import { Database } from "sql.js";
import { Finding, HotspotRow } from "./lib/types";

const app = express();
const PORT = parseInt(process.env.PORT ?? "3000", 10);

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, "../public")));

let db: Database;

function requireApiKey(req: Request, res: Response, next: NextFunction): void {
  const key = req.headers["x-api-key"];
  const expected = process.env.API_KEY;
  if (expected && key !== expected) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", version: "1.0.0" });
});

app.post("/api/reports", requireApiKey, (req: Request, res: Response) => {
  const body = req.body as {
    meta?: { commit_sha?: string; branch?: string };
    summary?: { risk_score?: number; gate_passed?: boolean; by_severity?: Record<string, number>; by_tool?: Record<string, number> };
    findings?: Finding[];
    commit_sha?: string;
    branch?: string;
    risk_score?: number;
    gate_passed?: boolean;
  };

  const commitSha = body.meta?.commit_sha ?? body.commit_sha ?? "unknown";
  const branch = body.meta?.branch ?? body.branch ?? "unknown";
  const riskScore = body.summary?.risk_score ?? body.risk_score ?? 0;
  const gatePassed = body.summary?.gate_passed ?? body.gate_passed ?? false;
  const findings: Finding[] = body.findings ?? [];
  const bySeverity = body.summary?.by_severity ?? computeBySeverity(findings);
  const byTool = body.summary?.by_tool ?? computeByTool(findings);

  run(db,
    `INSERT INTO reports (commit_sha, branch, risk_score, gate_passed, findings_json, by_severity_json, by_tool_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [commitSha, branch, riskScore, gatePassed ? 1 : 0,
     JSON.stringify(findings), JSON.stringify(bySeverity), JSON.stringify(byTool)]
  );

  const row = queryOne(db, "SELECT last_insert_rowid() as id");
  res.status(201).json({ id: row?.id, message: "report ingested" });
});

app.get("/api/reports", (req: Request, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? "50", 10), 200);
  const offset = parseInt(req.query.offset as string ?? "0", 10);

  const rows = queryAll(db,
    `SELECT id, commit_sha, branch, risk_score, gate_passed, scanned_at, by_severity_json, by_tool_json
     FROM reports ORDER BY scanned_at DESC LIMIT ? OFFSET ?`,
    [limit, offset]
  );

  res.json(rows.map(r => ({
    id: r.id,
    commit_sha: r.commit_sha,
    branch: r.branch,
    risk_score: r.risk_score,
    gate_passed: r.gate_passed === 1 || r.gate_passed === true,
    scanned_at: r.scanned_at,
    by_severity: JSON.parse(r.by_severity_json as string ?? "{}"),
    by_tool: JSON.parse(r.by_tool_json as string ?? "{}"),
  })));
});

app.get("/api/reports/:id", (req: Request, res: Response) => {
  const row = queryOne(db, `SELECT * FROM reports WHERE id = ?`, [req.params.id]);
  if (!row) {
    res.status(404).json({ error: "not found" });
    return;
  }
  res.json({
    id: row.id,
    commit_sha: row.commit_sha,
    branch: row.branch,
    risk_score: row.risk_score,
    gate_passed: row.gate_passed === 1 || row.gate_passed === true,
    scanned_at: row.scanned_at,
    findings: JSON.parse(row.findings_json as string ?? "[]"),
    by_severity: JSON.parse(row.by_severity_json as string ?? "{}"),
    by_tool: JSON.parse(row.by_tool_json as string ?? "{}"),
  });
});

app.get("/api/trend", (req: Request, res: Response) => {
  const n = Math.min(parseInt(req.query.n as string ?? "30", 10), 100);

  const rows = queryAll(db,
    `SELECT commit_sha, branch, risk_score, gate_passed, scanned_at
     FROM reports ORDER BY scanned_at DESC LIMIT ?`,
    [n]
  );

  res.json(rows.reverse().map(r => ({
    commit_sha: r.commit_sha,
    commit_short: (r.commit_sha as string).slice(0, 7),
    branch: r.branch,
    risk_score: r.risk_score,
    gate_passed: r.gate_passed === 1 || r.gate_passed === true,
    scanned_at: r.scanned_at,
  })));
});

app.get("/api/summary", (_req: Request, res: Response) => {
  const latest = queryOne(db, `SELECT * FROM reports ORDER BY scanned_at DESC LIMIT 1`);
  const totalRow = queryOne(db, `SELECT COUNT(*) as c FROM reports`);
  const passedRow = queryOne(db, `SELECT COUNT(*) as c FROM reports WHERE gate_passed = 1`);
  const avgRow = queryOne(db, `SELECT AVG(risk_score) as avg FROM reports`);

  const total = Number(totalRow?.c ?? 0);
  const passed = Number(passedRow?.c ?? 0);
  const failed = total - passed;
  const avgScore = Number(avgRow?.avg ?? 0);

  res.json({
    total_runs: total,
    passed,
    failed,
    pass_rate: total > 0 ? Math.round((passed / total) * 100) : 0,
    avg_risk_score: Math.round(avgScore),
    latest: latest ? {
      commit_sha: latest.commit_sha,
      commit_short: (latest.commit_sha as string).slice(0, 7),
      branch: latest.branch,
      risk_score: Number(latest.risk_score),
      gate_passed: latest.gate_passed === 1 || latest.gate_passed === true,
      scanned_at: latest.scanned_at,
    } : null,
  });
});

app.get("/api/hotspots", (_req: Request, res: Response) => {
  const rows = queryAll(db,
    `SELECT findings_json FROM reports ORDER BY scanned_at DESC LIMIT 20`
  );

  const fileCounts: Record<string, { count: number; severities: string[] }> = {};
  for (const row of rows) {
    const findings: Finding[] = JSON.parse(row.findings_json as string ?? "[]");
    for (const f of findings) {
      if (!f.file || f.file === "requirements.txt" || f.file === "package.json") continue;
      if (!fileCounts[f.file]) fileCounts[f.file] = { count: 0, severities: [] };
      fileCounts[f.file].count++;
      if (!fileCounts[f.file].severities.includes(f.severity)) {
        fileCounts[f.file].severities.push(f.severity);
      }
    }
  }

  const hotspots: HotspotRow[] = Object.entries(fileCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)
    .map(([file, data]) => ({ file, count: data.count, severities: data.severities }));

  res.json(hotspots);
});

function computeBySeverity(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function computeByTool(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.tool] = (out[f.tool] ?? 0) + 1;
  return out;
}

async function start(): Promise<void> {
  db = await initDb();

  const countRow = queryOne(db, "SELECT COUNT(*) as c FROM reports");
  const count = Number(countRow?.c ?? 0);

  if (count === 0) {
    console.log("No data found - seeding demo data...");
    const { seed } = await import("./seed");
    await seed(db);
    console.log("Demo data ready.");
  }

  app.listen(PORT, () => {
    console.log(`SecurePipeline Dashboard running on http://localhost:${PORT}`);
    console.log(`API key auth: ${process.env.API_KEY ? "enabled" : "disabled (dev mode)"}`);
  });
}

start().catch(err => {
  console.error("Failed to start:", err);
  process.exit(1);
});

export default app;
