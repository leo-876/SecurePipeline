import { Database } from "sql.js";
import { initDb, saveDb } from "./lib/db";

const BRANCHES = ["main", "main", "main", "feature/auth-refactor", "fix/cve-remediation", "main"];

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomSha(): string {
  return Array.from({ length: 40 }, () => "0123456789abcdef"[randomInt(0, 15)]).join("");
}

function makeFindings(score: number): object[] {
  const findings = [];
  const criticalCount = score >= 70 ? randomInt(1, 3) : 0;
  const highCount = Math.floor(score / 20);
  const mediumCount = Math.floor(score / 5);

  for (let i = 0; i < criticalCount; i++) {
    findings.push({
      tool: ["trivy", "safety"][randomInt(0, 1)],
      severity: "critical",
      rule_id: `CVE-2024-${randomInt(10000, 99999)}`,
      message: "Critical CVE in base image layer",
      file: "Dockerfile",
      line: 0,
      cvss: 9.8,
    });
  }
  for (let i = 0; i < highCount; i++) {
    findings.push({
      tool: ["bandit", "semgrep"][randomInt(0, 1)],
      severity: "high",
      rule_id: ["B303", "B506", "B602", "hardcoded-secret-assignment"][randomInt(0, 3)],
      message: "High severity SAST finding",
      file: `target-app/src/${"app.py db.py utils.py".split(" ")[randomInt(0, 2)]}`,
      line: randomInt(1, 150),
    });
  }
  for (let i = 0; i < mediumCount; i++) {
    findings.push({
      tool: "semgrep",
      severity: "medium",
      rule_id: "flask-debug-enabled",
      message: "Medium severity finding",
      file: "target-app/src/app.py",
      line: randomInt(1, 150),
    });
  }

  return findings;
}

export async function seed(db?: Database): Promise<void> {
  if (!db) {
    db = await initDb();
  }

  const now = Date.now();
  const runs: { ts: number; score: number; branch: string }[] = [];

  let baseScore = 75;
  for (let day = 44; day >= 0; day--) {
    const scansToday = randomInt(1, 3);
    for (let s = 0; s < scansToday; s++) {
      const jitter = randomInt(-8, 8);
      const score = Math.max(0, Math.min(100, baseScore + jitter));
      const ts = now - (day * 86400000) + (s * 3600000 * randomInt(1, 6));
      const branch = BRANCHES[randomInt(0, BRANCHES.length - 1)];
      runs.push({ ts, score, branch });
    }
    if (day === 20) {
      baseScore += 30;
    } else if (baseScore > 15) {
      baseScore -= randomInt(0, 3);
    }
  }

  for (const r of runs) {
    const findings = makeFindings(r.score);
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byTool: Record<string, number> = {};
    for (const f of findings as any[]) {
      bySeverity[f.severity as string]++;
      byTool[f.tool] = (byTool[f.tool] ?? 0) + 1;
    }

    db.run(
      `INSERT INTO reports (commit_sha, branch, risk_score, gate_passed, findings_json, by_severity_json, by_tool_json, scanned_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [randomSha(), r.branch, r.score, r.score < 70 ? 1 : 0,
       JSON.stringify(findings), JSON.stringify(bySeverity), JSON.stringify(byTool),
       new Date(r.ts).toISOString()]
    );
  }

  saveDb(db);
  console.log(`Seeded ${runs.length} scan reports across 45 days`);
}

async function main(): Promise<void> {
  await seed();
  console.log("Start the dashboard: npm run dev");
  console.log("Open: http://localhost:3000");
}

if (require.main === module) {
  main().catch(console.error);
}
