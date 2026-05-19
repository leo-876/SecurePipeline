import initSqlJs, { Database } from "sql.js";
import fs from "fs";
import path from "path";

const DB_DIR = process.env.DB_DIR ?? path.join(__dirname, "../../data");
const DB_PATH = path.join(DB_DIR, "posture.db");

let _db: Database | null = null;

export async function getDb(): Promise<Database> {
  if (_db) return _db;

  const SQL = await initSqlJs();

  if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
  }

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(fileBuffer);
  } else {
    _db = new SQL.Database();
  }

  return _db;
}

export function saveDb(db: Database): void {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

export async function initDb(): Promise<Database> {
  const db = await getDb();

  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      commit_sha     TEXT    NOT NULL,
      branch         TEXT    NOT NULL DEFAULT 'unknown',
      risk_score     INTEGER NOT NULL DEFAULT 0,
      gate_passed    INTEGER NOT NULL DEFAULT 0,
      findings_json  TEXT    NOT NULL DEFAULT '[]',
      by_severity_json TEXT  NOT NULL DEFAULT '{}',
      by_tool_json   TEXT    NOT NULL DEFAULT '{}',
      scanned_at     TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_scanned_at ON reports(scanned_at DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_branch ON reports(branch)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_gate ON reports(gate_passed)`);

  saveDb(db);
  console.log(`Database initialised at ${DB_PATH}`);
  return db;
}

export function queryAll(db: Database, sql: string, params: (string | number | null)[] = []): Record<string, unknown>[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows: Record<string, unknown>[] = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject() as Record<string, unknown>);
  }
  stmt.free();
  return rows;
}

export function queryOne(db: Database, sql: string, params: (string | number | null)[] = []): Record<string, unknown> | null {
  const rows = queryAll(db, sql, params);
  return rows[0] ?? null;
}

export function run(db: Database, sql: string, params: (string | number | null)[] = []): void {
  db.run(sql, params);
  saveDb(db);
}
