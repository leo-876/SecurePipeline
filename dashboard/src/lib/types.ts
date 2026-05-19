export interface Finding {
  tool: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  rule_id: string;
  message: string;
  file: string;
  line: number;
  cwe?: string | number;
  cvss?: number;
  fixed_version?: string;
  commit?: string;
}

export interface ReportRow {
  id: number;
  commit_sha: string;
  branch: string;
  risk_score: number;
  gate_passed: number | boolean;
  findings_json: string;
  by_severity_json: string;
  by_tool_json: string;
  scanned_at: string;
}

export interface TrendPoint {
  commit_sha: string;
  commit_short?: string;
  branch: string;
  risk_score: number;
  gate_passed: number | boolean;
  scanned_at: string;
}

export interface HotspotRow {
  file: string;
  count: number;
  severities: string[];
}

export interface SummaryResponse {
  total_runs: number;
  passed: number;
  failed: number;
  pass_rate: number;
  avg_risk_score: number;
  latest: {
    commit_sha: string;
    commit_short: string;
    branch: string;
    risk_score: number;
    gate_passed: boolean;
    scanned_at: string;
  } | null;
}
