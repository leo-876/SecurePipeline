package devsecops_test

import data.devsecops
import future.keywords.if

clean_report := {
  "meta": {"commit_sha": "abc123", "branch": "main", "scanned_at": "2026-05-21T10:00:00Z"},
  "summary": {"total_findings": 0, "risk_score": 0, "gate_passed": true, "by_severity": {}, "by_tool": {}},
  "findings": [],
}

with_finding(report, finding) := new_report if {
  new_report := json.patch(report, [
    {"op": "add", "path": "/findings/-", "value": finding},
    {"op": "replace", "path": "/summary/total_findings", "value": count(report.findings) + 1},
  ])
}

with_score(report, score) := new_report if {
  new_report := json.patch(report, [
    {"op": "replace", "path": "/summary/risk_score", "value": score},
  ])
}

test_clean_report_passes if {
  devsecops.allow with input as clean_report
}

test_clean_report_no_violations if {
  count(devsecops.violations) == 0 with input as clean_report
}

test_secret_blocks if {
  secret_finding := {
    "tool": "gitleaks", "severity": "critical",
    "rule_id": "aws-access-key", "message": "AWS key found",
    "file": "config.py", "line": 5,
  }
  report := with_finding(clean_report, secret_finding)
  not devsecops.allow with input as report
}

test_secret_violation_rule_id if {
  secret_finding := {
    "tool": "gitleaks", "severity": "critical",
    "rule_id": "github-pat", "message": "GitHub PAT found",
    "file": ".env", "line": 3,
  }
  report := with_finding(clean_report, secret_finding)
  violations := devsecops.violations with input as report
  some v in violations
  v.rule == "no-secrets"
}

test_critical_cve_blocks if {
  cve := {
    "tool": "trivy", "severity": "critical",
    "rule_id": "CVE-2024-12345", "message": "Critical CVE",
    "file": "Dockerfile", "line": 0, "cvss": 9.8,
  }
  report := with_finding(clean_report, cve)
  not devsecops.allow with input as report
}

test_critical_sast_blocks if {
  finding := {
    "tool": "bandit", "severity": "critical",
    "rule_id": "B602", "message": "Shell injection",
    "file": "app.py", "line": 42,
  }
  report := with_finding(clean_report, finding)
  not devsecops.allow with input as report
}

test_score_70_blocks if {
  report := with_score(clean_report, 70)
  not devsecops.allow with input as report
}

test_score_69_passes if {
  report := with_score(clean_report, 69)
  devsecops.allow with input as report
}

test_score_100_blocks if {
  report := with_score(clean_report, 100)
  not devsecops.allow with input as report
}

test_medium_finding_passes if {
  finding := {
    "tool": "semgrep", "severity": "medium",
    "rule_id": "flask-debug", "message": "Debug mode",
    "file": "app.py", "line": 10,
  }
  report := with_finding(clean_report, finding)
  devsecops.allow with input as report
}

test_low_finding_passes if {
  finding := {
    "tool": "bandit", "severity": "low",
    "rule_id": "B105", "message": "Hardcoded default",
    "file": "app.py", "line": 8,
  }
  report := with_finding(clean_report, finding)
  devsecops.allow with input as report
}

test_elevated_score_warning if {
  report := with_score(clean_report, 50)
  warnings := devsecops.warnings with input as report
  some w in warnings
  w.rule == "elevated-risk-score"
}

test_low_score_no_warning if {
  report := with_score(clean_report, 30)
  warnings := devsecops.warnings with input as report
  not some w in warnings
  w.rule == "elevated-risk-score"
  true
}

test_report_contains_allow if {
  r := devsecops.report with input as clean_report
  r.allow == true
}

test_report_contains_summary if {
  r := devsecops.report with input as clean_report
  r.summary.commit_sha == "abc123"
  r.summary.branch == "main"
  r.summary.risk_score == 0
}
