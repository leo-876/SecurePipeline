#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 5, "low": 1, "info": 0}


def normalise_severity(raw: str) -> str:
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "WARNING": "medium",
        "ERROR": "high",
        "NOTE": "low",
        "INFO": "info",
    }
    return mapping.get(raw.upper(), "low")


def parse_gitleaks(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    if raw is None:
        return []
    findings = []
    for item in raw:
        findings.append({
            "tool": "gitleaks",
            "severity": "critical",
            "rule_id": item.get("RuleID", "unknown"),
            "message": f"Secret detected: {item.get('Description', '')}",
            "file": item.get("File", ""),
            "line": item.get("StartLine", 0),
            "commit": item.get("Commit", ""),
        })
    return findings


def parse_safety(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    findings = []
    vulns = raw.get("vulnerabilities", raw) if isinstance(raw, dict) else raw
    for item in vulns:
        cvss = float(item.get("cvss", item.get("CVSSv3", 0.0)) or 0.0)
        severity = (
            "critical" if cvss >= 9.0
            else "high" if cvss >= 7.0
            else "medium" if cvss >= 4.0
            else "low"
        )
        pkg = item.get("package_name", item.get("package", ""))
        ver = item.get("analyzed_version", "")
        advisory = item.get("advisory", "")
        findings.append({
            "tool": "safety",
            "severity": severity,
            "rule_id": item.get("vulnerability_id", item.get("CVE", "unknown")),
            "message": f"{pkg} {ver} - {advisory}",
            "file": "requirements.txt",
            "line": 0,
            "cvss": cvss,
        })
    return findings


def parse_npm_audit(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    findings = []
    vulns = raw.get("vulnerabilities", {})
    for pkg, info in vulns.items():
        severity = normalise_severity(info.get("severity", "low"))
        findings.append({
            "tool": "npm_audit",
            "severity": severity,
            "rule_id": "npm-" + pkg,
            "message": f"{pkg}: {info.get('title', 'vulnerability')} ({info.get('range', '')})",
            "file": "package.json",
            "line": 0,
        })
    return findings


def parse_bandit(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    findings = []
    for item in raw.get("results", []):
        severity = normalise_severity(item.get("issue_severity", "low"))
        confidence = item.get("issue_confidence", "MEDIUM")
        if severity == "high" and confidence == "LOW":
            severity = "medium"
        findings.append({
            "tool": "bandit",
            "severity": severity,
            "rule_id": item.get("test_id", "unknown"),
            "message": item.get("issue_text", ""),
            "file": item.get("filename", ""),
            "line": item.get("line_number", 0),
            "cwe": item.get("issue_cwe", {}).get("id"),
        })
    return findings


def parse_semgrep(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    findings = []
    for item in raw.get("results", []):
        severity = normalise_severity(item.get("extra", {}).get("severity", "WARNING"))
        findings.append({
            "tool": "semgrep",
            "severity": severity,
            "rule_id": item.get("check_id", "unknown"),
            "message": item.get("extra", {}).get("message", ""),
            "file": item.get("path", ""),
            "line": item.get("start", {}).get("line", 0),
            "cwe": item.get("extra", {}).get("metadata", {}).get("cwe"),
        })
    return findings


def parse_trivy(path: Optional[str]) -> List[Dict]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text())
    findings = []
    for result in raw.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = normalise_severity(vuln.get("Severity", "LOW"))
            cvss = 0.0
            scores = vuln.get("CVSS", {})
            for source_scores in scores.values():
                v3 = source_scores.get("V3Score", 0.0)
                if v3:
                    cvss = max(cvss, float(v3))
            findings.append({
                "tool": "trivy",
                "severity": severity,
                "rule_id": vuln.get("VulnerabilityID", "unknown"),
                "message": f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} - {vuln.get('Title', '')}",
                "file": result.get("Target", ""),
                "line": 0,
                "cvss": cvss,
                "fixed_version": vuln.get("FixedVersion"),
            })
    return findings


def compute_risk_score(findings: List[Dict]) -> int:
    score = 0
    for f in findings:
        score += SEVERITY_WEIGHTS.get(f["severity"], 0)
    return min(score, 100)


def gate_passed(findings: List[Dict]) -> bool:
    criticals = [f for f in findings if f["severity"] == "critical"]
    secrets = [f for f in findings if f["tool"] == "gitleaks"]
    score = compute_risk_score(findings)
    return len(criticals) == 0 and len(secrets) == 0 and score < 70


def main():
    parser = argparse.ArgumentParser(description="Aggregate scan findings")
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--branch", default="unknown")
    parser.add_argument("--gitleaks")
    parser.add_argument("--safety")
    parser.add_argument("--npm-audit")
    parser.add_argument("--bandit")
    parser.add_argument("--semgrep")
    parser.add_argument("--trivy")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    all_findings: List[Dict] = []
    all_findings.extend(parse_gitleaks(args.gitleaks))
    all_findings.extend(parse_safety(args.safety))
    all_findings.extend(parse_npm_audit(args.npm_audit))
    all_findings.extend(parse_bandit(args.bandit))
    all_findings.extend(parse_semgrep(args.semgrep))
    all_findings.extend(parse_trivy(args.trivy))

    score = compute_risk_score(all_findings)
    passed = gate_passed(all_findings)

    by_severity: Dict[str, int] = {s: 0 for s in SEVERITY_RANK}
    by_tool: Dict[str, int] = {}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1

    report = {
        "meta": {
            "commit_sha": args.commit_sha,
            "branch": args.branch,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "aggregator_version": "1.0.0",
        },
        "summary": {
            "total_findings": len(all_findings),
            "risk_score": score,
            "gate_passed": passed,
            "by_severity": by_severity,
            "by_tool": by_tool,
        },
        "findings": all_findings,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2))

    status = "PASS" if passed else "BLOCK"
    print(f"\n{status}  Risk score: {score}/100")
    print(f"  Total findings: {len(all_findings)}")
    for sev in ["critical", "high", "medium", "low"]:
        count = by_severity.get(sev, 0)
        if count:
            print(f"    {sev.upper():10s} {count}")
    print(f"\n  Report written to: {args.output}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
