#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_opa(report_path: str, policy_path: str) -> dict:
    result = subprocess.run(
        [
            "opa", "eval",
            "--data", policy_path,
            "--input", report_path,
            "--format", "json",
            "data.devsecops.report",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"OPA error: {result.stderr}", file=sys.stderr)
        sys.exit(2)

    output = json.loads(result.stdout)
    return output["result"][0]["expressions"][0]["value"]


def format_decision(decision: dict) -> None:
    allowed = decision.get("allow", False)
    summary = decision.get("summary", {})
    violations = decision.get("violations", [])
    warnings = decision.get("warnings", [])

    status = "ALLOWED - deployment may proceed" if allowed else "BLOCKED - deployment prevented"
    print(f"\n{'='*60}")
    print(f"  OPA Policy Decision: {status}")
    print(f"{'='*60}")
    print(f"  Commit:      {summary.get('commit_sha', 'unknown')[:12]}")
    print(f"  Branch:      {summary.get('branch', 'unknown')}")
    print(f"  Risk Score:  {summary.get('risk_score', 0)}/100")
    print(f"  Findings:    {summary.get('total_findings', 0)} total")

    if violations:
        print(f"\n  VIOLATIONS ({len(violations)}):")
        for v in violations:
            print(f"    [{v['rule']}] {v['message']}")

    if warnings:
        print(f"\n  WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"    [{w['rule']}] {w['message']}")

    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Run OPA policy gate")
    parser.add_argument("--report", required=True, help="Path to aggregate.json")
    parser.add_argument(
        "--policy",
        default="opa/policies/devsecops.rego",
        help="Path to devsecops.rego",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write the OPA decision JSON",
    )
    args = parser.parse_args()

    if not Path(args.report).exists():
        print(f"Error: report file not found: {args.report}", file=sys.stderr)
        sys.exit(2)

    decision = run_opa(args.report, args.policy)
    format_decision(decision)

    if args.output:
        Path(args.output).write_text(json.dumps(decision, indent=2))

    sys.exit(0 if decision.get("allow", False) else 1)


if __name__ == "__main__":
    main()
