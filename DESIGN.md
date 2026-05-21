# Design Decisions

This document captures the key architectural choices in SecurePipeline and the reasoning behind them. It's intended to be a reference for portfolio discussions.

## Why OPA instead of inline gate logic?

The pipeline could block on findings directly in each GitHub Actions step - Gitleaks and Trivy both support `--exit-code 1`. The problem with that approach is fragmentation: each tool has its own threshold configuration scattered across the workflow YAML. There's no single place to audit what the policy actually is.

OPA inverts this. The Rego policy is the single source of truth for what constitutes a blocking finding. It's version-controlled alongside the application code, it can be reviewed in PRs, and it's independently testable with `opa test` before any code ships. The same `.rego` file could enforce identical policy across a Jenkins pipeline, a GitLab CI workflow, or a Tekton pipeline - the CI orchestrator becomes interchangeable.

The structured violation objects (each with a `rule` ID, `severity`, and `message`) also make pipeline failures actionable. "Pipeline failed" is useless. "Blocked by `no-critical-cves`: 2 critical CVEs in base image layers" tells you exactly what to fix.

## Why aggregate findings before the gate?

Fail-fast - blocking as soon as any stage finds something - sounds efficient but discourages security adoption in practice. Engineers who hit three sequential "fix one thing, discover another" failures stop trusting the pipeline. Running all scanners in parallel and collecting everything before the gate means one run, one complete picture.

The tradeoff is that critical secrets still surface (via the `no-secrets` rule), but the developer sees all findings at once rather than peeling back an onion.

## Why SHA-256 for password hashing (and why leave it)?

`app.py` deliberately uses SHA-256 for password hashing - Bandit flags this as B324 (use of weak hash for security). This is intentional: it gives the pipeline a finding to catch and demonstrates that the SAST gate detects weak crypto patterns. A comment in the code explains the intentionality.

In a real system, passwords should be hashed with bcrypt, scrypt, or Argon2 (via `passlib` or `argon2-cffi`). The finding is present to demonstrate the pipeline working correctly, not as a recommendation.

## Why SQLite for the dashboard?

The dashboard is a portfolio demonstration tool, not a production service. SQLite with WAL mode handles dozens of concurrent reads without issues and requires zero infrastructure. The schema is simple enough that migrating to PostgreSQL later would be a one-hour task if needed.

## Gate threshold: why 70?

The 70/100 threshold is somewhat arbitrary but calibrated against the weighting:
- 1 critical finding = 40 points (almost always a block by itself)
- 2 high findings = 40 points (block)  
- 4 high findings scattered across tools = 80 points (block)
- 10 medium findings = 50 points (no block, but warning fires at 40)

This means a healthy codebase with only low/medium findings from a first-pass SAST run won't be blocked - it encourages teams to adopt the pipeline incrementally rather than treating every medium finding as a show-stopper.

## Nightly audit rationale

CVEs are published continuously; a pipeline that only scans on push gives a false sense of security. A dependency that was clean on Monday can have a critical CVE by Thursday. The nightly workflow + auto-issue creation ensures the team is notified without requiring a commit to trigger discovery.
