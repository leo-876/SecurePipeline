package devsecops

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    count(violations) == 0
}

violations contains violation if {
    secrets := [f | f := input.findings[_]; f.tool == "gitleaks"]
    count(secrets) > 0
    violation := {
        "rule": "no-secrets",
        "severity": "critical",
        "message": sprintf(
            "Pipeline blocked: %d hardcoded secret(s) detected. Remove and rotate immediately.",
            [count(secrets)]
        ),
        "findings": secrets,
    }
}

violations contains violation if {
    criticals := [f | f := input.findings[_]; f.severity == "critical"]
    count(criticals) > 0
    violation := {
        "rule": "no-critical-findings",
        "severity": "critical",
        "message": sprintf(
            "Pipeline blocked: %d critical finding(s) across all scanners.",
            [count(criticals)]
        ),
        "findings": criticals,
    }
}

violations contains violation if {
    input.summary.risk_score >= 70
    violation := {
        "rule": "risk-score-threshold",
        "severity": "high",
        "message": sprintf(
            "Pipeline blocked: aggregate risk score %d/100 exceeds threshold of 70.",
            [input.summary.risk_score]
        ),
        "findings": [],
    }
}

violations contains violation if {
    cve_criticals := [f |
        f := input.findings[_]
        f.tool in {"safety", "trivy", "npm_audit"}
        f.severity == "critical"
    ]
    count(cve_criticals) > 0
    violation := {
        "rule": "no-critical-cves",
        "severity": "critical",
        "message": sprintf(
            "Pipeline blocked: %d critical CVE(s) in dependencies or container layers.",
            [count(cve_criticals)]
        ),
        "findings": cve_criticals,
    }
}

violations contains violation if {
    sast_highs := [f |
        f := input.findings[_]
        f.tool in {"bandit", "semgrep"}
        f.severity in {"high", "critical"}
    ]
    count(sast_highs) > 0
    violation := {
        "rule": "no-high-sast-findings",
        "severity": "high",
        "message": sprintf(
            "Pipeline blocked: %d high/critical SAST finding(s). Review and remediate before merging.",
            [count(sast_highs)]
        ),
        "findings": sast_highs,
    }
}

warnings contains warning if {
    mediums := [f | f := input.findings[_]; f.severity == "medium"]
    count(mediums) >= 5
    warning := {
        "rule": "medium-finding-accumulation",
        "message": sprintf(
            "%d medium findings detected. Consider scheduling a remediation sprint.",
            [count(mediums)]
        ),
    }
}

warnings contains warning if {
    input.summary.risk_score >= 40
    input.summary.risk_score < 70
    warning := {
        "rule": "elevated-risk-score",
        "message": sprintf(
            "Risk score %d/100 is elevated. Aim to reduce below 40 for a healthy baseline.",
            [input.summary.risk_score]
        ),
    }
}

report := {
    "allow": allow,
    "violations": violations,
    "warnings": warnings,
    "summary": {
        "commit_sha": input.meta.commit_sha,
        "branch": input.meta.branch,
        "scanned_at": input.meta.scanned_at,
        "risk_score": input.summary.risk_score,
        "total_findings": input.summary.total_findings,
        "violation_count": count(violations),
        "warning_count": count(warnings),
    },
}
