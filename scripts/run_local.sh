#!/usr/bin/env bash
# Runs the full DevSecOps pipeline locally, mirroring what GitHub Actions does.
#
# Usage:
#   chmod +x scripts/run_local.sh
#   ./scripts/run_local.sh [--skip-docker] [--skip-opa]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS="$REPO_ROOT/reports"
SKIP_DOCKER=false
SKIP_OPA=false

for arg in "$@"; do
  case $arg in
    --skip-docker) SKIP_DOCKER=true ;;
    --skip-opa) SKIP_OPA=true ;;
  esac
done

mkdir -p "$REPORTS"

COMMIT_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "local-$(date +%s)")
BRANCH=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "local")

# On Windows, pip installs CLI tools to Scripts/ which may not be on PATH
# in Git Bash. Try python -m <tool> as a fallback before giving up.
have_python_tool() {
  local tool="$1"
  command -v "$tool" &>/dev/null || python -m "$tool" --version &>/dev/null 2>&1 || python3 -m "$tool" --version &>/dev/null 2>&1
}

run_python_tool() {
  local tool="$1"
  shift
  if command -v "$tool" &>/dev/null; then
    "$tool" "$@"
  else
    python -m "$tool" "$@" 2>/dev/null || python3 -m "$tool" "$@"
  fi
}

echo ""
echo "==================================================="
echo "       SecurePipeline - Local DevSecOps Run"
echo "==================================================="
echo "  Commit: ${COMMIT_SHA:0:12}  Branch: $BRANCH"
echo ""

echo "[1/5] Secrets scan (Gitleaks)..."
if command -v gitleaks &>/dev/null; then
  gitleaks detect \
    --source "$REPO_ROOT" \
    --format json \
    --report-path "$REPORTS/gitleaks.json" \
    --exit-code 0 \
    2>/dev/null || true
  echo "     gitleaks.json written"
else
  echo "     gitleaks not found, skipping"
  echo "     (Windows install: https://github.com/gitleaks/gitleaks/releases)"
  echo "[]" > "$REPORTS/gitleaks.json"
fi

echo "[2/5] Dependency CVE scan..."

if have_python_tool safety; then
  run_python_tool safety check \
    -r "$REPO_ROOT/target-app/requirements.txt" \
    --json \
    --continue-on-error \
    > "$REPORTS/safety.json" 2>&1 || true
  echo "     safety.json written"
else
  echo "     safety not found, install: pip install safety"
  echo '{"vulnerabilities":[]}' > "$REPORTS/safety.json"
fi

if [ -d "$REPO_ROOT/dashboard/node_modules" ] && command -v npm &>/dev/null; then
  (cd "$REPO_ROOT/dashboard" && npm audit --json > "$REPORTS/npm-audit.json" 2>&1 || true)
  echo "     npm-audit.json written"
else
  echo "     npm audit skipped (run: cd dashboard && npm install)"
  echo '{"vulnerabilities":{}}' > "$REPORTS/npm-audit.json"
fi

echo "[3/5] SAST analysis (Bandit + Semgrep)..."

if have_python_tool bandit; then
  run_python_tool bandit \
    -r "$REPO_ROOT/target-app/src/" \
    -f json \
    -o "$REPORTS/bandit.json" \
    --exit-zero 2>/dev/null || true
  echo "     bandit.json written"
else
  echo "     bandit not found, install: pip install bandit"
  echo '{"results":[]}' > "$REPORTS/bandit.json"
fi

if have_python_tool semgrep; then
  run_python_tool semgrep \
    --config "$REPO_ROOT/scanner/semgrep_rules.yml" \
    --json \
    --output "$REPORTS/semgrep.json" \
    "$REPO_ROOT/target-app/src/" \
    2>/dev/null || true
  echo "     semgrep.json written"
else
  echo "     semgrep not found, install: pip install semgrep"
  echo '{"results":[]}' > "$REPORTS/semgrep.json"
fi

echo "[4/5] Container scan (Trivy)..."

if [ "$SKIP_DOCKER" = true ]; then
  echo "     skipped (--skip-docker)"
  echo '{"Results":[]}' > "$REPORTS/trivy.json"
elif command -v trivy &>/dev/null && command -v docker &>/dev/null; then
  echo "     Building image..."
  docker build -t securepipeline-local:scan "$REPO_ROOT/target-app/" -q
  trivy image \
    --format json \
    --output "$REPORTS/trivy.json" \
    --exit-code 0 \
    securepipeline-local:scan 2>/dev/null || true
  echo "     trivy.json written"
else
  echo "     trivy or docker not found, skipping"
  echo '{"Results":[]}' > "$REPORTS/trivy.json"
fi

echo "[5/5] OPA policy gate..."

run_python_tool python "$REPO_ROOT/scanner/aggregate.py" \
  --commit-sha "$COMMIT_SHA" \
  --branch "$BRANCH" \
  --gitleaks "$REPORTS/gitleaks.json" \
  --safety "$REPORTS/safety.json" \
  --npm-audit "$REPORTS/npm-audit.json" \
  --bandit "$REPORTS/bandit.json" \
  --semgrep "$REPORTS/semgrep.json" \
  --trivy "$REPORTS/trivy.json" \
  --output "$REPORTS/aggregate.json" || \
python3 "$REPO_ROOT/scanner/aggregate.py" \
  --commit-sha "$COMMIT_SHA" \
  --branch "$BRANCH" \
  --gitleaks "$REPORTS/gitleaks.json" \
  --safety "$REPORTS/safety.json" \
  --npm-audit "$REPORTS/npm-audit.json" \
  --bandit "$REPORTS/bandit.json" \
  --semgrep "$REPORTS/semgrep.json" \
  --trivy "$REPORTS/trivy.json" \
  --output "$REPORTS/aggregate.json"

GATE_RESULT=$?

if [ "$SKIP_OPA" = false ] && command -v opa &>/dev/null; then
  python "$REPO_ROOT/scanner/opa_input.py" \
    --report "$REPORTS/aggregate.json" \
    --policy "$REPO_ROOT/opa/policies/devsecops.rego" \
    --output "$REPORTS/opa-decision.json" || \
  python3 "$REPO_ROOT/scanner/opa_input.py" \
    --report "$REPORTS/aggregate.json" \
    --policy "$REPO_ROOT/opa/policies/devsecops.rego" \
    --output "$REPORTS/opa-decision.json"
  GATE_RESULT=$?
fi

echo ""
if [ $GATE_RESULT -eq 0 ]; then
  echo "==================================================="
  echo "  All gates passed - deployment cleared"
  echo "==================================================="
else
  echo "==================================================="
  echo "  Gate blocked - deployment prevented"
  echo "==================================================="
fi

echo ""
echo "  Reports written to: $REPORTS/"
echo "  To view in dashboard: cd dashboard && npm run dev"
echo ""

exit $GATE_RESULT
