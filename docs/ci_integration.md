# CI/CD Integration Guide

RiskBot is designed to run natively in your CI pipelines (GitHub Actions, GitLab CI) to gate changes based on risk.

**Config file**: `riskbot.yaml` (repo-local, versioned with code).

## 1. Quick Start (GitHub Actions)

**GitHub Check name**: `RiskBot / Risk Score` (stable name for branch protection rules).


Add `.github/workflows/riskbot_pr.yml` to your repository:

```yaml
uses: your-org/riskbot/.github/workflows/riskbot_pr.yml@main
with:
  enforcement: report_only # Change to 'enforce' to block merges
```

Or copy the full workflow from `workflows/riskbot_pr.yml`.

### Prerequisites
- **GITHUB_TOKEN**: Automatically provided by Actions.
- **Config**: Ensure `riskbot.yaml` exists in repo root.

### Exit Codes
- `0` = PASS (or `report_only` mode)
- `1` = FAIL (blocking)
- `2` = WARN (non-blocking signal, useful for scripts)

## 2. Configuration (`riskbot.yaml`)

The behavior of the CI check is controlled by your repo configuration.

```yaml
scoring:
  enforcement: report_only # 'report_only' (always pass) vs 'enforce' (fail job on high risk)

thresholds:
  fail_score: 75
  fail_prob: 0.75
  
  overrides:
    prod:
      fail_score: 60 # Stricter for production branches
```

### Environment Variables
- `RISKBOT_ENFORCEMENT`: Override config (e.g., `enforce` in CI settings).
- `RISKBOT_ENV`: active environment (`prod`, `staging`) to load overrides.

## 3. Deployment Gating

To gate deployments, run RiskBot on the commit *before* deploying.

```bash
# Example Shell Script
python3 -m riskbot.cli analyze-pr \
  --repo owner/repo \
  --pr 123 \
  --output result.json

# Check decision
DECISION=$(jq -r .decision result.json)
if [ "$DECISION" == "FAIL" ]; then
  echo "RiskBot prevented deploy."
  exit 1
fi
```

## 4. GitLab CI

See [GitLab Integration](gitlab_ci.md) for detailed `.gitlab-ci.yml` setup.
