# ComplianceBot (formerly RiskBot) - Engineering Policy Enforcement

RiskBot is a deterministic, explainable change-risk analysis system for GitHub repositories. It analyzes pull requests and repository history to estimate the risk that a change will introduce bugs, regressions, or instability, and it explains *why* a change is risky in terms engineers actually understand.

RiskBot is designed as an engineering decision-support tool, not a black-box AI reviewer. It integrates cleanly into CI/CD workflows and scales from individual repos to team-level engineering operations.

---

## Table of Contents

* [Project Structure](#project-structure)
* [What Problem RiskBot Solves](#what-problem-riskbot-solves)
* [Core Capabilities](#core-capabilities)
* [How RiskBot Works](#how-riskbot-works)
* [Installation](#installation)
* [Authentication](#authentication)
* [CLI Commands](#cli-commands)
* [End-to-End Usage](#end-to-end-usage)
* [Real World Output](#real-world-output)
* [Data Quality Guarantees](#data-quality-guarantees)
* [Design Philosophy](#design-philosophy)
* [License](#license)
* [Author](#author)

---

## Project Structure

The codebase is organized into modular components for ingestion, scoring, and reporting.

```text
change-risk-predictor/
riskbot/ # Core application package
cli.py # CLI entrypoint (analyze-pr, hotspots, review-priority)
server.py # FastAPI server for GitHub Webhooks
main.py # Entrypoint logic
config.py # Configuration loading
features/ # Feature extraction (churn, complexity, history)
hotspots/ # Predictive bug hotspot engine
review/ # Review prioritization logic
scoring/ # Risk scoring models and thresholds
ingestion/ # Data providers (GitHub/GitLab) and normalization
explain/ # Explanation generation (Markdown/JSON)
storage/ # SQL/File storage backend
templates/ # Text templates for output
scripts/ # Operational scripts
ingest_repo.py # Batch ingestion script
verify_providers.py # Auth and provider verification
tests/ # Unit and integration tests
docs/ # Documentation assets
riskbot.yaml # Main configuration file
requirements.txt # Python dependencies
Procfile # Deployment configuration
Dockerfile # Container definition
README.md # Project documentation
```

---

## What Problem RiskBot Solves

Modern software teams merge large numbers of pull requests under time pressure. Existing tools focus on *style*, *tests*, or *security*, but rarely answer higher-level questions such as:

* Which PR should be reviewed first?
* Is this change actually risky, or just large?
* Where are bugs most likely to appear next sprint?
* When should a merge be blocked vs allowed?

RiskBot treats **code changes themselves as risk signals** and produces a clear, auditable assessment that helps engineers prioritize attention and reduce operational risk.

---

## Core Capabilities

### 1. Pull Request Risk Analysis

Analyze an individual PR and receive:

* Risk score (0-100)
* Risk probability (0.0-1.0)
* Risk level: LOW / MEDIUM / HIGH
* Decision: PASS / WARN / FAIL
* Human-readable explanation
* Machine-readable JSON output

```bash
riskbot analyze-pr --repo owner/repo --pr 6
```

### 2. Predictive Bug Hotspots

RiskBot analyzes repository history to surface **files most likely to cause future bugs**.

```bash
riskbot hotspots --repo owner/repo
```

Hotspot scoring considers:
* Historical change frequency
* Incident correlation
* Recent churn
* Limited-history uncertainty

This helps teams focus refactoring, testing, and reviews where it matters most.

### 3. PR Priority Triage

Automatically rank open PRs by urgency:

```bash
riskbot review-priority --repo owner/repo --open
```

Output priorities:
* **P0** - review immediately
* **P1** - review soon
* **P2** - normal priority

This is particularly useful for release managers, platform teams, and on-call rotations.

---

## How RiskBot Works

RiskBot combines deterministic heuristics with statistical normalization. There is no opaque ML black box in the critical path.

### Signals Used

* **Churn metrics**: lines changed, distribution, concentration
* **File history**: prior incidents and risky areas
* **Context signals**: dependencies, critical paths
* **Stability smoothing**: bounded normalization to avoid noisy scores

### Key Properties

* Deterministic (same input -> same output)
* Explainable (every score is justified)
* Robust to partial data
* Safe defaults (never blocks silently)

---

## Installation

### From source

```bash
git clone https://github.com/abishekgiri/change-risk-predictor
cd change-risk-predictor
pip install -e .
```

---

## Authentication

RiskBot can operate on public repositories without authentication, but **full fidelity analysis requires GitHub API access**.

Set a GitHub token:

```bash
export GITHUB_TOKEN='ghp_your_token_here'
```

Recommended scopes:
* Public repos: `public_repo`
* Private repos: `repo`

---

## CLI Commands

### Analyze a PR

```bash
riskbot analyze-pr --repo owner/repo --pr 6
```

Optional explicit token:

```bash
riskbot analyze-pr --repo owner/repo --pr 6 --token $GITHUB_TOKEN
```

### Find Hotspots

```bash
riskbot hotspots --repo owner/repo
```

### Review Priority

```bash
riskbot review-priority --repo owner/repo --open
```

Sync GitHub labels:

```bash
riskbot review-priority --repo owner/repo --open --sync-labels
```

---

## End-to-End Usage

Run the full pipeline:

```bash
riskbot analyze-pr --repo owner/repo --pr 6 \
&& riskbot hotspots --repo owner/repo \
&& riskbot review-priority --repo owner/repo --open
```

---

## Real World Output

Actual output from running `analyze-pr` on a public PR:

```json
// riskbot analyze-pr --repo abishekgiri/change-risk-predictor- --pr 6
{
"risk_score": 13,
"risk_prob": 0.13,
"risk_level": "LOW",
"decision": "PASS",
"reasons": [
"Moderate Churn: 108 LOC"
],
"evidence": [
"Files changed: 1",
"Modified: .github/workflows/ci-risk-bot.yml",
"Total churn: 108 LOC",
"Commits: 1",
"Concentrated Churn: 100% in single file"
],
"model_version": "baseline-v1",
"data_quality": "FULL"
}
```

---

## Data Quality Guarantees

RiskBot explicitly reports data completeness:

* **FULL** - all signals available
* **PARTIAL** - limited GitHub data (safe fallback behavior)

RiskBot never silently degrades or invents data.

---

## Design Philosophy

RiskBot follows three core principles:
1. **Explainability over accuracy claims**
2. **Determinism over hype**
3. **Engineering trust over novelty**

RiskBot does not claim to predict bugs perfectly. It provides **structured risk signals** that engineers can reason about.

---

## License

MIT License

---

## Author

**Abishek Kumar Giri**
Computer Science - Software & Systems Engineering

> RiskBot is built on the belief that **boring, explainable systems are the ones engineers trust in production**.
