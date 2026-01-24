# Phase 6: Enterprise UX & Trust

**Status:** Production Ready 
**Version:** 6.0

Phase 6 transforms ComplianceBot from a "black box" ML tool into a trusted partner for engineering teams. It focuses on **Explainability**, **Actionability**, and **Transparency**. Engineers get clear reasons for blocks, and managers get high-level compliance visibility.

---

## Core Features

### 1. Deterministic Explanation Engine (`ux/explain.py`)
We moved away from raw "Risk Scores" (e.g., "0.82") to semantic **Decision Narratives**.
- **Input:** Raw features (churn, hotspots, dependencies).
- **Logic:** Deterministic rule sets (no AI hallucinations).
- **Output:** Human-readable explanations.

**Example Output:**
> **Deployment BLOCKED due to high risk factors.**
> * **Extremely High Code Churn:** Change touches 21,517 lines.
> * **Critical Hotspot Modified:** Modifies `auth/login.py` (Tier-0).

### 2. Actionable Remediation (`ux/remediation.py`)
Every explanation is paired with specific actions to unblock the engineer.
- **High Churn?** -> "Split this PR into smaller atomic changes."
- **Tier-0 Dependency?** -> "Request Principal Engineer review."
- **No Tests?** -> "Add regression tests."

### 3. Compliance Analytics (`ux/analytics.py`)
Aggregates immutable audit logs into strategic metrics for leadership.
- **Block Rate:** Are we slowing down or speeding up?
- **Top Violations:** Which policies cause the most friction?
- **Risk Trends:** Is the organization getting safer over time?

---

## Usage

Phase 6 features are automatically integrated into the CLI.

### Run Analysis with Explanations
```bash
python3 -m compliancebot.cli analyze-pr --repo owner/repo --pr 123
```

You will see a new section in the output:
```text
============================================================
DECISION EXPLANATION
============================================================
Deployment APPROVED (Standard Risk). (Risk Score: 10/100)
Primary Drivers:
- Low Churn: Change touches 12 lines.

Recommended Actions:
- No specific actions required.
============================================================
```

### Accessing Dashboards
Dashboards are currently generated as static Markdown reports inside the Evidence Bundle.
Look for `reports/dashboard.md` in your audit artifacts.

---

## Verification

We provide a master script to verify the entire "Trust Layer" stack in one go. This runs the Explanation Engine assertions, Analytics aggregation tests, and End-to-End CLI verification.

```bash
# Run All Phase 6 Verifications
./scripts/run_phase6.sh
```

Expected Output:
```text
=== Running Phase 6: Explanation Engine ===
Verifying Phase 6 Explanation Engine
====================================

1. Testing High Churn Scenario...
Summary: Deployment BLOCKED due to high risk factors.
Top Factor: Extremely High Code Churn
High Churn Logic Verified

2. Testing Hotspot + Dependency Scenario...
Narrative Preview:
---
Deployment allowed with WARNINGS. (Risk Score: 65/100)
...
Ranking Logic Verified
Pass Logic Verified

Explanation Engine Verification Successful
=== Running Phase 6: Analytics & Dashboard ===
Verifying Phase 6 Analytics & Dashboard
=======================================

1. Daily Stats Verification...
Aggregation Logic Verified

2. Dashboard Generation Verification...
Dashboard Generation Verified

Analytics Verification Successful
=== Running Phase 6: End-to-End UX ===
Verifying Phase 6 Enterprise UX End-to-End
==========================================
Running CLI: python3 -m compliancebot.cli pick-hard --repo prometheus/prometheus --mode huge_churn

--- CLI Output Snippet ---
============================================================
DECISION EXPLANATION
============================================================
Operational Risk Gate: BLOCK (Score: 75/100)
Compliance Status: COMPLIANT
------------------------------------------------------------
Deployment BLOCKED due to high risk factors. (Risk Score: 75/100)
Primary Drivers:
- **Extremely High Code Churn**: Change touches 21517 lines (Threshold: 500)

Recommended Actions:
- Split this PR into smaller, atomic changes.
- Add comprehensive regression tests for the affected module.
============================================================

Audit Logged: 2726f97e4017...
Report-Only Mode: Result=COMPLIANT -> EXIT 0

--------------------------
Found UI Element: ' DECISION EXPLANATION'
Found UI Element: 'Recommended Actions:'
Found UI Element: 'Audit Bundle & Reports:'
Found UI Element: 'Audit Logged:'
Correct Diagnosis (Churn Detected)

Phase 6 Complete Verification Successful
Phase 6 FULLY VERIFIED
```

---

## Why This System Matters

Modern software organizations ship faster than ever, but most failures are still caused by risky changes that were entirely predictable. Large pull requests touching unstable files, critical dependencies, or historically fragile modules repeatedly slip through CI pipelines because traditional checks only validate correctness, not risk.

This system exists to close that gap.

Instead of asking “Does the code build and tests pass?”, it answers the harder and more valuable question:

> **“Should this change be allowed to ship right now?”**

### What Makes This Different

Most risk tools behave like black boxes: they produce a score, block a deploy, and leave engineers confused and frustrated. That approach fails in real organizations because trust, not accuracy, is the limiting factor.

This system is designed explicitly for enterprise trust.

- **Deterministic decisions**: The same change will always produce the same result. No stochastic behavior. No hidden state.
- **Human-readable explanations**: Every decision is accompanied by a clear narrative explaining *why* it was made, grounded in concrete evidence (e.g., code churn, historical hotspots, critical dependency impact).
- **Actionable remediation**: When a deployment is blocked or warned, the system explains exactly *how* to unblock it—smaller PRs, additional tests, senior review, canary deploys—turning friction into guidance.
- **Audit-grade logging**: Every decision, explanation, override, and outcome is recorded immutably. This enables compliance, post-incident analysis, and executive reporting without manual effort.
- **Operational risk ≠ compliance**: The system cleanly separates operational risk gating from compliance checks, reflecting how real enterprises actually operate.

### Why This Matters in Practice

- **For engineers**: Fewer surprise rollbacks and clearer expectations before code merges.
- **For managers**: Visibility into deployment risk trends, override behavior, and whether teams are genuinely improving over time.
- **For organizations**: Transforms CI/CD from a passive gate into an active risk management system—one that scales with team size, codebase complexity, and release velocity.

### The Core Idea

> **Failures are rarely random.**
> They leave footprints in version history, dependency graphs, and change patterns.
> 
> **This system makes those signals visible, explainable, and actionable—before they turn into incidents.**
