# ReleaseGate

Jira-native workflow enforcement engine with declarative policy controls and a tamper-evident audit ledger.

ReleaseGate enforces policy at Jira workflow transition time (for example, `Ready for Release -> Done`). It evaluates risk metadata attached to Jira issues, returns a deterministic decision, and records immutable audit artifacts suitable for SOC2/ISO-style controls.

## Why ReleaseGate Exists

Jira manages workflow. GitHub manages code.

What most teams still miss is a native enforcement layer that can:

- Block release transitions based on risk
- Require structured approvals
- Produce tamper-evident audit records
- Keep decisions deterministic and auditable

ReleaseGate fills that gap.

It is not advisory.
It is not a dashboard.
It is a governance primitive.

## Core Capabilities

### 1) Transition-Level Hard Enforcement

- Enforces policy on Jira transitions
- Deterministic decision model
- Explicit statuses: `ALLOWED`, `BLOCKED`, `SKIPPED`, `ERROR` (with `CONDITIONAL` supported)
- Optional strict fail-closed behavior
- No silent fail-open for missing critical inputs

### 2) Declarative Policy Engine

- YAML/JSON policy definitions
- Compiled policy loading
- Strict schema validation (`extra="forbid"`)
- Explicit operator/result enums
- Policy fingerprinting via `policy_hash`

Example compiled-style policy:

```yaml
policy_id: SEC-PR-001
version: "1.0.0"
name: "High Risk Requires Extra Approval"
scope: pull_request
controls:
  - signal: core_risk.severity_level
    operator: "=="
    value: "HIGH"
enforcement:
  result: BLOCK
  message: "High risk change requires additional approval"
```

### 3) Immutable Override Ledger

- Append-only records
- `UPDATE` and `DELETE` blocked at DB trigger level
- Hash-chained override events
- Per-repo verification and global verification
- Optional startup verification with fail-fast on corruption

### 4) SOC2-Ready Audit Export (`soc2_v1`)

Stable export contract fields:

- `decision`
- `reason_code`
- `human_message`
- `actor`
- `policy_version`
- `inputs_present`
- `override_id`
- `chain_verified` (when requested)

Formats:

- JSON
- CSV

### 5) Deterministic Demo Flow

One-command reproducible flow:

```bash
make demo
```

Output includes:

- Jira issue key
- Transition attempted
- Exact block reason
- Override actor and reason
- Decision IDs
- Export file paths

## Minimal GitHub Integration (By Design)

ReleaseGate intentionally keeps GitHub integration metadata-only:

- Uses PR counters (`changed_files`, `additions`, `deletions`)
- Attaches risk metadata to Jira issue property (`releasegate_risk`)
- Does not store source code, file contents, or diffs
- Does not clone repos for enforcement decisions

## Architecture Overview

```text
GitHub PR -> Metadata Risk Classification
          -> Jira Issue Property (releasegate_risk)
          -> Jira/Forge Workflow Validator
          -> Policy Engine (versioned + hashed)
          -> ALLOWED / BLOCKED / SKIPPED / ERROR
          -> Immutable Audit + Override Ledger
          -> SOC2 Export (JSON/CSV)
```

## Security Model

- Forge validator module included for Atlassian boundary enforcement
- Metadata-only risk path for GitHub integration
- Tamper-evident override chain
- Explicit strict-mode and ledger-verification controls

Environment toggles:

```bash
RELEASEGATE_STRICT_MODE=true
RELEASEGATE_LEDGER_VERIFY_ON_STARTUP=true
RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION=true
```

## API Surface

Primary endpoints:

- `POST /integrations/jira/transition/check`
- `GET /integrations/jira/metrics/internal`
- `GET /audit/export?repo=<repo>&contract=soc2_v1&format=json`
- `GET /audit/export?repo=<repo>&contract=soc2_v1&format=csv`
- `GET /audit/ledger/verify`

## Observability

Internal counters exposed at `/integrations/jira/metrics/internal`:

- `transitions_evaluated`
- `transitions_blocked`
- `overrides_used`
- `skipped_count`
- `transitions_error`

## Development

Install and run locally:

```bash
pip install -r requirements.txt
uvicorn releasegate.server:app --reload
```

Run tests:

```bash
pytest
```

Current test suite includes coverage for:

- Workflow validator edge cases
- Missing risk/policy handling
- Strict mode behavior
- Override chain integrity
- SOC2 export contract
- Minimal GitHub metadata risk flow

## Deterministic Replay

Replay against original input snapshots and policy fingerprints is planned as the next hardening phase.

## Versioning

Current milestone: `v1.0.0-governance-core`

## Positioning

ReleaseGate is built as:

- Jira governance infrastructure
- Workflow enforcement primitive
- Compliance-aware SDLC control layer

It is not:

- An analytics dashboard
- A developer productivity UI
- A source-code scanner

## License

MIT
