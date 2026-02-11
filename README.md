# ReleaseGate

**Jira-native workflow governance and enforcement engine** with a declarative policy control plane, tamper-evident audit ledger, signed checkpoints, and reproducible audit proof packs.

ReleaseGate enforces risk-aware policies at Jira workflow transition time (e.g., `Ready for Release` → `Done`), blocks non-compliant releases, and produces cryptographically verifiable audit artifacts suitable for compliance programs (SOC2-style controls, change governance, separation of duties).

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v2.0.0--policy--control--plane-green.svg)](https://github.com/abishekgiri/change-risk-predictor-/releases/tag/v2.0.0-policy-control-plane)
[![Tests](https://img.shields.io/badge/tests-98%20passing-success.svg)](#development)

---

## Why ReleaseGate Exists

**Jira manages workflow.**  
**GitHub manages code.**

But there is no native enforcement layer that:

- Blocks risky releases based on policy
- Requires structured, role-aware approvals
- Prevents self-approval and override abuse
- Produces tamper-evident, replayable decision records
- Generates portable audit evidence bundles

**ReleaseGate fills that enforcement gap.**

It is **not advisory**.  
It is **not analytics**.  
It is a **governance control plane**.

---

## Core Capabilities

### 1. Transition-Level Hard Enforcement

- Deterministic `ALLOW` / `BLOCK` / `SKIPPED` decisions
- Strict fail-closed mode (configurable)
- Idempotent transition handling
- Concurrency-safe override processing
- Runs inside Atlassian Forge trust boundary

**Environment flags:**

```bash
RELEASEGATE_STRICT_MODE=true
RELEASEGATE_LEDGER_VERIFY_ON_STARTUP=true
RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION=true
```

### 2. Declarative Policy Control Plane

- YAML / JSON DSL
- Explicit version field
- Strict schema validation (`extra="forbid"`)
- Policy lint + CI enforcement
- Policy scoping (org / repo context overlays)
- Policy simulation ("what-if" mode)

**Example policy:**

```yaml
version: 1

policies:
  - id: high_risk_release
    when:
      risk: HIGH
      environment: production
    require:
      approvals: 2
      roles: [EngineeringManager, Security]
```

Each decision stores:

- `policy_id`
- `policy_version`
- `policy_hash`
- Full policy snapshot
- Full input snapshot

**Policies are treated as immutable artifacts.**

### 3. Separation of Duties Enforcement

ReleaseGate enforces governance constraints such as:

- PR author cannot self-approve
- Override requestor cannot self-approve
- Role-based approval validation
- Time-bound overrides with required justification

Overrides include:

- `expires_at`
- `justification`
- `actor_id`
- Idempotency key
- Ledger reference

### 4. Immutable Audit Ledger

- Append-only storage
- No `UPDATE` / `DELETE`
- Hash-chained entries
- Ledger verification API
- Startup integrity verification
- Migration-safe schema constraints

Each ledger entry references:

- Decision ID
- Policy hash
- Input snapshot hash
- Override linkage (if applicable)

### 5. Cryptographic Checkpointing

ReleaseGate generates **signed root checkpoints** (daily / weekly):

- Root hash of ledger state
- Digital signature
- Stored separately from primary ledger
- Verification API and CLI support

**This makes tampering detectable even with database access.**

### 6. Audit Proof Pack (Evidence Bundle)

Export a portable proof bundle (ZIP / JSON) containing:

- `decision_snapshot`
- `policy_snapshot`
- `input_snapshot`
- `override_snapshot` (if applicable)
- `chain_proof`
- `checkpoint_proof`
- `schema_version` metadata

**This allows independent verification outside the system.**

### 7. Deterministic Replay

Replay any historical decision using:

- Stored policy snapshot
- Stored input snapshot
- Original policy hash

Replay verifies:

- Outcome consistency
- Policy binding integrity
- Snapshot correctness

**Reproducibility is built-in.**

### 8. Policy Simulation ("What-If" Mode)

Simulate new policies against the last N decisions:

Metrics include:

- `would_newly_block`
- `would_unblock`
- `delta`
- Impact breakdown

**This enables safe policy rollout before enforcement.**

### 9. Minimal Metadata-Only GitHub Integration

ReleaseGate:

- Does **NOT** clone repositories
- Does **NOT** store diffs
- Does **NOT** store source code
- Does **NOT** persist access tokens

It consumes **PR metadata only**:

- `changed_files`
- `additions`
- `deletions`

Risk metadata is attached to Jira issue properties.

**Security posture is intentionally minimal.**

---

## Architecture Overview

```
GitHub PR → Risk Metadata (counters only)
            ↓
Jira Issue Property (releasegate_risk)
            ↓
Forge Workflow Validator
            ↓
Policy Control Plane
            ↓
ALLOW / BLOCK
            ↓
Immutable Ledger
            ↓
Signed Checkpoints
            ↓
Proof Pack Export
```

---

## Project Structure

```
change-risk-predictor/
├── releasegate/                    # Core enforcement engine
│   ├── audit/                      # Audit ledger & checkpointing
│   │   ├── checkpoints.py          # Signed checkpoint engine
│   │   ├── overrides.py            # Override ledger with idempotency
│   │   └── reader.py               # Ledger query interface
│   ├── decision/                   # Decision model & types
│   │   ├── types.py                # Policy snapshot binding
│   │   └── factory.py              # Decision creation
│   ├── engine_core/                # Isolated engine components
│   │   ├── decision_model.py       # Core decision logic
│   │   ├── policy_parser.py        # Policy DSL parser
│   │   └── evaluator.py            # Policy evaluation engine
│   ├── enforcement/                # Enforcement actions
│   │   ├── planner.py              # Enforcement planning
│   │   ├── runner.py               # Enforcement execution
│   │   └── actions/                # GitHub/Jira actions
│   ├── integrations/               # External integrations
│   │   ├── jira/                   # Jira workflow gate
│   │   │   ├── workflow_gate.py    # Transition enforcement
│   │   │   ├── client.py           # Jira API client
│   │   │   ├── routes.py           # Jira webhook routes
│   │   │   └── types.py            # Jira-specific types
│   │   └── github_risk.py          # GitHub metadata ingestion
│   ├── policy/                     # Policy control plane
│   │   ├── loader.py               # Policy registry loader
│   │   ├── policy_types.py         # Policy schema definitions
│   │   ├── lint.py                 # Policy validation & linting
│   │   └── simulation.py           # What-if simulation engine
│   ├── replay/                     # Deterministic replay
│   │   └── decision_replay.py      # Replay engine & API
│   ├── storage/                    # Database layer
│   │   └── schema.py               # SQLAlchemy models
│   ├── observability/              # Metrics & monitoring
│   │   └── internal_metrics.py     # Enforcement metrics
│   ├── cli.py                      # CLI commands
│   ├── server.py                   # FastAPI server
│   └── engine.py                   # Main engine orchestration
│
├── forge/                          # Atlassian Forge app
│   ├── release-gate/               # Forge validator
│   │   ├── src/index.js            # Validator entry point
│   │   ├── manifest.yml            # Forge manifest
│   │   └── static/                 # Admin UI
│   └── package.json
│
├── tests/                          # Test suite (98 passing)
│   ├── audit/                      # Audit ledger tests
│   │   └── test_overrides_chain.py
│   ├── decision/                   # Decision model tests
│   ├── enforcement/                # Enforcement tests
│   ├── integrations/               # Integration tests
│   │   └── jira/
│   ├── test_audit_checkpoints.py   # Checkpoint tests
│   ├── test_audit_proof_pack.py    # Proof pack export tests
│   ├── test_policy_simulation.py   # Simulation tests
│   ├── test_decision_replay.py     # Replay tests
│   └── test_policy_lint.py         # Policy lint tests
│
├── scripts/                        # Utility scripts
│   ├── demo_block_override_export.py
│   ├── seed_phase9_db.py
│   └── verify_phase*.py
│
├── docs/                           # Documentation
│   ├── architecture.md
│   ├── security_and_roles.md
│   ├── user_guide.md
│   ├── demo-flow.md
│   └── phases/                     # Phase documentation
│
├── .github/workflows/              # CI/CD
│   └── compliance-check.yml        # Policy lint enforcement
│
├── Makefile                        # Build targets
├── Dockerfile                      # Container image
├── docker-compose.yml              # Local stack
├── requirements.txt                # Python dependencies
├── pyproject.toml                  # Package metadata
└── README.md                       # This file
```

---

## Observability

Internal enforcement metrics:

- `transitions_evaluated`
- `transitions_blocked`
- `overrides_used`
- `skipped_count`
- `transitions_error`

**Available at:**

```
GET /integrations/jira/metrics/internal
```

---

## CLI Commands

### Generate demo flow

```bash
make demo
```

### Create signed checkpoint

```bash
releasegate checkpoint create
```

### Verify ledger + checkpoint

```bash
releasegate verify-ledger
releasegate verify-checkpoint
```

### Export proof pack

```bash
releasegate export-proof-pack --decision-id <id>
```

### Run policy simulation

```bash
releasegate simulate --last 100
```

### Lint policy definitions

```bash
releasegate lint
```

---

## Development

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run locally

```bash
uvicorn releasegate.server:app --reload
```

### Run tests

```bash
pytest
```

**Current status:**

- 98 tests passing
- Policy lint integrated into CI
- Deterministic enforcement verified

---

## Versioning

**Current milestone:**

```
v2.0.0-policy-control-plane
```

This version establishes:

- Governance control plane
- Signed checkpoint system
- Audit proof pack export
- Policy simulation engine
- Separation-of-duties enforcement
- Idempotent override handling

**Previous milestone:**

```
v1.0.0-governance-core
```

---

## Security Model

- Metadata-only ingestion
- No source code storage
- No diff retention
- No token persistence
- Hash-chained ledger
- Signed checkpoint verification
- Fail-closed configuration option

**ReleaseGate is designed to minimize data risk while maximizing governance integrity.**

---

## Positioning

### ReleaseGate is:

- Jira governance infrastructure
- Workflow enforcement primitive
- SDLC control layer
- Audit-ready policy engine

### ReleaseGate is not:

- A dashboard
- An analytics tool
- A developer scoring system
- A source code scanner

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Abishek Kumar Giri

---

## Contributing

This project enforces:

- Policy lint via CI
- Full test coverage for new features
- Deterministic behavior verification

See [docs/architecture.md](docs/architecture.md) for design principles.

---

## Support

For issues, questions, or feature requests, please open an issue on GitHub:

https://github.com/abishekgiri/change-risk-predictor-/issues
