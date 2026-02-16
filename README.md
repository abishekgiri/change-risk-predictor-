# ReleaseGate

**Jira-native workflow governance and enforcement engine** with a declarative policy control plane, tamper-evident audit ledger, signed checkpoints, and reproducible audit proof packs.

ReleaseGate enforces risk-aware policies at Jira workflow transition time (e.g., `Ready for Release` → `Done`), blocks non-compliant releases, and produces cryptographically verifiable audit artifacts suitable for compliance programs (SOC2-style controls, change governance, separation of duties).

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v2.0.0--policy--control--plane-green.svg)](https://github.com/abishekgiri/change-risk-predictor-/releases/tag/v2.0.0-policy-control-plane)
[![Tests](https://img.shields.io/badge/tests-98%20passing-success.svg)](#development)

See also: [Contributing](CONTRIBUTING.md), [Security Policy](SECURITY.md), [Changelog](CHANGELOG.md).

Attestation and audit verification docs:
- [Attestation Contract](docs/ATTESTATION.md)
- [Verification Guide](docs/VERIFICATION.md)
- [Auditor Quickstart](docs/AUDITOR_QUICKSTART.md)
- [External Anchoring Wave Plan (55-step)](docs/external-anchoring-wave-plan-55.md)

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

## Decision Semantics Source of Truth

Decision output fields, `reason_code` meanings, and strict/permissive behavior are defined only in `docs/decision-model.md`.
Other docs (including this README) are descriptive and defer to that spec.
Forge runtime hardening and failure handling is documented in `docs/forge-hardening.md`.

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

## Trust Guarantees

- Signed attestations are deterministic (`Ed25519`) and verifiable offline.
- Public signing keys are published via root-signed manifests:
  - `/.well-known/releasegate-keys.json`
  - `/.well-known/releasegate-keys.sig`
- Key status semantics are explicit (`ACTIVE`, `DEPRECATED`, `REVOKED`).
- Transparency log records every attestation issuance in append-only storage.
- Transparency APIs:
  - `GET /transparency/latest` (default `50`, max clamp `500`, rejects `<= 0`)
  - `GET /transparency/{attestation_id}`
- Merkle anchoring rules (leaf format, ordering, parent hash, proof verification):
  - `docs/transparency_merkle.md`
- Signed daily external roots are published to:
  - `roots/YYYY-MM-DD.json`
  - Generated by GitHub Actions via `releasegate export-root --date <YYYY-MM-DD> --out roots/<YYYY-MM-DD>.json`
  - Default scheduler exports **yesterday's** UTC root (stable/finalized day)
- Roots are produced deterministically from ordered leaves using canonical JSON and signed with an Ed25519 root key.
- Root signing secret format:
  - `RELEASEGATE_ROOT_SIGNING_KEY` accepts Ed25519 private key as PEM, or 32-byte raw key (hex/base64)
  - `RELEASEGATE_ROOT_KEY_ID` identifies the root key used to sign published roots
- External root verification uses the pinned root public key (`RELEASEGATE_ROOT_KEY_ID`).
- Transparency proofs relate to published roots as:
  - `GET /transparency/proof/{attestation_id}` → inclusion proof
  - `GET /transparency/root/{date_utc}` / `roots/YYYY-MM-DD.json` → anchored root hash for verification
- Logs include `engine_build` metadata (`git_sha`, `version`) for traceability.
- DSSE + in-toto export is available for supply-chain interoperability:
  - CLI: `releasegate analyze-pr --repo ORG/REPO --pr 15 --tenant default --emit-dsse att.dsse.json`
  - API: `GET /attestations/{attestation_id}.dsse`
  - Top-level DSSE fields:
    - `payloadType: application/vnd.in-toto+json`
    - `payload` (base64 canonical in-toto Statement)
    - `signatures[{keyid,sig}]`
  - SDK verification:
    - `verify_dsse(envelope, public_keys_by_key_id)`

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
├── docs/                           # Current source-of-truth docs
│   ├── architecture.md
│   ├── decision-model.md
│   ├── policy-dsl.md
│   ├── security.md
│   ├── jira-config.md
│   ├── forge-hardening.md
│   ├── contracts/
│   └── legacy/                     # Superseded/historical docs
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

### One-command demo

```bash
make demo
```

### Validate deploy-time policy bundle

```bash
python -m releasegate.cli validate-policy-bundle
```

### Validate Jira transition/role mappings

```bash
python -m releasegate.cli validate-jira-config
python -m releasegate.cli validate-jira-config --check-jira
```

### Create signed checkpoint

```bash
python -m releasegate.cli checkpoint-override --repo org/service --tenant demo
```

### Verify DB migration status

```bash
python -m releasegate.cli db-migration-status
```

### Export proof pack

```bash
python -m releasegate.cli proof-pack --decision-id <id> --tenant demo --format json
```

### Verify proof pack offline

```bash
python -m releasegate.cli verify-proof-pack /path/to/proof-pack.json
```

### Export deterministic proofpack v1 zip

```bash
python -m releasegate.cli proofpack --decision-id <id> --tenant demo --out proofpack.zip
```

### Verify deterministic proofpack v1 zip

```bash
python -m releasegate.cli verify-pack proofpack.zip --format json
```

### Verify Merkle inclusion for an attestation

```bash
python -m releasegate.cli verify-inclusion --attestation-id <attestation_id> --tenant demo --format json
```

### Run policy simulation

```bash
python -m releasegate.cli simulate-policies --repo org/service --tenant demo --limit 100
```

### Lint policy definitions

```bash
python -m releasegate.cli lint-policies
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

### Golden Demo

Prerequisites: Python 3.11+, `make` (Docker optional; not required for `make golden`).

```bash
make golden
```

Artifacts are written to `out/golden/`.
`✅ PASS` means risk attach, transition block, override, proof-pack export+verify, replay, and simulation all succeeded.
Manual verify: `python -m releasegate.cli verify-proof-pack out/golden/proof_pack.json --format json --signing-key <key>`.

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
