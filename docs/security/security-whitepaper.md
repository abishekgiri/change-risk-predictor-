# ReleaseGate Security Whitepaper

## 1. Executive Summary

ReleaseGate is a governance enforcement layer for Jira workflow transitions. It evaluates change risk and policy controls before allowing state changes (for example, `Ready for Release` to `Done`), then records deterministic, tamper-evident decision artifacts for audit and compliance workflows.

## 2. Threat Model

ReleaseGate is designed to reduce the impact of the following classes of failure:

- Unauthorized workflow transitions into protected states
- Policy tampering between policy authoring and policy enforcement
- Evidence or decision record manipulation after decision issuance
- Insider override abuse and self-approval patterns
- Audit log mutation or deletion
- Supply chain drift between evaluated policy and active policy snapshot

## 3. Security Architecture

Core components:

- Jira integration layer (transition check and authorization)
- Policy engine (snapshot-bound decision evaluation)
- Decision ledger (append-only, deterministic decision records)
- Evidence graph and proof bundle generator
- Dashboard and drill-down interfaces for governance operations

Enforcement flow:

1. Jira transition request enters ReleaseGate.
2. Policy engine resolves active snapshot for the tenant/scope.
3. Risk and policy evaluation produces an allow/block decision.
4. Decision is written to append-only audit records.
5. Evidence and proofs are exported for auditor verification.

## 4. Key Security Controls

| Control | Description |
| --- | --- |
| Immutable policy snapshot binding | Every decision references the policy snapshot/hash used at evaluation time. |
| Deterministic replay | Historical decisions can be recomputed to verify reproducibility. |
| Tamper-evident ledgers | Audit records are append-oriented and verifiable through proof artifacts. |
| Separation of duties | Approval and override workflows support role separation constraints. |
| Time-bound overrides | Manual override actions are TTL-bound and audited. |
| Fail-closed enforcement options | Outage and degraded-mode behavior is explicitly documented and controlled. |

## 5. Data Protection Model

ReleaseGate is built as a metadata-governance control plane:

- No source code ingestion is required for core Jira transition governance.
- Decision records store governance metadata, context, and policy bindings.
- Sensitive secrets are expected to be injected through secret-management systems.
- Tenant boundaries and role/scopes are enforced through auth context.

## 6. Operational Security Posture

ReleaseGate publishes controls and behavior documentation that supports enterprise review:

- Failure-mode semantics and SLA targets (`docs/sla_failure_modes.md`, `docs/sla.md`)
- Regional and residency strategy (`docs/multi_region_strategy.md`)
- Proof verification and auditor workflows (`docs/compliance/*`)

## 7. Trust & Audit Fabric

ReleaseGate provides a cryptographic trust layer that makes system integrity provable rather than claimed.

### Trust Score

A 0–100 composite score aggregated from six weighted components:

| Component | Weight | Criteria |
| --- | --- | --- |
| Ledger Integrity | 25 | All override hash chains are valid with no broken links |
| Checkpoint Freshness | 20 | Latest signed checkpoint is within 36 hours |
| Checkpoint Signed | 15 | Latest checkpoint carries an Ed25519 cryptographic signature |
| Signal Freshness | 15 | Zero-trust mode active — stale signals are rejected |
| Key Integrity | 15 | No signing keys have been flagged as compromised |
| External Anchoring | 10 | At least one checkpoint anchored to an external system |

### Evidence Graph

Structured query interface over the decision history. Supports filtering by status, approval state, actor, workflow, and time window. Every result includes four integrity hashes (decision, input, policy, replay) enabling independent verification.

### Tamper-Evidence Guarantees

- **Append-only tables**: 10+ audit tables are protected by database triggers that raise exceptions on UPDATE or DELETE attempts. Works on both SQLite and PostgreSQL.
- **Merkle trees**: Transparency log entries are organized into Merkle trees with inclusion proofs for any individual record.
- **DSSE envelopes**: Decision attestations use Dead Simple Signing Envelopes with Ed25519 signatures.
- **RFC 3161 anchoring**: Checkpoints can be anchored to external timestamp authorities for independent proof of existence.

### Zero-Trust Signal Freshness

Configurable enforcement that rejects stale input signals:

- `max_age_seconds`: Maximum allowable age for signal data
- `require_computed_at`: Signals must carry a computation timestamp
- `require_signal_hash`: Signals must include a content hash for integrity
- `fail_on_stale`: When enabled, stale signals cause a hard block rather than a warning

## 8. Validation and Assurance

Operational assurance is supported by:

- Automated test suites for policy, onboarding, metrics, and quota paths
- Dashboard contracts and typed API responses
- Replay and evidence tooling for post-incident and audit workflows
- Trust score monitoring through the audit dashboard
- Tamper-evidence proof tests validating append-only trigger protection

This whitepaper complements (does not replace) tenant-specific security assessments, threat modeling, and infrastructure controls required by each enterprise deployment.
