# Auditor Walkthrough

## Audience

External auditors, internal audit, compliance reviewers, and security assessors.

## Objective

Verify that ReleaseGate governance decisions are:

- policy-bound
- tamper-evident
- attributable
- independently verifiable

## Walkthrough Steps

## 1) Select a Decision Sample

Choose a representative set of decisions (allowed, blocked, override-used) from the review window.

Recommended fields per sample:

- `decision_id`
- `created_at`
- `release_status`
- `reason_code`
- `policy_hash`

## 2) Open Decision Explainer

Navigate to decision explain view and capture:

- decision outcome and reason chain
- bound policy hash / snapshot hash
- key signals and risk components
- evidence links / replay references

## 3) Export Proof Bundle

For each sampled decision, export the proof bundle and retain:

- decision payload
- policy snapshot
- evidence payload
- signature envelope
- anchor receipt/checkpoint metadata

## 4) Verify Bundle Integrity

Follow `/docs/compliance/proof_bundle_verification.md`:

- decision hash validation
- signature verification
- policy snapshot hash verification
- anchor verification

Record pass/fail for each sample.

## 5) Review Override Governance

Inspect override events for sampled period:

- who requested / approved overrides
- whether TTL and reason are present
- whether SoD conflicts were blocked

Required checks:

- override records are auditable
- no uncontrolled permanent override
- emergency actions are attributable

## 6) Review Policy Lifecycle Evidence

Inspect policy events and diffs:

- activation/rollback events
- affected scope metadata
- correlation to integrity or drift changes (if applicable)

This validates controlled change management and rollback traceability.

## 7) Document Findings

For each sampled decision/change:

- artifact completeness
- integrity verification result
- control exceptions (if any)
- remediation recommendation and owner

## Auditor Evidence Checklist

- [ ] Decision sample list with timestamps
- [ ] Proof bundles retained for sample
- [ ] Hash/signature verification records
- [ ] Anchor verification records
- [ ] Override governance review notes
- [ ] Policy lifecycle review notes
- [ ] Final exceptions and remediation log

## Optional PDF Export

If your audit process requires PDF artifacts:

```bash
pandoc docs/compliance/auditor_walkthrough.md -o docs/compliance/auditor_walkthrough.pdf
```

Generate PDF versions of the other compliance docs using the same pattern when needed.
