# SOC 2 / ISO 27001 Control Mapping

## Scope

This mapping connects ReleaseGate governance controls to common SOC 2 Trust Services Criteria and ISO 27001 Annex controls.

> Note: This is a technical control map for audits and customer reviews. Final attestation language should align with your formal audit scope and auditor guidance.

## Control Mapping Matrix

| ReleaseGate Control | SOC 2 (example) | ISO 27001 Annex A (example) | Evidence Source |
| --- | --- | --- | --- |
| Tamper-evident decision ledger | CC6.6, CC7.2 | A.8.15, A.8.16 | audit decisions, hash chain fields, proof bundles |
| Policy snapshot binding to decisions | CC7.2 | A.8.32 | decision + snapshot hash linkage |
| Override audit trail + TTL | CC7.3 | A.8.15, A.8.16 | override events, expiry metadata |
| Signal freshness (TTL) enforcement | CC6.6, CC7.2 | A.8.32 | stale-signal reason codes, decision traces |
| Separation of duties checks | CC6.1 | A.5.3, A.5.15 | SoD reason codes, approval records |
| Incident/degraded-mode audit events | CC7.4 | A.5.24, A.5.25 | security audit events + outage fallback events |
| Anchoring/checkpoint verification trail | CC7.2 | A.8.15, A.8.16 | checkpoint and anchor receipts |

## Change Management Coverage

ReleaseGate contributes to change-management evidence through:

- policy lifecycle events (`DRAFT` -> `STAGED` -> `ACTIVE` / rollback)
- policy diff and impact evidence
- deterministic decision + policy hash binding
- replay/explainer artifacts for investigation

This supports control narratives around approved and traceable production changes.

## Separation of Duties Coverage

Operational SoD controls include:

- role-based access and scoped auth for governance operations
- override approval restrictions
- explicit conflict blocking when actor identities overlap in prohibited ways

Evidence examples:

- blocked decisions with SoD reason codes
- approval records and audit metadata
- override creation + approver linkage

## What to Provide During Audit

- representative proof bundles
- policy lifecycle event records
- override and approval evidence
- dashboard/explorer exports for sampled periods

These artifacts allow auditors to test both design effectiveness and operating effectiveness.
