# Compliance Control Mapping

This reference maps ReleaseGate capabilities to common governance and compliance frameworks.

## SOC 2 / ISO 27001 / FedRAMP Reference Map

| Framework | Control | ReleaseGate Capability |
| --- | --- | --- |
| SOC 2 | CC6.1/CC6.6 (logical access) | Tenant-aware role/scoped authorization and privileged action controls |
| SOC 2 | CC7.x (change monitoring) | Governance observability, trend metrics, drilldowns, and alerting pathways |
| SOC 2 | CC8.x (change management) | Policy simulation, activation ladder, rollback, activation history |
| ISO 27001 | A.6.1.2 (segregation of duties) | SoD and override workflow controls with auditability |
| ISO 27001 | A.12.1.2 (change management) | Workflow transition governance and policy-bound enforcement |
| ISO 27001 | A.12.4 (logging and monitoring) | Decision ledger, override logs, security events, evidence bundles |
| FedRAMP | CM-3 (configuration change control) | Policy snapshot binding + approval/rollout controls |
| FedRAMP | AU family (audit) | Deterministic decision records, proof packs, independent verification |
| FedRAMP | AC family (access control) | Tenant isolation, role assignment, scoped operation boundaries |

## Change Governance Coverage

ReleaseGate specifically supports:

- Transition-level enforcement before production-state movement
- Policy version and hash traceability
- Approval and override accountability with expiry windows
- Replay and evidence workflows for post-change verification

## Documentation Links

- Security whitepaper: `docs/security/security-whitepaper.md`
- SOC 2 readiness: `docs/compliance/soc2-readiness.md`
- Proof verification: `docs/compliance/proof_bundle_verification.md`
- SLA/failure modes: `docs/sla.md`, `docs/sla_failure_modes.md`
