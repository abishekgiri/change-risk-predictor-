# Documentation Index

Architecture overview:

```text
Architecture
 ├─ Governance Engine
 ├─ Observability
 ├─ SLA & Failure Modes
 ├─ Multi-Region Strategy
 ├─ Compliance Documentation
 └─ Deployment Automation
```

Current source-of-truth docs:

- `decision-model.md` — decision output contract and reason-code semantics
- `policy-dsl.md` — policy DSL/compiler target and validation rules
- `architecture.md` — module boundaries and flow
- `security.md` — security posture and controls
- `sla_failure_modes.md` — enforcement outage behavior, cache/grace semantics, and fail-mode controls
- `sla.md` — service-level targets for availability, latency, and anchoring recovery
- `multi_region_strategy.md` — multi-region architecture, residency model, failover, and regional key custody strategy
- `architecture/architecture.md` — executive architecture diagram and component responsibilities
- `compliance/` — auditor documentation pack:
  - `compliance/proof_bundle_verification.md`
  - `compliance/signal_freshness_model.md`
  - `compliance/soc2_iso_mapping.md`
  - `compliance/auditor_walkthrough.md`
  - `compliance/soc2-readiness.md`
  - `compliance/compliance-mapping.md`
- `security/security-whitepaper.md` — enterprise security whitepaper
- `business/roi-calculator.md` — governance ROI model for customer success and procurement
- `forge-installation.md` — Forge installation and Jira connection steps
- `install-2-hour-guide.md` — enterprise 2-hour install walkthrough
- `jira-config.md` — Jira transition/role mapping
- `forge-hardening.md` — Forge runtime hardening behavior
- `ops/external-anchoring-runbook.md` — daily anchoring operations runbook
- `ops/phase0-checkpoint-log.md` — manual Phase 0 reliability checkpoint history
- `attestations/dsse-intoto.md` — DSSE + in-toto interoperability contract
- `contracts/` — versioned artifact contracts (`soc2_v1`, `checkpoint_v1`, `proof_pack_v1`)
- `contracts/versioning_policy.md` — public artifact compatibility and deprecation policy

Legacy/superseded docs live under `legacy/` and are not normative.
