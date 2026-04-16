# ReleaseGate Audit Pack

This index is the starting point for procurement review, security assessment, and compliance audit. Every linked document is independently readable; this file explains what to read and in what order.

## For the Auditor

| Document | What it proves |
| --- | --- |
| [Security Whitepaper](security/security-whitepaper.md) | System design, controls, and trust fabric architecture |
| [Threat Model](security/threat-model.md) | What attacks are mitigated and which are out of scope |
| [Tamper-Evidence Architecture](security/tamper-evidence.md) | What is immutable, how tampering is detected, how to verify |
| [Verification Guide](VERIFICATION.md) | Step-by-step offline verification of attestations and proof packs |
| [Transparency Merkle Rules](transparency_merkle.md) | Leaf contract, tree rules, inclusion proof algorithm |

## For the Procurement Team

| Document | What it covers |
| --- | --- |
| [SLA Targets](sla.md) | Availability, latency, anchoring durability, incident response |
| [SLA Failure Modes](sla_failure_modes.md) | Behavior under outage, fail-closed semantics, degraded mode |
| [DPA Template](compliance/dpa-template.md) | Data processing scope, retention, security measures, audit rights |
| [SOC2 Readiness](compliance/soc2-readiness.md) | Mapping of controls to SOC2 Trust Service Criteria |
| [SOC2 / ISO Mapping](compliance/soc2_iso_mapping.md) | Cross-reference to ISO 27001 and SOC2 criteria |

## For the Security Reviewer

| Document | What it covers |
| --- | --- |
| [Threat Model](security/threat-model.md) | STRIDE-style analysis of attestation and trust fabric threats |
| [Attestation Architecture](ATTESTATION.md) | DSSE envelope format, Ed25519 signing, in-toto statement |
| [Proof Pack Contract v1](contracts/proof_pack_v1.md) | Schema and verification contract for portable proof bundles |
| [Proof Bundle Verification](compliance/proof_bundle_verification.md) | How to verify a proof bundle from first principles |
| [Signal Freshness Model](compliance/signal_freshness_model.md) | Zero-trust signal freshness enforcement and configuration |
| [External Anchoring Runbook](ops/external-anchoring-runbook.md) | RFC 3161 anchoring operation, failure modes, retry policy |

## Verification Quickstart

To independently verify a decision proof pack without network access to ReleaseGate:

```bash
# 1. Export a proof pack from the dashboard: /audit/export
#    or via API: GET /audit/proof-pack/{decision_id}

# 2. Verify offline
python -m releasegate.cli verify-pack \
  --pack releasegate-audit-export.zip \
  --format json \
  --key-file public-keys.json

# 3. Optional: verify RFC 3161 timestamp
python -m releasegate.cli verify-pack \
  --pack releasegate-audit-export.zip \
  --tsa-ca-bundle tsa-ca.pem

# Expected output for a clean bundle:
# {
#   "schema_valid": true,
#   "payload_hash_match": true,
#   "valid_signature": true,
#   "trusted_issuer": true,
#   "replay_match": true,
#   "inclusion_proof_valid": true
# }
```

## Trust Score

The fastest way to check system integrity posture is the trust score endpoint:

```
GET /audit/trust-status?tenant_id=<tenant>
```

A score ≥80 means all critical trust components are passing. Scores below 80 include a breakdown of which component is failing and why.

## What Is Immutable

Ten database tables are append-only, protected by triggers that prevent UPDATE and DELETE on both SQLite and PostgreSQL. A complete list with descriptions is in [Tamper-Evidence Architecture](security/tamper-evidence.md).

## Sample Audit Export

A sample SOC2 v1 export bundle (anonymized) is available at:

```
GET /audit/export?repo=<repo>&contract=soc2_v1&format=json&tenant_id=<tenant>
```

The dashboard export UI at `/audit/export` provides a graphical interface for generating and downloading export bundles.
