# Data Processing Agreement (DPA) Template

This template outlines the data processing commitments for ReleaseGate deployments. Adapt to your organization's legal requirements before execution.

## 1. Scope of Processing

ReleaseGate processes **governance metadata only**:

- Workflow transition requests (issue keys, transition IDs, timestamps)
- Policy evaluation context (risk scores, signal values, policy snapshot hashes)
- Decision records (allow/block verdicts with deterministic replay data)
- Override and approval records (actor identifiers, justifications, TTLs)
- Audit attestations (Ed25519 signatures, DSSE envelopes)

ReleaseGate does **not** process:

- Source code content
- Customer PII beyond actor identifiers (e.g., GitHub usernames)
- Financial, health, or other regulated personal data
- File contents, commit diffs, or binary artifacts

## 2. Data Categories

| Category | Examples | Retention |
| --- | --- | --- |
| Decision records | Audit decisions, policy snapshots | Configurable per tenant (default: indefinite for compliance) |
| Override records | Manual approvals, emergency overrides | Append-only, immutable |
| Attestations | Signed envelopes, key metadata | Append-only, immutable |
| Checkpoint data | Merkle roots, RFC 3161 anchors | Append-only, immutable |
| Operational logs | API request logs, error traces | 90 days rolling |
| Configuration | Tenant settings, policy definitions | Active until archived |

## 3. Security Measures

### Technical Controls

- **Encryption in transit**: TLS 1.2+ for all API communication
- **Encryption at rest**: Database-level encryption for production deployments
- **Append-only audit trail**: 10+ tables protected by database triggers preventing UPDATE/DELETE
- **Cryptographic integrity**: Ed25519 signatures on attestations and checkpoints
- **Merkle tree verification**: Inclusion proofs for transparency log entries
- **External anchoring**: RFC 3161 timestamp anchoring for independent proof-of-existence
- **Signal freshness**: Zero-trust rejection of stale input data

### Organizational Controls

- Role-based access control with scoped permissions
- Separation of duties for override and approval workflows
- Tenant isolation at the data layer
- Audit logging of all administrative actions

## 4. Sub-processors

ReleaseGate may use the following categories of sub-processors:

| Category | Purpose |
| --- | --- |
| Cloud infrastructure | Compute and storage hosting |
| Monitoring | Application performance and error tracking |
| External timestamp authorities | RFC 3161 anchoring for proof-of-existence |

Specific sub-processors will be listed in a supplementary schedule and updated with 30-day advance notice.

## 5. Data Subject Rights

ReleaseGate supports the following on request:

- **Access**: Export of all decision and audit records for a tenant
- **Portability**: Structured JSON/CSV export via the audit export API
- **Erasure**: Tenant data deletion (note: append-only audit records may be retained where legally required for compliance)

## 6. Breach Notification

- Detection-to-notification target: **72 hours**
- Notification includes: nature of breach, categories of data affected, mitigation steps taken, contact for further information
- Ongoing updates until resolution

## 7. Audit Rights

The data controller may:

- Request the current trust score and component breakdown via the API
- Run independent verification using proof bundles and Merkle inclusion proofs
- Export the full audit trail for external forensic review
- Inspect append-only trigger protection status

## 8. Data Deletion and Return

Upon termination:

- All tenant configuration and active data will be deleted within 30 days
- Audit records required for compliance obligations may be retained in encrypted, isolated storage for the legally required period
- A final export pack will be provided on request before deletion
