# Phase 5: Evidence & Audit Layer

**Status:** Production Ready 
**Version:** 5.0

Phase 5 introduces a robust **System of Record** to ComplianceBot. It ensures that every policy decision is not just "enforced" but also "proven." All compliance checks now generate immutable, tamper-evident evidence trails suitable for external audits (SOC 2, ISO 27001).

---

## Architecture

The Audit Layer sits downstream of the Policy Engine. It does not affect pass/fail logic but strictly observes and records the outcome.

### 1. Hash-Chained Audit Log (`audit/log.py`)
A continuous, append-only log of every event.
- **Format:** NDJSON (Newline Delimited JSON).
- **Integrity:** Uses SHA256 hash chaining.
- `event[N].previous_hash == hash(event[N-1])`
- Modification of any past event breaks the chain for all subsequent events.
- **Path:** `audit_bundles/logs/<repo>/audit.ndjson`

### 2. Immutable Evidence Bundles (`evidence/bundler.py`)
A self-contained directory created for *every* analysis run. It contains everything an auditor needs to verify the decision offline, years later.
- **Path:** `audit_bundles/<repo>/pr_<num>/<audit_id>/`
- **Manifest:** `manifest.json` contains SHA256 hashes of all files in the bundle.

---

## Bundle Structure

```text
audit_bundles/
owner_repo/
pr_123/
uuid-audit-id/
manifest.json # Root of Trust (hashes of all files below)
findings.json # Full technical findings with Traceability
policies_used.json # List of policy IDs active during run
inputs/
pr_metadata.json # Snapshot of PR state (author, branch, etc)
artifacts/
diff.patch # The actual code change (diff)
snippets/ # Extracted code snippets for specific violations
reports/
report.md # Human-readable summary
report.csv # Spreadsheet format
report.json # Machine-readable format
```

---

## Traceability

Every finding in `findings.json` and the generated reports is enriched with Phase 4 data:

| Field | Example | Description |
|-------|---------|-------------|
| `policy_id` | `SEC-PR-002.R1` | The specific compiled rule ID |
| `parent_policy` | `SEC-PR-002` | The human-readable policy name |
| `compliance` | `{"SOC2": "CC6.1"}` | Mapping to external standards |
| `dsl_source` | `policies/dsl/...` | Source file of the policy |

---

## Usage

Phase 5 features are enabled by default in the CLI.

### Basic Run
```bash
python3 -m compliancebot.cli analyze-pr --repo owner/repo --pr 123
```
*Creates a bundle in `./audit_bundles` and appends to the log.*

### Custom Output Location
```bash
python3 -m compliancebot.cli analyze-pr --repo owner/repo --pr 123 \
--audit-out /mnt/secure_volume/audit_logs
```

### Export Formats
Control which reports are generated in the bundle:
```bash
python3 -m compliancebot.cli analyze-pr ... --report json,csv
```
*(Options: `all` (default), `json`, `md`, `csv`, `none`)*

### Disable Audit (Dev Mode)
To ship faster or validte rules without creating noise:
```bash
python3 -m compliancebot.cli analyze-pr ... --no-bundle --no-audit-log
```

---

## Verification

We provide a suite of scripts to verify the integrity of the audit layer. To run the full verification suite (including unit tests, policy compilation, and all Phase 5 integrity checks):

```bash
PYTHONPATH=. pytest -q && \
PYTHONPATH=. python3 -m compliancebot.policy_engine.compile && \
PYTHONPATH=. python3 scripts/verify_phase5_audit_log.py && \
PYTHONPATH=. python3 scripts/verify_phase5_bundle.py && \
PYTHONPATH=. python3 scripts/verify_phase5_traceability.py && \
echo " ALL SYSTEMS (PHASE 5) VERIFIED"
```
