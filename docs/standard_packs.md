# Standard Rule Packs Documentation

ComplianceBot comes with three pre-built standard rule packs. These are technically verified implementations of common compliance controls.

## 1. SOC 2 Type II
Located in: `compliancebot/policies/dsl/standards/soc2/`

| Policy ID | Control | Logic |
|-----------|---------|-------|
| **SOC2_CC6** | Logical Access | Blocks hardcoded secrets (`secrets.detected`). Requires approvals for access changes. |
| **SOC2_CC7** | System Operations | Monitors privileged changes. Blocks environment boundary violations. |
| **SOC2_CC8** | Change Management | Requires at least 1 approval (`approvals.count >= 1`). Bans unauthorized licenses. |

## 2. ISO 27001:2013
Located in: `compliancebot/policies/dsl/standards/iso27001/`

| Policy ID | Annex A Control | Logic |
|-----------|-----------------|-------|
| **ISO27001_A9** | Access Control (A.9) | Enforces secret scanning and access reviews. |
| **ISO27001_A12** | Operations Security (A.12) | Separation of Dev/Prod environments. Change management enforcement. |
| **ISO27001_A14** | System Acquisition (A.14) | Secure engineering principles. License compliance. |

## 3. HIPAA Security Rule
Located in: `compliancebot/policies/dsl/standards/hipaa/`

| Policy ID | Section | Logic |
|-----------|---------|-------|
| **HIPAA_164_312_a** | Access Control | Technical policies for unique user ID (no shared secrets). |
| **HIPAA_164_312_b** | Audit Controls | Flags sensitive changes for audit trail generation. |
| **HIPAA_164_312_c** | Integrity | Protects ePHI from improper alteration (Environment/License checks). |

## Usage
These packs are compiled by default. You can extend or override them using Custom Company Policies (see `policy_authoring.md`).
