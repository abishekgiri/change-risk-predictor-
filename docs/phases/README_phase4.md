# ComplianceBot Phase 4: Policy Engine & DSL

**Status:** Production Ready (Verified)
**Version:** 4.0.0

## Overview
Phase 4 introduces a deterministic, compiled **Policy Engine** that replaces the hardcoded python logic of Phase 3. It allows compliance teams to write policies in a human-readable Domain Specific Language (DSL) which are then compiled into secure, verifiable YAML rules.

## Key Features
- **Custom DSL:** Write policies in `.dsl` files with strict typing and logical operators.
- **Compiler:** 1-to-many expansion (1 Policy -> N Rules) with ID normalization.
- **Standard Packs:** Out-of-the-box support for SOC 2 (CC6-8), ISO 27001 (A.9, A.12, A.14), and HIPAA.
- **Traceability:** Every finding is tagged with Policy ID, Version, Standard, and Effective Date.
- **Performance:** Evaluation latency < 0.1ms.

## Architecture
```mermaid
graph LR
A[Human Policy (.dsl)] -->|Compiler| B[Compiled Rule (.yaml)]
B -->|Loader| C[Compliance Engine]
D[Signals (Git/Risk/etc)] --> C
C -->|Evaluate| E[Audit Finding]
```

## Usage

### 1. Writing a Policy
Create a file in `compliancebot/policies/dsl/company/my_policy.dsl`:
```groovy
policy ACME_Sec_01 {
version: "1.0.0"
name: "Enforce Code Review"
effective_date: "2026-01-01"

control Approvals {
signals: [ approvals.count ]
}

rules {
require approvals.count >= 2
}
}
```

### 2. Compiling (Build)
Run the compiler to generate YAML artifacts and `manifest.json`:
```bash
python3 -m compliancebot.policy_engine.compile
```
Artifacts will be generated in `compliancebot/policies/compiled/`.

### 3. Evaluating
The engine automatically loads compiled policies.
```python
from compliancebot.engine import ComplianceEngine
engine = ComplianceEngine(config)
result = engine.evaluate(signals)

if result.overall_status == "BLOCK":
print("Compliance Check Failed!")
```

## Directory Structure
- `policies/dsl/`: Source code (human editable).
- `policies/compiled/`: Generated artifacts (DO NOT EDIT MANUALLY).
- `scripts/verify_phase4_*.py`: Verification test suite.

## Standard Rule Packs
| Standard | Coverage | Path |
|----------|----------|------|
| **SOC 2** | CC6 (Access), CC7 (Ops), CC8 (Change) | `dsl/standards/soc2` |
| **ISO 27001** | A.9, A.12, A.14 | `dsl/standards/iso27001` |
| **HIPAA** | 164.312 (a/b/c) | `dsl/standards/hipaa` |

## Verification
To run the full Phase 4 verification suite:
```bash
PYTHONPATH=. \
python3 -m compliancebot.policy_engine.compile && \
python3 scripts/verify_phase4_dsl.py && \
python3 scripts/verify_phase4_standards.py && \
python3 scripts/verify_phase4_traceability.py && \
echo "PHASE 4 VERIFIED"
```
