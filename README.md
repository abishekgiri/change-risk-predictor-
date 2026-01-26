# ComplianceBot

**Deterministic Compliance Enforcement & Change Risk Analysis for Modern CI/CD**

ComplianceBot is an enterprise-grade compliance and change-risk analysis platform designed for software teams that require **predictable enforcement**, **audit-ready evidence**, and **transparent decision-making**.

It enforces security and compliance policies (SOC 2, ISO 27001, HIPAA) and evaluates operational change risk across pull requests — **without using machine learning in the enforcement path**.

AI is used only as a non-enforcing assistant to explain decisions and suggest remediation, never to make or modify decisions.

---

## Why ComplianceBot Exists

Most compliance and security tooling fails in one of two ways:

1. **Manual processes** that are slow, inconsistent, and unscalable
2. **Black-box automation** that makes unpredictable decisions and destroys trust

ComplianceBot takes a different approach.

**Every enforcement decision is deterministic, explainable, and auditable.**

This makes ComplianceBot suitable for:
- Regulated environments
- External audits
- High-risk production systems
- Organizations that require trust in automation

---

## Core Guarantees

- **No ML in enforcement** — decisions are 100% reproducible
- **Immutable audit evidence** — every run produces a tamper-evident bundle
- **Policy-as-Code** — compliance rules are versioned and reviewed like software
- **AI never enforces** — it can explain and suggest, but cannot block or approve
- **Full traceability** — every decision links back to source policy and evidence

---

## High-Level Architecture

ComplianceBot is built in explicit phases, each adding capability while preserving determinism.

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 7: AI Assistant (Optional) │
│ • AI Explanations • Fix Suggestions • Safety Gate │
└─────────────────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 6: Enterprise UX & Trust │
│ • Human Explanations • Remediation • Analytics │
└─────────────────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 5: Evidence & Audit Layer │
│ • Hash-Chained Logs • Evidence Bundles • Traceability │
└─────────────────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: Policy Engine & DSL │
│ • Policy-as-Code • Compiler • Standard Packs │
└─────────────────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Core Compliance Controls │
│ • Secrets • Privileged Code • Approvals │
└─────────────────────────────────────────────────────────────┘
```

**Authority vs Assistant** separation is enforced at the architecture level.

---

## Quick Start

### Requirements

- **Python 3.10+**
- GitHub Personal Access Token (read-only is sufficient for analysis)

### Installation

```bash
git clone https://github.com/yourusername/change-risk-predictor.git
cd change-risk-predictor

pip install -r requirements.txt

cp .env.example .env
# add GITHUB_TOKEN to .env
```

### GitHub Action Usage

Integrate directly into your CI pipeline without managing Python dependencies:

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on:
  pull_request:

jobs:
  compliance:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v3
      - uses: abishekgiri/change-risk-predictor-@v1
        with:
          mode: report_only # or 'block' to enforce
          token: ${{ secrets.GITHUB_TOKEN }}
```

See [docs/phase8_packaging.md](docs/phase8_packaging.md) for full documentation.

### Demo (Recommended)

Run a real, high-risk scenario against a large public repository:

```bash
python3 -m compliancebot.cli pick-hard \
 --repo prometheus/prometheus \
 --mode huge_churn \
 --ai-explain \
 --ai-suggestions
```

This demonstrates:
- Deterministic enforcement
- Human-readable explanations
- AI assistant output
- Full audit bundle generation

---

## CLI Usage

### Analyze a Pull Request

```bash
python3 -m compliancebot.cli analyze-pr \
 --repo owner/repo \
 --pr 123
```

### With AI Assistance (Non-Enforcing)

```bash
python3 -m compliancebot.cli analyze-pr \
 --repo owner/repo \
 --pr 123 \
 --ai-explain \
 --ai-suggestions
```

### Enforcement Modes

```bash
COMPLIANCEBOT_ENFORCEMENT=enforce # hard gate
COMPLIANCEBOT_ENFORCEMENT=report_only
```

### Exit Codes

- **0** → PASS
- **1** → BLOCK
- **2** → WARN

---

## Policy-as-Code

Policies are written in a human-readable DSL and compiled into deterministic YAML.

```groovy
policy ACME_Sec_01 {
 version: "1.0.0"
 name: "Enforce Code Review"
 
 control Approvals {
 signals: [ approvals.count ]
 }
 
 rules {
 require approvals.count >= 2
 }
}
```

Policies are:
- **Versioned**
- **Reviewed**
- **Compiled**
- **Fully traceable** to enforcement results

 **Documentation:** [docs/phases/README_phase4.md](docs/phases/README_phase4.md)

---

## Compliance Controls

Out-of-the-box enterprise controls include:

- Secret scanning (AWS keys, tokens, private keys)
- Privileged file modification detection
- Approval enforcement
- License compliance
- Environment boundary protection

 **Documentation:** [docs/phases/README_phase3.md](docs/phases/README_phase3.md)

---

## Immutable Audit Bundles

Every run produces a tamper-evident audit bundle:

```
audit_bundles/{repo}/{pr}/{uuid}/
├── manifest.json # SHA256 hashes
├── findings.json # Technical findings
├── policies_used.json # Active policies
├── inputs/ # PR snapshot
├── artifacts/ # Code diffs
├── reports/ # Human & machine reports
└── ai/ # Optional AI artifacts
```

AI artifacts are stored separately to preserve authority immutability.

 **Documentation:** [docs/phases/README_phase5.md](docs/phases/README_phase5.md)

---

## Explainable Decisions (Phase 6)

All decisions are accompanied by deterministic explanations:

```
Operational Risk Gate: BLOCK (Score: 75/100)

Primary Drivers:
- Extremely High Code Churn: 21,517 lines (Threshold: 500)

Recommended Actions:
- Split PR into smaller changes
- Add regression tests
```

 **Documentation:** [docs/phases/README_phase6.md](docs/phases/README_phase6.md)

---

## AI Assistant (Phase 7 — Optional)

### The Iron Rule of AI in Compliance

> **AI can explain and suggest, but never enforce.**

AI operates **after** decisions are made and must pass a Safety Gate.

Example output:

```
AI ASSISTANT (Non-Enforcing) [Safety Gate: PASS]

Key reasons:
• Change volume is high (21,517 lines)
• Churn threshold exceeded

Evidence Refs:
risk_score, factor:extremely_high_code_churn
```

AI outputs are:
- **Fact-locked**
- **Evidence-referenced**
- **Audited**
- **Persisted separately**

 **Documentation:** [docs/phases/README_phase7.md](docs/phases/README_phase7.md)

---

## Project Structure

```
change-risk-predictor/
├── compliancebot/ # Core application
│ ├── ai/ # Phase 7: AI Assistant
│ │ ├── explain_writer.py
│ │ ├── fix_suggester.py
│ │ ├── safety_gate.py
│ │ └── provider.py
│ ├── audit/ # Phase 5: Audit & Evidence
│ │ ├── log.py
│ │ └── traceability.py
│ ├── evidence/
│ │ └── bundler.py
│ ├── ux/ # Phase 6: Enterprise UX
│ │ ├── explain.py
│ │ ├── remediation.py
│ │ └── analytics.py
│ ├── policies/ # Phase 4: Policy definitions
│ │ ├── dsl/ # Human-readable policies
│ │ │ ├── standards/ # SOC2, ISO27001, HIPAA
│ │ │ └── company/ # Custom policies
│ │ └── compiled/ # Generated YAML (DO NOT EDIT)
│ ├── policy_engine/
│ │ ├── compile.py
│ │ └── loader.py
│ ├── engine.py # Compliance Engine
│ └── cli.py # Command-line interface
├── scripts/ # Verification & utilities
│ ├── run_phase3.sh
│ ├── run_phase4.sh
│ ├── run_phase5.sh
│ ├── run_phase6.sh
│ └── run_phase7.sh
├── tests/ # Test suite
│ ├── test_engine.py
│ ├── test_policies.py
│ ├── test_audit.py
│ └── test_ai.py
├── docs/ # Documentation
│ ├── phases/ # Phase-specific docs
│ │ ├── README_phase3.md
│ │ ├── README_phase4.md
│ │ ├── README_phase5.md
│ │ ├── README_phase6.md
│ │ └── README_phase7.md
│ ├── policy_authoring.md
│ ├── standard_packs.md
│ ├── ci_integration.md
│ └── dsl_reference.md
├── audit_bundles/ # Generated audit evidence
├── .env.example # Environment template
├── requirements.txt # Python dependencies
├── compliancebot.yaml # Configuration
└── README.md # This file
```

---

## Verification

Each phase includes its own verification script:

```bash
./scripts/run_phase3.sh
./scripts/run_phase4.sh
./scripts/run_phase5.sh
./scripts/run_phase6.sh
./scripts/run_phase7.sh
```

Run all tests:

```bash
pytest
```

---

## Configuration

### Environment Variables

```bash
GITHUB_TOKEN=...
COMPLIANCEBOT_ENFORCEMENT=report_only
COMPLIANCEBOT_AI_PROVIDER=mock
```

### Policy Configuration

```yaml
scoring:
 enforcement: report_only
 
policies:
 enabled:
 - SOC2
 - ISO27001
 - HIPAA
```

---

## Design Principles

### 1. Determinism over ML

**ML may assist interpretation, but must never control enforcement in compliance-critical systems.**

All enforcement decisions are deterministic and reproducible.

### 2. Auditability first

Every decision produces cryptographic evidence suitable for external audits.

### 3. Separation of concerns

**Authority decides. Assistant explains.**

The enforcement layer and AI layer are architecturally separated.

### 4. Policy-as-Code

Compliance rules are versioned, reviewed, and tested like software.

### 5. Zero trust automation

No implicit trust. Everything is proven with evidence.

---

## Documentation

- **[Phase 3 – Core Controls](docs/phases/README_phase3.md)**: Secret scanning, privileged code detection, approvals
- **[Phase 4 – Policy Engine](docs/phases/README_phase4.md)**: DSL, compiler, standard packs
- **[Phase 5 – Audit Layer](docs/phases/README_phase5.md)**: Immutable evidence bundles, hash-chained logs
- **[Phase 6 – Trust & UX](docs/phases/README_phase6.md)**: Explanation engine, remediation, analytics
- **[Phase 7 – AI Assistant](docs/phases/README_phase7.md)**: AI explanations, fix suggestions, safety gate

Additional resources:
- [Policy Authoring Guide](docs/policy_authoring.md)
- [Standard Packs Reference](docs/standard_packs.md)
- [CI/CD Integration](docs/ci_integration.md)
- [DSL Reference](docs/dsl_reference.md)

---

## Status

**Production Ready (Core Architecture Verified)**

All phases 3–7 are complete, verified, and auditable.

---

## License

MIT License — see [LICENSE](LICENSE).

---

**ComplianceBot** — Deterministic compliance automation with complete transparency and auditability.
trigger Mon Jan 26 01:50:16 EST 2026
trigger Mon Jan 26 01:52:40 EST 2026
trigger3 Mon Jan 26 01:57:18 EST 2026
trigger4 Mon Jan 26 01:58:02 EST 2026
trigger5 Mon Jan 26 01:59:31 EST 2026
trigger-final Mon Jan 26 02:03:33 EST 2026
trigger-final Mon Jan 26 02:10:09 EST 2026
trigger-final Mon Jan 26 02:12:05 EST 2026
