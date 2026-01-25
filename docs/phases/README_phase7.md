# Phase 7: AI Assistant Layer

**Status:** Production Ready 
**Version:** 7.0

Phase 7 introduces an AI Assistant layer on top of the deterministic Trust Layer (Phase 6).

This phase adheres to the **Iron Rule of AI in Compliance**:

> **AI can explain and suggest, but never enforce.**

All enforcement remains deterministic. AI operates strictly as a non-authoritative assistant, guarded by a rigorous Safety Gate.

---

## Architecture of Trust

The system enforces strict separation between **Authority** and **Assistant** responsibilities.

### 1. Authority Layer (Phase 6)
- Calculates risk scores
- Makes PASS / WARN / BLOCK decisions
- Generates immutable audit artifacts
- Source of truth

### 2. Assistant Layer (Phase 7)
- Reads authority audit artifacts
- Rewrites technical logs into human-readable narratives
- Suggests remediation actions
- Persists AI outputs separately for auditability
- Never modifies decisions

Phase 7 is entirely optional and can be disabled without affecting enforcement or compliance outcomes.

---

## Core Features

### 1. AI Explanation Writer (`ai/explain_writer.py`)
Transforms deterministic explanations into clear, persona-aware narratives (e.g., engineer-focused or executive-friendly), without inventing facts.

**Evidence-Locked Reasoning:**
- AI explanations inject factual data from the authority record
- Example: `"Change volume is high (21517 lines changed)"` instead of generic `"Code churn > 500 lines"`
- All numbers and file paths are verified against authority evidence

**Input:** `Violation: Change exceeds churn threshold` 
**AI Output:** 
```
Risk is high because this change exceeds the configured churn threshold 
and modifies historically sensitive components.

Key reasons:
• Change volume is high (21517 lines changed)
• Code churn > 500 lines
• Hotspot modified

Evidence Refs: risk_score, factor:extremely_high_code_churn
```

---

### 2. Suggested Fixes (`ai/fix_suggester.py`)
Provides non-enforcing engineering guidance to unblock risky changes.

**Example:** 
```
• Add Regression Tests (M)
 Why: Hotspot modified
 Evidence: file:core/auth.py
```

**Safety:** Unsafe advice (e.g., disabling security controls) is actively filtered.

---

### 3. The Safety Gate (`ai/safety_gate.py`)
**Checkpoint Charlie.** All AI output must pass this gate before being shown.

- **Fact consistency:** Hallucinated scores or files → REJECT
- **Decision contradiction:** AI disagrees with authority → REJECT
- **Evidence integrity:** References missing artifacts → REJECT
- **Numeric hallucination:** AI invents numbers not in authority record → REJECT

**Status Display:** CLI shows `[Safety Gate: PASS]` or `[Safety Gate: FAIL]` prominently.

---

## Usage

### Live Demo
See the Authority and AI Assistant working together on a "Hard" test case:

```bash
python3 -m compliancebot.cli pick-hard \
 --repo prometheus/prometheus \
 --mode huge_churn \
 --ai-explain \
 --ai-suggestions
```

**Expected Output:**
```
AI ASSISTANT (Non-Enforcing) [Safety Gate: PASS]
============================================================
AI Summary: High risk detected due to churn.

Key reasons:
• Change volume is high (21517 lines changed)
• Code churn > 500 lines
• Hotspot modified

Next steps:
• Split PR
• Add tests

Evidence Refs: risk_score, factor:extremely_high_code_churn
------------------------------------------------------------
Disclaimer: AI-generated. Verify against audit evidence.
============================================================

SUGGESTED FIXES
============================================================
• Add Regression Tests (M)
 Why: Hotspot modified
 Evidence: file:core/auth.py
------------------------------------------------------------
Disclaimer: AI-generated. Verify before applying.
============================================================

AI artifacts written to: audit_bundles/prometheus_prometheus/pr_17855/{uuid}/ai
```

### Developer API
```python
from compliancebot.ai.explain_writer import AIExplanationWriter
from compliancebot.ai.safety_gate import AISafetyGate

# 1. Generate AI Explanation
writer = AIExplanationWriter()
ai_json = writer.generate(
 decision_context={"decision": "BLOCK", "risk_score": 75, "evidence": {"churn": 21517}},
 authority_explanation=authority_explanation
)

# 2. Validate Safety
gate = AISafetyGate()
errors = gate.validate_explanation(ai_json, authority_record)
if not errors:
 print(f"[Safety Gate: PASS]")
 print(ai_json['summary'])
else:
 print(f"[Safety Gate: FAIL] {errors}")
```

---

## Audit Bundle Persistence

All AI artifacts are persisted to the audit bundle for full traceability:

```
audit_bundles/{repo}/{pr}/{uuid}/
├── ai/
│ ├── ai_explanation.v1.json # Full AI explanation with evidence refs
│ ├── fix_suggestions.v1.json # Suggested fixes with effort estimates
│ └── ai_safety_report.json # Safety gate validation results
├── artifacts/
├── findings.json
├── manifest.json
└── reports/
```

This ensures:
- **Auditability:** Every AI output is traceable
- **Reproducibility:** AI explanations can be replayed
- **Compliance:** Meets enterprise audit requirements

---

## Verification

We provide a master script to verify the entire AI pipeline and Safety Gate.

```bash
# Run All Phase 7 Verifications
./scripts/run_phase7.sh
```

**Expected Output:**
```text
=== Phase 7: AI Explanations ===
[PASS] AI Explanation Schema Verified
[PASS] Evidence References Present
[PASS] Disclaimer Present

=== Phase 7: Fix Suggestions ===
[PASS] Standard Suggestion Verified
[PASS] Safety Filter Verified: Unsafe suggestion removed.

=== Phase 7: Safety Gate ===
[PASS] Valid Explanation Passed
[PASS] Contradiction Caught
[PASS] Unsafe Content Caught
[PASS] Numeric Hallucination Caught

=== Phase 7: End-to-End ===
[PASS] AI Explanation Generated & Safe
[PASS] Fix Suggestions Generated & Safe
[PASS] Artifacts written to audit_bundles/mock_phase7/ai/

Phase 7 Pipeline Verified
Phase 7 FULLY VERIFIED
```

---

## Enterprise-Grade Features

Phase 7 includes production-ready polish:

1. **Evidence-Locked Reasoning**: AI injects real data (e.g., `21517 lines changed`)
2. **Safety Gate Status**: Prominently displays `[Safety Gate: PASS]` in CLI
3. **Evidence Traceability**: Prints `Evidence Refs:` for all explanations and suggestions
4. **Audit Bundle Persistence**: AI artifacts written to canonical bundle structure
5. **Fact Consistency Checks**: Numeric hallucination detection prevents invented numbers

---

## Manifesto

**Why separate AI?**

In compliance and security, **predictability is paramount**. An ML model that blocks a deployment 99% of the time correctly is still a failure because the 1% error destroys trust.

By keeping the **Enforcement** deterministic (Phase 6) and using **AI** only for **Explanation** (Phase 7), we get the best of both worlds:

1. **Reliability:** The gate never flakes.
2. **Usability:** The output is human-friendly.
3. **Safety:** Hallucinations are impossible to act upon because they cannot change the decision.
4. **Auditability:** Every AI output is traceable to authority evidence.
5. **Trust:** Engineers can verify AI claims against immutable audit logs.

---

## Future Enhancements

Phase 7 is production-ready with mock AI. Future work could include:

- **Real LLM Integration**: Replace `MockProvider` with OpenAI/Anthropic/Claude
- **Policy Recommendation**: AI suggests new policies based on violation patterns
- **Violation Clustering**: Group similar violations for batch remediation
- **False-Positive Analysis**: Learn from override patterns to improve policies
- **Multi-Language Support**: Generate explanations in different languages

---

**Phase 7 Status: COMPLETE**

All core features implemented, verified, and polished to enterprise standards.
