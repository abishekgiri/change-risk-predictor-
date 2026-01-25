import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compliancebot.explain.types import ExplanationReport, Contributor
from compliancebot.explain import markdown

def test_markdown_determinism():
 """
 Snapshot test: ensures markdown output is deterministic.
 Same report → same markdown string.
 """
 # Create a fixed report
 report: ExplanationReport = {
 "risk_score": 82,
 "risk_prob": 0.76,
 "decision": "FAIL",
 "risk_level": "HIGH",
 "top_contributors": [
 {
 "id": "critical_path",
 "title": "Critical paths touched",
 "impact": 0.45,
 "severity": "HIGH",
 "summary": "Touched critical paths: auth/, payments/",
 "details": [
 "Critical path score: 1.00",
 "Matched patterns: auth/, payments/",
 "Files: auth/login.py, payments/processor.py"
 ],
 "evidence": ["Linked to issue #342"],
 "metrics": {}
 },
 {
 "id": "churn",
 "title": "High churn",
 "impact": 0.35,
 "severity": "MEDIUM",
 "summary": "High churn for this repo (z=2.13)",
 "details": [
 "Total churn: 1240 LOC (added 700, deleted 540)",
 "Files changed: 31 (above p90=18)",
 "Concentration: top file = 62% of churn"
 ],
 "evidence": [],
 "metrics": {}
 },
 {
 "id": "dependency",
 "title": "Blast radius",
 "impact": 0.20,
 "severity": "MEDIUM",
 "summary": "Large blast radius: impacts 6 services",
 "details": [
 "Dependency risk score: 0.60",
 "Includes tier-0 services: auth, payments, checkout"
 ],
 "evidence": [],
 "metrics": {}
 }
 ],
 "all_contributors": None,
 "explain_version": "v1",
 "feature_version": "v6",
 "model_version": "baseline-v1"
 }
 
 # Render markdown
 md_output = markdown.render(report)
 
 # Expected snapshot (golden output)
 expected = """**ComplianceBot: HIGH** — 82/100 (76%) — **FAIL**

### Top Risk Contributors

1. **Critical paths touched** ( HIGH) — Touched critical paths: auth/, payments/
 - Critical path score: 1.00
 - Matched patterns: auth/, payments/
 - Files: auth/login.py, payments/processor.py

2. **High churn** (🟡 MEDIUM) — High churn for this repo (z=2.13)
 - Total churn: 1240 LOC (added 700, deleted 540)
 - Files changed: 31 (above p90=18)
 - Concentration: top file = 62% of churn

3. **Blast radius** (🟡 MEDIUM) — Large blast radius: impacts 6 services
 - Dependency risk score: 0.60
 - Includes tier-0 services: auth, payments, checkout

### Evidence

- Linked to issue #342

<details>
<summary>Metadata</summary>

- **Feature Version**: v6
- **Model Version**: baseline-v1
- **Explain Version**: v1
</details>"""
 
 # Assert exact match
 assert md_output == expected, f"Markdown output does not match snapshot.\n\nExpected:\n{expected}\n\nGot:\n{md_output}"
 
 print("✅ Markdown snapshot test passed (deterministic output verified)")

def test_markdown_determinism_multiple_runs():
 """
 Run markdown rendering multiple times to ensure stability.
 """
 report: ExplanationReport = {
 "risk_score": 50,
 "risk_prob": 0.50,
 "decision": "WARN",
 "risk_level": "MEDIUM",
 "top_contributors": [],
 "all_contributors": None,
 "explain_version": "v1",
 "feature_version": "v6",
 "model_version": None
 }
 
 # Render 10 times
 outputs = [markdown.render(report) for _ in range(10)]
 
 # All should be identical
 assert len(set(outputs)) == 1, "Markdown output is not deterministic across multiple runs"
 
 print("✅ Markdown stability test passed (10 identical renders)")

if __name__ == "__main__":
 test_markdown_determinism()
 test_markdown_determinism_multiple_runs()
 print("\n✅ All explainability snapshot tests passed")
