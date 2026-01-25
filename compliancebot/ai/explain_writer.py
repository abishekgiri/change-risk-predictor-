import json
import os
from typing import Dict, Any
from compliancebot.ai.provider import get_provider

class AIExplanationWriter:
    """
    Rewrites deterministic authority explanations into tailored AI narratives.
    Strictly follows schemas/ai_explanation_v1.json.
    """
    def __init__(self):
        self.provider = get_provider()
        self.schema_path = os.path.join(os.path.dirname(__file__), "../../schemas/ai_explanation_v1.json")
        with open(self.schema_path) as f:
            self.schema = json.load(f)

    def generate(self, decision_record: Dict[str, Any], authority_explanation: Any) -> Dict[str, Any]:
        """
        Generates AI explanation JSON from authority inputs.
        """
        # 1. Construct Evidence-Based Prompt
        # We assume authority_explanation can be a DecisionExplanation obj or dict
        expl_text = getattr(authority_explanation, "narrative", str(authority_explanation))
        factors = getattr(authority_explanation, "factors", [])
        
        prompt = f"""
        You are a compliance assistant. Rewrite the following deterministic explanation for a software engineer.
        
        INPUT DATA (AUTHORITY):
        - Decision: {decision_record.get('decision', 'UNKNOWN')}
        - Risk Score: {decision_record.get('risk_score', 0)}
        - Narrative: {expl_text}
        - Verified Factors: {[f.label for f in factors] if factors else "None"}
        
        INSTRUCTIONS:
        1. Summarize the key reasons clearly.
        2. Suggest next steps based on the input narrative.
        3. CITE EVIDENCE: You must include "evidence_refs" listing the factors used (e.g. "factor:churn").
        4. DISCLAIMER: You must include "AI-generated. Verify against audit evidence."
        
        OUTPUT FORMAT: Must match the provided JSON schema.
        """
        
        # 2. Call AI Provider
        try:
            ai_output = self.provider.generate_json(prompt, self.schema)
            
            # 1. Normalize summary to avoid "AI Summary: AI Summary: ..."
            summary = ai_output.get("summary", "")
            if isinstance(summary, str):
                for prefix in ("AI Summary:", "Summary:"):
                    if summary.strip().lower().startswith(prefix.lower()):
                        summary = summary.split(":", 1)[1].strip()
                ai_output["summary"] = summary

            # 2. Evidence-lock at least one key reason (prevents vague AI reasons)
            def _get_churn(decision_record: Dict[str, Any]) -> Any:
                # Search common locations used by Phase 6 + CLI
                for keypath in (
                    ("evidence", "churn"),
                    ("features", "churn"),
                    ("features", "lines_changed"),
                    ("evidence", "lines_changed"),
                    ("feature_vector", "churn"),
                    ("feature_vector", "lines_changed"),
                ):
                    cur = decision_record
                    ok = True
                    for k in keypath:
                        if isinstance(cur, dict) and k in cur:
                            cur = cur[k]
                        else:
                            ok = False
                            break
                    if ok and cur is not None:
                        return cur
                return None

            churn = _get_churn(decision_record)

            if churn is not None and isinstance(churn, (int, float)):
                reasons = ai_output.get("key_reasons") or []
                if isinstance(reasons, list):
                    # Only add if high churn logic implies it, or just factual statement
                    if churn > 500: # Threshold context awareness would be better, but simple fact is good
                        locked = f"Change volume is high ({churn} lines changed)"
                        # Avoid duplicates grossly
                        if not any(str(churn) in r for r in reasons):
                            reasons.insert(0, locked)
                        ai_output["key_reasons"] = reasons

            # 3. Post-processing: Enforce Dynamic Evidence Refs match REAL IDs for Trust
            real_refs = ["risk_score"]
            if hasattr(authority_explanation, "factors"):
                for f in authority_explanation.factors:
                    # Prefer exact ID if available, else reliable slug
                    fid = getattr(f, "id", None)
                    if fid:
                        real_refs.append(f"factor:{fid}")
                    else:
                        slug = f.label.lower().replace(" ", "_").replace("/", "_")
                        real_refs.append(f"factor:{slug}")
            
            # Merge with AI generated refs but prefer real ones for strictness?
            # Actually, simply appending to ensures coverage.
            # But wait, Provider returns the dict. The prompt asked for refs.
            # Let's augment the result.
            current_refs = ai_output.get("evidence_refs", [])
            # Add real refs if missing
            for r in real_refs:
                if r not in current_refs:
                    current_refs.append(r)
            
            # Remove generic mock ref if real refs present
            if len(real_refs) > 1 and "factor:churn" in current_refs:
                current_refs.remove("factor:churn")
            
            ai_output["evidence_refs"] = current_refs

            return ai_output
        except Exception as e:
            # Fallback for safety
            return {
                "error": str(e),
                "summary": "AI generation failed.",
                "disclaimer": "AI-generated. Error occurred."
            }

