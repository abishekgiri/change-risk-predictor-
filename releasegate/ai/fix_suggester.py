import importlib.resources as resources
import json
from typing import Dict, Any, List
from releasegate.ai.provider import get_provider

class AIFixSuggester:
    """
    Generates non-enforcing engineering suggestions.
    Strictly filters out unsafe advice.
    """
    def __init__(self):
        self.provider = get_provider()
        # Packaged data dir (releasegate/schemas/) via importlib.resources
        # so this resolves from an installed wheel, not just a dev checkout.
        _ref = resources.files("releasegate.schemas").joinpath("fix_suggestions_v1.json")
        self.schema = json.loads(_ref.read_text(encoding="utf-8"))

        self.unsafe_terms = ["disable security", "skip tests", "bypass", "turn off", "ignore"]

    def propose(self, decision_record: Dict[str, Any], factors: List[Any]) -> Dict[str, Any]:
        """
        Generates suggestions JSON.
        """
        # 1. Build Prompt
        factor_desc = "\n".join([f"- {f.label}: {f.evidence}" for f in factors])

        prompt = f"""
        You are a senior engineer helper. Suggest 3 concrete fixes for this blocked PR.

        RISK FACTORS:
        {factor_desc}

        INSTRUCTIONS:
        1. Propose constructive engineering actions (e.g. "Add regression tests", "Use feature flag").
        2. NEVER suggest disabling checks or security.
        3. CITE EVIDENCE: Use "evidence_refs" (e.g. "file:foo.py").

        OUTPUT FORMAT: JSON matching schema.
        """

        # 2. Call AI
        try:
            result = self.provider.generate_json(prompt, self.schema)

            # 3. Post-Generation Safety Filter
            safe_suggestions = []
            if "suggestions" in result:
                for s in result["suggestions"]:
                    text_blob = (s.get("title", "") + s.get("why", "")).lower()
                    if any(term in text_blob for term in self.unsafe_terms):
                        # unsafe - skip
                        continue
                    safe_suggestions.append(s)

            result["suggestions"] = safe_suggestions
            return result

        except Exception:
            return {"suggestions": []}
