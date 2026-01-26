from typing import Dict, Any, List

class AISafetyGate:
    """
    The Checkpoint Charlie for AI content.
    Prevents hallucinations and contradictions.
    """
    
    def validate_explanation(self, ai_json: Dict, authority_record: Dict) -> List[str]:
        """
        Returns list of violation errors. Empty list = PASS.
        """
        errors = []
        
        # 1. Fact Consistency: Risk Score
        # (This is tricky if AI isn't forced to output it. If it does, check it.)
        
        # 2. Evidence Links
        # AI 'evidence_refs' must exist in authority context?
        # For MVP: Ensure list exists and isn't empty if we require it.
        if "evidence_refs" not in ai_json:
            errors.append("Missing 'evidence_refs' field.")
        
        # 3. Disclaimer
        if "disclaimer" not in ai_json:
            errors.append("Missing AI disclaimer.")
        elif "AI-generated" not in ai_json["disclaimer"]:
            errors.append("Disclaimer must state 'AI-generated'.")
        
        # 4. Keyword Contradictions (Simple heuristic)
        # If Authority is BLOCK, AI shouldn't say "Approved"
        auth_decision = authority_record.get("decision", "UNKNOWN")
        summary = ai_json.get("summary", "").lower()
        
        if auth_decision == "BLOCK" and "approve" in summary:
            errors.append("Contradiction: Authority BLOCKED but AI mentions 'approve'.")
        
        # 5. Numeric Fact Consistency (Anti-Hallucination)
        # Extract numbers from AI text and ensure they exist in Authority source
        # This prevents "Churn > 500" becoming "Churn > 700"
        
        # Build whitelist of allowed numbers from authority
        allowed_numbers = self._extract_numbers(str(authority_record))
        ai_numbers = self._extract_numbers(str(ai_json))
        
        for num in ai_numbers:
            if num not in allowed_numbers:
                # Allow minor deviations or simple integers (0,1)? strict for now.
                # Actually, 0 and 1 are common in JSON structures, skipping them for noise reduction
                if num in [0, 1]: continue
                errors.append(f"Hallucinated Number: {num} found in AI but not in Authority record.")

        return errors

    def _extract_numbers(self, text: str) -> set:
        import re
        # Find all integers. Floats left out for simplicity in MVP
        return set(int(x) for x in re.findall(r'\d+', text))

    def validate_suggestions(self, suggestions_json: Dict) -> List[str]:
        errors = []
        suggestions = suggestions_json.get("suggestions", [])
        
        for s in suggestions:
            # Check Evidence
            if not s.get("evidence_refs"):
                errors.append(f"Suggestion '{s.get('title')}' missing evidence_refs.")
            
            # Content Filter (Double check)
            blob = (s.get("title","") + s.get("why","")).lower()
            if "disable" in blob and "security" in blob:
                errors.append("Unsafe suggestion detected (disable security).")
        
        return errors

