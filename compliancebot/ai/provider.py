import os
import json
from typing import Dict, Any, Optional

class AIProvider:
    """
    Abstract interface for AI generation.
    """
    def generate_json(self, prompt: str, schema: Dict[str, Any], model: str = "mock") -> Dict[str, Any]:
        raise NotImplementedError

    def generate_text(self, prompt: str, model: str = "mock") -> str:
        raise NotImplementedError

class MockProvider(AIProvider):
    """
    Deterministic mock provider for CI/Testing.
    Returns safe, schema-compliant dummy data.
    """
    def generate_json(self, prompt: str, schema: Dict[str, Any], model: str = "mock") -> Dict[str, Any]:
        # Simple heuristic to return valid data based on prompt context
        if "explanation" in prompt.lower():
            return {
                "summary": "High risk detected due to churn.",
                "tone": "engineer",
                "key_reasons": ["Code churn > 500 lines", "Hotspot modified"],
                "next_steps": ["Split PR", "Add tests"],
                "evidence_refs": ["risk_score", "factor:churn"],
                "disclaimer": "AI-generated. Verify against audit evidence."
            }
        elif "fix" in prompt.lower():
            return {
                "suggestions": [
                    {
                        "title": "Add Regression Tests",
                        "why": "Hotspot modified",
                        "evidence_refs": ["file:core/auth.py"]
                    }
                ]
            }
        return {}

    def generate_text(self, prompt: str, model: str = "mock") -> str:
        return "Mock AI Response: Validated."

def get_provider() -> AIProvider:
    """
    Factory to get the correct provider based on env.
    """
    # In future, check os.getenv("OPENAI_API_KEY")
    return MockProvider()
