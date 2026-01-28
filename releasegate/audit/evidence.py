import json
import time
from typing import Dict, Any, List

class EvidenceBundler:
    """
    Generates Audit Evidence Bundles.
    """
    def bundle(self, 
        control_result: Dict[str, Any], 
        raw_signals: Dict[str, Any],
        engine_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        
        bundle = {
            "audit_id": f"audit_{int(time.time())}_{raw_signals.get('entity_id')}",
            "timestamp": raw_signals.get("timestamp"),
            "actor": raw_signals.get("author"),
            "entity": {
                "type": "pull_request",
                "id": raw_signals.get("entity_id"),
                "repo": raw_signals.get("repo_slug"),
                "head_sha": engine_metadata.get("head_sha", "unknown")
            },
            "control_result": control_result["control_result"],
            "severity": control_result["severity"],
            "policies_evaluated": len(control_result.get("policies", [])),
            "triggered_policies": [
                p["policy_id"] for p in control_result.get("policies", []) if p["triggered"]
            ],
            "signals_evaluated": {
                "churn": raw_signals.get("total_churn"),
                "files_changed_count": len(raw_signals.get("files_changed", [])),
                "core_risk_score": engine_metadata.get("core_risk_score")
            },
            "raw_metrics": {
                "files": raw_signals.get("files_changed", [])[:50], # Cap size
                "touched_services": raw_signals.get("touched_services", [])
            },
            "full_result": control_result
        }
        return bundle

    def export_json(self, bundle: Dict[str, Any], path: str):
        with open(path, "w") as f:
            json.dump(bundle, f, indent=2)

 
 # PDF export could be added here using a library later
