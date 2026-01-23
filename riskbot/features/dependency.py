from typing import Dict, Tuple, Any, List
from riskbot.features.types import RawSignals, FeatureExplanation
from riskbot.features import normalize
# from riskbot.ingestion.dependency_graph import DependencyGraph # If available

class DependencyEngine:
    """
    Computes blast radius and dependency risk.
    """
    def __init__(self):
        # In prod: self.graph = DependencyGraph("service_graph.yaml")
        # For now, we use a placeholder or partial logic
        pass

    def compute_features(self, raw: RawSignals) -> Tuple[Dict[str, float], FeatureExplanation]:
        # Inputs
        # If upstream ingestion already computed blast_radius (int), usage that.
        # Or if "touched_services" list exists, count it.
        
        # Fallback logic if blast_radius not in raw context (it might not be if parser is simple)
        # But we added `touched_services` to RawSignals type.
        
        # Check raw context
        services = raw.get("touched_services", [])
        files = raw.get("files_changed", [])
        
        # Simple heuristic if graph not fully wired:
        # Count imports? Or just use touched files count as proxy for connectivity?
        # Let's rely on an explicit 'blast_radius' if injected, else 0.
        
        # But wait, RawSignals definition allows 'blast_radius' derived?
        # The user spec says "RawSignals... touched_services: list[str] OR blast_radius: int"
        # Let's support an inferred blast radius from files for MVP
        
        radius = 0
        if services:
            radius = len(services)
        else:
            # Heuristic: count distinct top-level dirs as "services"
            top_dirs = set()
            for f in files:
                parts = f.split("/")
                if len(parts) > 1:
                    top_dirs.add(parts[0])
            radius = len(top_dirs)
            
        # Normalize
        # 0 -> 0.0
        # 10 services -> 1.0 (p90)
        dep_score = normalize.minmax(radius, 0.0, 10.0)
        
        expl: FeatureExplanation = []
        if dep_score > 0.5:
            expl.append(f"Blast Radius: Impacts {radius} service areas")
            
        features = {
            "dependency_risk_score": dep_score
        }
        return features, expl
