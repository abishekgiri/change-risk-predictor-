import yaml
import os
from typing import Dict, List, Set, Any

class DependencyGraph:
    """
    Calculates Blast Radius based on a service dependency graph.
    """
    def __init__(self, config_path: str = "service_graph.yaml"):
        self.graph = self._load_graph(config_path)

    def _load_graph(self, path: str) -> Dict:
        if not os.path.exists(path):
            print(f"Warning: {path} not found. Returning empty graph.")
            return {}
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading graph: {e}")
            return {}

    def get_downstream_impact(self, modified_files: List[str]) -> Dict[str, Any]:
        """
        Identify which services are affected by changes to specific files/modules.
        Returns:
            - impacted_services: List of service names
            - blast_radius_score: Integer score
        """
        # 1. Map files to services/modules
        affected_nodes = set()
        for f in modified_files:
            # Naive mapping: checks if service name is in file path
            # Example: "services/auth/..." -> "auth"
            for service in self.graph.keys():
                if service in f:
                    affected_nodes.add(service)

        # 2. Traverse Graph (Downstream)
        impacted_services = set(affected_nodes)
        queue = list(affected_nodes)
        
        while queue:
            current = queue.pop(0)
            # Find what depends on current
            # Graph format: Service -> depends_on: [List]
            # So current is an upstream dependency. We need to find who lists current in their 'depends_on'.
            
            # This is O(N*M), slow for huge graphs but fine for MVP.
            # Ideally, self.graph should be pre-inverted (upstream -> downstream).
            for sname, details in self.graph.items():
                deps = details.get("depends_on", [])
                if current in deps and sname not in impacted_services:
                    impacted_services.add(sname)
                    queue.append(sname)

        # 3. Calculate Score
        # Base score = count of services
        # We could weight them by criticality if defined in yaml
        score = len(impacted_services)
        
        return {
            "direct_hits": list(affected_nodes),
            "impacted_services": list(impacted_services),
            "blast_radius_score": score
        }

if __name__ == "__main__":
    # Test
    # Create dummy yaml first if not exists
    if not os.path.exists("service_graph.yaml"):
        dummy_data = """
        auth:
            tier: 0
            depends_on: []
        payments:
            tier: 0
            depends_on: ["auth"]
        checkout:
            tier: 1
            depends_on: ["payments", "auth"]
        frontend:
            tier: 2
            depends_on: ["checkout", "auth"]
        """
        with open("service_graph.yaml", "w") as f:
            f.write(dummy_data.strip())
            
    dg = DependencyGraph()
    # Simulate change to Auth
    impact = dg.get_downstream_impact(["services/auth/login.py"])
    print("Change to Auth:")
    print(impact)
