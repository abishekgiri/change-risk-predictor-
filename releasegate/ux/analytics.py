from typing import List, Dict
from datetime import datetime
from collections import defaultdict
from compliancebot.ux.types import DecisionRecord

class ComplianceAnalytics:
    """
    Aggregates historical DecisionRecords into trusted metrics.
    """
    
    def aggregate_daily_stats(self, records: List[DecisionRecord]) -> Dict[str, Dict]:
        """
        Groups metrics by date.
        Returns: { "YYYY-MM-DD": { "total": 10, "block": 2, "pass": 8, "risk_avg": 45.5 } }
        """
        daily = defaultdict(lambda: {"total": 0, "block": 0, "warn": 0, "pass": 0, "risk_sum": 0})
        
        for r in records:
            # Parse ISO date -> YYYY-MM-DD
            date_key = r.timestamp.split("T")[0]
            stats = daily[date_key]
            
            stats["total"] += 1
            if r.decision == "BLOCK":
                stats["block"] += 1
            elif r.decision == "WARN":
                stats["warn"] += 1
            else:
                stats["pass"] += 1
            
            stats["risk_sum"] += r.risk_score
        
        # Post-process averages
        results = {}
        for date, stats in daily.items():
            avg_risk = stats["risk_sum"] / stats["total"] if stats["total"] > 0 else 0
            stats["risk_avg"] = round(avg_risk, 2)
            del stats["risk_sum"] # Cleanup intermediate
            results[date] = dict(stats)
        
        return results

    def get_top_violations(self, records: List[DecisionRecord], top_n: int = 5) -> List[Dict]:
        """
        Returns most frequent triggering policies.
        """
        policy_counts = defaultdict(int)
        for r in records:
            if r.decision in ["BLOCK", "WARN"] and r.policy_id:
                policy_counts[r.policy_id] += 1
        
        sorted_policies = sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"policy": k, "count": v} for k,v in sorted_policies[:top_n]]

