from typing import List
from compliancebot.ux.analytics import ComplianceAnalytics
from compliancebot.ux.types import DecisionRecord
import json

class DashboardGenerator:
    """
    Generates a read-only executive summary dashboard (Markdown).
    """
    def __init__(self, analytics: ComplianceAnalytics):
        self.analytics = analytics
    
    def generate_markdown(self, records: List[DecisionRecord], title: str = "Compliance Posture") -> str:
        daily_stats = self.analytics.aggregate_daily_stats(records)
        top_violations = self.analytics.get_top_violations(records)
        
        lines = [f"# {title}", ""]
        
        # 1. Executive Summary
        total_deploys = len(records)
        blocks = sum(1 for r in records if r.decision == "BLOCK")
        block_rate = (blocks / total_deploys * 100) if total_deploys else 0
        
        lines.append("## Executive Summary")
        lines.append(f"- **Total Scans**: {total_deploys}")
        lines.append(f"- **Block Rate**: {block_rate:.1f}%")
        lines.append("")
        
        # 2. Daily Trends Table
        lines.append("## Daily Trends")
        lines.append("| Date | Scans | Blocked | Avg Risk |")
        lines.append("|------|-------|---------|----------|")
        
        # Sort dates
        sorted_dates = sorted(daily_stats.keys(), reverse=True)
        for date in sorted_dates:
            s = daily_stats[date]
            lines.append(f"| {date} | {s['total']} | {s['block']} | {s['risk_avg']} |")
        
        lines.append("")
        
        # 3. Top Violations
        lines.append("## Top Policy Violations")
        lines.append("| Policy ID | Incidents |")
        lines.append("|-----------|-----------|")
        for v in top_violations:
            lines.append(f"| `{v['policy']}` | {v['count']} |")
        
        return "\n".join(lines)

