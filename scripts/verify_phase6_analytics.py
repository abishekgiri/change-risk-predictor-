from datetime import datetime
from compliancebot.ux.analytics import ComplianceAnalytics
from compliancebot.ux.dashboard import DashboardGenerator
from compliancebot.ux.types import DecisionRecord, DecisionExplanation

def verify_analytics():
 print("Verifying Phase 6 Analytics & Dashboard")
 print("=======================================")
 
 # 1. Generate Mock Data (3 days)
 records = []
 
 # Day 1: 2 pass, 1 block
 for i in range(3):
 records.append(DecisionRecord(
 decision_id=f"d1_{i}", timestamp="2025-10-01T10:00:00Z", repo="foo/bar", pr_number=i,
 decision="BLOCK" if i==0 else "PASS", risk_score=90 if i==0 else 10,
 risk_level="HIGH" if i==0 else "LOW", policy_id="SEC-001" if i==0 else "",
 explanation=DecisionExplanation("foo", [], "narrative"), features={}
 ))
 
 # Day 2: 1 pass
 records.append(DecisionRecord(
 decision_id="d2_0", timestamp="2025-10-02T10:00:00Z", repo="foo/bar", pr_number=10,
 decision="PASS", risk_score=5, risk_level="LOW", policy_id="",
 explanation=DecisionExplanation("foo", [], "narrative"), features={}
 ))
 
 # 2. Test Aggregation
 analytics = ComplianceAnalytics()
 daily = analytics.aggregate_daily_stats(records)
 
 print("\n1. Daily Stats Verification...")
 print(f"Stats: {daily}")
 
 assert "2025-10-01" in daily
 assert daily["2025-10-01"]["total"] == 3
 assert daily["2025-10-01"]["block"] == 1
 assert daily["2025-10-01"]["risk_avg"] > 30 # (90+10+10)/3 = 36.6
 print("✅ Aggregation Logic Verified")
 
 # 3. Test Dashboard
 print("\n2. Dashboard Generation Verification...")
 gen = DashboardGenerator(analytics)
 md = gen.generate_markdown(records)
 
 print("--- Dashboard Snippet ---")
 print("\n".join(md.splitlines()[:10]))
 print("...")
 print("-------------------------")
 
 assert "# Compliance Posture" in md
 assert "Block Rate" in md
 assert "2025-10-01" in md
 print("✅ Dashboard Generation Verified")
 
 print("\nAnalytics Verification Successful")

if __name__ == "__main__":
 verify_analytics()
