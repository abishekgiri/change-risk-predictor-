import sqlite3
import pandas as pd
import sys
import os

# Add project root to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riskbot.scoring.calibration import RiskCalibrator
from riskbot.config import RISK_DB_PATH

def compare_curves():
    print("📊 Calibration Comparison: Phase 2 (Heuristic) vs Phase 3A (Unified)")
    print("================================================================")
    
    conn = sqlite3.connect(RISK_DB_PATH)
    
    # 1. Fetch Data
    df = pd.read_sql_query("SELECT risk_score, feature_version, label_value, label_version FROM pr_runs", conn)
    conn.close()
    
    if df.empty:
        print("No data found.")
        return

    # 2. Simulate V1 vs V2
    # V1 used heuristic keywords (simulated here by filtering for old version or mapping)
    # Actually, current ingest script writes version="v2".
    # But we can compare "Raw Score" buckets against "Label Value".
    
    print(f"Total Rows: {len(df)}")
    print(f"V2 Rows (Phase 3A): {len(df[df['label_version'] == 'v2'])}")
    
    # Let's train a calibrator on the new labels
    cal = RiskCalibrator()
    cal.fit() # This uses the V2 data (since sql query in class filters for current schema usually, let's check class)
    
    print("\n[New Unified Curve]")
    print(f"{'Bucket':<10} | {'Prob':<10}")
    print("-" * 25)
    for bucket, prob in sorted(cal.calibration_curve.items()):
        print(f"{bucket:<10} | {prob:<10.2f}")
        
    print("\nAnalysis:")
    print("If the curve is monotonic (0.1 -> 0.9), unification worked.")
    print("If flat (0.5), we need more labeled data (Cold Start).")

if __name__ == "__main__":
    compare_curves()
