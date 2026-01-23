import sqlite3
import pandas as pd
import sys
import os

# Add project root to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riskbot.config import RISK_DB_PATH

def print_header(title):
    print(f"\n{title}")
    print("=" * len(title))

def generate_report():
    print("📊 RiskBot Label Coverage Report")
    print(f"Database: {RISK_DB_PATH}")
    
    if not os.path.exists(RISK_DB_PATH):
        print("Error: Database not found. Run ingest_repo.py first.")
        return

    conn = sqlite3.connect(RISK_DB_PATH)
    
    # 1. Overview
    try:
        df = pd.read_sql_query("SELECT * FROM pr_runs", conn)
    except Exception as e:
        print(f"Error reading pr_runs: {e}")
        return

    total_rows = len(df)
    
    # Check if V2 schema (label_value) exists
    if 'label_value' in df.columns:
        risky = len(df[df['label_value'] == 1])
        safe = len(df[df['label_value'] == 0])
        unknown = total_rows - (risky + safe)
        
        print_header("1. Dataset Overview")
        print(f"Total Changes:  {total_rows}")
        print(f"Risky (1):      {risky} ({risky/total_rows*100:.1f}%)")
        print(f"Safe (0):       {safe} ({safe/total_rows*100:.1f}%)")
        print(f"Unknown (NULL): {unknown} ({unknown/total_rows*100:.1f}%)")
        
        print_header("2. Label Sources")
        if 'label_source' in df.columns:
            sources = df['label_source'].value_counts()
            for source, count in sources.items():
                print(f"- {source}: {count}")
    else:
        print("Warning: Old Schema (V1) detected. 'label_value' column missing.")
        
    conn.close()
    print("\n✅ Report Complete")

if __name__ == "__main__":
    generate_report()
