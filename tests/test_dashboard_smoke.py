import os
import sqlite3
from compliancebot.config import DB_PATH

def test_dashboard_data_smoke():
    """
    Verifies that the database used by the dashboard exists and has data.
    This ensures the dashboard won't crash on startup due to missing tables.
    """
    assert os.path.exists(DB_PATH), f"DB not found at {DB_PATH}"
    
    conn = sqlite3.connect(DB_PATH)
    try:
        # Check Stats Query
        total = conn.execute("SELECT COUNT(*) FROM pr_runs").fetchone()[0]
        assert total > 0, "Dashboard DB should have runs (did mock_data.py run?)"
        
        # Check Labels Query
        labeled = conn.execute("SELECT COUNT(*) FROM pr_labels").fetchone()[0]
        assert labeled >= 0
        
    finally:
        conn.close()
