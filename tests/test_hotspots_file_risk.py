from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from releasegate.hotspots import file_risk


def test_recent_churn_uses_datetime_comparison_for_mixed_timestamp_formats(tmp_path):
    db_path = tmp_path / "hotspots.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """
            CREATE TABLE pr_runs (
                repo TEXT,
                files_json TEXT,
                churn REAL,
                label_value INTEGER,
                created_at TEXT
            )
            """
        )
        now = datetime.now(timezone.utc)
        rows = [
            (
                "acme/repo",
                json.dumps(["src/app.py"]),
                10.0,
                0,
                (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            ),
            (
                "acme/repo",
                json.dumps(["src/app.py"]),
                20.0,
                1,
                (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            ),
            (
                "acme/repo",
                json.dumps(["src/app.py"]),
                30.0,
                1,
                (now - timedelta(days=180)).strftime("%Y-%m-%d %H:%M:%S"),
            ),
        ]
        conn.executemany(
            "INSERT INTO pr_runs (repo, files_json, churn, label_value, created_at) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()

    original_db_path = file_risk.DB_PATH
    file_risk.DB_PATH = str(db_path)
    try:
        result = file_risk.aggregate_file_risks("acme/repo", window_days=90)
    finally:
        file_risk.DB_PATH = original_db_path

    assert "src/app.py" in result
    record = result["src/app.py"]
    assert record["changes"] == 3
    assert record["total_churn"] == 60.0
    assert record["recent_churn"] == 30.0
    assert record["incidents"] == 2
