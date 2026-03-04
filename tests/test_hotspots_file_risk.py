from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from releasegate.hotspots import file_risk


def test_parse_timestamp_accepts_none_empty_and_datetime_inputs():
    assert file_risk._parse_timestamp(None) is None
    assert file_risk._parse_timestamp("") is None
    assert file_risk._parse_timestamp("   ") is None

    dt = datetime(2026, 3, 3, 12, 34, 56, tzinfo=timezone.utc)
    parsed = file_risk._parse_timestamp(dt)
    assert parsed == dt


def test_parse_timestamp_normalizes_supported_formats_to_utc():
    sqlite_ts = "2026-03-03 12:34:56"
    iso_z_ts = "2026-03-03T12:34:56Z"
    iso_offset_ts = "2026-03-03T07:34:56-05:00"

    parsed_sqlite = file_risk._parse_timestamp(sqlite_ts)
    parsed_iso_z = file_risk._parse_timestamp(iso_z_ts)
    parsed_iso_offset = file_risk._parse_timestamp(iso_offset_ts)

    assert parsed_sqlite is not None
    assert parsed_iso_z is not None
    assert parsed_iso_offset is not None
    assert parsed_sqlite.tzinfo == timezone.utc
    assert parsed_iso_z.tzinfo == timezone.utc
    assert parsed_iso_offset.tzinfo == timezone.utc
    assert parsed_sqlite == parsed_iso_z == parsed_iso_offset


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
