from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import sqlite3
import uuid

from fastapi.testclient import TestClient
import pytest

from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _unwrap_envelope(response) -> dict:
    body = response.json()
    assert body.get("generated_at")
    assert body.get("trace_id")
    assert isinstance(body.get("data"), dict)
    return body["data"]


def _insert_metric_event(
    *,
    tenant_id: str,
    metric_name: str,
    metric_value: int = 1,
    created_at: datetime,
    metadata: dict | None = None,
) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO metrics_events (tenant_id, event_id, metric_name, metric_value, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                uuid.uuid4().hex,
                metric_name,
                metric_value,
                created_at.astimezone(timezone.utc).isoformat(),
                json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_phase1_validation_endpoint_summarizes_filtered_batch() -> None:
    _reset_db()
    base = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    prefix = "phase1-batch-"

    session_specs = [
        {
            "tenant_id": f"{prefix}01",
            "time_to_first_value": 240,
            "hesitation": 2,
            "time_to_canary": 420,
            "total_transitions": 87,
            "canary": True,
        },
        {
            "tenant_id": f"{prefix}02",
            "time_to_first_value": 360,
            "hesitation": 6,
            "time_to_canary": 700,
            "total_transitions": 52,
            "canary": True,
        },
        {
            "tenant_id": f"{prefix}03",
            "time_to_first_value": 500,
            "hesitation": 14,
            "time_to_canary": None,
            "total_transitions": 12,
            "canary": False,
        },
        {
            "tenant_id": "other-batch-01",
            "time_to_first_value": 200,
            "hesitation": 1,
            "time_to_canary": 300,
            "total_transitions": 94,
            "canary": True,
        },
    ]

    for index, spec in enumerate(session_specs):
        connected_at = base + timedelta(minutes=index * 5)
        first_value_at = connected_at + timedelta(seconds=spec["time_to_first_value"])
        snapshot_at = first_value_at + timedelta(seconds=5)
        _insert_metric_event(
            tenant_id=spec["tenant_id"],
            metric_name="onboarding_jira_connected",
            created_at=connected_at,
        )
        _insert_metric_event(
            tenant_id=spec["tenant_id"],
            metric_name="onboarding_first_value_ready",
            created_at=first_value_at,
            metadata={
                "starter_pack": "conservative",
                "total_transitions": spec["total_transitions"],
            },
        )
        _insert_metric_event(
            tenant_id=spec["tenant_id"],
            metric_name="onboarding_time_to_first_value_seconds",
            metric_value=spec["time_to_first_value"],
            created_at=first_value_at,
        )
        _insert_metric_event(
            tenant_id=spec["tenant_id"],
            metric_name="onboarding_snapshot_shown",
            created_at=snapshot_at,
            metadata={
                "starter_pack": "conservative",
                "total_transitions": spec["total_transitions"],
            },
        )
        _insert_metric_event(
            tenant_id=spec["tenant_id"],
            metric_name="onboarding_snapshot_hesitation_seconds",
            metric_value=spec["hesitation"],
            created_at=snapshot_at + timedelta(seconds=spec["hesitation"]),
            metadata={
                "starter_pack": "conservative",
                "total_transitions": spec["total_transitions"],
            },
        )
        if spec["canary"]:
            canary_at = snapshot_at + timedelta(seconds=spec["hesitation"] + 20)
            _insert_metric_event(
                tenant_id=spec["tenant_id"],
                metric_name="onboarding_canary_enabled",
                created_at=canary_at,
            )
            _insert_metric_event(
                tenant_id=spec["tenant_id"],
                metric_name="onboarding_time_to_canary_seconds",
                metric_value=int(spec["time_to_canary"] or 0),
                created_at=canary_at,
            )

    response = client.get(
        "/internal/onboarding/phase1/validation",
        params={"days": 30, "tenant_prefix": prefix},
        headers=jwt_headers(tenant_id="ops-control", roles=["admin"], scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = _unwrap_envelope(response)

    assert payload["sessions_count"] == 3
    assert payload["connected_count"] == 3
    assert payload["first_value_count"] == 3
    assert payload["canary_enabled_count"] == 2
    assert payload["onboarding_completion_rate"] == 1.0
    assert payload["canary_conversion_rate"] == 2 / 3
    assert payload["activation_drop_off_rate"] == pytest.approx(1 / 3)
    assert payload["median_time_to_first_value_seconds"] == 360.0
    assert payload["median_time_to_canary_seconds"] == 560.0
    assert payload["median_hesitation_seconds"] == 6.0
    assert payload["hesitation_bands"] == {
        "instant_trust": 1,
        "acceptable_thinking": 1,
        "hesitation_or_doubt": 1,
    }
    assert payload["cohorts"]["ideal_flow"] == 1
    assert payload["cohorts"]["converted_after_thinking"] == 1
    assert payload["cohorts"]["activation_drop_off"] == 1
    assert payload["exit_criteria"]["sample_size_ready"] is False
    assert payload["exit_criteria"]["official_phase1_proven"] is False
    assert len(payload["sessions"]) == 3
    assert all(item["tenant_id"].startswith(prefix) for item in payload["sessions"])


def test_phase1_validation_endpoint_marks_phase1_proven_when_exit_criteria_are_met() -> None:
    _reset_db()
    base = datetime(2026, 4, 13, 18, 0, tzinfo=timezone.utc)
    prefix = "phase1-proof-"

    for index in range(5):
        tenant_id = f"{prefix}{index + 1:02d}"
        connected_at = base + timedelta(minutes=index * 3)
        first_value_seconds = 180 + (index * 30)
        hesitation_seconds = 2 + (index % 2)
        canary_seconds = 420 + (index * 40)
        total_transitions = 80 + index
        first_value_at = connected_at + timedelta(seconds=first_value_seconds)
        snapshot_at = first_value_at + timedelta(seconds=5)
        canary_at = connected_at + timedelta(seconds=canary_seconds)

        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_jira_connected",
            created_at=connected_at,
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_first_value_ready",
            created_at=first_value_at,
            metadata={"starter_pack": "conservative", "total_transitions": total_transitions},
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_time_to_first_value_seconds",
            metric_value=first_value_seconds,
            created_at=first_value_at,
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_snapshot_shown",
            created_at=snapshot_at,
            metadata={"starter_pack": "conservative", "total_transitions": total_transitions},
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_snapshot_hesitation_seconds",
            metric_value=hesitation_seconds,
            created_at=snapshot_at + timedelta(seconds=hesitation_seconds),
            metadata={"starter_pack": "conservative", "total_transitions": total_transitions},
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_canary_enabled",
            created_at=canary_at,
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_time_to_canary_seconds",
            metric_value=canary_seconds,
            created_at=canary_at,
        )

    response = client.get(
        "/internal/onboarding/phase1/validation",
        params={"days": 30, "tenant_prefix": prefix},
        headers=jwt_headers(tenant_id="ops-control", roles=["admin"], scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = _unwrap_envelope(response)

    assert payload["sessions_count"] == 5
    assert payload["connected_count"] == 5
    assert payload["first_value_count"] == 5
    assert payload["canary_enabled_count"] == 5
    assert payload["onboarding_completion_rate"] == 1.0
    assert payload["activation_drop_off_rate"] == 0.0
    assert payload["median_time_to_first_value_seconds"] < 600.0
    assert payload["median_time_to_canary_seconds"] < 900.0
    assert payload["median_hesitation_seconds"] < 5.0
    assert payload["exit_criteria"]["sample_size_ready"] is True
    assert payload["exit_criteria"]["first_value_under_10_minutes"] is True
    assert payload["exit_criteria"]["canary_under_15_minutes"] is True
    assert payload["exit_criteria"]["onboarding_completion_gte_80_pct"] is True
    assert payload["exit_criteria"]["activation_drop_off_lt_20_pct"] is True
    assert payload["exit_criteria"]["median_hesitation_lt_5_seconds"] is True
    assert payload["exit_criteria"]["official_phase1_proven"] is True


def test_phase1_validation_endpoint_treats_exact_twenty_percent_drop_off_as_not_proven() -> None:
    _reset_db()
    base = datetime(2026, 4, 13, 20, 0, tzinfo=timezone.utc)
    prefix = "phase1-boundary-"

    for index in range(5):
        tenant_id = f"{prefix}{index + 1:02d}"
        connected_at = base + timedelta(minutes=index * 2)
        first_value_at = connected_at + timedelta(seconds=180)
        snapshot_at = first_value_at + timedelta(seconds=5)

        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_jira_connected",
            created_at=connected_at,
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_first_value_ready",
            created_at=first_value_at,
            metadata={"starter_pack": "conservative", "total_transitions": 80},
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_time_to_first_value_seconds",
            metric_value=180,
            created_at=first_value_at,
        )
        _insert_metric_event(
            tenant_id=tenant_id,
            metric_name="onboarding_snapshot_shown",
            created_at=snapshot_at,
            metadata={"starter_pack": "conservative", "total_transitions": 80},
        )
        if index < 4:
            canary_at = connected_at + timedelta(seconds=420)
            _insert_metric_event(
                tenant_id=tenant_id,
                metric_name="onboarding_snapshot_hesitation_seconds",
                metric_value=3,
                created_at=snapshot_at + timedelta(seconds=3),
                metadata={"starter_pack": "conservative", "total_transitions": 80},
            )
            _insert_metric_event(
                tenant_id=tenant_id,
                metric_name="onboarding_canary_enabled",
                created_at=canary_at,
            )
            _insert_metric_event(
                tenant_id=tenant_id,
                metric_name="onboarding_time_to_canary_seconds",
                metric_value=420,
                created_at=canary_at,
            )

    response = client.get(
        "/internal/onboarding/phase1/validation",
        params={"days": 30, "tenant_prefix": prefix},
        headers=jwt_headers(tenant_id="ops-control", roles=["admin"], scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = _unwrap_envelope(response)

    assert payload["activation_drop_off_rate"] == pytest.approx(0.2)
    assert payload["exit_criteria"]["activation_drop_off_lt_20_pct"] is False
    assert payload["exit_criteria"]["official_phase1_proven"] is False
