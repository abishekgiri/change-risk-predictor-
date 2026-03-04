from datetime import datetime, timedelta, timezone

from releasegate.governance.signal_freshness import (
    compute_risk_signal_hash,
    ensure_risk_signal_hash,
    evaluate_risk_signal_freshness,
    resolve_signal_freshness_policy,
)


def test_signal_freshness_blocks_stale_signal_in_strict_mode():
    policy = resolve_signal_freshness_policy(
        policy_overrides={"max_age_seconds": 60, "require_computed_at": True},
        strict_enabled=True,
    )
    risk_meta = {
        "releasegate_risk": "LOW",
        "risk_level": "LOW",
        "risk_score": 25,
        "computed_at": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
    }
    result = evaluate_risk_signal_freshness(risk_meta=risk_meta, policy=policy)
    assert result["stale"] is True
    assert result["should_block"] is True
    assert result["reason_code"] == "SIGNAL_STALE"


def test_signal_freshness_requires_hash_when_configured():
    policy = resolve_signal_freshness_policy(
        policy_overrides={"require_signal_hash": True},
        strict_enabled=True,
    )
    risk_meta = {
        "releasegate_risk": "LOW",
        "risk_level": "LOW",
        "risk_score": 25,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    result = evaluate_risk_signal_freshness(risk_meta=risk_meta, policy=policy)
    assert result["stale"] is True
    assert result["should_block"] is True
    assert result["reason_code"] == "SIGNAL_HASH_MISSING"


def test_signal_freshness_accepts_valid_fresh_signal():
    policy = resolve_signal_freshness_policy(
        policy_overrides={"max_age_seconds": 3600, "require_signal_hash": True},
        strict_enabled=True,
    )
    risk_meta = ensure_risk_signal_hash(
        {
            "releasegate_risk": "MEDIUM",
            "risk_level": "MEDIUM",
            "risk_score": 60,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    assert risk_meta["signal_hash"] == compute_risk_signal_hash(risk_meta)
    result = evaluate_risk_signal_freshness(risk_meta=risk_meta, policy=policy)
    assert result["stale"] is False
    assert result["should_block"] is False
    assert result["reason_code"] is None
