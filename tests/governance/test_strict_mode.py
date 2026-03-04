from releasegate.governance.strict_mode import apply_strict_fail_closed


def test_strict_mode_blocks_missing_risk():
    result = apply_strict_fail_closed(
        strict_enabled=True,
        risk_present=False,
    )
    assert result is not None
    assert result["reason_code"] == "RISK_MISSING"


def test_strict_mode_blocks_provider_timeout():
    result = apply_strict_fail_closed(
        strict_enabled=True,
        provider_timeout=True,
    )
    assert result is not None
    assert result["reason_code"] == "PROVIDER_TIMEOUT"


def test_strict_mode_allows_missing_risk_when_disabled():
    result = apply_strict_fail_closed(
        strict_enabled=False,
        risk_present=False,
    )
    assert result is None
