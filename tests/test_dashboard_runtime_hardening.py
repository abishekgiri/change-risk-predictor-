from __future__ import annotations

import pytest

from releasegate import server


def test_parse_allowed_origins_deduplicates_and_strips(monkeypatch):
    monkeypatch.setenv(
        "RELEASEGATE_ALLOWED_ORIGINS",
        " https://a.example.com , https://b.example.com,https://a.example.com ",
    )
    parsed = server._parse_allowed_origins()
    assert parsed == ["https://a.example.com", "https://b.example.com"]


def test_validate_startup_environment_allows_missing_internal_key_in_development(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ENV", "development")
    monkeypatch.delenv("RELEASEGATE_INTERNAL_SERVICE_KEY", raising=False)
    server._validate_startup_environment()


def test_validate_startup_environment_requires_production_envs(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ENV", "production")
    monkeypatch.delenv("RELEASEGATE_INTERNAL_SERVICE_KEY", raising=False)
    monkeypatch.delenv("RELEASEGATE_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("RELEASEGATE_JWT_SECRET", raising=False)
    monkeypatch.delenv("RELEASEGATE_KEY_ENCRYPTION_SECRET", raising=False)
    monkeypatch.setattr(server, "ALLOWED_ORIGINS", [])

    with pytest.raises(RuntimeError) as exc:
        server._validate_startup_environment()
    message = str(exc.value)
    assert "RELEASEGATE_INTERNAL_SERVICE_KEY" in message
    assert "RELEASEGATE_ALLOWED_ORIGINS" in message
    assert "RELEASEGATE_JWT_SECRET" in message
    assert "RELEASEGATE_KEY_ENCRYPTION_SECRET" in message
