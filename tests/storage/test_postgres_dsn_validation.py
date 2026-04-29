"""Unit tests for the DSN-validation guard in PostgresStorageBackend.

These tests do NOT need a real Postgres — they only exercise the parse-time
validation in `_validate_dsn_or_raise`.  Integration tests against a live DB
live in `test_postgres_integration.py`.

Why this file exists: during the 2026-04-29 DSN rotation, a malformed
secret (Render External URL pasted without the 'postgresql://' prefix)
silently no-op'd writes for hours because the malformed string sailed
through __init__ and only failed inside psycopg2 — where broad except
clauses in cli.py caught it without surfacing.  These tests pin down the
fail-loud contract so the next misconfiguration trips immediately.
"""
from __future__ import annotations

import pytest

from releasegate.storage.postgres_impl import (
    InvalidPostgresDSNError,
    _validate_dsn_or_raise,
)


# ── DSNs that MUST be accepted ───────────────────────────────────────────────
@pytest.mark.parametrize(
    "dsn",
    [
        # Canonical form — what Render External URL produces.
        "postgresql://u:p@host.example.com:5432/db?sslmode=require",
        # Without explicit port (psycopg2 defaults to 5432) — Render's URL
        # actually omits :5432, which we confirmed in the 2026-04-29 run.
        "postgresql://u:p@host.example.com/db",
        # Postgres scheme alias.
        "postgres://u:p@host.example.com:5432/db",
        # Without query string.
        "postgresql://u:p@host.example.com:5432/db",
        # Hostname with hyphens and dots (Render hosts look like this).
        "postgresql://u:p@dpg-d6b58hgboq4c73blih10-a.oregon-postgres.render.com:5432/releasegate_db?sslmode=require",
    ],
)
def test_valid_dsn_does_not_raise(dsn: str) -> None:
    _validate_dsn_or_raise(dsn)  # no assertion needed — just must not raise


# ── DSNs that MUST be rejected ───────────────────────────────────────────────
@pytest.mark.parametrize(
    "dsn,reason",
    [
        # The actual production failure mode: scheme missing.
        ("u:p@host.example.com:5432/db", "no scheme prefix"),
        # Wrong scheme — SQLAlchemy-style prefix; psycopg2 rejects this too.
        ("postgresql+psycopg2://u:p@host.example.com:5432/db", "sqlalchemy prefix"),
        # MySQL / other.
        ("mysql://u:p@host.example.com:3306/db", "wrong driver"),
        # Empty path entirely.
        ("postgresql://", "scheme only, no host"),
        # Scheme without authority.
        ("postgresql:///db", "host empty"),
        # Plain garbage.
        ("not-a-dsn-at-all", "non-url string"),
        # Just a hostname with no scheme.
        ("host.example.com", "host only, no scheme"),
    ],
)
def test_invalid_dsn_raises_with_actionable_message(dsn: str, reason: str) -> None:
    with pytest.raises(InvalidPostgresDSNError) as exc_info:
        _validate_dsn_or_raise(dsn)

    msg = str(exc_info.value)
    # Must be actionable: tell the operator the expected format.
    assert "postgresql://" in msg
    # Password-leak check is enforced by the dedicated test below
    # (test_password_never_echoed_in_error) — kept separate so this
    # parameterised test stays focused on the actionable-message contract.


def test_invalid_dsn_error_subclasses_value_error() -> None:
    """Existing call sites use `except ValueError:` to catch missing DSNs.

    InvalidPostgresDSNError must subclass ValueError so those paths keep
    working without code changes elsewhere.
    """
    with pytest.raises(ValueError):
        _validate_dsn_or_raise("not-a-dsn")


def test_message_calls_out_the_most_common_cause() -> None:
    """The 2026-04-29 incident root cause should be in the error message
    so the next operator hits it before consulting docs.
    """
    with pytest.raises(InvalidPostgresDSNError) as exc_info:
        _validate_dsn_or_raise("u:p@host.example.com:5432/db")

    msg = str(exc_info.value)
    assert "postgresql://" in msg
    assert "scheme prefix" in msg.lower() or "scheme" in msg.lower()


def test_password_never_echoed_in_error() -> None:
    """If someone pastes their DSN into the env without a scheme, the
    password should NOT be rendered back in the error message — even
    truncated.  (urlparse stuffs the whole string into `.path` when
    there's no '://', so an unguarded `f"got {dsn!r}"` would leak it.)
    """
    secret_password = "viE1UCCxuYMuMAxGhgP8"  # nosec - example only
    bad_dsn = f"u:{secret_password}@host.example.com/db"
    with pytest.raises(InvalidPostgresDSNError) as exc_info:
        _validate_dsn_or_raise(bad_dsn)

    msg = str(exc_info.value)
    assert secret_password not in msg, "password leaked in InvalidPostgresDSNError message"
