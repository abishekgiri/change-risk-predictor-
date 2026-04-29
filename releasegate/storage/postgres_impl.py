from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence
from urllib.parse import urlparse

import os
import threading

from releasegate.storage.base import StorageBackend


# Schemes psycopg2 accepts in URL-form DSNs.  Postgres aliases "postgres://"
# and "postgresql://"; everything else (including SQLAlchemy-style
# "postgresql+psycopg2://...") is rejected here so we fail at construction
# time instead of inside an opaque OperationalError later.
_VALID_DSN_SCHEMES = frozenset({"postgresql", "postgres"})


class InvalidPostgresDSNError(ValueError):
    """Raised when RELEASEGATE_POSTGRES_DSN can't be parsed as a Postgres URL.

    Subclasses ValueError so existing callers' `except ValueError:` paths
    keep working; consumers who care about the specific failure mode can
    catch InvalidPostgresDSNError to differentiate from missing-DSN.
    """


def _validate_dsn_or_raise(dsn: str) -> None:
    """Hard-fail if the DSN string isn't a parseable Postgres URL.

    The two failure modes we've actually seen in CI:
      1. Secret pasted without the 'postgresql://' scheme prefix — urlparse
         dumps the whole string into `path`, leaving scheme='' and host=None.
      2. Whitespace, surrounding quotes, or trailing newline captured into
         the secret value.

    Either way, psycopg2.connect() will raise an opaque OperationalError
    ('could not translate host name "..." to address' or similar) at the
    first INSERT — by which time the broad try/except in cli.py already
    swallowed it into errors[].  Failing here surfaces the real cause
    upfront, with a message that explains how to fix it.
    """
    parsed = urlparse(dsn)
    scheme_ok = parsed.scheme in _VALID_DSN_SCHEMES
    host_ok = bool(parsed.hostname)
    if scheme_ok and host_ok:
        return
    # Don't echo the DSN itself in the message — even partial leakage of a
    # password is unacceptable in CI logs.
    detail_bits = []
    if not scheme_ok:
        detail_bits.append(
            f"scheme={parsed.scheme!r} (expected one of {sorted(_VALID_DSN_SCHEMES)})"
        )
    if not host_ok:
        detail_bits.append("hostname=<unset>")
    raise InvalidPostgresDSNError(
        "RELEASEGATE_POSTGRES_DSN is not a valid Postgres URL: "
        + ", ".join(detail_bits)
        + ". Expected format: 'postgresql://USER:PASSWORD@HOST:PORT/DB?sslmode=require'. "
        "Most common cause: the GitHub Actions secret was saved without the "
        "'postgresql://' scheme prefix. Re-paste the full External Database URL "
        "from your Postgres provider — do NOT add quotes or trailing newlines."
    )

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:  # pragma: no cover
    psycopg2 = None
    RealDictCursor = None


class PostgresStorageBackend(StorageBackend):
    def __init__(self, dsn: Optional[str] = None):
        self._dsn = (
            dsn
            or os.getenv("RELEASEGATE_POSTGRES_DSN")
            or os.getenv("DATABASE_URL")
        )
        if not self._dsn:
            raise ValueError("Postgres DSN missing. Set RELEASEGATE_POSTGRES_DSN or DATABASE_URL.")
        # Validate DSN structure up-front.  A malformed DSN (most often a
        # secret pasted without the 'postgresql://' scheme) otherwise sails
        # through __init__ and only blows up later as an opaque psycopg2
        # OperationalError — or, worse, gets swallowed by callers' broad
        # except-clauses, so the workflow looks clean while writes go
        # nowhere.  Catching it here surfaces the real problem at the point
        # the backend is configured.
        _validate_dsn_or_raise(self._dsn)
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for PostgresStorageBackend")
        self._local = threading.local()

    @property
    def name(self) -> str:
        return "postgres"

    def _adapt_sql(self, query: str) -> str:
        # Existing codebase uses sqlite-style '?' placeholders.
        return query.replace("?", "%s")

    def _active_tx(self) -> Optional[Dict[str, Any]]:
        return getattr(self._local, "tx_state", None)

    @contextmanager
    def connect(self) -> Iterator[Any]:
        active = self._active_tx()
        if active is not None:
            yield active["conn"]
            return
        conn = psycopg2.connect(self._dsn)
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor() as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                return cur.rowcount
        with self.connect() as conn:
            with conn.cursor() as cur:
                q = self._adapt_sql(query)
                # psycopg2 treats '%' as interpolation markers when a params tuple is
                # provided (even an empty one). Some DDL (e.g., plpgsql RAISE strings)
                # legitimately contains '%' characters, so avoid passing params when
                # there are none.
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                conn.commit()
                return cur.rowcount

    def fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                row = cur.fetchone()
                return dict(row) if row else None
        with self.connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                row = cur.fetchone()
                return dict(row) if row else None

    def fetchall(self, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        with self.connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                rows = cur.fetchall()
                return [dict(r) for r in rows]

    @contextmanager
    def transaction(self) -> Iterator["PostgresStorageBackend"]:
        active = self._active_tx()
        if active is not None:
            active["depth"] += 1
            try:
                yield self
            finally:
                active["depth"] -= 1
            return

        conn = psycopg2.connect(self._dsn)
        state = {"conn": conn, "depth": 1}
        self._local.tx_state = state
        try:
            yield self
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._local.tx_state = None
            conn.close()
