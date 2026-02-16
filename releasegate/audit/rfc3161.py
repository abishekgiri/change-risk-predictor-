from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests


class RFC3161Error(RuntimeError):
    """Raised when RFC3161 timestamp operations fail."""


def _normalize_sha256(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1]
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise RFC3161Error("payload_hash must be sha256:<64-hex> or 64-hex")
    return raw


def _require_openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise RFC3161Error("openssl binary not found; required for RFC3161 operations")
    return path


def _run(cmd: list[str], *, stdin: Optional[bytes] = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            input=stdin.decode("utf-8") if isinstance(stdin, bytes) else None,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        message = stderr or stdout or str(exc)
        raise RFC3161Error(message) from exc


def _build_query_file(*, payload_hash: str, out_path: Path) -> None:
    openssl = _require_openssl()
    _run(
        [
            openssl,
            "ts",
            "-query",
            "-sha256",
            "-digest",
            payload_hash,
            "-cert",
            "-out",
            str(out_path),
        ]
    )


def request_rfc3161_token(
    *,
    payload_hash: str,
    tsa_url: str,
    timeout_seconds: int = 10,
) -> bytes:
    digest = _normalize_sha256(payload_hash)
    endpoint = str(tsa_url or "").strip()
    if not endpoint:
        raise RFC3161Error("tsa_url is required when RFC3161 is enabled")

    with tempfile.TemporaryDirectory(prefix="releasegate-ts-") as tmp:
        query_path = Path(tmp) / "request.tsq"
        _build_query_file(payload_hash=digest, out_path=query_path)
        query_bytes = query_path.read_bytes()

    try:
        response = requests.post(
            endpoint,
            data=query_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=max(1, int(timeout_seconds)),
        )
    except Exception as exc:
        raise RFC3161Error(f"failed to call TSA endpoint: {exc}") from exc

    if response.status_code >= 400:
        raise RFC3161Error(f"TSA responded with HTTP {response.status_code}")
    token = response.content or b""
    if not token:
        raise RFC3161Error("TSA returned empty timestamp token")
    return token


def verify_rfc3161_token(
    *,
    payload_hash: str,
    token_bytes: bytes,
    ca_bundle_path: Optional[str],
) -> None:
    digest = _normalize_sha256(payload_hash)
    if not token_bytes:
        raise RFC3161Error("timestamp token is empty")
    if not ca_bundle_path:
        raise RFC3161Error("RFC3161 verification requires --tsa-ca-bundle or RELEASEGATE_RFC3161_CA_BUNDLE")

    ca_path = Path(str(ca_bundle_path)).expanduser()
    if not ca_path.exists() or not ca_path.is_file():
        raise RFC3161Error(f"RFC3161 CA bundle not found: {ca_path}")

    openssl = _require_openssl()
    with tempfile.TemporaryDirectory(prefix="releasegate-ts-verify-") as tmp:
        query_path = Path(tmp) / "request.tsq"
        token_path = Path(tmp) / "response.tsr"
        token_path.write_bytes(token_bytes)
        _build_query_file(payload_hash=digest, out_path=query_path)
        _run(
            [
                openssl,
                "ts",
                "-verify",
                "-queryfile",
                str(query_path),
                "-in",
                str(token_path),
                "-CAfile",
                str(ca_path),
            ]
        )


def mint_rfc3161_artifact(
    *,
    payload_hash: str,
    tsa_url: str,
    timeout_seconds: int = 10,
) -> Tuple[Dict[str, str], bytes]:
    token = request_rfc3161_token(
        payload_hash=payload_hash,
        tsa_url=tsa_url,
        timeout_seconds=timeout_seconds,
    )
    normalized = _normalize_sha256(payload_hash)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "format": "rfc3161",
        "hash_alg": "sha256",
        "payload_hash": f"sha256:{normalized}",
        "tsa_url": tsa_url,
        "generated_at": now,
        "token_sha256": f"sha256:{hashlib.sha256(token).hexdigest()}",
    }
    return metadata, token


def verify_rfc3161_artifact(
    *,
    payload_hash: str,
    metadata: Dict[str, str],
    token_bytes: bytes,
    ca_bundle_path: Optional[str],
) -> Tuple[bool, Optional[str]]:
    if not isinstance(metadata, dict):
        return False, "RFC3161 metadata is missing or invalid"

    try:
        expected_hash = _normalize_sha256(payload_hash)
    except RFC3161Error as exc:
        return False, str(exc)

    meta_hash = str(metadata.get("payload_hash") or "")
    try:
        meta_hash = _normalize_sha256(meta_hash)
    except RFC3161Error as exc:
        return False, f"RFC3161 metadata payload_hash invalid: {exc}"

    if meta_hash != expected_hash:
        return False, "RFC3161 payload hash mismatch"

    token_sha = str(metadata.get("token_sha256") or "")
    if token_sha:
        try:
            normalized_token_sha = _normalize_sha256(token_sha)
        except RFC3161Error as exc:
            return False, f"RFC3161 metadata token_sha256 invalid: {exc}"
        actual_token_sha = hashlib.sha256(token_bytes).hexdigest()
        if normalized_token_sha != actual_token_sha:
            return False, "RFC3161 token digest mismatch"

    try:
        verify_rfc3161_token(
            payload_hash=f"sha256:{expected_hash}",
            token_bytes=token_bytes,
            ca_bundle_path=ca_bundle_path,
        )
    except RFC3161Error as exc:
        return False, str(exc)
    return True, None


def is_rfc3161_enabled() -> bool:
    value = str(os.getenv("RELEASEGATE_RFC3161_ENABLED", "false")).strip().lower()
    return value in {"1", "true", "yes", "on"}


def default_rfc3161_tsa_url() -> str:
    return str(os.getenv("RELEASEGATE_RFC3161_TSA_URL") or "").strip()


def default_rfc3161_timeout_seconds() -> int:
    raw = str(os.getenv("RELEASEGATE_RFC3161_TIMEOUT_SECONDS") or "10").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 10
    return max(1, value)


def default_rfc3161_ca_bundle() -> Optional[str]:
    value = str(os.getenv("RELEASEGATE_RFC3161_CA_BUNDLE") or "").strip()
    return value or None

