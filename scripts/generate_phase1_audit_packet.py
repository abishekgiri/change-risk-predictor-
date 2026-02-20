#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for key, value in (headers or {}).items():
        k = str(key)
        if k.lower() in {"authorization", "x-signature", "x-internal-service-key"}:
            redacted[k] = "<redacted>"
        else:
            redacted[k] = value
    return redacted


def _json_dump(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


@dataclass
class HttpResult:
    status_code: int
    headers: Dict[str, str]
    body_text: str
    body_json: Dict[str, Any] | List[Any] | str | None


def _http_request(
    *,
    url: str,
    method: str,
    headers: Dict[str, Any],
    body: Dict[str, Any] | None,
    timeout_seconds: float,
) -> HttpResult:
    encoded_body = None
    merged_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    if body is not None:
        encoded_body = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if "Content-Type" not in merged_headers:
            merged_headers["Content-Type"] = "application/json"
    req = urllib_request.Request(
        url=url,
        data=encoded_body,
        headers=merged_headers,
        method=method.upper(),
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as resp:
            text = resp.read().decode("utf-8")
            code = int(getattr(resp, "status", 200))
            headers_map = {str(k): str(v) for k, v in resp.headers.items()}
    except HTTPError as exc:
        text = exc.read().decode("utf-8")
        code = int(exc.code)
        headers_map = {str(k): str(v) for k, v in exc.headers.items()} if exc.headers else {}
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc

    parsed: Dict[str, Any] | List[Any] | str | None
    try:
        parsed = json.loads(text) if text else {}
    except Exception:
        parsed = text
    return HttpResult(
        status_code=code,
        headers=headers_map,
        body_text=text,
        body_json=parsed,
    )


def _build_request_capture(
    *,
    name: str,
    method: str,
    endpoint: str,
    headers: Dict[str, Any],
    body: Dict[str, Any] | None,
) -> Dict[str, Any]:
    return {
        "scenario": name,
        "captured_at": _utc_now_iso(),
        "method": method.upper(),
        "endpoint": endpoint,
        "headers": _redact_headers(headers),
        "body": body,
    }


def _build_response_capture(
    *,
    name: str,
    result: HttpResult,
) -> Dict[str, Any]:
    return {
        "scenario": name,
        "captured_at": _utc_now_iso(),
        "status_code": result.status_code,
        "headers": result.headers,
        "body": result.body_json,
    }


def _require_response_fields(
    *,
    scenario: str,
    payload: Dict[str, Any],
    required_fields: List[str],
) -> List[str]:
    missing = []
    for field in required_fields:
        if payload.get(field) in (None, ""):
            missing.append(field)
    return missing


def _ensure_status(actual: int, expected: int, *, scenario: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{scenario}: expected HTTP {expected}, got {actual}")


def _write_readme(path: Path, zip_name: str) -> None:
    text = f"""Phase 1 Audit Packet
Generated at: {_utc_now_iso()}

This packet contains 5 smoke scenarios:
1. ALLOW (normal path)
2. Expired override DENY
3. SoD DENY
4. Strict-mode timeout/provider-error DENY
5. Idempotency conflict (same key, different payload)

All request files have sensitive headers redacted.
Zip artifact: {zip_name}
"""
    path.write_text(text, encoding="utf-8")


def _zip_dir(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(source_dir.rglob("*")):
            if item.is_file():
                zf.write(item, item.relative_to(source_dir))


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_request(config: Dict[str, Any], name: str) -> Dict[str, Any]:
    try:
        return config["scenarios"][name]
    except Exception as exc:
        raise RuntimeError(f"Missing scenario config: {name}") from exc


def _run_single_scenario(
    *,
    base_url: str,
    default_headers: Dict[str, Any],
    scenario_name: str,
    scenario: Dict[str, Any],
    output_dir: Path,
    timeout_seconds: float,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    endpoint = str(scenario.get("endpoint") or "").strip()
    method = str(scenario.get("method") or "POST").upper()
    request_body = scenario.get("request")
    headers = {**default_headers, **(scenario.get("headers") or {})}
    full_url = f"{base_url.rstrip('/')}{endpoint}"

    request_capture = _build_request_capture(
        name=scenario_name,
        method=method,
        endpoint=endpoint,
        headers=headers,
        body=request_body,
    )
    result = _http_request(
        url=full_url,
        method=method,
        headers=headers,
        body=request_body,
        timeout_seconds=timeout_seconds,
    )
    response_capture = _build_response_capture(name=scenario_name, result=result)

    expected_status = int(scenario.get("expected_status", 200))
    _ensure_status(result.status_code, expected_status, scenario=scenario_name)

    body_json = result.body_json if isinstance(result.body_json, dict) else {}
    required_fields = list(scenario.get("required_response_fields") or [])
    missing = _require_response_fields(
        scenario=scenario_name,
        payload=body_json,
        required_fields=required_fields,
    )
    if missing:
        raise RuntimeError(f"{scenario_name}: missing required response fields: {missing}")

    _json_dump(output_dir / f"{scenario_name}.request.json", request_capture)
    _json_dump(output_dir / f"{scenario_name}.response.json", response_capture)
    return request_capture, response_capture


def _run_idempotency_conflict(
    *,
    base_url: str,
    default_headers: Dict[str, Any],
    scenario: Dict[str, Any],
    output_dir: Path,
    timeout_seconds: float,
) -> None:
    endpoint = str(scenario.get("endpoint") or "").strip()
    method = str(scenario.get("method") or "POST").upper()
    request_a = scenario.get("request_a")
    request_b = scenario.get("request_b")
    idem_key = str(scenario.get("idempotency_key") or "").strip()
    if not idem_key:
        raise RuntimeError("idempotency_conflict: idempotency_key is required")
    if not isinstance(request_a, dict) or not isinstance(request_b, dict):
        raise RuntimeError("idempotency_conflict: request_a and request_b must be objects")

    headers = {**default_headers, **(scenario.get("headers") or {})}
    headers["Idempotency-Key"] = idem_key
    full_url = f"{base_url.rstrip('/')}{endpoint}"

    first_result = _http_request(
        url=full_url,
        method=method,
        headers=headers,
        body=request_a,
        timeout_seconds=timeout_seconds,
    )
    _ensure_status(first_result.status_code, int(scenario.get("first_expected_status", 200)), scenario="idempotency.first")

    second_capture = {
        "scenario": "05-idempotency-conflict",
        "captured_at": _utc_now_iso(),
        "method": method.upper(),
        "endpoint": endpoint,
        "headers": _redact_headers(headers),
        "idempotency_key": idem_key,
        "first_request_body": request_a,
        "conflict_request_body": request_b,
    }
    second_result = _http_request(
        url=full_url,
        method=method,
        headers=headers,
        body=request_b,
        timeout_seconds=timeout_seconds,
    )
    _ensure_status(second_result.status_code, int(scenario.get("expected_status", 409)), scenario="idempotency.second")

    second_response_capture = {
        "scenario": "05-idempotency-conflict",
        "captured_at": _utc_now_iso(),
        "status_code": second_result.status_code,
        "headers": second_result.headers,
        "body": second_result.body_json,
        "first_call": {
            "status_code": first_result.status_code,
            "body": first_result.body_json,
        },
    }

    _json_dump(output_dir / "05-idempotency-conflict.request.json", second_capture)
    _json_dump(output_dir / "05-idempotency-conflict.response.json", second_response_capture)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Phase 1 smoke scenarios and generate an audit packet.")
    parser.add_argument("--config", required=True, help="Path to JSON config describing endpoints and payloads.")
    parser.add_argument(
        "--output-dir",
        default="/tmp/phase1-audit-packet",
        help="Directory to write packet files.",
    )
    parser.add_argument(
        "--zip-path",
        default="/tmp/Pillar1-AuditPacket.zip",
        help="Zip output path.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=20.0,
        help="HTTP timeout per request.",
    )
    args = parser.parse_args()

    config = _load_json(Path(args.config))
    base_url = str(config.get("base_url") or "").strip()
    if not base_url:
        raise RuntimeError("config.base_url is required")
    default_headers = dict(config.get("default_headers") or {})

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    _run_single_scenario(
        base_url=base_url,
        default_headers=default_headers,
        scenario_name="01-allow",
        scenario=_scenario_request(config, "allow"),
        output_dir=out_dir,
        timeout_seconds=float(args.timeout_seconds),
    )
    _run_single_scenario(
        base_url=base_url,
        default_headers=default_headers,
        scenario_name="02-expired-override-deny",
        scenario=_scenario_request(config, "expired_override_deny"),
        output_dir=out_dir,
        timeout_seconds=float(args.timeout_seconds),
    )
    _run_single_scenario(
        base_url=base_url,
        default_headers=default_headers,
        scenario_name="03-sod-deny",
        scenario=_scenario_request(config, "sod_deny"),
        output_dir=out_dir,
        timeout_seconds=float(args.timeout_seconds),
    )
    _run_single_scenario(
        base_url=base_url,
        default_headers=default_headers,
        scenario_name="04-strict-timeout-deny",
        scenario=_scenario_request(config, "strict_timeout_deny"),
        output_dir=out_dir,
        timeout_seconds=float(args.timeout_seconds),
    )
    _run_idempotency_conflict(
        base_url=base_url,
        default_headers=default_headers,
        scenario=_scenario_request(config, "idempotency_conflict"),
        output_dir=out_dir,
        timeout_seconds=float(args.timeout_seconds),
    )

    readme_path = out_dir / "README.txt"
    _write_readme(readme_path, Path(args.zip_path).name)

    manifest = {
        "generated_at": _utc_now_iso(),
        "files": [],
    }
    for file_path in sorted(out_dir.glob("*.json")):
        manifest["files"].append(
            {
                "filename": file_path.name,
                "sha256": _sha256_file(file_path),
            }
        )
    _json_dump(out_dir / "manifest.json", manifest)

    zip_path = Path(args.zip_path)
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    _zip_dir(out_dir, zip_path)
    print(f"packet_dir={out_dir}")
    print(f"zip_path={zip_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
