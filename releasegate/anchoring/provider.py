from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

import requests

from releasegate.attestation.sdk import verify_inclusion_proof
from releasegate.audit.transparency import (
    get_or_compute_transparency_root,
    get_transparency_inclusion_proof,
)
from releasegate.config import get_anchor_provider_name, is_anchoring_enabled
from releasegate.storage.base import resolve_tenant_id


class AnchorProviderError(RuntimeError):
    """Raised when anchoring provider operations fail."""


class AnchorProvider(Protocol):
    name: str

    def anchor(
        self,
        *,
        attestation_id: str,
        attestation_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        ...

    def verify(self, *, receipt: Dict[str, Any]) -> bool:
        ...

    def anchor_root(
        self,
        *,
        date_utc: str,
        root_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        ...

    def verify_root(
        self,
        *,
        receipt: Dict[str, Any],
        expected_root_hash: str,
    ) -> bool:
        ...


@dataclass(frozen=True)
class LocalTransparencyAnchorProvider:
    """Adapter over the built-in transparency log + Merkle proof store."""

    name: str = "local_transparency"

    def anchor(
        self,
        *,
        attestation_id: str,
        attestation_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        effective_tenant = resolve_tenant_id(tenant_id)
        proof = get_transparency_inclusion_proof(
            attestation_id=attestation_id,
            tenant_id=effective_tenant,
        )
        if not proof:
            return None

        date_utc = str(proof.get("date_utc") or "").strip()
        root = None
        if date_utc:
            root = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=effective_tenant)

        return {
            "provider": self.name,
            "tenant_id": effective_tenant,
            "attestation_id": attestation_id,
            "attestation_hash": attestation_hash,
            "root": root,
            "inclusion_proof": proof,
        }

    def verify(self, *, receipt: Dict[str, Any]) -> bool:
        proof = receipt.get("inclusion_proof") if isinstance(receipt, dict) else None
        if not isinstance(proof, dict):
            return False
        return bool(verify_inclusion_proof(proof))

    def anchor_root(
        self,
        *,
        date_utc: str,
        root_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        effective_tenant = resolve_tenant_id(tenant_id)
        root = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=effective_tenant)
        if not root:
            return None
        return {
            "provider": self.name,
            "tenant_id": effective_tenant,
            "date_utc": str(date_utc),
            "root_hash": str(root_hash),
            "root": root,
            "external_ref": f"local:{effective_tenant}:{date_utc}:{root_hash}",
        }

    def verify_root(
        self,
        *,
        receipt: Dict[str, Any],
        expected_root_hash: str,
    ) -> bool:
        if not isinstance(receipt, dict):
            return False
        if str(receipt.get("provider") or "").strip().lower() != self.name:
            return False
        root = receipt.get("root") if isinstance(receipt.get("root"), dict) else {}
        receipt_root_hash = str(
            root.get("root_hash")
            or receipt.get("root_hash")
            or ""
        ).strip()
        return bool(receipt_root_hash and receipt_root_hash == str(expected_root_hash or "").strip())


@dataclass(frozen=True)
class HttpTransparencyAnchorProvider:
    """
    External transparency anchor provider.
    Posts daily Merkle roots to an external service.
    """

    name: str = "http_transparency"

    def _endpoint(self) -> str:
        url = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_URL") or "").strip()
        if not url:
            raise AnchorProviderError("RELEASEGATE_ANCHOR_HTTP_URL is required for http_transparency provider")
        return url

    def _timeout_seconds(self) -> float:
        raw = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_TIMEOUT_SECONDS") or "5").strip()
        try:
            return max(0.1, float(raw))
        except Exception:
            return 5.0

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        token = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_TOKEN") or "").strip()
        if token:
            header_name = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_AUTH_HEADER") or "Authorization").strip()
            if header_name.lower() == "authorization" and not token.lower().startswith("bearer "):
                headers[header_name] = f"Bearer {token}"
            else:
                headers[header_name] = token
        return headers

    def anchor(
        self,
        *,
        attestation_id: str,
        attestation_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        return None

    def verify(self, *, receipt: Dict[str, Any]) -> bool:
        return isinstance(receipt, dict) and str(receipt.get("provider") or "").strip().lower() == self.name

    def anchor_root(
        self,
        *,
        date_utc: str,
        root_hash: str,
        tenant_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        effective_tenant = resolve_tenant_id(tenant_id)
        payload = {
            "tenant_id": effective_tenant,
            "date_utc": str(date_utc),
            "root_hash": str(root_hash),
        }
        response = requests.post(
            self._endpoint(),
            json=payload,
            headers=self._headers(),
            timeout=self._timeout_seconds(),
        )
        if response.status_code not in {200, 201, 202}:
            raise AnchorProviderError(
                f"http_transparency anchor failed with status {response.status_code}: {response.text[:200]}"
            )
        body: Dict[str, Any]
        try:
            decoded = response.json()
            body = decoded if isinstance(decoded, dict) else {"value": decoded}
        except Exception:
            body = {"raw": response.text[:2000]}
        external_ref = str(
            body.get("log_index")
            or body.get("entry_id")
            or body.get("uuid")
            or body.get("id")
            or ""
        ).strip() or None
        return {
            "provider": self.name,
            "tenant_id": effective_tenant,
            "date_utc": str(date_utc),
            "root_hash": str(root_hash),
            "external_ref": external_ref,
            "response": body,
        }

    def verify_root(
        self,
        *,
        receipt: Dict[str, Any],
        expected_root_hash: str,
    ) -> bool:
        if not isinstance(receipt, dict):
            return False
        if str(receipt.get("provider") or "").strip().lower() != self.name:
            return False
        actual_root = str(
            (receipt.get("response") or {}).get("root_hash")
            or receipt.get("root_hash")
            or ""
        ).strip()
        return bool(actual_root and actual_root == str(expected_root_hash or "").strip())


def get_anchor_provider(*, name: Optional[str] = None) -> AnchorProvider:
    selected = str(name or get_anchor_provider_name()).strip().lower()
    if selected in {"", "local", "local_transparency", "transparency"}:
        return LocalTransparencyAnchorProvider()
    if selected in {"http", "http_transparency", "rekor_http"}:
        return HttpTransparencyAnchorProvider()
    raise AnchorProviderError(
        f"Unsupported anchor provider: {selected}. Supported: local_transparency, http_transparency"
    )


def anchor_attestation(
    *,
    attestation_id: str,
    attestation_hash: str,
    tenant_id: Optional[str],
    provider_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not is_anchoring_enabled():
        return None
    provider = get_anchor_provider(name=provider_name)
    return provider.anchor(
        attestation_id=attestation_id,
        attestation_hash=attestation_hash,
        tenant_id=tenant_id,
    )


def verify_anchor_receipt(
    *,
    receipt: Dict[str, Any],
    provider_name: Optional[str] = None,
) -> bool:
    provider = get_anchor_provider(name=provider_name)
    return provider.verify(receipt=receipt)


def anchor_root(
    *,
    date_utc: str,
    root_hash: str,
    tenant_id: Optional[str],
    provider_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not is_anchoring_enabled():
        return None
    provider = get_anchor_provider(name=provider_name)
    return provider.anchor_root(
        date_utc=date_utc,
        root_hash=root_hash,
        tenant_id=tenant_id,
    )


def verify_root_anchor_receipt(
    *,
    receipt: Dict[str, Any],
    expected_root_hash: str,
    provider_name: Optional[str] = None,
) -> bool:
    provider = get_anchor_provider(name=provider_name)
    return provider.verify_root(receipt=receipt, expected_root_hash=expected_root_hash)
