from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

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


def get_anchor_provider(*, name: Optional[str] = None) -> AnchorProvider:
    selected = str(name or get_anchor_provider_name()).strip().lower()
    if selected in {"", "local", "local_transparency", "transparency"}:
        return LocalTransparencyAnchorProvider()
    raise AnchorProviderError(
        f"Unsupported anchor provider: {selected}. Supported: local_transparency"
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
