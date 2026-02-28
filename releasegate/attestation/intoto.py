from __future__ import annotations

from typing import Any, Dict

from releasegate.utils.canonical import sha256_json


STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE_RELEASEGATE_V1 = "https://releasegate.dev/attestation/v1"
PREDICATE_TYPE_PROOF_PACK_V1 = "https://releasegate.dev/proof-pack/v1"


def build_intoto_statement(attestation: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be a JSON object")

    subject = attestation.get("subject") if isinstance(attestation.get("subject"), dict) else {}
    repo = str(subject.get("repo") or "").strip()
    commit_sha = str(subject.get("commit_sha") or "").strip()
    if not repo:
        raise ValueError("attestation.subject.repo is required")
    if not commit_sha:
        raise ValueError("attestation.subject.commit_sha is required")

    # Use a stable sha256 digest for the subject. This keeps the statement
    # verifiable and avoids overloading sha256 with git SHA-1 commits.
    signature = attestation.get("signature") if isinstance(attestation.get("signature"), dict) else {}
    signed_payload_hash = str(signature.get("signed_payload_hash") or "").strip()
    if not signed_payload_hash:
        raise ValueError("attestation.signature.signed_payload_hash is required")
    digest_sha256 = signed_payload_hash.split(":", 1)[1] if ":" in signed_payload_hash else signed_payload_hash
    digest_sha256 = digest_sha256.strip().lower()

    # Freeze subject naming: git+https URL with repo + commit.
    subject_name = f"git+https://github.com/{repo}@{commit_sha}"

    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": digest_sha256,
                },
            }
        ],
        "predicateType": PREDICATE_TYPE_RELEASEGATE_V1,
        "predicate": attestation,
    }


def build_proof_pack_statement(
    proof_bundle: Dict[str, Any],
    *,
    export_checksum: str,
) -> Dict[str, Any]:
    if not isinstance(proof_bundle, dict):
        raise ValueError("proof_bundle must be a JSON object")
    digest = str(export_checksum or "").strip().lower()
    if not digest:
        digest = sha256_json(proof_bundle)

    decision_id = str(
        (proof_bundle.get("ids") or {}).get("decision_id")
        or proof_bundle.get("decision_id")
        or ""
    ).strip()
    if not decision_id:
        raise ValueError("proof bundle decision_id is required")
    tenant_id = str(proof_bundle.get("tenant_id") or "").strip()

    subject_name = f"urn:releasegate:proof-pack:{tenant_id}:{decision_id}"
    predicate = {
        "bundle_version": proof_bundle.get("bundle_version"),
        "schema_version": proof_bundle.get("schema_version"),
        "tenant_id": tenant_id,
        "decision_id": decision_id,
        "ids": proof_bundle.get("ids") if isinstance(proof_bundle.get("ids"), dict) else {},
        "integrity": (
            proof_bundle.get("integrity") if isinstance(proof_bundle.get("integrity"), dict) else {}
        ),
        "evidence_graph_hash": str(
            ((proof_bundle.get("evidence_graph") or {}).get("graph_hash"))
            or ((proof_bundle.get("integrity") or {}).get("graph_hash"))
            or ""
        ),
        "export_checksum": digest,
    }

    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [
            {
                "name": subject_name,
                "digest": {"sha256": digest},
            }
        ],
        "predicateType": PREDICATE_TYPE_PROOF_PACK_V1,
        "predicate": predicate,
    }
