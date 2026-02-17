from __future__ import annotations

from typing import Any, Dict


STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE_RELEASEGATE_V1 = "https://releasegate.dev/attestation/v1"


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

    # Prefer a stable sha256 digest for the subject. This keeps the statement
    # verifiable and avoids overloading sha256 with git SHA-1 commits.
    signature = attestation.get("signature") if isinstance(attestation.get("signature"), dict) else {}
    signed_payload_hash = str(signature.get("signed_payload_hash") or "").strip()
    digest_sha256 = ""
    if signed_payload_hash:
        digest_sha256 = signed_payload_hash.split(":", 1)[1] if ":" in signed_payload_hash else signed_payload_hash
        digest_sha256 = digest_sha256.strip().lower()

    subject_name = repo if not commit_sha else f"{repo}@{commit_sha}"

    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": digest_sha256 or commit_sha,
                },
            }
        ],
        "predicateType": PREDICATE_TYPE_RELEASEGATE_V1,
        "predicate": attestation,
    }
