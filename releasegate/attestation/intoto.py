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

    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [
            {
                "name": repo,
                "digest": {
                    "sha256": commit_sha,
                },
            }
        ],
        "predicateType": PREDICATE_TYPE_RELEASEGATE_V1,
        "predicate": attestation,
    }

