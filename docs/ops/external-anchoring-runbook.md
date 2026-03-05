# External Anchoring Runbook

## Purpose
Operate daily checkpoint anchoring with independent verification across two destinations:
- Immutable object-store style artifact sink.
- Git-mirror append-only anchor log.

## Runtime Components
- Independent checkpoint publisher: `releasegate.anchoring.independent_checkpoints`.
- External artifact writer: `releasegate.audit.anchor_scheduler`.
- Validation endpoint: `GET /audit/checkpoints/{checkpoint_id}/proof`.

## Key Environment Variables
- `RELEASEGATE_ANCHORING_ENABLED=true`
- `RELEASEGATE_ANCHOR_PROVIDER=http_transparency` (or approved non-local provider in strict mode)
- `RELEASEGATE_EXTERNAL_ANCHOR_BASE_DIR` (optional)
- `RELEASEGATE_EXTERNAL_ANCHOR_IMMUTABLE_DIR` (optional override)
- `RELEASEGATE_EXTERNAL_ANCHOR_GIT_MIRROR_DIR` (optional override)
- `RELEASEGATE_CHECKPOINT_SIGNING_KEY` or tenant key lifecycle must provide active signing key

## Daily Operation
1. Generate independent checkpoint for UTC day.
2. Publish provider anchor receipt.
3. Persist immutable artifact (`object_lock/.../checkpoint_id.json`).
4. Append git-mirror JSONL entry (`git_mirror/.../anchors.jsonl`).
5. Verify using `/audit/checkpoints/{checkpoint_id}/proof`.

## Key Rotation
1. Rotate checkpoint signing key through standard key lifecycle endpoint.
2. Confirm new key is active.
3. Publish new checkpoint.
4. Verify signature using proof endpoint and captured public key metadata.

## Failure Alerts
Trigger alerts when:
- Checkpoint generation fails.
- External provider anchor verification fails.
- Immutable artifact write fails.
- Git mirror append fails.
- Proof verification returns `valid=false`.

## Backfill Procedure
1. Identify missing UTC dates.
2. Run checkpoint creation for each missing date (oldest to newest).
3. Publish external artifacts for each checkpoint.
4. Re-run proof verification for each backfilled checkpoint.
5. Record incident/audit note with affected dates and remediation timestamp.

## Verification Checklist
- Signature valid.
- Checkpoint hash matches payload.
- Chain continuity (`prev_checkpoint_hash`) preserved.
- Ledger root and size match expected daily root.
- Both artifact destinations contain the checkpoint reference.
