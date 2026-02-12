# ReleaseGate Technical Roadmap

## Scope Freeze
ReleaseGate is a Jira-native release governance and enforcement engine.

## Done
- Transition-level Jira workflow enforcement is implemented (allow/block/skipped/error).
- Declarative policy engine is implemented with strict schema validation.
- Policy snapshot binding is implemented on decisions (`policy_id`, `policy_version`, `policy_hash`).
- Immutable override ledger is implemented (append-only, hash chained, verifiable).
- Deterministic decision replay is implemented.
- Strict mode and separation-of-duties controls are implemented.
- Policy simulation (`what-if`) capability is implemented.
- Signed checkpointing and proof-pack export are implemented.

## Next
- Maintain and publish compatibility guarantees for 3 public artifacts:
- `soc2_v1` export contract.
- `proof_pack_v1` format.
- `checkpoint_v1` format.
- Add CI checks to prevent breaking changes in those contracts.
- Add explicit deprecation/version policy before introducing any `v2` artifact.

## Non-Goals
- No dashboards.
- No ML scoring.
- No source-code or diff storage.
- No repository cloning for deep analysis.
- No code-intelligence features.

## Public Artifacts
- `soc2_v1`: `docs/contracts/soc2_v1.md`
- `proof_pack_v1`: `docs/contracts/proof_pack_v1.md`
- `checkpoint_v1`: `docs/contracts/checkpoint_v1.md`
