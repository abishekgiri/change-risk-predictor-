# Public Contract Versioning Policy

This policy governs ReleaseGate's public artifact contracts:

- `soc2_v1`
- `proof_pack_v1`
- `checkpoint_v1`

These contracts are compatibility-sensitive and are part of the project's public API surface.

## Compatibility Guarantee

- All three `*_v1` contracts are stable for the entire `v2.x` release line.
- Consumers may rely on the field names, field meanings, canonicalization rules, ordering rules, and signature/hash behavior documented in each contract file.
- A breaking change is never shipped under the same contract id.

Normative references:

- `docs/contracts/soc2_v1.md`
- `docs/contracts/proof_pack_v1.md`
- `docs/contracts/checkpoint_v1.md`
- `docs/releases/v2.0.0.md`

## Allowed Changes Within `v2.x`

- Documentation clarifications that do not change runtime behavior.
- Additive fields only where the contract explicitly allows additive evolution.
- New artifact versions introduced alongside the existing contract, for example `soc2_v2`, `proof_pack_v2`, or `checkpoint_v2`.
- New verification tooling or CI coverage that strengthens enforcement without changing artifact bytes or field semantics.

## Changes That Require A New Contract Version

The following are breaking changes and must ship as a new contract version:

- Removing, renaming, or changing the type of an existing field.
- Changing the meaning of an existing field or verdict.
- Changing canonical JSON rules, hash inputs, or signature verification semantics.
- Changing required file sets or archive ordering for `proof_pack_v1`.
- Changing top-level object names or required verification keys for `checkpoint_v1`.
- Changing exported key names or record semantics for `soc2_v1`.

If one of these changes is necessary, introduce a new contract id such as `*_v2` and keep the previous version available during migration.

## Deprecation Policy

- A stable contract version is not deprecated within the same major release line in which it is declared stable.
- `soc2_v1`, `proof_pack_v1`, and `checkpoint_v1` remain supported throughout `v2.x`.
- A contract may only be marked deprecated after its successor is implemented, documented, and covered by CI.
- Deprecation must be announced in the contract docs and release notes before removal.
- Removal may only happen in a later major release.

## Release Requirements For Any Future `*_v2`

Before introducing a new public artifact version:

1. Add the new contract doc under `docs/contracts/`.
2. Publish migration guidance in release notes and changelog entries.
3. Keep the previous contract available during the migration window.
4. Add or extend CI checks so both the old and new contracts are verified intentionally.

## CI Enforcement

- Local verification entrypoint: `make verify-public-contracts`
- CI workflow: `.github/workflows/public-contracts.yml`

These checks are intended to fail fast if a code or schema change would drift from the documented public contracts.
