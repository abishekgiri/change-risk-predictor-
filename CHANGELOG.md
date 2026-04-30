# Changelog

All notable changes to this project will be documented in this file.

## [v2.2.0] - 2026-04-30 — Deterministic Governance

The headline milestone: `decision_id` is now deterministic across CI re-runs, with storage idempotency that follows from it. Each CI invocation still produces its own DSSE-signed attestation, so the per-run forensic chain is preserved.

### Added

-   **Allowlist architecture for decision-id seed** (PR #128) — `_VERDICT_BEARING_SIGNAL_KEYS = {"metrics", "dependency_provenance", "override_flags"}` is the entire surface that influences `decision_id`. Anything else is run-of-record by default.
-   **Contract test for signal classification** (PR #128) — `TestSignalKeyClassificationContract` in `tests/attestation/test_decision_id_stability.py` fails CI when a contributor adds a new `signals_payload` key without explicit classification.
-   **DSN validation at storage layer** (PR #122) — `PostgresStorageBackend.__init__` raises `InvalidPostgresDSNError` (a `ValueError` subclass) immediately on a malformed DSN; no more silent fallback.
-   **`change_records` + `change_state_transitions` in canonical schema** (PR #123) — `init_db()` and forward-only migration `20260429_043_change_records_canonical` create them on cold-start. Fresh Postgres deployments work without manual DDL.
-   **`workflow_dispatch` + `pr_number` input** (PRs #118, #119) — `gh workflow run compliance-check.yml --ref main -f pr_number=<N>` enables ad-hoc verification runs.
-   **`Verify analysis produced a report` step** (PR #124) — fails the workflow job if `compliance_report.json` is missing, regardless of enforcement mode. Closes the silent-green failure mode.

### Changed

-   **`decision_id` is now `analysis-<sha256(seed)[:24]>`** with the seed locked down to verdict-bearing fields only. Same PR + same commit + same policy → same `decision_id`. Verified empirically on real public PR #125.
-   **Storage idempotency** is now full-stack. Re-runs collapse on `chg_<sha1(tenant|decision_id)>` and `cor_<sha1(tenant|repo|pr|sha)>` unique constraints. `change_records` does not grow on re-runs.
-   **`bundle.signals` retains full forensic metadata** including `workflow_run.run_id`, `run_attempt`, `ref`, `sha`, `actor`, plus `source_ref` — even though these no longer affect `decision_id`. The DSSE attestation captures the complete run-of-record per invocation.
-   **CI workflow** — `compliance-check.yml` now uses `--tenant local`, supports both `pull_request` and `workflow_dispatch` events, and fails loudly when `analyze-pr` does not produce a report.

### Fixed

-   **Determinism drift** that produced different `decision_id`s on re-runs of the same PR. Three iterations: PR #126 scrubbed `workflow_run.run_id` + `run_attempt`; PR #127 dropped `issued_at`; PR #128 replaced the blocklist with the allowlist that closes the class of bug.
-   **Render-vs-Neon DSN mismatch** — CI was misrouted to a Neon DB while the dashboard read Render. Resolved 2026-04-29 by updating the GitHub Actions secret to the correct Render external DSN; the new DSN validation makes future rotations safer.
-   **Cold-start onboarding** previously failed silently on a fresh Postgres because `change_records` was created lazily by `_ensure_tables()` rather than `init_db()`.

### Removed

-   The blocklist iterations (`_VOLATILE_WORKFLOW_RUN_FIELDS`) introduced in PRs #126 and #127 — superseded by the allowlist in PR #128.

### Audit / forensic guarantees (unchanged)

The properties below were unaffected by this release; they're called out so it's clear nothing was lost in pursuit of determinism:

-   `attestation_id` and `signed_payload_hash` are per-run unique (each CI invocation is its own signed envelope).
-   `audit_decisions.created_at` records when each signing happened.
-   `deploy_id` (in `change_records` and `cross_system_correlations`) captures `gha_<RUN_ID>_a<ATTEMPT>` per run.
-   DSSE attestations remain Ed25519-signed with key id `rg-ci-2026-02`.

### Tagline

> **Deterministic governance with per-run cryptographic audit trails.**

---

## [v2.1.0] - 2026-04-23

Previously documented only in the README's Versioning section; backfilled here for traceability.

### Added

-   **Trust & audit fabric** — trust score, signed daily checkpoints, RFC 3161 external anchoring, formal evidence graph, proof-of-history export (SOC2 v1).
-   **Governance operations dashboard** — Next.js UI for decisions, proof, and audit evidence.
-   **Daily signed transparency roots** auto-published via `chore(roots): publish signed daily root` PRs.

### Changed

-   **Policy control plane** matured to support registry, inheritance, advanced lint, simulation, and CI gating.

---

## [v2.0.0-policy-control-plane] - 2026-02-12

### Added
-   **Policy Control Plane**: Declarative YAML-based policy engine with versioning and schemas.
-   **Immutable Audit Ledger**: Hash-chained, append-only ledger for all decisions.
-   **Signed Checkpoints**: Cryptographic checkpoints for ledger integrity.
-   **Audit Proof Packs**: Exportable, verifiable evidence bundles (JSON/ZIP).
-   **Offline Verification**: CLI tool to verify proof packs without server access.
-   **Policy Simulation**: "What-if" analysis for policy changes against historical data.
-   **Tenant Isolation**: Strict tenant scoping with composite primary keys.
-   **Performance Caching**: Tenant-scoped caching for policies and Jira configurations.
-   **Forge Integration**: Hardened Jira workflow validator with structured logging.

### Changed
-   **Rebranding**: Unified product name to **ReleaseGate** (formerly Change Risk Predictor / RiskBot).
-   **Architecture**: Decoupled decision engine from integration layers.
-   **API Security**: Enhanced auth with route-aware precedence and strict JWT validation.

### Removed
-   Legacy risk scoring heuristics (replaced by policy engine).
-   Direct-to-database writes (replaced by ledger recorder).

---

## [v1.0.0-governance-core] - 2026-01-XX

### Added
-   Initial release governance features.
-   Basic Jira integration.
-   GitHub PR metadata ingestion.
