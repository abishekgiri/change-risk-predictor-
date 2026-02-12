# Changelog

All notable changes to this project will be documented in this file.

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
