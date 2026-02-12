# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v2.0.x  | :white_check_mark: |
| v1.0.x  | :x:                |

## Reporting a Vulnerability

**Do not open a GitHub issue for security vulnerabilities.**

Please email **security-report@releasegate.io** (or the maintainer directly) with:
1.  A description of the vulnerability.
2.  Steps to reproduce.
3.  Impact assessment.

We will acknowledge receipt within 48 hours and provide a timeline for remediation.

## Threat Model

ReleaseGate operates as a governance control plane.
-   **Trust Boundary**: The `releasegate` server and database are trusted.
-   **Untrusted Input**: Webhooks from GitHub/Jira and policy definitions from users are treated as untrusted until validated.
-   **Audit Integrity**: The audit ledger is designed to be tamper-evident. Any bypass of the ledger is considered a critical vulnerability.

## Critical Security Controls

-   **Signature Verification**: Webhooks must be signed.
-   **Role Enforcement**: RBAC checks are mandatory for all overrides.
-   **Replay Protection**: Nonces and timestamps are enforced.
