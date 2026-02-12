# Contributing to ReleaseGate

We welcome contributions to ReleaseGate! As a governance and enforcement engine, we emphasize **determinism**, **security**, and **auditability**.

## Core Principles

1.  **Fail-Closed**: If a policy or check fails unpredictably, the release must be blocked.
2.  **Audit Everything**: Every decision, override, and configuration change must be auditable.
3.  **Deterministic**: The same input + same policy + same context must yield the same decision.
4.  **Minimal Permissions**: We request the absolute minimum scope necessary from integrations.

## Development Setup

1.  Clone the repository:
    ```bash
    git clone https://github.com/abishekgiri/change-risk-predictor
    cd change-risk-predictor
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Run the test suite:
    ```bash
    pytest
    ```

## Submitting Changes

1.  Create a feature branch.
2.  Draft your changes.
3.  **Add tests**. New features without tests will not be accepted.
4.  Run `make test` (or `pytest`) to ensure all checks pass.
5.  Submit a Pull Request.

## Policy Changes

If modifying default policies or the policy engine, ensure you run the policy simulation suite:
```bash
python -m releasegate.cli simulate-policies --repo <test-repo>
```

## Security

Please review [SECURITY.md](SECURITY.md) for our security policy and reporting guidelines.
