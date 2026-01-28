# ReleaseGate User Guide

## Installation

```bash
pip install releasegate
```

## Quick Start

Evaluate a pull request:

```bash
releasegate evaluate --repo owner/repo --pr 123 --format json
```

Enforce the decision immediately:

```bash
releasegate evaluate --repo owner/repo --pr 123 --enforce
```

Output:
```json
{
  "decision_id": "8ecd7182-0569...",
  "release_status": "ALLOWED",
  "matched_policies": [],
  "message": "No policies matched."
}
```

## Policy Authoring

Policies are defined in YAML and evaluated deterministically.

### Example Policy

```yaml
id: prod-critical-change
description: Block high risk changes in production
priority: 10
when:
  environment:
    eq: "PRODUCTION"
  context:
    change.lines_changed:
      gt: 500
then:
  decision: "BLOCKED"
  message: "Change is too large for automatic approval in PRODUCTION"
```

## Enforcement

ReleaseGate supports retroactive enforcement. This separation of evaluation and execution allows for delayed governance and robust retries.

### Enforce a previous decision

```bash
# Dry run to see what actions will be taken
releasegate enforce --decision-id <ID> --dry-run

# Execute actions (Idempotent)
releasegate enforce --decision-id <ID>
```

## Auditing

All decisions are recorded by default. These records are immutable and hash-verified.

### Query Audit Log

List recent decisions for a repository:
```bash
releasegate audit --repo owner/repo
```

Filter by status:
```bash
releasegate audit --repo owner/repo --status BLOCKED
```

Show full details for a specific decision:
```bash
releasegate audit --decision-id <ID> --format json
```
