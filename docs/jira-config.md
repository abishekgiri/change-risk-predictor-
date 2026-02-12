# Jira Mapping Configuration

ReleaseGate uses two Jira mapping files:

- `releasegate/integrations/jira/jira_transition_map.yaml`
- `releasegate/integrations/jira/jira_role_map.yaml`

## Transition Map (`jira_transition_map.yaml`)

```yaml
version: 1
jira:
  project_keys: ["DEMO"]
  issue_types: ["Bug", "Task"]
gate_bindings:
  release_gate: ["SEC-PR-001", "SEC-PR-003"]
transitions:
  - transition_id: "31"
    transition_name: "Done"
    gate: release_gate
    mode: strict
    applies_to:
      branches: ["main"]
      environments: ["PRODUCTION"]
```

Validation rules:

- `version` is required (`1`).
- each transition entry must define `transition_id` or `transition_name`.
- `gate` must resolve to known policy IDs (direct policy ID or `gate_bindings` alias).
- duplicate transition mappings (after project/issue-type scope expansion) are rejected.

## Role Map (`jira_role_map.yaml`)

```yaml
version: 1
roles:
  admin:
    jira_groups: ["jira-administrators"]
    jira_project_roles: ["Administrators"]
  operator:
    jira_groups: ["release-operators"]
```

Validation rules:

- `version` is required (`1`).
- allowed role keys: `admin`, `operator`, `auditor`, `read_only`.
- each role must include at least one resolver: `jira_groups` or `jira_project_roles`.

## Validation Command

```bash
python -m releasegate.cli validate-jira-config
```

Optional live Jira metadata checks:

```bash
python -m releasegate.cli validate-jira-config --check-jira
```

Exit behavior:

- `0` for `OK` or `WARN`
- non-zero for `FAIL`
