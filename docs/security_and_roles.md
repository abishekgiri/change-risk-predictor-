# Security & RBAC Model

ComplianceBot uses a **Shift-Left Compliance** model where controls are enforced in the CI/CD pipeline. Requires strict role mapping to be audit-compliant.

## Roles

| Role | GitHub Permission | Capabilities |
| :--- | :--- | :--- |
| **Developer** | Read / Write | • Trigger Compliance Checks (via PR)<br>• View Control Results<br>• Fix Policy Violations |
| **Maintainer** | Maintain / Admin | • **Approve Overrides** (via Labels)<br>• Merge Compliant PRs |
| **Compliance Officer** | Admin (Repo or Org) | • **Define Policies** (via `policies/` dir)<br>• Audit Logs Access<br>• Configure Webhooks |

## Override Security
Overrides are performed using **Protected Labels**.

1. **Restriction**: Only users with `Maintain` or `Admin` access can apply labels to Pull Requests.
2. **Audit**: The identity of the user who applied the label is logged by GitHub events and captured in the `ComplianceBot` Audit Evidence bundle.

### Approved Override Labels
- `compliance-override`
- `emergency`
- `hotfix-approved`

## Policy Security
Policies are defined as code in the `compliancebot/policies/` directory.
- This directory should be protected via **CODEOWNERS**.
- Changes to policies trigger a self-compliance check.
