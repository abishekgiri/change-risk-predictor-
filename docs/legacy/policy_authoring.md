# Policy Authoring Guide

## Best Practices

### 1. Naming Conventions
- **IDs:** Use `CATEGORY-SUB-NUM` format.
 - Standard: `SOC2_CC6`, `ISO27001_A9`
 - Internal: `ACME_SEC_001`
- **Filenames:** Use snake_case matching the ID (e.g., `acme_sec_001.dsl`).

### 2. Logic Strategy
Prefer `require` for simple gates. It reads better.
- **Good:** `require approvals.count >= 1`
- **Bad:** `when approvals.count < 1 { enforce BLOCK }`

Use `when` for specific negative checks.
- **Good:** `when secrets.detected == true { enforce BLOCK }`

### 3. Signal Discovery
Available signals come from Phase 2 (Core Risk) and Phase 3 (Controls).
Common signals:
- `approvals.count` (int)
- `approvals.security_review` (int)
- `secrets.detected` (bool)
- `secrets.severity` (string: "LOW", "MEDIUM", "HIGH")
- `licenses.banned_detected` (bool)
- `env.production_violation` (bool)
- `deployment.risk_score` (int, 0-100)

### 4. Versioning
- Always increment `version` on change.
- Use `effective_date` for future policies.
- Use `supersedes` to link to the previous version.

### 5. Compliance Mapping
Always map to a standard if possible.
```groovy
compliance {
 SOC2: "CC6.1"
 ISO27001: "A.9.1"
}
```
This enables automatic audit evidence generation.
