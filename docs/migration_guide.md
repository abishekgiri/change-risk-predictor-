# Migration Guide: Phase 3 to Phase 4

## Architectural Shift
- **Phase 3:** Logic was hardcoded in Python `Control` classes (e.g., `CoreRiskControl`).
- **Phase 4:** Logic is declarative in `.dsl` files. Python classes only **emit signals**.

## Migration Steps

### 1. Identify Control Logic
Look at `check()` methods in Python controls.
*Example (Phase 3 Python):*
```python
if secrets_found:
 return Finding(severity="CRITICAL")
```

### 2. Map to Signals
Identify the signal that represents the condition.
- `secrets_found` -> `secrets.detected`

### 3. Write DSL
Create a new `.dsl` file.
```groovy
policy LEGACY_MIGRATION_01 {
 rules {
 when secrets.detected == true { enforce BLOCK }
 }
}
```

### 4. Compile
Run the compiler:
```bash
python3 -m compliancebot.policy_engine.compile
```

### 5. Verify
Run the engine against the new compiled policy to ensure it triggers under the same conditions as the old Python code.

## Runtime Changes
No runtime code changes are needed in `main.py`. The `ComplianceEngine` automatically prefers compiled policies if present.
