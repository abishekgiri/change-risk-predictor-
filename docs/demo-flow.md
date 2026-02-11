# ReleaseGate Demo Flow

This demo creates and exports the exact sequence:

1. `BLOCKED` decision
2. `ALLOWED` override decision
3. Immutable override-ledger entry
4. Audit export in JSON and CSV

## Run (one command)

```bash
make demo
```

or:

```bash
python scripts/demo_block_override_export.py \
  --repo org/service-api \
  --pr 184 \
  --issue REL-184 \
  --actor release-manager@company.com \
  --reason "Emergency release override approved"
```

## Output

The command prints:

- Jira issue key
- Transition attempted
- Exact block reason
- Override actor + reason
- Decision IDs
- JSON/CSV export paths

Files:
- JSON: `audit_bundles/demo_flow/<repo>__pr_<n>__<timestamp>.json`
- CSV: `audit_bundles/demo_flow/<repo>__pr_<n>__<timestamp>.csv`

## API Export (optional)

If the API server is running:

```bash
curl "http://localhost:8000/audit/export?repo=org/service-api&pr=184&include_overrides=true&verify_chain=true&format=json"
curl "http://localhost:8000/audit/export?repo=org/service-api&pr=184&include_overrides=true&format=csv"
```
