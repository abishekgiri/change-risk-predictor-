# ReleaseGate — Longer Quickstart

This walkthrough runs ReleaseGate end-to-end against a local SQLite store: it generates a signed governance decision, builds a portable proof pack from that decision, verifies the pack offline without any server access, and verifies the Merkle inclusion proof of the underlying attestation. Three minutes from a clean machine; no GitHub or Jira credentials required.

## 1. Set up environment

```bash
set -euo pipefail
export COMPLIANCE_DB_PATH=/tmp/rg_demo.db
export RELEASEGATE_STORAGE_BACKEND=sqlite
export RELEASEGATE_TENANT_ID=demo
```

## 2. Generate signing key

```bash
openssl genpkey -algorithm ED25519 -out /tmp/rg_private.pem
openssl pkey -in /tmp/rg_private.pem -pubout -out /tmp/rg_public.pem
export RELEASEGATE_SIGNING_KEY="$(cat /tmp/rg_private.pem)"
```

## 3. Run migrations + create demo decisions

```bash
python -m releasegate.cli db-migrate >/dev/null

DEMO_JSON="$(make demo-json)"
DECISION_ID="$(printf '%s' "$DEMO_JSON" | python -c 'import json,sys; print(json.load(sys.stdin)["blocked_decision_id"])')"
```

## 4. Build a proof pack

```bash
OUT_JSON="$(python -m releasegate.cli proofpack --decision-id "$DECISION_ID" --tenant demo --out /tmp/proofpack.zip --format json)"
ATT_ID="$(printf '%s' "$OUT_JSON" | python -c 'import json,sys; print(json.load(sys.stdin)["attestation_id"])')"
```

## 5. Verify offline

```bash
# No server / no DB needed — pure file-and-key verification.
python -m releasegate.cli verify-pack /tmp/proofpack.zip --format json --key-file /tmp/rg_public.pem
python -m releasegate.cli verify-inclusion --attestation-id "$ATT_ID" --tenant demo --format json
```

Success looks like: `verify-pack` returns `"ok": true`, and `verify-inclusion` returns `"ok": true` with a `"root_hash"` value.

## 6. Cleanup

```bash
rm -f /tmp/rg_demo.db /tmp/proofpack.zip /tmp/rg_private.pem /tmp/rg_public.pem
```

---

For a UI view of the same data — decisions, evidence, policies — start the dashboard locally (`cd dashboard-ui && npm run dev`) and open `http://localhost:3000/overview`.

See [`architecture.md`](architecture.md) for the policy DSL, attestation contract, audit fabric, and deployment surface.
