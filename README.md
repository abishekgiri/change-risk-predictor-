# ReleaseGate

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ReleaseGate is evidence infrastructure for software changes — so you can prove to auditors and CISOs that every deploy was approved, reviewed, and safe.

Built for fintech, healthtech, and regulated SaaS companies with 30–150 engineers, GitHub + Jira, ≥3 deploys/week, and a SOC 2 or ISO audit in the next 12 months.

## What you get

Every approved change produces a portable evidence pack — a signed bundle that an auditor can verify offline, without access to your infrastructure. The decision gate is deterministic: same pull request, same policy, same commit produces the same signed verdict every time, with a per-run signature that ties each execution back to a specific CI invocation. The audit ledger is hash-chained and append-only, so any tampering is detectable from the outside.

## Five-minute quickstart

```bash
# 1. Install
pip install -r requirements.txt

# 2. Score a pull request and emit a signed attestation
releasegate analyze-pr \
  --repo your-org/your-repo \
  --pr 42 \
  --tenant default \
  --emit-dsse attestation.dsse.json

# 3. Verify the signed attestation offline
releasegate verify-dsse \
  --dsse attestation.dsse.json \
  --key-file public.pem \
  --require-keyid <your-key-id>
```

A longer walkthrough lives in [`docs/quickstart.md`](docs/quickstart.md).

## Customer-installable GitHub Action

The [ReleaseGate Action](https://github.com/abishekgiri/releasegate-action) drops into any GitHub repository's workflow and signs that repository's deploys against your ReleaseGate tenant key. No infrastructure to operate. Tenant provisioning during the design-partner phase is by email — see [pricing](https://releasegate.io/pricing).

## Dashboard

<!-- TODO: capture dashboard screenshot and link as
     docs/img/dashboard.png.  See PR #134 review. -->
<!-- ![dashboard](docs/img/dashboard.png) -->

## License & support

MIT — see [LICENSE](LICENSE).
Issues and requests: <https://github.com/abishekgiri/change-risk-predictor-/issues>

---

See [`docs/architecture.md`](docs/architecture.md) for technical detail (policy DSL, attestation contract, audit fabric, deployment surface).
