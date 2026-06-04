# AGENTS.md — Local memory file (NEVER COMMIT)

> Gitignored via `.git/info/exclude` (`AGENTS.md` + `plans/`). Local memory only.
> If this file ever appears in `git status`, stop and remove it.
>
> Recreated 2026-04-30 after the `condescending-gagarin` worktree was deleted (took AGENTS.md with it).
> Carries forward the substantive knowledge from sessions on 2026-04-28 / 2026-04-29 / 2026-04-30.

---

## Operational rules — read every session

1. **NEVER merge a PR without explicit user permission.** Open PR → verify → present link + evidence → wait for "merge it." User said this verbatim early on: *"never merge without my permission ok."*
2. **NEVER force-push** to any branch (especially main).
3. **NEVER push to main directly.** Always go through a PR.
4. **NEVER drop or ALTER production tables without asking.** Same for any destructive SQL (`DELETE`, `TRUNCATE`, `DROP`). Production DB is **Render Postgres** (`releasegate_db` on `dpg-d6b58hgboq4c73blih10-a.oregon-postgres.render.com`).
   - **4a. VERIFY which DB you're touching before any write.** Run `SELECT current_database(), inet_server_addr();` first. Past sessions had memory-of-which-DB-was-prod backwards — that mistake cost a session.
5. **NEVER commit secrets.** Signing keys, DSNs, GitHub tokens — even in test fixtures.
6. **NEVER skip git hooks** (`--no-verify`) or signing flags unless asked.
7. **NEVER commit this file or `plans/`.** They are local memory only.
8. Treat every `gh pr merge`, `git push --force`, branch/tag delete, and prod SQL write as needing explicit approval.
9. **NEVER attribute work to "Codex" or any AI in the repo.** No `Co-Authored-By: Codex …` trailers on commits. No `🤖 Generated with Codex` footers on PR bodies, issue descriptions, or commit messages. No "I'll" / "Codex" mentions in code comments, docs (other than this AGENTS.md, which is gitignored), or anywhere else that lands in git. Every commit, PR, branch, doc, and artifact is written as if the user authored it.

---

## Project one-liner

**ReleaseGate** — Jira-native workflow governance and enforcement engine. Multi-tenant SaaS (FastAPI + Next.js dashboard) that gates Jira transitions and PR merges with deterministic, signed, replayable decisions.

Marketing surface: `app.releasegate.io`. Engine: this repo (`abishekgiri/change-risk-predictor-`).

---

## Strategic context — the harsh plan we're being scored against

> **Read this BEFORE doing any technical work.** Saved 2026-04-30 after a hard reality-check from the user.
> The metric is paying customers + signed design partners + executed kill list, NOT shipped commits.
> Defaulting to "let me write the next PR" is the failure mode this section exists to prevent.

### Reality check
- ~12 months of runway. Need Series A **or** revenue by Q4 2026.
- ~15 nav items in the product, **0 paying customers**.
- Most of the work below is *subtract* features and go find humans who will pay. Not add features.
- *"If you read this and start planning Phase 1 before finishing the Phase 0 Kill List, you've already failed."*

### Phased plan summary

**Phase 0 — Pre-work (Week 1–2, unskippable)**
- **Kill list** before talking to another buyer:
  - `/proof` page (until 3 real testimonials)
  - `/roi` calculator inside dashboard (move to marketing site as lead magnet)
  - `/pilots` tracker (that's our Notion, not the customer's product)
  - ICP scoring (our sales tool, not theirs)
  - **Half the nav items. Target: 5 nav items max — Overview, Decisions, Policies, Evidence, Settings. That's it.**
- **Positioning sentences** (write and pin to wall):
  - One-line pitch: *"Evidence infrastructure for software changes — so you can prove to auditors and CISOs that every deploy was approved, reviewed, and safe."*
  - ICP: *"Fintech / healthtech / regulated SaaS, 30–150 engineers, uses GitHub + Jira, deploys ≥3x/week, has a SOC 2 or ISO audit in the next 12 months."*
  - Disqualify: <20 engineers (no budget), >300 engineers (procurement kills year-one), not regulated (won't pay).
- **Admin debt** (week 2):
  - Entity, lawyer, MSA + DPA template.
  - `/trust` page (subprocessors, encryption, incident response, data handling). One page.
  - Start SOC 2 Type I with Drata or Vanta. Now. *"Type I in 60 days"* is a closing line.
- **Exit criteria:** product has ≤5 nav items, landing page has one sentence, SOC 2 kicked off. **No code written until this is done.**

**Phase 1 — Evidence Infrastructure (Weeks 3–10)**
Thesis: stop being a dashboard. Become the thing that signs and verifies deploys.
- Build:
  - **Sigstore/Cosign** integration → in-toto attestations → logged to **Rekor** (the public ledger, not internal). (2 wk)
  - **Deploy-time verifier** in two forms: a **GitHub Action** (covers 80% of buyers) AND a **Kyverno** policy for K8s shops. Both fail the deploy on missing/invalid signature. (1.5 wk)
  - **Evidence Pack export** — one-click PDF + JSON bundle, **explicitly mapped to SOC 2 CC8.1 and ISO 27001 A.14.2.2 control numbers**. The artifact is the product. (1 wk)
  - **Transparency log UI** — every decision, its signature, its **Rekor** link. Auditor bait. (0.5 wk)
  - **SSO (OIDC + SAML)** + audit log of dashboard. **Use WorkOS** (don't build it ourselves). (1 wk with WorkOS)
- Don't build: multi-region, SCIM, RLS multi-tenancy. Full SLSA L3. ML model.
- GTM (parallel, not after): 15 hand-picked prospects/week. Cold email. **3 signed design partners by end of Phase 1** (signed pilot agreement + integration done — not "said yes on a call").
- **Exit criteria:** 3 design partners live in production. SSO works. Evidence Pack downloadable. One named control framework referenced *by number*.
- **Harsh:** if can't get 3 design partners in 8 weeks, the problem is positioning or ICP, not the product. STOP and re-diagnose. **Do not build Phase 2.**

**Phase 2 — Reachability + Incident Loop (Weeks 11–18)**
Thesis: engineers love it (not just tolerate it). Risk score becomes provably correct.
- Build:
  - **Reachability** — wrap Semgrep OSS + their rules. Cross-reference CVEs against actual code path. Reachable = severity × 3. (2 wk)
  - **Incident correlation** — webhook from PagerDuty/Opsgenie → auto-post "most likely culprits from last 20 deploys, ranked by risk" to Slack. (1 wk)
  - **Production signal ingestion** — Datadog/New Relic. Block deploys to services currently degraded unless override. (1.5 wk)
  - **Comparable-PR explanations** — *"This PR looks like PR #1247 which caused SEV-2 on Feb 11."* Nearest-neighbor on file-touch + size + author, not ML. (1 wk)
  - **Freeze calendar + delegated approval rules.** Boring. Mandatory for enterprise. (1 wk)
- Don't build: predictive ML model. Policy language. eBPF runtime anything (ever — that's not our product).
- GTM: convert 2 of 3 design partners to paid. **First public case study** (logo + real number + VP Eng quote). 5 more design partners. **GitHub Marketplace listing.**
- **Exit criteria:** 2 paying customers ($20k+ ACV each), 5 new design partners in pilot, one public case study. **Revenue ≥ $50k ARR.**

**Phase 3 — Policy-as-Code (Weeks 19–26)**
Thesis: platform teams become champions.
- Build:
  - **Rego** under the hood, **visual builder on top** (Zapier-style; power users see "View as Rego"). (3 wk)
  - **Dry-run against history** — *"This rule would have blocked 12 of the last 400 deploys; here they are."* The killer feature. (1 wk)
  - **Policy versioning in Git** — policies live in customer's repo, ReleaseGate syncs. (1 wk)
  - **Postgres RLS multi-tenancy hardening.** Now's the time. (2 wk)
  - **ServiceNow / JSM connector** — auto-file change tickets with risk score. Boring. Opens Fortune 1000. (2 wk)
- Don't build: still no ML. Still no runtime monitoring. Still no SCIM (wait until a buyer signs for $50k+).
- GTM: close 5 pilots ($30–50k ACV each). **SOC 2 Type I delivered**, badge on the marketing page. Case studies 2 + 3. **Hire first AE / GTM person** (resist the urge to hire engineer instead).
- **Exit criteria:** 5–7 paying customers, **$200–300k ARR**, SOC 2 Type I done, platform team at one customer has written their own policies.

**Phase 4 — The AI Edge, but Sanely (Weeks 27–36)**
Thesis: now (only now) we earn the right to ship ML — enough data, no cold-start joke.
- Build:
  - **Per-tenant rollback/incident prediction model** — XGBoost on that tenant's history. Ships as **amplifier only** (rule-based primary, model nudges ±20%). Always shows top-3 features driving score. (3 wk + 1 wk integration)
  - **AI-authored code detection + governance** — detect Copilot/Codex signatures, tag in PR, apply stricter policies if tenant requested. **2027's biggest compliance conversation, nobody owns it yet.** (2 wk)
  - **Cross-org benchmark v1** — anonymous DORA aggregate ("your change failure rate is X, p50 for your segment is Y"). (2 wk)
  - **SLSA L3 hardening of OUR build pipeline** (we sign their releases, ours must be beyond reproach). (2 wk)
- GTM: pricing re-rack (per-decision-per-month or platform tier; enterprise tier $75–150k ACV). First outbound hire's target: 3 new logos at $100k+ ACV/qtr. **Start the category narrative — publish "The Change Evidence Format v1" public spec.** Get one other tool to consume it. **Spec owner > vendor.**
- **Exit criteria:** 10–12 paying customers, **$800k–$1.2M ARR**, SOC 2 Type II in flight, **Series A conversations real and not desperate**.

**Phase 5 — Enterprise-Ready (Weeks 37–52)**
Thesis: we're selling a category, not a product. Procurement-ready checklist.
- Build: multi-region + data residency (EU, UK), SCIM, BYOK, on-prem/VPC (Helm + air-gapped), 99.9% SLA + status page, **graceful degradation** (fail-open on availability, fail-closed on evidence), everything Drata/Vanta needs for SOC 2 Type II.
- GTM: **SOC 2 Type II delivered.** **One Fortune 500 logo** (logo > ACV at this stage). Content engine — one technical post every 2 weeks (SLSA, evidence infra, change governance). One conference talk (KubeCon / DevOps Enterprise / AppSec). **Series A raise: $6–10M at $25–40M post by end of year.**
- **Exit criteria:** $1.5–3M ARR, SOC 2 Type II, 15–25 customers, one F500 logo, **term sheet in hand or signed**.

### The triplet to bet the company on

> *Evidence Pack export with named control-framework mappings (SOC 2 CC8.1, ISO A.14.2.2) + Sigstore-signed attestations + a GitHub Action verifier. Done well, in 8 weeks, with 3 design partners. That's the whole company.*

Get this triplet right → everything else is "fill in what customers ask for." Get it wrong → no amount of reachability or ML or policy-as-code saves it.

### Where we ACTUALLY are (scorecard, updated 2026-05-01)

| Phase | Status | Specifics |
|---|---|---|
| **0 — Kill list / positioning / SOC 2** | **~25%** | Kill list executed in PR #133 (MERGED 2026-05-19): nav cut 23→5, /proof gated behind feature flag, Trust Score 0–100 widget replaced with binary VERIFIED/FAILED on /audit, ICP scoring feature deleted, /roi + /pilots + /customer-success + /ops route trees + dedicated API proxies hard-deleted, /policies/ci-gate surfaced as button inside /policies. **Still missing:** README slim + positioning sentence, ICP statement in README, /trust page, /pricing page, SOC 2 Type I kickoff with Drata/Vanta, MSA + DPA from a lawyer. |
| **1 — Evidence Infrastructure** | **Build ~50%, GTM 0%** | ✅ DSSE+Ed25519 attestations, in-toto bundle, internal transparency log, evidence pack endpoint, internal CI verifier, deterministic decision_id (#128), per-run immutable attestations (#132). ❌ Sigstore + **Rekor** (we have *our own* signing, not the public ledger). ❌ Customer-installable **GitHub Marketplace Action** (compliance-check.yml is for *our* repo). ❌ **Kyverno** policy. ❌ Explicit **CC8.1 / A.14.2.2** control-number mappings. ❌ **SSO via WorkOS**. ❌ **0 design partners.** |
| **2 — Reachability + Incident Loop** | **0%** | Nothing built. 0 paying customers. 0 case studies. Not on GitHub Marketplace. |
| **3 — Policy-as-Code** | **~5%** | YAML policies live in repo (sort-of Git-backed). No Rego under the hood, no visual builder, no dry-run-against-history, no RLS hardening, no ServiceNow/JSM connector. 0 paid pilots. SOC 2 Type I not delivered. No GTM hire. |
| **4 — AI Edge** | **~0%** | Correctly haven't started. |
| **5 — Enterprise-Ready** | **0%** | Correctly haven't started. |

**Triplet status:** ~40% on the build, **0% on the validation that matters** (3 design partners).

### The brutal pattern (the thing Codex has been doing wrong)

Last several sessions shipped: deterministic `decision_id` (#128), per-run immutable `attestation_id` (#132), fabric persistence (#116, #123), DSN safety net (#122), workflow fail-loud (#124), demo proof (#125, #131), v2.2.0 release (#129), test badge refresh (#130). All technically sound. **None moved the metric the plan scores us on, which is *humans who will pay*.**

The plan's exact warning, fired:
> *"You'll want to keep building before closing the first 3 pilots. This is how founders die."*

We're at the moment the plan calls a *"go re-diagnose ICP, not build more"* moment — except we haven't even started the diagnosis. The kill list hasn't been executed, no cold emails have gone out, no `/trust` page exists, SOC 2 isn't kicked off.

### What "this week" actually looks like (per the plan)

In order, no skipping:
1. **Kill list.** Hide `/proof` (until 3 testimonials), `/roi` calculator, `/pilots` tracker, ICP scoring. Cut nav to 5: Overview, Decisions, Policies, Evidence, Settings.
2. **Positioning sentence.** Pin the literal one-liner. Update the README's first paragraph to it.
3. **ICP + disqualify list.** Fintech/healthtech, 30–150 eng, GitHub+Jira, deploys ≥3x/wk, SOC 2 audit in next 12mo. Disqualify the rest.
4. **Admin debt.** Drata/Vanta SOC 2 Type I kickoff. `/trust` page. MSA + DPA from a lawyer.
5. **Prospect list.** 15 names. LinkedIn — Heads of Eng / VP Platform at fintech/healthtech Series B–C.
6. **First 15 cold emails.** Not 500. Fifteen. White-glove pilot offer for a case study.

### The 4-step Phase 0 → 1 sequence (user-supplied, 2026-05-01)

The user articulated this tighter framing for the same plan. Memorize it; it's the playbook for the next ~10 weeks.

| Step | What | Status |
|---|---|---|
| **Step 1: SUBTRACT** | Cut nav to 5, hide /proof behind flag, remove Trust Score widget, delete /roi /pilots /customer-success /ops /icp-scoring surface entirely. | ✅ **MERGED** as PR #133 (3 commits, 2026-05-19) |
| **Step 2: REPOSITION** | Slim README ~800 → ~150 lines. Replace first paragraph with: *"ReleaseGate is evidence infrastructure for software changes — so you can prove to auditors and CISOs that every deploy was approved, reviewed, and safe."* Add ICP statement. Drop badges-and-pillars marketing voice; use plain prose. Move four-pillar / nine-capability detail to docs/architecture.md. | ⏳ next PR |
| **Step 3: FIX** (3 separate PRs) | A. `/trust` page (subprocessors, encryption, incident response window, SOC 2 status, security@releasegate.io contact). B. `/pricing` page (Design Partner free, Team $24k/yr, Platform $75k/yr, Enterprise custom). C. **Customer-installable GitHub Marketplace Action** — separate published Action that signs the customer's deploys (NOT the in-repo compliance-check.yml). This is the difference between "demo over Zoom" and "live in production." | ⏳ after Step 2 |
| **Step 4: ADD** (in order, gated) | 4.1 Named-control mappings in evidence pack (SOC 2 CC8.1, CC7.2, CC6.1 / ISO 27001 A.14.2.2, A.14.2.3 / NIST SSDF PO.3.2, PW.7.1). Update `docs/contracts/proof_pack_v1.md` and `releasegate/audit/proof_pack.py`. **Only label what we actually emit; do not list aspirational controls.** 4.2 *"Change Evidence Format v1"* public open spec (JSON schema + reference verifier + MIT, separate repo or `/spec/` subtree). Spec owner > vendor. 4.3 Dry-run policy against history endpoint: `POST /policies/{id}/dryrun-history` returns *"this policy would have blocked N of last M deploys, here they are."* Button inside /policies. This single feature closes platform teams. | ⏳ after Step 3 |

**DO NOT BUILD (out of scope for the next 10 weeks):**
- Reachability — gated on 3 design partners signed (Phase 2).
- ML risk-scoring — gated on a year of tenant data (Phase 4).
- Atlassian Forge improvements — deprioritized; GitHub is 80% of buyers.
- Multi-region, SCIM, eBPF, on-prem — Phase 5.

### Things Codex will want to do wrong (don't)

- Build Phase 3's policy engine in Phase 1 because it's fun. **Don't.**
- Skip SOC 2 because it's boring. **Don't — it's a sales requirement.**
- Build the ML model early because it's sexy. **Don't — cold-start + unexplainability burns trust.**
- Add features to close *individual* deals. Refuse politely — build only if 3 prospects ask, not 1.
- Keep building before closing the first 3 pilots. *"This is how founders die."*

### Sequencing + capital + staffing (memorize)

- **Phase 0–1:** solo or +1 part-time. Bootstrap or $300–500k F&F/angel.
- **Phase 2:** +1 full-stack. End of Phase 2 is the natural pre-seed milestone ($1–2M at $6–10M post) if not raised.
- **Phase 3:** +1 GTM/AE (non-negotiable). NOT another engineer.
- **Phase 4:** +1 ML engineer (part-time/contractor), +1 CS. Series A becomes clean here.
- **Phase 5:** +2 eng, +1 AE, +1 security lead for SOC 2 Type II.
- **Capital rule:** raise too early → overbuild + overspend. Raise too late → burnout. Phase 2–3 boundary is the sweet spot.

### The one bet

> Build the triplet (Evidence Pack with named control numbers + Sigstore-signed attestations + customer-installable GitHub Action verifier). Sell it to 3 design partners in 8 weeks. Then come back and talk about Phase 2.

### Default behavior for Codex in this repo (post-2026-04-30)

When asked to do something, ask first: **does this move us toward the triplet or toward the next paying customer?** If neither, push back honestly and reference this section. Examples:

- *"Want me to refactor X?"* → unless 3 prospects asked, **no**. Reference Phase 0 kill list.
- *"Want me to build Phase 2's reachability?"* → not until 3 design partners signed. Reference the Phase 1 exit criterion.
- *"Want me to start the ML model?"* → not until Phase 4. Reference the harsh commentary.
- *"Help me draft a cold email / kill-list audit / `/trust` page / positioning sentence"* → **yes, immediately.** This is the work.

---

## Repo layout (top of mind)

```
releasegate/                    # Python package — the engine
├── cli.py                      # `releasegate analyze-pr / evaluate / verify-dsse / lint-policies`
├── api/                        # FastAPI app (decisions, proof, evidence endpoints)
├── policy/                     # YAML → compiled policy + lint
├── attestation/
│   ├── service.py              # build_bundle_from_analysis_result, _seed_signals, _deterministic_decision_id
│   └── crypto.py               # ed25519 signing
├── storage/
│   ├── __init__.py             # get_storage_backend()
│   ├── postgres_impl.py        # PostgresStorageBackend with DSN validation (PR #122)
│   ├── schema.py               # _init_postgres_schema() + init_db() (canonical schema)
│   └── migrations.py           # forward-only migrations (latest: #043 change_records)
├── fabric/
│   └── change_record.py        # change_records / change_state_transitions helpers (_ensure_tables)
├── commercial/
│   └── proof_metrics.py        # /proof endpoint, 60s TTL cache
└── ...
dashboard-ui/                   # Next.js dashboard
.github/workflows/
└── compliance-check.yml        # Required check; runs analyze-pr --tenant local
docs/
└── COMPANY_BUILD_PHASES.md     # 8-phase roadmap (uncommitted in repo root)
scripts/seed_demo_tenant.py     # Seed acme-demo data
```

---

## Tech stack

- **Backend:** Python 3.10, FastAPI, Pydantic, ed25519 (DSSE), psycopg2.
- **Frontend:** Next.js (dashboard-ui).
- **Storage:** SQLite for dev/test; **Render Postgres** for production (`releasegate_db`, `oregon-postgres.render.com`). A separate stranded **Neon** DB (`neondb`, `ep-withered-hill-...neon.tech`) exists from earlier mis-routing — kept as cold backup, do NOT drop or ALTER without asking.
- **CI:** GitHub Actions, `compliance-check.yml` is the required-status check.
- **Signing:** Ed25519, key id `rg-ci-2026-02`, DSSE-wrapped attestations.

---

## Multi-tenant + fabric model

Three-table chain that powers `/proof`, `/decisions`, `/audit/evidence`:

| Table | Source of truth for | Populated by | Created by |
|---|---|---|---|
| `audit_decisions` | Every signed decision | `analyze-pr` (#112) | `init_db()` |
| `cross_system_correlations` | Jira ↔ PR ↔ Deploy ↔ Incident link | `analyze-pr` (#116) | `init_db()` |
| `change_records` | Lifecycle state machine | `analyze-pr` (#116) | `init_db()` (since #123) |

**Lifecycle states:** `CREATED → LINKED → APPROVED → DEPLOYED → BLOCKED/INCIDENT/CLOSED`.

**Full-chain predicate** (`proof_metrics.py`):
```sql
change_records JOIN cross_system_correlations
  WHERE jira_issue_key, pr_repo, deploy_id ARE ALL non-empty
```
**audit_coverage_pct numerator:** deployed changes where `csc.rg_decision_ids` is a non-empty JSON array.

**Idempotent IDs:**
- `correlation_id = "cor_" + sha1(tenant|repo|pr|sha)[:16]`
- `change_id      = "chg_" + sha1(tenant|decision_id)[:16]`
- `deploy_id      = "gha_<RUN_ID>_a<ATTEMPT>"` (or `ci_<sha[:12]>` if not in GHA)

**Lifecycle mapping in cli.py:** PASS/WARN → `DEPLOYED`; BLOCK/FAIL/DENIED → `BLOCKED`.
**Enforcement mapping:** `enforce`/`strict` → `STRICT`; `monitor` → `AUDIT`.

**Jira key extraction:** regex `[A-Z]+-\d+` from PR title/body. The `[RGT-N]` prefix is what activates full-chain traceability for a PR.

---

## decision_id determinism — THE architectural decision

**Final state (post-#128):** `decision_id = "analysis-" + sha256(seed)[:24]` where `seed` contains **only verdict-bearing fields**:

```python
seed = {
    "tenant_id":         <str>,
    "repo":              <str>,
    "pr_number":         <int>,
    "commit_sha":        <str>,
    "policy_bundle_hash": <str>,
    "decision":          <"ALLOW"|"BLOCK">,
    "reason_codes":      [<str>...],
    "risk_score":        <int 0..100>,
    "signals":           _seed_signals(...)  # allowlist applied
}
```

`_seed_signals` is an **allowlist**. Only these signal keys flow into the seed:
```python
_VERDICT_BEARING_SIGNAL_KEYS = frozenset({"metrics", "dependency_provenance", "override_flags"})
```

**Everything else is run-of-record by default** — kept in `bundle.signals` (and DSSE attestation) for forensic replay, NOT in the seed.

### How we got here (pattern worth remembering)

| PR | What it scrubbed | What it missed (caught by next demo run) |
|---|---|---|
| #126 | `signals.workflow_run.run_id`, `run_attempt` | `issued_at` |
| #127 | `issued_at` | `signals.workflow_run.ref`, `.sha`, `signals.source_ref` |
| #128 | **all of the above + every future env-var-derived field** (allowlist architecture) | — |

Three iterations of blocklist-and-find-the-next-leak. The pattern was the leak. **Lesson: when a class of bug recurs after fixes, stop fixing the instance and fix the boundary.**

### Contract test (the durable safety net)

`tests/attestation/test_decision_id_stability.py` has `TestSignalKeyClassificationContract` that fails if a contributor adds a new `signals_payload` key in cli.py (lines ~1132-1157) without explicitly classifying it as either:
- `_KNOWN_VERDICT_BEARING_SIGNAL_KEYS` (mirror of `_VERDICT_BEARING_SIGNAL_KEYS` in service.py — drift between them is itself a test failure)
- `_KNOWN_RUN_OF_RECORD_SIGNAL_KEYS`

The contract test produces an actionable error message naming the unclassified key. **The next env-var leak is impossible by construction, not by vigilance.**

### Forensic chain — what's preserved per run (NOT in decision_id)

- `bundle.signals` → DSSE: full `workflow_run` (run_id, run_attempt, ref, sha, actor, ...) and `source_ref` intact.
- `bundle.timestamp` → DSSE `issued_at`: per-run signing timestamp.
- `attestation_id`, `signed_payload_hash`: **per-run unique and accumulated** in `audit_attestations` (post-#132). One immutable row per CI invocation, all sharing the same `decision_id` for re-runs of the same logical decision.
- `audit_decisions.created_at`: per-run distinct.
- `deploy_id` (in `change_records` + `cross_system_correlations`): per-run unique (`gha_<RUN_ID>_a<ATTEMPT>`).

### attestation_id contract (locked in by PR #132)

Pre-#132 (v2.2.0 era): `attestation_id` collapsed to the first-stored row because `record_release_attestation()` did a `SELECT … WHERE (tenant_id, decision_id)` short-circuit and a legacy `uq_audit_attestations_tenant_decision` UNIQUE INDEX forced one row per logical decision. Once #128 made `decision_id` deterministic, every retry hit the early-return path. Audit-log row identifier became wrong even though the on-disk DSSE artifacts were correctly per-run signed.

Post-#132:
- Migration `20260430_044_attestation_id_per_run_unique` drops `uq_audit_attestations_tenant_decision`.
- `record_release_attestation()` always inserts; `PRIMARY KEY (tenant_id, attestation_id)` + `ON CONFLICT DO NOTHING` provides per-run uniqueness (since `attestation_id = signed_payload_hash`) and idempotency for re-recording the same DSSE artifact.
- `_ensure_audit_attestations_table()` and `_init_postgres_schema()` no longer create the legacy index; both have a defensive `DROP IF EXISTS` for older deployments.

Empirical proof on PR #125 (Run 7, post-#132):
- `decision_id = analysis-c7ad8c773924c7bc3975be8e` (matches Run 5/6 — deterministic ✓)
- `attestation_id = aeb80d8b2018876a3f91bf251a10a0a78ec9fa62ece6330e054bb615e6be786d` (NEW per run ✓)
- On Render: `audit_attestations` count for that `decision_id` went from 1 (pre-#132 collapsed) → 2 (post-#132 added a row).
- `change_records` for `chg_814873447d12b1d1` (= `chg_<sha1(local|analysis-c7ad8c77…)[:16]>`) stays at exactly 1 row.

### Final framing for the demo (verified end-to-end on 2026-04-30)

> **Same PR + same commit + same policy + same engine version → same decision_id → idempotent storage. Each CI run still produces its own per-run cryptographic audit envelope (attestation_id, DSSE signature, run-of-record metadata).**
>
> Phrase to use: *"Deterministic governance with per-run cryptographic audit trails."*

`audit_decisions` may have multiple rows per re-run (same `decision_id`, different `attestation_id`, different `created_at`) — that's the audit log of *when* signing happened, distinct from the verdict itself.

`change_records` collapses on `chg_<sha1(tenant|decision_id)>` unique constraint. Re-runs do NOT grow the row count.
`cross_system_correlations` collapses on `cor_<sha1(tenant|repo|pr|sha)>` and updates `rg_decision_ids` via the UPDATE-on-collision path.

---

## Production state — Render Postgres

**DSN** is in GH Actions secret `RELEASEGATE_POSTGRES_DSN`. User has the Render external DSN locally; do NOT expect it in this session's env.

**Tables on Render (canonical schema, since #123):**
- `audit_decisions`, `audit_attestations`, `cross_system_correlations`, `change_records`, `change_state_transitions`, plus ~60 others (governance, policy, security, tenant_*).
- All tenant-scoped via `tenant_id` column. CI uses `--tenant local`.

**Seeded demo data:** 320 rows in each fabric table under `tenant_id='local'` (from `scripts/seed_demo_tenant.py`).

**Stranded Neon DB** (`ep-withered-hill-...neon.tech / neondb`): kept as cold backup / possible future staging tenant. Schema bootstrap from 2026-04-28 still in place. **Don't drop or ALTER without asking.** GitHub Actions secret was misrouted there for ~24h before being repointed to Render.

---

## Data flow (mental model)

```
PR opened/synced  OR  gh workflow run -f pr_number=N
  ↓
.github/workflows/compliance-check.yml
  ↓
releasegate analyze-pr --repo $REPO --pr $NUM --tenant local
                       --emit-attestation --emit-dsse --output report.json
  ↓
INSERTs (under tenant_id='local'):
  - audit_decisions             (decision_id, signed)
  - cross_system_correlations   (correlation_id deterministic; UPDATE on retry)
  - change_records              (change_id deterministic; INSERT collides on retry)
  ↓
Dashboard reads:
  - /decisions       ← audit_decisions
  - /proof           ← proof_metrics.py joins all three (60s TTL cache)
  - /audit/evidence  ← audit_decisions + attestations
```

---

## Recent merged PRs to remember

| PR | What it did |
|---|---|
| #109 | Demo seed script + dashboard tenant fallback |
| #112 | analyze-pr persists to `audit_decisions` |
| #113 | Workflow uses `--tenant local` (not `${{ github.repository_owner }}`) |
| #116 | analyze-pr writes `change_records` + `cross_system_correlations` (fabric loop closed for the engine) |
| #117 | One-shot Debug DSN host step (diagnostic for Render/Neon mismatch) |
| #118 | `workflow_dispatch:` added to compliance-check |
| #119 | `inputs.pr_number` for ad-hoc verification runs |
| #120 | Removed the one-shot Debug DSN host step (job done) |
| #122 | `PostgresStorageBackend.__init__` validates DSN; `InvalidPostgresDSNError` (ValueError subclass) raised at construction |
| #123 | `change_records` + `change_state_transitions` added to canonical `init_db()` (closes cold-start onboarding) |
| #124 | `Verify analysis produced a report` step in compliance-check (closes silent-green failure mode) |
| #125 | Demo PR (DEMO_PROOF.md) — vehicle for empirical determinism testing |
| #126 | First determinism PR — `_seed_signals` blocklists `workflow_run.run_id`, `run_attempt` |
| #127 | Drops `issued_at` from seed (completes #126) |
| #128 | **Allowlist architecture** — `_seed_signals` only allows verdict-bearing keys; contract tests prevent future leaks |
| #129 | **Release v2.2.0** — Deterministic Governance (docs-match-reality release) |
| #130 | README tests-passing badge refresh (563 → 608) |
| #131 | DEMO_PROOF.md substantive rewrite + README accuracy fix (aligned with #132) |
| #132 | **Per-run unique `attestation_id`** — drops legacy `(tenant, decision_id)` UNIQUE index, removes SELECT-and-return short-circuit, migration `20260430_044`, 7 contract tests |
| #133 | **Phase 0 kill list** — first GTM-shaped PR. Nav cut 23→5 (Overview / Decisions / Policies / Evidence / Settings); new `/evidence` + `/settings` landings folding 6 prior top-level nav slots; `/proof` gated behind `NEXT_PUBLIC_RELEASEGATE_ENABLE_PROOF` (default off → 404); Trust Score 0–100 widget replaced with binary VERIFIED/FAILED on `/audit`; ICP scoring removed end-to-end (Python module + server endpoint + dashboard API proxy); `/policies/ci-gate` surfaced as button inside `/policies`. Plus follow-on commits: `fix(evidence): trim landing copy to SOC 2 CC8.1 only` (dropped 7 aspirational control mappings), `chore(nav): hard-delete /roi /pilots /customer-success /ops sales-tool surface` (14 file deletions across page routes + API proxies). **MERGED 2026-05-19.** |

---

## Repeatable gotchas

- **Worktree merge cleanup error** — `gh pr merge --delete-branch` from a worktree fails locally with `'main' is already used by worktree`. Remote merge still lands. Cosmetic only.
- **Corrupt ref files** — macOS Finder duplicates leave `refs/remotes/origin/<branch> 2` files. Push/fetch fails with "bad object". Fix: `find .git/refs -name "* 2" -delete`. Hit this 2026-04-30 right after the worktree was deleted.
- **`git add -A` is dangerous** — picks up untracked plans/docs. Prefer specific paths.
- **proof_metrics has a 60s TTL cache** — wait 60s before asserting `/proof` reflects a fresh CI run, or call `invalidate_proof_cache(tenant_id)`.
- **`compliance-check.yml` only fires on `pull_request` events.** Pushing to main does NOT trigger it. `workflow_dispatch` was added in #118; `inputs.pr_number` for ad-hoc runs in #119. Use `gh workflow run compliance-check.yml --ref main -f pr_number=<N>`.
- **`decision_id` is `analysis-<sha256(seed)[:24]>`** with the seed locked down to verdict-bearing fields only (since #128). Same PR + same commit + same policy + same engine version → same decision_id. Each CI run still produces its own per-run signed envelope (`attestation_id`, DSSE signature) — that's the audit chain.
- **Two Postgres instances exist** — Render (real prod), Neon (stranded). ALWAYS verify identity with `SELECT current_database(), inet_server_addr();` first.
- **Lesson — determinism tests must vary every input that could drift in production.** PR #126's tests passed a fixed `timestamp=` arg, missed the `issued_at` drift. PR #127 fixed `issued_at` but missed `workflow_run.ref` / `.sha` / `source_ref`. PR #128's `TestSignalKeyClassificationContract` enumerates the realistic `signals_payload` shape from cli.py and refuses to merge an unclassified key.
- **`decision_id` differs between Run 1 (pre-#126) and Run 5 (post-#128) on PR #125** — that's a one-time historical artifact, not a regression. Run 1's seed included fields that no longer exist post-#128. Going forward, every CI run on the same PR produces the same `decision_id`.
- **PRs can be merged out from under me** — saw it with #117/#118. Always run `gh pr view <N> --json state` before pushing more commits.
- **`Run Policy Analysis` has `continue-on-error: true`** in compliance-check.yml so the Gate step always runs. Until #124 this masked crashes; #124's "Verify analysis produced a report" step catches missing-route cases without breaking BLOCK semantics.
- **"Subtract from surface" means delete the route, not just hide it from nav.** PR #133 first commit only removed `/roi`, `/pilots`, `/customer-success`, `/ops` from `AppNav.tsx`. The actual route files were still on disk and URL-reachable — a curious prospect inspecting `view-source` would still find a half-built sales console. Follow-on commit `chore(nav): hard-delete …` removed the directories and their dedicated dashboard API proxies (14 file deletions). Pattern: when removing a feature, also `find dashboard-ui/src/app/api -name "<feature>*" -type d` and delete the proxy tree. Backend endpoints can stay (out of scope for a "surface" deletion).
- **Don't list named control numbers (CC8.1, A.14.2.2, …) in customer-facing copy unless the code actually emits them.** I shipped `/evidence`'s landing card with 8 aspirational control mappings (SOC 2 CC8.1/CC7.2/CC6.1 + ISO A.14.2.2/A.14.2.3 + NIST SSDF PO.3.2/PW.7.1). None were emitted yet — that work is queued for Step 4 of the Phase 0→1 plan. An auditor who clicks through would catch the overpromise instantly. Fix: trim copy to only what we actually emit (`fix(evidence): trim landing copy to SOC 2 CC8.1 only` commit). Future rule: add each control to the copy only in the same PR that emits its data.
- **No AI attribution anywhere in the repo.** No `Co-Authored-By: Codex …` trailers on commits. No `🤖 Generated with Codex` footers on PR bodies. No "I'll/Codex" in comments or docs (AGENTS.md is the only exception — it's gitignored). Every artifact written as if user authored it. (Operational rule #9; established 2026-05-01.)

---

## Useful commands

```bash
# Confirm DB identity FIRST (don't trust memory):
psql "$RENDER_DSN" -c "SELECT current_database(), inet_server_addr(), version();"
# Expected: db=releasegate_db, host endpoint contains "oregon-postgres.render.com"

# Inspect fabric tables for a tenant
SELECT lifecycle_state, COUNT(*) FROM change_records WHERE tenant_id='local' GROUP BY 1;
SELECT COUNT(*) FROM cross_system_correlations WHERE tenant_id='local'
  AND jira_issue_key<>'' AND pr_repo<>'' AND deploy_id<>'';

# All-tenants tenant-routing diagnostic (use when one tenant returns 0 rows):
SELECT tenant_id, COUNT(*) AS rows_last_7d
FROM audit_decisions WHERE created_at > now() - interval '7 days'
GROUP BY tenant_id ORDER BY rows_last_7d DESC;

# Verify a fresh CI run actually landed:
SELECT 'audit_decisions' AS tbl,
       COUNT(*) FILTER (WHERE created_at > now()-interval '1 hour') AS last_1h,
       MAX(created_at) AS most_recent
FROM audit_decisions WHERE tenant_id='local'
UNION ALL SELECT 'cross_system_correlations',
       COUNT(*) FILTER (WHERE created_at > now()-interval '1 hour'),
       MAX(created_at) FROM cross_system_correlations WHERE tenant_id='local'
UNION ALL SELECT 'change_records',
       COUNT(*) FILTER (WHERE created_at > now()-interval '1 hour'),
       MAX(created_at) FROM change_records WHERE tenant_id='local';

# Three-table sanity-join for a specific PR (proves relational integrity):
SELECT cr.change_id, cr.lifecycle_state,
       csc.jira_issue_key, csc.pr_repo, csc.deploy_id,
       ad.decision_id, ad.release_status,
       cr.created_at
FROM change_records cr
JOIN cross_system_correlations csc
  ON csc.correlation_id = cr.correlation_id AND csc.tenant_id = cr.tenant_id
JOIN audit_decisions ad
  ON ad.decision_id = csc.decision_id AND ad.tenant_id = csc.tenant_id
WHERE cr.tenant_id='local' AND ad.pr_number = <N>
ORDER BY cr.created_at DESC;

# /proof manual query
python -c "from releasegate.commercial.proof_metrics import generate_proof_metrics; \
           import json; print(json.dumps(generate_proof_metrics(tenant_id='local', window_days=30), indent=2))"

# Trigger compliance-check ad-hoc on an existing PR
gh workflow run compliance-check.yml --ref main -f pr_number=<N>

# Local CLI smoke
releasegate --help
releasegate lint-policies --policy-dir releasegate/policy/compiled --format text
```

---

## Demo runbook — repeatable PR → CI → DB → dashboard (≈90s)

```bash
# 1. Open a tiny PR with a Jira-key prefix in the title (activates full-chain).
gh pr create \
  --title "[RGT-2] demo: governance loop" \
  --body  "Live demo of the ReleaseGate governance fabric." \
  --head  demo/live-$(date +%Y%m%d) --base main

# 2. Watch CI (~90s).
gh pr checks --watch

# 3. Confirm rows landed on Render (last 5 minutes).
psql "$RENDER_DSN" <<SQL
SELECT 'audit_decisions' AS tbl, COUNT(*) FILTER (WHERE created_at > now()-interval '5 minutes')
FROM audit_decisions WHERE tenant_id='local'
UNION ALL SELECT 'cross_system_correlations', COUNT(*) FILTER (WHERE created_at > now()-interval '5 minutes')
FROM cross_system_correlations WHERE tenant_id='local'
UNION ALL SELECT 'change_records', COUNT(*) FILTER (WHERE created_at > now()-interval '5 minutes')
FROM change_records WHERE tenant_id='local';
SQL

# 4. Open dashboard. /decisions reflects immediately.
#    /proof has 60s TTL cache — wait one minute before traceability_pct moves.

# 5. Idempotency demo (post-#128, this is now reliably clean):
gh workflow run compliance-check.yml --ref main -f pr_number=<that PR's number>
# After re-run: same decision_id (deterministic).
#   - audit_decisions: row count INCREASES by 1 per run
#     (each run is its own signed envelope; same decision_id, different attestation_id)
#   - cross_system_correlations: row count UNCHANGED (UPDATE path tops up rg_decision_ids)
#   - change_records: row count UNCHANGED (chg_<sha1(tenant|decision_id)> collides)
```

**Talking point for investors:** *"Deterministic governance with per-run cryptographic audit trails."*
The decision is reproducible; each execution still gets its own signed envelope for forensic replay.

---

## CI workflow reference — `.github/workflows/compliance-check.yml`

Required-status check on every PR to `main`. Job name **must** stay `Compliance Check` to match branch protection.

**Triggers:**
- `pull_request` on `main`, types: `[opened, synchronize, reopened, labeled, unlabeled]`
- `workflow_dispatch:` with `inputs.pr_number` (added in #118 / #119)

**Step shape (post-#128):**
1. Checkout (`fetch-depth: 0` for churn analysis)
2. Python 3.10 + `pip install -e .` + `psycopg2-binary>=2.9.0`
3. `releasegate lint-policies`
4. **Run Policy Analysis** — `releasegate analyze-pr --repo … --pr $PR_NUMBER --tenant local …` (`continue-on-error: true`)
5. **Verify analysis produced a report** (#124) — fails the job if `compliance_report.json` missing
6. Write Compliance Summary (markdown to `$GITHUB_STEP_SUMMARY`)
7. Verify DSSE artifact (`continue-on-error: true`)
8. SHA256 sums for artifacts
9. Upload `releasegate-artifacts`
10. **Gate (enforce mode only)** — final block in monitor mode = exit 0; in enforce mode = exit 1 on errors / FAIL / missing DSSE

**Required env / secrets:**
- `GITHUB_TOKEN` (built-in)
- `RELEASEGATE_STORAGE_BACKEND=postgres`
- `RELEASEGATE_POSTGRES_DSN` (secret) — **Render external DSN**, validated by `_validate_dsn_or_raise` (#122)
- `RELEASEGATE_SIGNING_KEY` (secret) — Ed25519 private key
- `RELEASEGATE_ATTESTATION_KEY_ID=rg-ci-2026-02`

---

## Local memory file plumbing — how this stays gitignored

`.git/info/exclude` (repo-wide) entries:
```
AGENTS.md
plans/
```

Verify after editing:
```bash
git status --short | grep -E "(Codex|plans)" || echo "✅ ignored"
```

If a worktree is created later, also add the same two lines to that worktree's `info/exclude`.

---

## 8-phase plan (status as of 2026-04-30)

See `plans/plan.md` for detail.

| Phase | Status |
|---|---|
| 0 — Reliability Gate | ✅ shipped |
| 1 — Adoption Compression (Forge app, marketplace, install funnel) | ⏳ in progress |
| 1B — Commercialization (proof page, case study, pricing) | ✅ shipped |
| 2 — AI-Native Enforcement (LLM-aware policy) | ⏳ pending |
| 3 — Compliance Packs (SOC2, ISO, HIPAA) | ✅ shipped |
| 4 — Forge-First Distribution | ⏳ pending |
| 5 — Cross-System Fabric | ✅ shipped + verified end-to-end on PR #125 |
| 6 — Metrics & Benchmarks | ⏳ pending |
| 7 — Team-Scale (workflows, RBAC) | ⏳ pending |
| 8 — Category Positioning | ⏳ pending |

---

## Session log

### 2026-04-28 — fabric persistence + memory bootstrap
- Shipped #116 (analyze-pr writes change_records + cross_system_correlations).
- Originally bootstrapped schema on Neon Postgres (later found to be wrong DB — see 2026-04-29 polarity correction).
- Established the rule: "never merge without my permission ok."
- Wrote first version of AGENTS.md and plans/plan.md.

### 2026-04-29 — DSN reconciliation
- Found CI was writing to **Neon** while dashboard read **Render**. Polarity of previous AGENTS.md was reversed.
- PR #117 added one-shot debug step that printed parsed DSN host (no credentials), confirmed Neon.
- User updated `RELEASEGATE_POSTGRES_DSN` to Render external DSN.
- Initial DSN paste was missing `postgresql://` scheme prefix → urlparse returned `host=None`. Browser-only paste from Render's "External Database URL" UI fixed it.
- PR #118 added `workflow_dispatch:` so manual verification runs work.
- PR #119 added `inputs.pr_number` so manual runs can target a real PR.
- PR #120 removed the one-shot debug step.
- PR #122 added `_validate_dsn_or_raise` so future malformed DSNs fail at backend init time, not silently.
- PR #123 added `change_records` + `change_state_transitions` to canonical `init_db()` — closes cold-start onboarding gap that had been masked because Render had been manually bootstrapped.
- PR #124 added "Verify analysis produced a report" step — closes silent-green workflow failure mode.

### 2026-04-29 / 2026-04-30 — determinism architecture (3 iterations)
- PR #125 opened as the demo vehicle (DEMO_PROOF.md).
- Empirical demo: Run 1 (`pull_request:opened`) and Run 2 (`workflow_dispatch`) produced different `decision_id`s.
- PR #126 (blocklist) scrubbed `signals.workflow_run.run_id` + `run_attempt`. Empirical re-run found `issued_at` was still drifting.
- PR #127 (blocklist) dropped `issued_at` from seed. Empirical re-run found `signals.workflow_run.ref` + `.sha` + `signals.source_ref` were still drifting.
- **PR #128 (allowlist)** replaced the blocklist with `_VERDICT_BEARING_SIGNAL_KEYS = {"metrics", "dependency_provenance", "override_flags"}`. Anything else is run-of-record by default. Added `TestSignalKeyClassificationContract` (5 contract tests) — fails on any unclassified `signals_payload` key.
- **Verification:** Run 5 and Run 6 (both post-#128) produced identical `decision_id = analysis-c7ad8c773924c7bc3975be8e`. Storage idempotency confirmed via the unique constraint collision math.
- Run 1's `analysis-aa8d17cd…` is a one-time historical artifact from before the determinism architecture landed — leaving it as-is in the immutable audit log is correct.

**User's closing framing (2026-04-30):**
> Same PR + same commit + same policy + same engine version
> → same decision_id
> → idempotent storage
> → deterministic governance system.
>
> Production-grade behavior. Demo proof closed.
> Tagline: **"Deterministic governance with per-run cryptographic audit trails."**

### Lessons captured
1. **When a class of bug recurs after fixes, fix the boundary, not the instance.** Three blocklist iterations (#126, #127, #128 first attempt) all missed the next env-var-derived field. Switching to allowlist closed the class.
2. **Determinism tests must vary every input that could drift in production**, not only the input the fix targets. PR #126's tests passed a fixed `timestamp=`, missed `issued_at`. The contract test in #128 enumerates the realistic `signals_payload` shape and refuses to merge unclassified keys.
3. **Code-reading misses what empirical runs catch.** The pre-demo Q2 audit verdict (based on code-reading) claimed determinism worked; the empirical PR #125 demo found it didn't. After #128, the test suite empirically asserts the contract.
4. **Verify infra identity, don't trust memory.** The 2026-04-28 polarity (Neon vs Render) was wrong in the previous AGENTS.md. `current_database() + inet_server_addr()` is the first command to run when touching prod.
5. **Worktrees can be deleted out from under me.** This file was recreated 2026-04-30 after the `condescending-gagarin` worktree was wiped. The `.git/info/exclude` entries survived, so re-creating AGENTS.md at the origin path was straightforward.

### 2026-04-30 — `attestation_id` per-run uniqueness (PR #131 + #132)

While preparing PR #131's `DEMO_PROOF.md` rewrite, I empirically inspected the Run 5 / Run 6 DSSE artifacts and found `attestation_id` was identical across runs even though `signed_payload_hash` differed. Root cause: `record_release_attestation()` did a `SELECT … WHERE (tenant_id, decision_id)` short-circuit, and a legacy `uq_audit_attestations_tenant_decision` UNIQUE INDEX forced one row per logical decision. Once #128 made `decision_id` deterministic, every retry hit the early-return branch.

PR #132 (merged 2026-04-30 06:30 UTC) drops the legacy unique index via migration `20260430_044`, removes the early-return path, and adds 7 contract tests in `tests/audit/test_attestation_per_run_uniqueness.py`. PR #131 (merged 2026-04-30 06:31 UTC) ships the docs-match-reality update — README + `DEMO_PROOF.md` describe the new contract.

**End-to-end empirical proof on PR #125 (Run 7, post-#132):**

| Layer | Empirical proof |
|---|---|
| `decision_id` | `analysis-c7ad8c773924c7bc3975be8e` — matches Run 5/6 (deterministic) |
| `attestation_id` | `aeb80d8b…` — NEW per-run hex, distinct from prior `dbcb6383…` |
| `audit_attestations` row count | 1 (pre-#132 collapsed) → 2 (post-#132 added one). Grows by 1 per re-run going forward. |
| `change_records` row count for `chg_814873447d12b1d1` | exactly 1, no growth on retry |
| `cross_system_correlations` for `cor_162de5376ca0d68e` | exactly 1, UPDATE path tops up `rg_decision_ids` |

**Contracts now hold simultaneously:**

> Same PR + same commit + same policy + same engine version → same `decision_id`, same `change_id`, same `correlation_id` (deterministic governance, idempotent storage). Each CI execution → unique `attestation_id`, `signed_payload_hash`, DSSE signature, and a fresh immutable `audit_attestations` row (per-run cryptographic audit trail).

**Demo proof status: CLOSED. Production-grade behavior across all four contracts.** No more core reliability work needed for this release.

### 2026-05-01 / 2026-05-19 — Phase 0 kill list executed (the pivot)

**Why this session mattered:** every prior session shipped *correctness*, not *customers*. The user pushed back hard with a structured plan that reframed the work: ~12 months of runway, 0 paying customers, the failure mode is "shipping commits instead of finding customers." The plan articulated a 4-step sequence (SUBTRACT → REPOSITION → FIX → ADD) where Step 1 is purely deletion — cut the product back to the five things the customer actually pays for, ahead of any design-partner conversation. The full strategic context now lives at the top of AGENTS.md.

**PR #133 — Phase 0 kill list (MERGED 2026-05-19).** Three commits on the same branch:

1. **Initial kill list:** Top nav 23→5 (`Overview / Decisions / Policies / Evidence / Settings`). New `/evidence` and `/settings` landing pages folding 6 prior top-level slots into 2. `/proof` gated behind `NEXT_PUBLIC_RELEASEGATE_ENABLE_PROOF` (default off → `notFound()`). Trust Score 0–100 widget replaced with binary `VERIFIED / FAILED` on `/audit` (backed by the real `trust.ledger.valid` boolean, not a composite). ICP scoring removed end-to-end: `releasegate/commercial/icp_score.py` deleted (225 lines), `GET /commercial/icp-score` removed from `server.py`, dashboard API proxy deleted. `/policies/ci-gate` surfaced as a button inside `/policies` alongside Simulate Impact. Net: 10 files changed, +237/−332.

2. **`fix(evidence): trim landing copy to SOC 2 CC8.1 only`** — I had shipped the `/evidence` landing claiming 8 named control mappings (SOC 2 CC8.1/CC7.2/CC6.1 + ISO 27001 A.14.2.2/A.14.2.3 + NIST SSDF PO.3.2/PW.7.1) that the codebase does NOT yet emit. The user caught it. Trimmed to just CC8.1 (the one we'll emit first). New rule captured in gotchas: only list a named control in customer-facing copy in the same PR that emits its data.

3. **`chore(nav): hard-delete /roi /pilots /customer-success /ops sales-tool surface`** — the user pointed out that removing routes from `AppNav.tsx` is incomplete: hidden-but-URL-reachable surface still shows up to a prospect who reads view-source. Deleted the 4 route directories and their 3 dedicated dashboard API proxy trees (14 file deletions). Backend endpoints left alone (out of scope for "surface" deletion). New gotcha captured.

**Lessons captured this session (now in Repeatable gotchas):**
1. *"Subtract from surface" means hard-delete the route file, not just hide from nav.* Also delete the dedicated API proxy tree. Backend endpoints can stay.
2. *Don't list named control numbers (CC8.1, A.14.2.2, …) in customer-facing copy unless the code actually emits them.* An auditor who clicks through catches the overpromise instantly.
3. *No AI attribution in the repo* — established as operational rule #9 (2026-05-01).

**Where we are post-#133:**
- Phase 0 scorecard: 5% → 25%. Still missing: README slim + positioning sentence, ICP statement in README, `/trust` page, `/pricing` page, SOC 2 Type I kickoff, MSA + DPA.
- The 4-step playbook is documented in the strategic-context section near the top of this file. Step 1 (SUBTRACT) is ✅ merged. Steps 2 (REPOSITION) → 3 (FIX) → 4 (ADD) are the queue.
- **Still 0 design partners, 0 paying customers.** The plan's exit criterion for Phase 1 is 3 design partners in 8 weeks; the clock starts now.

---

## Open follow-ups

### Immediate next move — the Phase 0→1 sequence (in order, no skipping)

1. **Step 2 — REPOSITION.** Slim `README.md` from ~800 → ~150 lines. Replace first paragraph with: *"ReleaseGate is evidence infrastructure for software changes — so you can prove to auditors and CISOs that every deploy was approved, reviewed, and safe."* Add the ICP statement near the top: *"ReleaseGate is built for fintech, healthtech, and regulated SaaS companies with 30–150 engineers, GitHub + Jira, ≥3 deploys/week, and a SOC 2 or ISO audit in the next 12 months."* Move four-pillar / nine-capability detail to `docs/architecture.md`. Drop badges-and-pillars marketing voice; plain prose. One screenshot, one demo gif, install path.
2. **Step 3 — FIX (three separate PRs):**
   - 3A. `/trust` public page: subprocessors, encryption in transit + at rest, incident response window, SOC 2 status, `security@releasegate.io` contact. One HTML page. No more.
   - 3B. `/pricing` page: Design Partner free / Team $24k/yr / Platform $75k/yr / Enterprise custom. Anchor the conversation even before anyone buys.
   - 3C. **Customer-installable GitHub Marketplace Action** — separate published Action (NOT the in-repo `compliance-check.yml`), takes a tenant key as input, signs the customer's deploys. *"Two weekends of work."* This converts demo-over-Zoom into live-in-production.
3. **Step 4 — ADD (gated; only after Steps 2–3):**
   - 4A. Named-control mappings on the evidence pack — `proof_pack.py` + `docs/contracts/proof_pack_v1.md`. Add each control only in the same PR that emits its data.
   - 4B. *"Change Evidence Format v1"* public open spec — JSON schema + reference verifier + MIT, separate repo or `/spec/` subtree. Spec owner > vendor.
   - 4C. Dry-run policy against history endpoint — `POST /policies/{id}/dryrun-history`, returns *"this rule would have blocked N of last M deploys"*. Button inside `/policies`.

**Hard exit criterion for Phase 1:** 3 design partners signed in 8 weeks. If we can't, the problem is positioning or ICP, not the product — re-diagnose, do not build Phase 2.

### Carried (non-blocking; from earlier sessions)

1. **Branch cleanup.** Local branches across multiple sessions still linger (~60 from prior phases) — leave them alone unless the user explicitly authorizes nuking. Corrupt ref `refs/heads/fix/decision-id-allowlist-seed-signals 2` (macOS Finder duplicate) was cleaned up 2026-04-30.
2. **Dashboard UI verification.** Code-side query layer (`proof_metrics.py`) is verified correct; the rendered UI is user-side. After 60s cache TTL, `/proof` should reflect every CI run on PR #125.
3. **Render DSN rotation hygiene.** Recommended periodic rotation; #122's fail-loud validation makes it safer to verify.
4. **Backend endpoints that became dead surface after #133** — `/commercial/roi-estimate`, `/commercial/pilots`, `/ops/*` server routes are now likely unreferenced (the dashboard surfaces were deleted). Out of scope for #133 ("surface" deletion only); revisit if dead-code analysis confirms they're orphaned.

### Long-haul strategic (Phases 2+, do not start until Phase 1 closes)

5. **Phase 2** — Reachability (Semgrep + CVE cross-reference), incident correlation (PagerDuty / Opsgenie webhook → Slack), production signal ingestion (Datadog / New Relic), comparable-PR explanations, freeze calendar. **Gated on 3 design partners signed.**
6. **Phase 4** — Per-tenant XGBoost rollback prediction (amplifier only, ±20% on rule-based score), AI-authored code detection, cross-org DORA benchmark v1, SLSA L3 hardening of our own build pipeline. **Gated on 12+ months of tenant data.**
7. **Phase 5** — Multi-region, SCIM, BYOK, on-prem/VPC, 99.9% SLA, SOC 2 Type II, F500 logo, Series A raise.

**DO NOT BUILD:** Forge improvements (deprioritized — GitHub is 80% of buyers), eBPF anything (not our product), Kyverno integration (gated on a K8s-shop design partner explicitly asking).
7. **`docs/COMPANY_BUILD_PHASES.md`** is uncommitted at the repo root from earlier sessions. Probably should be either committed or moved to `plans/` (which is gitignored). User's call.

## Imported Claude Cowork project instructions
