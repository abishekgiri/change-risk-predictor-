# ReleaseGate — Phased Roadmap to Series A

_Saved 2026-04-21. Harsh, real, 12-month plan combining the Advanced Pillars
(contextual reachability, SLSA provenance, predictive scoring, policy-as-code)
with the GTM-first sequencing we discussed. One founder + optional contractor
assumptions. Series A target Q4 2026._

---

## Reality check before you start

- ~15 nav items in the product. 0 paying customers.
- Most phases below **subtract** features and **go find humans who will pay**.
- If you read this and feel defensive, that's the signal you need it.
- If you start Phase 1 before finishing the Phase 0 Kill List, you've already
  failed.

---

## Phase 0 — Pre-work (Week 1–2, unskippable)

The phase you'll want to skip. Don't.

### Kill list (delete before talking to another buyer)
- `/proof` page — nothing to show until 3 real testimonials.
- `/roi` calculator in-product — move to marketing site as lead magnet.
- `/pilots` tracker — that's your Notion, not the customer's product.
- ICP scoring — your sales tool, not theirs.
- Half the nav items. Target: **5 nav items max.** Overview, Decisions,
  Policies, Evidence, Settings. That's it.

### Positioning (pin to wall)
- **One-liner:** "Evidence infrastructure for software changes — so you can
  prove to auditors and CISOs that every deploy was approved, reviewed, and
  safe."
- **ICP:** fintech / healthtech / regulated SaaS, 30–150 engineers, GitHub +
  Jira, deploys ≥3x/week, SOC 2 or ISO audit in next 12 months.
- **Disqualify:** <20 engineers (no budget), >300 (procurement kills you year
  one), not regulated (they won't pay).

### Admin debt (ship in week 2)
- Entity structure + lawyer + standard MSA + DPA template.
- `/trust` page: subprocessors, encryption, incident response, data handling.
- Start SOC 2 Type I with Drata or Vanta. Yes, now. "Type I in 60 days" is a
  closing line.

**Exit criteria:** ≤5 nav items, one-sentence landing page, SOC 2 kicked off.
No new code until this is done.

---

## Phase 1 — Evidence Infrastructure (Weeks 3–10, ~2 months)

**Thesis:** Stop being a dashboard. Become the thing that signs and verifies
deploys. Un-bypassable layer. Reason someone pays $30–50k ARR.

### Build
1. **Sigstore/Cosign for decisions.** Every approved PR → signed in-toto
   attestation → Rekor transparency log. (2 weeks)
2. **Deploy-time verifier.** Two forms: **GitHub Action** (80% of buyers) +
   **Kyverno policy** for K8s. Fail the deploy if signature missing/invalid.
   (1.5 weeks)
3. **Evidence Pack export.** One-click PDF + JSON bundle per window, mapped
   explicitly to SOC 2 CC8.1 and ISO 27001 A.14.2.2. _The artifact is the
   product._ (1 week)
4. **Transparency log UI.** Every decision + signature + Rekor link. Auditor
   bait. (0.5 week)
5. **SSO (OIDC + SAML) + dashboard audit log.** Use WorkOS. (1 week with, 3
   without — use WorkOS.)

### Don't build yet
- Multi-region, SCIM, RLS multi-tenancy.
- Full SLSA L3 — market as "SLSA-aligned, targeting L3."
- Your own ML model. Rules only.

### Go-to-market (parallel, not after)
- Find **15 prospects by hand** on LinkedIn: "Head of Engineering" / "VP
  Platform" at fintech/healthtech Series B–C. Send 15 cold emails/week. Not
  500. 15.
- **Offer:** free 30-day pilot, white-glove onboarding by you personally, in
  exchange for a case study if it works.
- **Goal: 3 signed design partners by end of Phase 1.** Signed pilot +
  integration live. Not "3 who said yes on a call."

**Exit criteria:** 3 design partners live in production. SSO works. Evidence
Pack downloadable. One named control framework referenced by number.

**Harsh note:** If you can't land 3 partners in 8 weeks, the problem is not
the product — it's positioning or ICP. Stop and re-diagnose. Do **not** build
Phase 2.

---

## Phase 2 — Reachability + Incident Loop (Weeks 11–18, ~2 months)

**Thesis:** Engineers must *love* it, not tolerate it. Kill alert fatigue,
make the risk score provably correct.

### Build
1. **Reachability via integration (not build).** Wrap Semgrep OSS + their
   rules. For each PR, cross-reference CVEs against code paths actually
   touched. Score amplifier: reachable = severity × 3. (2 weeks)
2. **Incident correlation loop.** PagerDuty/Opsgenie webhook → auto-post "most
   likely culprits from the last 20 deploys, ranked by risk" into linked Slack
   channel. (1 week)
3. **Production signal ingestion.** Datadog/New Relic: current error rate per
   service feeds risk score. Block deploys to degraded services unless
   override. (1.5 weeks)
4. **Comparable-PR explanations.** "Looks like PR #1247 which caused SEV-2 on
   Feb 11." Nearest-neighbor on file-touch + size + author. No ML yet.
   (1 week)
5. **Freeze calendar + delegated approval rules.** Boring. Mandatory for
   enterprise. (1 week)

### Don't build yet
- Predictive ML. Still not yet.
- Policy language. Still not yet.
- eBPF runtime anything. _Ever._ Not your product.

### Go-to-market
- **Convert 2 of 3 design partners to paid.** If 2/3 won't convert, the
  product isn't a top-3 problem for them — ask what is.
- **First public case study.** Logo + real number ("audit prep 3 weeks → 2
  days") + VP Eng quote.
- **Second cohort: 5 more design partners.** Same ICP, same outreach, now
  with one case study.
- **GitHub Marketplace listing.** Distribution + legitimacy.

**Exit criteria:** 2 paying ($20k+ ACV each), 5 new design partners in pilot,
one public case study. ≥ **$50k ARR.**

---

## Phase 3 — Policy-as-Code (Weeks 19–26, ~2 months)

**Thesis:** Platform teams become champions. This is what promotes you from
"tool the VP bought" to "tool the platform team evangelizes."

### Build
1. **Rego under the hood, visual builder on top.** Users see a Zapier-style
   rule builder. Power users see "View as Rego." (3 weeks)
2. **Dry-run against history.** "This rule would have blocked 12 of last 400
   deploys — here they are." _The killer feature._ (1 week)
3. **Policy versioning in Git.** Policies live in customer's repo,
   ReleaseGate syncs. (1 week)
4. **Multi-tenancy hardening with Postgres RLS.** Next cohort needs it.
   (2 weeks)
5. **ServiceNow / Jira Service Management connector.** Auto-file change
   tickets with risk score. Boring. Opens Fortune 1000. (2 weeks)

### Don't build yet
- Still no ML.
- Still no runtime monitoring.
- Still no SCIM. Wait until a $50k+ buyer explicitly asks.

### Go-to-market
- **Close 5 pilots from Phase 2.** Target: 5 paid, $30–50k ACV each.
- **SOC 2 Type I report delivered.** Badge on marketing page.
- Second and third case studies.
- **Hire first AE / founding GTM.** Not engineer. Salesperson. You will
  resist this. Do it anyway.

**Exit criteria:** 5–7 paying customers, **$200–300k ARR**, SOC 2 Type I done,
platform team at ≥1 customer writing their own policies.

---

## Phase 4 — AI Edge, Sanely (Weeks 27–36, ~2.5 months)

**Thesis:** Now, and only now, you earn the right to ship ML. You have 7
customers × months of history — cold-start isn't a joke anymore.

### Build
1. **Per-tenant rollback/incident prediction model.** Trained on _that
   tenant's_ history. Features: author, file churn, test coverage delta,
   touched services, recent incident rate on affected service. XGBoost is
   fine — don't overthink. (3 weeks)
2. **Model ships as amplifier only.** Rule-based score is primary. Model
   nudges ±20%. Never sole decider. Always shows top 3 features driving the
   score. (1 week)
3. **AI-authored code detection + governance.** Detect Copilot/Claude
   signatures (commit metadata, patterns), tag in PR, apply stricter policies
   if tenant requests. 2027's biggest compliance conversation. Own it.
   (2 weeks)
4. **Cross-org benchmark v1.** Anonymous aggregate: "your change failure rate
   is X, p50 for your segment is Y." DORA metrics, done right. (2 weeks)
5. **SLSA L3 hardening of your own build pipeline.** You sign their deploys;
   your pipeline must be beyond reproach. Reproducible builds, hermetic env,
   KMS-managed keys. (2 weeks)

### Go-to-market
- **Pricing re-rack.** Move from per-seat to per-decision-per-month or
  platform tier. Enterprise platform tier $75–150k ACV.
- **First AE target:** 3 new logos in quarter, $100k+ ACV each.
- **Start category narrative.** Write a public spec —
  _"The Change Evidence Format v1."_ Open JSON schema. Get 1 other tool to
  consume it. Now you're the spec owner, not a vendor. Long game — start now.

**Exit criteria:** 10–12 paying customers, **$800k–$1.2M ARR**, SOC 2 Type II
in flight, Series A conversations real and not desperate.

---

## Phase 5 — Enterprise-Ready (Weeks 37–52, last quarter)

**Thesis:** No longer selling a product. Selling a category. Enterprise
checkbox list that procurement demands.

### Build
- Multi-region + data residency (EU, UK)
- SCIM provisioning
- BYOK / customer-managed encryption keys
- On-prem / VPC deploy (Helm chart, air-gapped mode)
- SLAs: 99.9% uptime, status page, contractual breach notification
- **Graceful degradation:** ReleaseGate down ≠ deploys blocked (fail-open on
  availability, fail-closed on evidence). Hardest engineering problem in the
  category. Prevents vendor-lock-in panic.
- Everything the SOC 2 Type II auditor wants

### Go-to-market
- SOC 2 Type II delivered
- One F500 logo (even small deal — logo > ACV at this stage)
- Content engine: one technical blog every 2 weeks on evidence infra, SLSA,
  change governance. Not SEO spam — real depth.
- First conference talk (KubeCon, DevOps Enterprise Summit, AppSec con)
- **Series A raise:** $6–10M at $25–40M post. Close by end of year.

**Exit criteria:** **$1.5–3M ARR**, SOC 2 Type II, 15–25 customers, one F500
logo, term sheet in hand or signed.

---

## Harsh running commentary

### What you'll want to do wrong
- Build Phase 3's policy engine in Phase 1 because it's fun. Don't.
- Skip SOC 2 because it's boring. Don't — it's a sales requirement.
- Build ML early because it's sexy. Don't — cold-start + unexplainability
  will burn your trust.
- Add features to close individual deals. Build if **3 prospects ask**, not 1.
- Keep building before closing first 3 pilots. **This is how founders die.**
  If you can't close 3 on the Phase 1 product, Phase 2 won't save you.

### What nobody will tell you
- Phase 1 is the only phase where failure is really dangerous. No 3 pilots
  in 8 weeks = you don't have a company yet, you have a side project. Fix is
  ICP re-diagnosis, not more code.
- You will build 30–40% of features nobody asks for. Normal. Kill them.
- **Sequencing > features.** Shipping out of order (ML before reachability,
  policy before evidence) is the #1 way technical founders in this space die.

### Staffing
- Phase 0–1: solo or +1 part-time.
- Phase 2: +1 full-stack engineer.
- Phase 3: +1 GTM/AE (non-negotiable).
- Phase 4: +1 ML engineer (part-time/contractor), +1 CS.
- Phase 5: +2 engineering, +1 AE, +1 security lead for SOC 2 Type II.

### Capital
- Phase 0–1: current savings + friends/family/angel ($300–500k).
- Phase 2 end: natural pre-seed if unraised ($1–2M at $6–10M post).
- Phase 4 exit: Series A becomes clean, non-desperate raise.
- Raise earlier → overbuild + overspend. Later → burnt out. Phase 2–3
  boundary is the sweet spot.

---

## The one thing to bet the company on

**Evidence Pack export with named control-framework mappings (SOC 2 CC8.1,
ISO A.14.2.2) + Sigstore-signed attestations + a GitHub Action verifier.**

That triplet, done well, in 8 weeks, with 3 design partners, is the whole
company. Everything else is amplification.

- Get it right → rest of phases become "fill in what customers ask for."
- Get it wrong → no amount of reachability / ML / policy-as-code saves you.

Build that. Sell it. Then come back for Phase 2.
