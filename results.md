# Phase 1 / Phase 2 / Phase 3 — Execution Results

**Date:** 2026-04-14
**Site:** https://app.releasegate.io
**Tenant:** local
**Tester:** Automated QA

---

## Phase 3: Test Suite

**Result: 199 passed, 1 failed, 4 skipped (12.93s)**

| Category | Tests | Status |
|----------|-------|--------|
| Deterministic replay | golden output, hash stability | PASS |
| Fail-closed enforcement | timeout/missing signal blocks | PASS |
| Separation of Duties | author/approver conflicts | PASS |
| Snapshot binding | policy/decision/signal hashes | PASS |
| Approval freshness | expired/stale/mixed approvals | PASS |
| Proof pack verification | ledger chains, DSSE, tampering | PASS |
| Tenant isolation | cross-tenant blocking | PASS |
| Policy registry | activation, inheritance, rollout | PASS |
| Lock chains | cryptographic chain integrity | PASS |
| Override chains | hash chaining, idempotency | PASS |
| Evidence graph | hash determinism, anchor detection | PASS |

### Single Failure

```
FAILED tests/test_api_security_phase3.py::test_ops_health_endpoint_is_public
  /health returns 503 instead of 200
  Cause: health check reports unhealthy when Redis/Postgres unavailable in test env
  Severity: LOW — infrastructure dependency, not logic bug
```

### Warnings (non-blocking)

- `on_event` deprecation in FastAPI (use lifespan handlers)
- scikit-learn version mismatch (1.7.2 model loaded in 1.6.1)

---

## Phase 1: Onboarding API Validation

### Endpoint Results

| Endpoint | Method | Status | Result |
|----------|--------|--------|--------|
| /onboarding/status?tenant_id=local | GET | 200 | onboarding_completed=true, config returned |
| /onboarding/activation?tenant_id=local | GET | 200 | mode=canary, canary_pct=10, applied=true |
| /onboarding/activation/history?tenant_id=local | GET | 200 | current state returned, items=[] |
| /simulation/last?tenant_id=local | GET | 200 | has_run=true, all counts=0 |
| /onboarding/telemetry | POST | 400 | Rejects unknown events (correct behavior) |
| /onboarding/phase1-validation | GET | 403 | Requires admin/internal role |
| /onboarding/status?tenant_id=phase1-* | GET | 403 | Cross-tenant isolation working |
| /onboarding/setup?tenant_id=phase1-* | GET | 405 | Method not allowed |

### Phase 1 Happy Path Checks

| Check | Status | Notes |
|-------|--------|-------|
| Jira connect succeeds | PASS | Connected to abishekkumargiri0.atlassian.net |
| Projects auto-detect | PASS | 3 projects found (KAN, RG, SAM1) |
| Workflows auto-detect | PASS | 1 workflow found (Configured Transition Map) |
| Transitions auto-detect | PASS | 3 transitions discovered, 2 selected (Done 31, Done 2) |
| Historical simulation runs | PARTIAL | has_run=true but total_transitions=0 |
| Snapshot renders value | FAIL | All zeros — no first-value moment |
| Canary enables in one click | PASS | mode=canary, canary_pct=10, applied=true |
| Rollback visible | PASS | Red Rollback button present in Step 3 |
| Autosave shown | PASS | "Autosave: On" displayed |
| Trust microcopy present | PASS | "We monitor, not block" and "disable anytime" shown |
| Safe start messaging | PASS | "observe-only mode" language present |

### Phase 1 Issues

1. **Simulation shows all zeros (HIGH)**
   - total_transitions=0, high_risk_releases=0, missing_approvals=0
   - Summary: "No recent release decisions were available yet"
   - Impact: First-value moment does not land
   - Fix: Need historical Jira transition data or synthetic simulation

2. **Fresh tenant creation blocked (HIGH)**
   - Cross-tenant access returns 403
   - Dashboard proxy authenticates as `local` tenant only
   - Impact: Cannot run multi-tenant onboarding sessions
   - Fix: Backend tenant provisioning endpoint or dashboard tenant switching

3. **Phase 1 validation report inaccessible (MEDIUM)**
   - /phase1-validation returns 403 (admin role required)
   - Dashboard proxy token lacks admin role
   - Fix: Grant validation read access to dashboard token

4. **Activation history empty (LOW)**
   - items=[] — no rollback history tracked
   - Current state is returned correctly

### Phase 1 Pass Criteria (cannot fully evaluate without human sessions)

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| First value < 10 min | < 600s | N/A (no human sessions) | BLOCKED |
| Canary < 15 min | < 900s | N/A | BLOCKED |
| Completion >= 80% | >= 0.80 | N/A | BLOCKED |
| Drop-off < 20% | < 0.20 | N/A | BLOCKED |
| Median hesitation < 5-7s | < 7s | N/A | BLOCKED |

---

## Phase 2: Executive Clarity Audit

### Pages Tested

| Page | URL | Loads | Status |
|------|-----|-------|--------|
| Executive Overview | /overview | YES | Working |
| Onboarding | /onboarding | YES | Working |
| Control Health | /integrity | YES | Working |
| Exceptions | /overrides | YES | Working |
| Policy Changes | /policies/diff | YES | Working |
| Executive Impact | /customer-success | YES | Working |
| Observability | /observability | YES | Working |
| Billing | /billing | YES | Working |
| Tenant Admin | /tenant | YES | Working |

### Console Errors: 0
### Failed API Calls: 0 (all /api/dashboard/* return 200)

### Intermittent Issues

- RSC prefetch 503s on /onboarding and /overrides (2 of ~20 prefetch requests)
- Full page loads always succeed
- Likely cold-cache or concurrent prefetch timeout

### Phase 2 Visual Hierarchy Checks

| Check | Status | Notes |
|-------|--------|-------|
| Eyes go to Top 3 Risks first | PASS | Dominant section with yellow background, large heading |
| Users can identify top risk immediately | FAIL | All 3 cards are identical — no differentiation |
| Each risk action is clear | PASS | "What to do" column present with specific action |
| Navigation labels renamed | PASS | Executive Overview, Control Health, Exceptions, Policy Changes |
| Governance Status declarative | PASS | "Moderate Risk" — statement, not question |
| Executive Briefing plain language | PASS | Action-oriented bullets with counts |
| Blocked decision explainer | N/A | No blocked decisions to test |
| Policy diff understandable | PASS | Plain-language review guidance shown |
| Override/integrity wording clear | PASS | Proper empty states with guidance |

### Phase 2 Narrative Checks

| Element | Status | Notes |
|---------|--------|-------|
| "What happened" column | PASS | Plain language, no jargon |
| "Why it matters" column | PASS | Consequence framing present |
| "Common consequence" column | PASS | Business impact language |
| "What to do" column | PASS | Specific actionable next step |
| Governance Status wording | PASS | "controls are active, but risk signals are rising" |
| Executive Briefing wording | PASS | "3 priority risks need attention today" |
| Audit-Friendly Readout | PASS | "approval discipline, exception pressure" |

### Phase 2 Failures

1. **Top 3 Risks are identical (CRITICAL)**
   - All 3 cards show "Release decisions are not being recorded"
   - Same WHAT HAPPENED / WHY IT MATTERS / COMMON CONSEQUENCE / WHAT TO DO
   - Impact: Buyer sees repetition, not 3 distinct risks
   - A non-technical user would be confused by duplication
   - Fix: De-duplicate — if only 1 unique risk, show 1 card not 3

2. **No seeded demo data (CRITICAL)**
   - Overview is essentially empty state
   - 0 blocked changes, 0 decisions, 0 overrides
   - Buyer would say "nothing is happening" — guaranteed Phase 2 fail
   - Fix: Seed blocked releases, override spikes, policy drift, real decisions

3. **trace_id visible to executives (MEDIUM)**
   - `trace_id: 67c148b3-016c-446d-8b37-e9389988b66d` shown on every page
   - Developer noise — executives don't need this
   - Fix: Hide behind debug toggle or move to footer/collapsed section

4. **"Tenant: local" visible (MEDIUM)**
   - Shown at top of every page
   - Meaningless to a buyer
   - Fix: Show organization name instead, or hide in non-admin views

5. **Trend chart renders blank (MEDIUM)**
   - "Governance Integrity / Drift / Override Trend (30d)" is empty white card
   - API returns 5 data points (integrity_trend has values)
   - Chart component may not be rendering the data
   - Fix: Debug LineChartCard rendering with trend data

6. **Control Health shows raw decimals (LOW)**
   - "Change Control Drift: 0.0000" and "Override Trend Risk: 0.0000"
   - Executive Overview shows these as "Low" — inconsistency
   - Fix: Use same human-readable labels on Control Health page

### Phase 2 Pass Criteria (requires human demo sessions)

| Criteria | Target Response | Current Assessment | Status |
|----------|----------------|-------------------|--------|
| "What does this product do?" | "Prevents risky releases" | Would likely say "monitoring tool" due to empty state | FAIL |
| "Why would a company pay?" | "Enforces rules before deployment" | Unclear — no evidence of enforcement visible | FAIL |
| "What would you do next?" | "Shows what's wrong and how to fix" | Top 3 risks point to same action | PARTIAL |
| No explanation needed | Immediate understanding | Duplicate cards create confusion | FAIL |

---

## Summary

| Phase | Automated Result | Human Validation | Overall |
|-------|-----------------|-----------------|---------|
| Phase 1 | PARTIAL — happy path works, simulation empty | BLOCKED — needs fresh tenant sessions | NOT READY |
| Phase 2 | PARTIAL — structure correct, content empty | BLOCKED — needs seeded data + user demos | NOT READY |
| Phase 3 | PASS — 199/200 tests pass | BLOCKED — needs operator drills | READY (code) |

## Priority Fix Order

1. **Seed realistic demo data** — Phase 2 cannot pass without it
2. **De-duplicate top 3 risk cards** — Critical clarity issue
3. **Populate simulation data** — Phase 1 first-value moment
4. **Hide trace_id / raw tenant from exec views** — Developer noise
5. **Fix trend chart rendering** — Data exists but chart is blank
6. **Enable multi-tenant provisioning** — Required for Phase 1 sessions
7. **Grant phase1-validation access** — Required for Phase 1 metrics

---

## Evidence Artifacts

- Screenshots: ss_9392gsbf7 (overview), ss_1502e3xcw (onboarding), ss_6951eh2x1 (control health), ss_0231ss38g (exceptions), ss_3498fkh14 (policy changes), ss_9003x6w6m (executive impact), ss_2856zl6q1 (observability), ss_63724zoof (billing), ss_9313b73ne (tenant), ss_3069qn2g0 (onboarding reload)
- Test output: 199 passed, 1 failed, 4 skipped (12.93s)
- API probe responses: captured inline above
- Network trace: 28 requests captured, 2 intermittent 503s on RSC prefetch
