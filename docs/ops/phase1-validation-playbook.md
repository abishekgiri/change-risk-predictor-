# Phase 1 Validation Playbook

Phase 1 is not done when the code feels ready.

Phase 1 is done when real users can:

1. connect Jira
2. see value in the risk snapshot
3. enable canary naturally

with the measured outcomes below.

## Validation Rule

Use a fresh tenant for each onboarding session.

Recommended naming:

- `phase1-2026-04-14-01`
- `phase1-2026-04-14-02`

This keeps the telemetry clean and makes it easy to filter the batch with a shared `tenant_prefix`.

## What To Measure

Official Phase 1 exit criteria:

- install to first value under `10 minutes`
- install to canary under `15 minutes`
- onboarding completion `>= 80%`
- activation drop-off `< 20%`

Recommended trust signal:

- median hesitation under `5 seconds`

Hesitation bands:

- `< 3 seconds` = instant trust
- `3-10 seconds` = acceptable thinking
- `> 10 seconds` = hesitation or doubt

## Run The Sessions

1. Recruit `5-10` Jira-first users who match the target profile.
2. Use the facilitation guide in `docs/ops/phase1-onboarding-session-script.md`.
3. Record qualitative notes in `docs/ops/phase1-validation-log-template.md`.
4. Keep the tenant prefix consistent for the batch.

## Pull The Quant Report

If the dashboard app is running:

```bash
curl "http://localhost:3000/api/dashboard/onboarding/phase1-validation?days=14&tenant_prefix=phase1-2026-04-14-"
```

If you want a single tenant:

```bash
curl "http://localhost:3000/api/dashboard/onboarding/phase1-validation?days=14&tenant_id=phase1-2026-04-14-01"
```

The report includes:

- median time to first value
- median time to canary
- median hesitation
- onboarding completion rate
- canary conversion rate
- activation drop-off rate
- hesitation bands
- per-session cohorts

## Interpret The Cohorts

- `ideal_flow` = user reached canary with low hesitation
- `converted_after_thinking` = user reached canary after a normal pause, but not instantly
- `needs_clarity` = user reached canary, but only after obvious hesitation
- `activation_drop_off` = user saw value, hesitated, and did not enable canary
- `stalled_after_value` = user got to value but did not go live
- `stalled_before_value` = user did not even reach the snapshot cleanly

## Decision Rule

Phase 1 is proven when:

- sample size is at least `5` connected sessions
- median first value is under `600` seconds
- median canary is under `900` seconds
- onboarding completion is at least `80%`
- activation drop-off is below `20%`

The report exposes these checks directly under `exit_criteria`.

## Tightening Loop

After each batch:

1. identify the largest bad cohort
2. ship one friction fix only
3. rerun another `5` sessions
4. compare the next report against the previous batch

Do not call Phase 1 complete from code intuition alone.
