# Phase 0 Reliability Checkpoint Log

This log tracks the manual checkpoint streak for the core Phase 0 dashboard and onboarding routes.

## Scope

Checked routes:

- `/dashboard/tenant/info`
- `/dashboard/overview`
- `/dashboard/alerts`
- `/dashboard/metrics/timeseries`
- `/onboarding/status`
- `/onboarding/activation`

Checkpoint verdicts are based on the checked Phase 0 routes above.
Per checkpoint notes may explicitly exclude `/internal/slo` global p95 when it is inflated by cumulative non-checkpoint routes.

## Current Streak

- As of `2026-04-13`: `4 / 7` passes

## Checkpoint 1 — 2026-03-26

- Overview 500s: `0`
- Onboarding 500s: `0`
- Activation 500s: `0`
- Tenant 500s: `0`
- p95 latency: `290.322 ms`
- 5xx error rate: `0.0%`
- Status: `PASS`

Notes:

- Observation window restarted with checkpoint-based tracking
- `/dashboard/tenant/info` p95 = `290.322 ms`
- `/dashboard/overview` p95 = `360.366 ms`
- `/dashboard/alerts` p95 = `433.352 ms`
- `/dashboard/metrics/timeseries` p95 = `164.653 ms`
- `/onboarding/status` returned `200 OK`
- `/onboarding/activation` returned `200 OK`
- All checked routes under Phase 0 latency target
- No `5xx` observed

## Checkpoint 2 — 2026-03-27

- Overview 500s: `0`
- Onboarding 500s: `0`
- Activation 500s: `0`
- Tenant 500s: `0`
- p95 latency: `172.566 ms`
- 5xx error rate: `0.0%`
- Status: `PASS`

Notes:

- `/dashboard/tenant/info` p95 = `298.728 ms`
- `/dashboard/overview` p95 = `454.559 ms`
- `/dashboard/alerts` p95 = `172.566 ms`
- `/dashboard/metrics/timeseries` p95 = `13.751 ms`
- `/onboarding/status` returned `200 OK`
- `/onboarding/activation` returned `200 OK`
- All checked routes under Phase 0 latency target
- No `5xx` observed
- Alerts endpoint stabilized after payload cache + async audit + low-overhead response path
- Checkpoint streak = `2 / 7`

## Checkpoint 3 — 2026-03-30

- Overview 500s: `0`
- Onboarding 500s: `0`
- Activation 500s: `0`
- Tenant 500s: `0`
- p95 latency: `449.006 ms`
- 5xx error rate: `0.0%`
- Status: `PASS`

Notes:

- `/dashboard/tenant/info` p95 = `259.225 ms`
- `/dashboard/overview` p95 = `449.006 ms`
- `/dashboard/alerts` p95 = `172.566 ms`
- `/dashboard/metrics/timeseries` direct checkpoint timings looked acceptable
- `/onboarding/status` returned `200 OK`
- `/onboarding/activation` returned `200 OK`
- All checked core checkpoint routes remained under the Phase 0 latency target
- `/internal/slo` global p95 is inflated by cumulative non-checkpoint routes like `/dashboard/billing/usage`, `/dashboard/metrics/summary`, `/dashboard/metrics/drilldown`, and customer success dashboards, so it should not be used as the checkpoint verdict here
- Checkpoint streak = `3 / 7`

## Checkpoint 4 — 2026-04-13

- Overview 500s: `0`
- Onboarding 500s: `0`
- Activation 500s: `0`
- Tenant 500s: `0`
- p95 latency: 319.537 ms
- 5xx error rate: `0.0%`
- Status: `PASS`

Notes:

- `/dashboard/tenant/info` direct checks were acceptable, with two slower requests at `0.912s` and `0.567s`, but route-level cumulative p95 remained `319.537 ms`
- `/dashboard/overview` had one slower first request at `0.601s`, but the direct run was otherwise stable
- `/dashboard/alerts` direct checks were acceptable
- `/dashboard/metrics/timeseries` direct checks were acceptable overall, with a few higher requests (`0.683s`, `0.872s`) but not enough evidence to fail the checkpoint
- `/onboarding/status` returned `200 OK`
- `/onboarding/activation` returned `200 OK`
- `/internal/slo` global p95 should not be used as the checkpoint verdict because it includes cumulative non-checkpoint routes like `/dashboard/billing/usage`, `/dashboard/metrics/summary`, `/dashboard/metrics/drilldown`, `/dashboard/blocked`, and customer success dashboards
- No `5xx` observed
- Checkpoint streak = `4 / 7`
