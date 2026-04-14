# Phase 1 Onboarding Session Script

Run 5 live onboarding sessions with real users from the target profile:

- Jira-first
- release-heavy
- at least mildly regulated or approval-sensitive

## Goal

Watch whether a new user can:

1. connect Jira
2. understand the risk snapshot
3. start canary protection

in under 15 minutes without confusion

Use a fresh tenant for each session and keep a shared prefix for the batch, such as `phase1-2026-04-14-01`.

## What To Say

Use the same prompt every time:

`Please set this up the way you would for your team. Think out loud as you go.`

Only help if they are completely blocked.

## What To Record

Capture exact timestamps for:

- session started
- Jira connected
- first transitions selected
- first simulation visible
- canary enabled
- session ended

Also record:

- where they paused for more than 5 seconds
- what they asked out loud
- where they hesitated before clicking
- whether they understood the risk snapshot without explanation

## Questions To Ask At The End

Ask these five questions:

1. `What did you think this product was doing after the first minute?`
2. `What part felt most confusing?`
3. `Did the risk snapshot feel credible? Why or why not?`
4. `What made you hesitate before enabling canary?`
5. `What would you need to trust this in production?`

## Session Note Template

```md
Session:
Role / company type:
Date:

Timing
- Jira connected:
- First simulation visible:
- Canary enabled:
- Total completion time:

Observed pauses
- 

Confusing moments
- 

Hesitation moments
- 

What they understood immediately
- 

What they misunderstood
- 

Trust blockers
- 

Direct quotes
- 

Outcome
- Completed / stalled
- Canary enabled: yes / no
```

## Success Bar

Phase 1 is healthy when:

- first value is under 10 minutes for most sessions
- canary is enabled in under 15 minutes for most sessions
- fewer than 20% of users stall before canary
- users can explain the value of the risk snapshot in their own words

Use `docs/ops/phase1-validation-playbook.md` to turn the session telemetry into the actual batch report.

## What To Fix First

If users struggle, fix in this order:

1. anything that prevents them from seeing the risk snapshot
2. anything that makes transition selection unclear
3. anything that creates hesitation before canary
4. any extra copy or UI that distracts from the 3-step flow
