# Governance ROI Calculator

Use this worksheet to quantify ReleaseGate economic impact for executive and procurement review.

## Inputs

- Annual production incidents tied to uncontrolled workflow changes: `A`
- Average incident cost (response + downtime + recovery): `B`
- Expected incident reduction rate with ReleaseGate controls: `C` (as decimal)
- Annual cost of ReleaseGate (license + ops): `D`

## Core Formulae

- Incidents prevented: `E = A * C`
- Annual savings: `F = E * B`
- Net value: `G = F - D`
- ROI multiple: `H = F / D`
- ROI percentage: `I = ((F - D) / D) * 100`

## Example

Assumptions:

- `A = 40` incidents/year
- `B = $25,000`
- `C = 0.125` (12.5% reduction)
- `D = $30,000`

Results:

- `E = 5` incidents prevented
- `F = $125,000` annual savings
- `G = $95,000` net value
- `H = 4.17x`
- `I = 316.7%`

## Additional Value Drivers

Include these in business cases where applicable:

- Audit prep time reduction via proof bundles and explainability
- Faster change approvals with policy simulation and activation ladder
- Reduced compliance exceptions from SoD and override governance controls
- Lower incident blast radius from fail-closed and rollback workflows

## Suggested Sales Narrative

1. Baseline current incident/compliance cost.
2. Estimate conservative preventable percentage.
3. Demonstrate modeled savings vs annual platform cost.
4. Validate assumptions during pilot using observability and customer-success dashboards.
