# GitLab CI Integration

RiskBot can run natively in GitLab pipelines to check MR risk levels.

## Configuration (.gitlab-ci.yml)

Add the following job to your pipeline configuration:

```yaml
stages:
 - risk-analysis
 - deploy

riskbot-check:
 stage: risk-analysis
 image: python:3.10
 rules:
 - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
 variables:
 # Set this in Project Settings -> CI/CD -> Variables
 # RISKBOT_ENFORCEMENT: "enforce" # Uncomment to fail pipeline on high risk
 script:
 - pip install -r requirements.txt # Or install riskbot from registry
 - export PYTHONPATH=$PYTHONPATH:.
 
 # Run Analysis
 - python3 -m riskbot.cli analyze-pr \
 --repo $CI_PROJECT_PATH \
 --pr $CI_MERGE_REQUEST_IID \
 --output risk_result.json

 artifacts:
 reports:
 # Optional: integrate with Code Quality if format adapted
 # codequality: risk_result.json 
 paths:
 - risk_result.json
 when: always

 # Post-processing: Publish Note (Optional)
 # You can add a step to curl the GitLab API to post a note on the MR
```

## Setup Requirements

1. **Variables**: Ensure `GITLAB_TOKEN` or sufficient permissions are available if using private API fetches.
2. **Runner**: Any docker runner with Python 3.10+ works.
3. **Enforcement**:
 - `report_only` (default): Job passes (exit 0) regardless of risk.
 - `enforce`: Job fails (exit 1) if decision is `FAIL`.

## PR/MR Comments
To post results as a comment, add a script step using `glab` or `curl`:

```bash
curl --request POST --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
 --data-urlencode "body=RiskBot Analysis: $(cat risk_result.json | jq -r .decision)" \
 "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
```
