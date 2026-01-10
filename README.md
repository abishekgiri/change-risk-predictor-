# RiskBot V1

Low-overhead change risk predictor for Pull Requests.

## Overview
RiskBot analyzes PRs to calculate a risk score (0-100) based on:
- **Files touched** (critical paths like `auth/`, `db/`)
- **Churn/Hotspots** (frequently changed files)
- **Change size** (LOC added/deleted)
- **Test coverage** (presence of test changes)

## Usage
### Local
```bash
python -m riskbot.main --base main --head feature-branch
```

### GitHub Actions
The bot runs automatically on PRs and posts a comment with the risk score.

## Installation
```bash
pip install -r requirements.txt
```
