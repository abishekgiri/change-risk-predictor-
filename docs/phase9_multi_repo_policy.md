# Phase 9: Multi-Repo Policy Enforcement

## Overview

Phase 9 extends the SaaS platform to support multiple repositories with organization-level policy inheritance and configurable enforcement strictness levels.

## Features

### 1. Organization-Level Policy Defaults

Organizations can define default policies that apply to all repositories:

```json
{
  "high_threshold": 80,
  "require_tests": true,
  "security_scan": true
}
```

### 2. Repository-Level Policy Overrides

Individual repositories can override specific organization policies:

```json
{
  "high_threshold": 60
}
```

The system performs a deep merge where repository overrides win, but organization defaults persist for non-overridden values.

### 3. Strictness Levels

Each repository has a configurable strictness level that determines how blocking violations are handled:

- **block**: GitHub Check fails on violations (red X)
- **warn**: GitHub Check succeeds with warning message (green check with warning text)
- **pass**: GitHub Check always succeeds, violations reported as informational

Strictness mapping applies only when the analysis result is BLOCK or NON_COMPLIANT. Compliant results always return success.

### 4. Stable GitHub Identifiers

The database schema uses stable GitHub identifiers for production reliability:

- `github_installation_id` for organizations
- `github_repo_id` for repositories
- `github_account_login` for human-readable organization names
- `full_name` for repository display (owner/repo format)

### 5. Soft Delete

Repositories removed from the GitHub App installation are marked as inactive rather than deleted, preserving historical data.

## Database Schema

### Organization Table

```sql
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    github_id INTEGER,
    github_installation_id INTEGER UNIQUE,
    installation_id INTEGER,
    login VARCHAR,
    github_account_login VARCHAR,
    default_policy_config JSON
);
```

### Repository Table

```sql
CREATE TABLE repositories (
    id SERIAL PRIMARY KEY,
    github_id INTEGER,
    github_repo_id INTEGER UNIQUE,
    org_id INTEGER REFERENCES organizations(id),
    name VARCHAR,
    full_name VARCHAR,
    policy_override JSON,
    strictness_level VARCHAR DEFAULT 'block',
    active BOOLEAN DEFAULT true
);
```

## API Endpoints

### Organization Policy Management

**Get Organization Policy**
```bash
GET /orgs/{org_id}/policy
```

**Set Organization Policy**
```bash
POST /orgs/{org_id}/policy
Content-Type: application/json

{
  "high_threshold": 80,
  "require_tests": true
}
```

### Repository Policy Management

**Get Effective Policy**
```bash
GET /repos/{repo_id}/policy/effective
```

Returns the merged policy configuration with strictness level and metadata.

**Set Repository Override**
```bash
POST /repos/{repo_id}/policy
Content-Type: application/json

{
  "high_threshold": 60
}
```

## Webhook Auto-Provisioning

The system automatically creates organization and repository records when:

- GitHub App is installed on an organization
- Repositories are added to the installation
- Pull requests are opened (creates missing records)

Repositories removed from the installation are marked as `active = false`.

## Worker Integration

The worker fetches the effective policy for each repository and applies strictness mapping:

```python
# Fetch repository and resolve effective policy
repo = db.query(Repository).filter_by(full_name=repo_slug).first()
effective_policy = resolve_effective_policy(db, repo.id)

# Apply strictness mapping only on BLOCK results
if verdict == "BLOCK":
    if strictness == "block":
        state = "failure"
    elif strictness == "warn":
        state = "success"  # with warning message
    else:  # "pass"
        state = "success"
```

## Testing

### Automated Verification

Run the comprehensive test suite:

```bash
python3 scripts/verify_phase9.py
```

Tests cover:
- Policy merge logic
- Effective policy resolution
- Strictness levels
- Soft delete functionality

### Database Seeding

Seed the database with test data:

```bash
python3 scripts/seed_phase9_db.py
```

The seed script is idempotent and can be run multiple times safely.

### Manual API Testing

```bash
# Get organization policy
curl -s http://localhost:8000/orgs/1/policy | python3 -m json.tool

# Get effective policy for repositories
curl -s http://localhost:8000/repos/1/policy/effective | python3 -m json.tool
curl -s http://localhost:8000/repos/2/policy/effective | python3 -m json.tool
curl -s http://localhost:8000/repos/3/policy/effective | python3 -m json.tool

# Test 404 error handling
curl -i http://localhost:8000/repos/999/policy/effective
```

## Policy Merge Example

**Organization Policy:**
```json
{
  "high_threshold": 80,
  "require_tests": true,
  "security_scan": true
}
```

**Repository Override:**
```json
{
  "high_threshold": 60
}
```

**Effective Policy (merged):**
```json
{
  "high_threshold": 60,
  "require_tests": true,
  "security_scan": true
}
```

The repository override for `high_threshold` wins (60 instead of 80), while `require_tests` and `security_scan` are inherited from the organization defaults.

## Files Modified

- `compliancebot/saas/db/models.py` - Added stable GitHub IDs and policy columns
- `compliancebot/saas/policy.py` - New file with merge logic and policy resolver
- `compliancebot/saas/worker/tasks.py` - Updated to use effective policy and strictness mapping
- `compliancebot/saas/api/main.py` - Added policy endpoints and webhook provisioning
- `scripts/verify_phase9.py` - Comprehensive test suite
- `scripts/seed_phase9_db.py` - Idempotent database seeding script

## Production Deployment

1. Run database migration to add new columns
2. Deploy updated worker and API code
3. Configure organization-level policies via API
4. Set repository-specific strictness levels as needed
5. Monitor webhook events for auto-provisioning

## Error Handling

The API returns proper HTTP status codes:

- `200 OK` - Successful policy retrieval or update
- `404 Not Found` - Repository or organization does not exist
- `500 Internal Server Error` - Unexpected server errors

All endpoints include descriptive error messages in the response body.
