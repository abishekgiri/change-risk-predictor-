#!/usr/bin/env python3
"""
Seed the database with test organizations and repositories for Phase 9 testing.
Idempotent - can be run multiple times safely.
"""

from compliancebot.saas.db.base import SessionLocal
from compliancebot.saas.db.models import Organization, Repository
from sqlalchemy.exc import IntegrityError

db = SessionLocal()

try:
    # Get or create test organization
    org = db.query(Organization).filter_by(github_installation_id=12345).first()
    
    if not org:
        org = Organization(
            github_installation_id=12345,
            github_account_login="test-org",
            login="test-org",
            default_policy_config={
                "high_threshold": 80,
                "require_tests": True,
                "security_scan": True
            }
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        print(f"✅ Created Organization: {org.github_account_login} (ID: {org.id})")
    else:
        print(f"ℹ️  Organization already exists: {org.github_account_login} (ID: {org.id})")
    
    # Get or create test repositories with different strictness levels
    repos_data = [
        {
            "github_repo_id": 1001,
            "full_name": "test-org/critical-service",
            "name": "critical-service",
            "strictness_level": "block",
            "policy_override": None
        },
        {
            "github_repo_id": 1002,
            "full_name": "test-org/experimental-feature",
            "name": "experimental-feature",
            "strictness_level": "warn",
            "policy_override": {"high_threshold": 60}  # Override to be more lenient
        },
        {
            "github_repo_id": 1003,
            "full_name": "test-org/documentation",
            "name": "documentation",
            "strictness_level": "pass",
            "policy_override": None
        }
    ]
    
    for repo_data in repos_data:
        existing_repo = db.query(Repository).filter_by(
            github_repo_id=repo_data["github_repo_id"]
        ).first()
        
        if not existing_repo:
            repo = Repository(
                github_repo_id=repo_data["github_repo_id"],
                full_name=repo_data["full_name"],
                name=repo_data["name"],
                org_id=org.id,
                strictness_level=repo_data["strictness_level"],
                policy_override=repo_data["policy_override"],
                active=True
            )
            db.add(repo)
            db.commit()
            print(f"✅ Created Repository: {repo.full_name} (strictness={repo.strictness_level})")
        else:
            print(f"ℹ️  Repository already exists: {existing_repo.full_name}")
    
    print("\n" + "="*60)
    print("Database seeded successfully!")
    print("="*60)
    print(f"\nOrganization ID: {org.id}")
    print(f"Repository IDs: 1, 2, 3")
    print("\nTest these endpoints:")
    print(f"  curl http://localhost:8000/orgs/{org.id}/policy")
    print(f"  curl http://localhost:8000/repos/1/policy/effective")
    print(f"  curl http://localhost:8000/repos/2/policy/effective")
    print(f"  curl http://localhost:8000/repos/3/policy/effective")
    
except IntegrityError as e:
    db.rollback()
    print(f"ℹ️  Database already seeded (IntegrityError: {str(e).split('DETAIL:')[0].strip()})")
    print("✅ No action needed - data already exists")
except Exception as e:
    db.rollback()
    print(f"❌ Error: {e}")
    raise
finally:
    db.close()
