#!/usr/bin/env python3
"""
Phase 9 Verification Script
Tests multi-repo policy inheritance and strictness enforcement.
"""

from compliancebot.saas.db.base import SessionLocal
from compliancebot.saas.db.models import Organization, Repository
from compliancebot.saas.policy import resolve_effective_policy, merge_configs


def test_policy_merge():
    """Test 1: Deep merge logic"""
    print("\n=== Test 1: Policy Merge Logic ===")
    
    org_config = {
        "high_threshold": 80,
        "rules": {
            "security": {"enabled": True, "level": "strict"}
        }
    }
    
    repo_config = {
        "high_threshold": 60,  # Override
        "rules": {
            "security": {"level": "relaxed"}  # Partial override
        }
    }
    
    merged = merge_configs(org_config, repo_config)
    
    assert merged["high_threshold"] == 60, "Repo override should win"
    assert merged["rules"]["security"]["enabled"] == True, "Org default should persist"
    assert merged["rules"]["security"]["level"] == "relaxed", "Repo override should win"
    
    print(f"✅ Merged config: {merged}")


def test_effective_policy():
    """Test 2: Effective policy resolution with database"""
    print("\n=== Test 2: Effective Policy Resolution ===")
    
    db = SessionLocal()
    try:
        # Clean up any existing test data
        db.query(Repository).filter(Repository.github_repo_id == 777).delete()
        db.query(Organization).filter(Organization.github_installation_id == 888).delete()
        db.commit()
        
        # Create test org with policy
        org = Organization(
            github_installation_id=888,
            github_account_login="test-org",
            default_policy_config={"high_threshold": 80, "require_tests": True},
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        
        # Create test repo with override
        repo = Repository(
            github_repo_id=777,
            full_name="test-org/test-repo",
            org_id=org.id,
            policy_override={"high_threshold": 60},  # Override threshold only
            strictness_level="warn",
            active=True,
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
        
        # Test effective policy
        effective = resolve_effective_policy(db, repo.id)
        
        assert effective["config"]["high_threshold"] == 60, "Repo override should win"
        assert effective["config"]["require_tests"] == True, "Org default should persist"
        assert effective["strictness"] == "warn", "Strictness should be warn"
        assert effective["repo_name"] == "test-org/test-repo", "Repo name should be set"
        
        print(f"✅ Effective policy: {effective}")
        
    finally:
        db.close()


def test_strictness_levels():
    """Test 3: Strictness level variations"""
    print("\n=== Test 3: Strictness Levels ===")
    
    db = SessionLocal()
    try:
        # Clean up
        db.query(Repository).filter(Repository.github_repo_id.in_([1001, 1002, 1003])).delete()
        db.query(Organization).filter(Organization.github_installation_id == 999).delete()
        db.commit()
        
        # Create org
        org = Organization(
            github_installation_id=999,
            github_account_login="acme-inc",
            default_policy_config={"high_threshold": 75},
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        
        # Create repos with different strictness levels
        repos = [
            ("block", 1001, "acme-inc/critical-service"),
            ("warn", 1002, "acme-inc/experimental-feature"),
            ("pass", 1003, "acme-inc/documentation"),
        ]
        
        for strictness, repo_id, full_name in repos:
            repo = Repository(
                github_repo_id=repo_id,
                full_name=full_name,
                org_id=org.id,
                strictness_level=strictness,
                active=True,
            )
            db.add(repo)
        
        db.commit()
        
        # Verify each repo has correct strictness
        for strictness, repo_id, full_name in repos:
            repo = db.query(Repository).filter(Repository.github_repo_id == repo_id).first()
            effective = resolve_effective_policy(db, repo.id)
            assert effective["strictness"] == strictness, f"Strictness should be {strictness}"
            print(f"✅ {full_name}: strictness={strictness}")
        
    finally:
        db.close()


def test_soft_delete():
    """Test 4: Soft delete (active flag)"""
    print("\n=== Test 4: Soft Delete ===")
    
    db = SessionLocal()
    try:
        # Clean up
        db.query(Repository).filter(Repository.github_repo_id == 2001).delete()
        db.commit()
        
        # Create repo
        repo = Repository(
            github_repo_id=2001,
            full_name="test-org/archived-repo",
            strictness_level="block",
            active=True,
        )
        db.add(repo)
        db.commit()
        
        # Soft delete
        repo.active = False
        db.commit()
        
        # Verify
        repo = db.query(Repository).filter(Repository.github_repo_id == 2001).first()
        assert repo.active == False, "Repo should be inactive"
        print(f"✅ Soft delete works: active={repo.active}")
        
    finally:
        db.close()


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 9 Verification Tests")
    print("=" * 60)
    
    try:
        test_policy_merge()
        test_effective_policy()
        test_strictness_levels()
        test_soft_delete()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
