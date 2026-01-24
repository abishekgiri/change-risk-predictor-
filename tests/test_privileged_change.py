"""
Unit tests for Privileged Code Change Detection.
"""
import pytest
from compliancebot.controls.privileged_change import PrivilegedChangeControl
from compliancebot.controls.types import ControlContext

def test_auth_path_detection():
 """Test detection of authentication code changes."""
 control = PrivilegedChangeControl()
 
 diff = {
 "auth/login.py": "@@ -1,1 +1,2 @@\n+# New auth logic\n",
 "utils/helpers.py": "@@ -1,1 +1,2 @@\n+# Helper\n"
 }
 
 config = {
 "privileged_paths": {
 "auth": ["auth/*", "**/authentication.py"],
 "payment": ["billing/*", "payments/*"],
 "crypto": ["crypto/*", "*/encryption.py"],
 "migrations": ["migrations/*", "*.sql"],
 "infra": ["terraform/*", "*.tf", "k8s/*"]
 }
 }
 
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff=diff,
 config=config,
 provider=None
 )
 
 result = control.execute(context)
 
 assert result.signals["privileged.detected"] is True
 assert result.signals["privileged.auth.detected"] is True
 assert result.signals["privileged.auth.count"] == 1
 assert len(result.findings) == 1
 assert result.findings[0].evidence["category"] == "auth"

def test_multiple_categories():
 """Test detection across multiple privileged categories."""
 control = PrivilegedChangeControl()
 
 diff = {
 "auth/login.py": "@@ -1,1 +1,2 @@\n+# Auth\n",
 "billing/stripe.py": "@@ -1,1 +1,2 @@\n+# Payment\n",
 "migrations/001_init.sql": "@@ -1,1 +1,2 @@\n+-- Migration\n"
 }
 
 config = {
 "privileged_paths": {
 "auth": ["auth/*"],
 "payment": ["billing/*"],
 "migrations": ["migrations/*", "*.sql"]
 }
 }
 
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff=diff,
 config=config,
 provider=None
 )
 
 result = control.execute(context)
 
 assert result.signals["privileged.detected"] is True
 assert result.signals["privileged.auth.detected"] is True
 assert result.signals["privileged.payment.detected"] is True
 assert result.signals["privileged.migrations.detected"] is True
 assert len(result.findings) == 3
 assert set(result.signals["privileged.categories"]) == {"auth", "payment", "migrations"}

def test_pattern_matching():
 """Test various pattern matching modes."""
 control = PrivilegedChangeControl()
 
 # Test exact match
 assert control._matches_pattern("auth/login.py", "auth/login.py")
 
 # Test prefix match
 assert control._matches_pattern("auth/login.py", "auth/*")
 assert control._matches_pattern("auth/subdir/file.py", "auth/*")
 
 # Test suffix match
 assert control._matches_pattern("migrations/001.sql", "*.sql")
 assert control._matches_pattern("db/schema.sql", "*.sql")
 
 # Test contains match
 assert control._matches_pattern("src/authentication.py", "*authentication*")
 assert control._matches_pattern("lib/authentication_helper.py", "*authentication*")
 
 # Test no match
 assert not control._matches_pattern("utils/helpers.py", "auth/*")
 assert not control._matches_pattern("README.md", "*.sql")

def test_no_privileged_changes():
 """Test when no privileged paths are modified."""
 control = PrivilegedChangeControl()
 
 diff = {
 "utils/helpers.py": "@@ -1,1 +1,2 @@\n+# Helper\n",
 "tests/test_utils.py": "@@ -1,1 +1,2 @@\n+# Test\n"
 }
 
 config = {
 "privileged_paths": {
 "auth": ["auth/*"],
 "payment": ["billing/*"]
 }
 }
 
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff=diff,
 config=config,
 provider=None
 )
 
 result = control.execute(context)
 
 assert result.signals["privileged.detected"] is False
 assert result.signals["privileged.count"] == 0
 assert len(result.findings) == 0

def test_empty_config():
 """Test with no privileged paths configured."""
 control = PrivilegedChangeControl()
 
 diff = {
 "auth/login.py": "@@ -1,1 +1,2 @@\n+# Auth\n"
 }
 
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff=diff,
 config={}, # No privileged_paths
 provider=None
 )
 
 result = control.execute(context)
 
 assert result.signals["privileged.detected"] is False
 assert len(result.findings) == 0

if __name__ == "__main__":
 pytest.main([__file__, "-v"])
