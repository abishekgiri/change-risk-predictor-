from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, JSON, Boolean
from sqlalchemy.sql import func
from compliancebot.saas.db.base import Base
import datetime
import enum

class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(Integer, primary_key=True, index=True)
    
    # Context
    installation_id = Column(String, index=True)
    repo_slug = Column(String, index=True)
    pr_number = Column(Integer)
    commit_sha = Column(String)
    
    # Result
    status = Column(String) # pending, success, failure, error
    verdict = Column(String) # PASS, BLOCK, WARN
    risk_score = Column(Integer)
    
    # Audit
    audit_id = Column(String) # UUID from bundling
    manifest_hash = Column(String)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

class StrictnessLevel(enum.Enum):
    PASS = "pass"      # Always pass, report only
    WARN = "warn"      # Report as warning/neutral
    BLOCK = "block"    # Enforce blocking on failure

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    github_id = Column(Integer, unique=True)  # Org GitHub ID
    github_installation_id = Column(Integer, unique=True, nullable=True)  # Stable installation ID
    installation_id = Column(Integer)  # Legacy, can be removed later
    login = Column(String)
    github_account_login = Column(String, nullable=True)  # Human-readable org name (e.g., "acme-inc")
    default_policy_config = Column(JSON, nullable=True)  # Org-level policy defaults

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True)
    github_id = Column(Integer, unique=True)  # Legacy
    github_repo_id = Column(Integer, unique=True, nullable=True)  # Stable GitHub repo ID
    org_id = Column(Integer, nullable=True)  # FK to Organization
    name = Column(String)  # Short name
    full_name = Column(String, nullable=True)  # owner/repo for display
    policy_override = Column(JSON, nullable=True)  # Repo-specific policy overrides
    strictness_level = Column(String, default="block")  # pass, warn, or block
    active = Column(Boolean, default=True)  # Soft-delete flag
