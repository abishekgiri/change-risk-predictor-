from sqlalchemy import Column, Integer, String, DateTime, Enum, Text
from sqlalchemy.sql import func
from compliancebot.saas.db.base import Base
import datetime

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

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    github_id = Column(Integer, unique=True)
    installation_id = Column(Integer)
    login = Column(String)
