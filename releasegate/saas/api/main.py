from fastapi import FastAPI, Request, HTTPException, Depends
from releasegate.saas.config import SaaSConfig
from releasegate.saas.worker.queue import job_queue
from releasegate.saas.db.base import SessionLocal
from releasegate.saas.db.models import Organization, Repository
from releasegate.saas.policy import resolve_effective_policy
import hmac
import hashlib
import json
from fastapi import FastAPI, Request, HTTPException, Depends
from releasegate.integrations.jira.routes import router as jira_router

app = FastAPI(title="ComplianceBot SaaS Control Plane")

app.include_router(jira_router, prefix="/integrations/jira", tags=["jira"])

async def verify_signature(request: Request):
    """
    Verify GitHub Webhook Signature (Diffie-Hellman HMAC-SHA256).
    """
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")
    
    body = await request.body()
    
    # Calculate expected signature
    secret = SaaSConfig.WEBHOOK_SECRET.encode()
    hash_object = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    return True

@app.post("/webhook")
async def webhook_handler(request: Request, authorized: bool = Depends(verify_signature)):
    """
    Receive GitHub events and enqueue analysis jobs.
    """
    event_type = request.headers.get("X-GitHub-Event")
    payload = await request.json()
    
    # We only care about PRs
    if event_type == "pull_request":
        action = payload.get("action")
        # Enqueue on open or update (synchronize)
        if action in ["opened", "synchronize", "reopened"]:
            installation = payload.get("installation")
            if not installation:
                return {"status": "ignored", "reason": "no_installation"}
            
            install_id = installation["id"]
            repo_full_name = payload["repository"]["full_name"]
            pr_number = payload["number"]
            head_sha = payload["pull_request"]["head"]["sha"]
            
            print(f"Enqueueing job for {repo_full_name} PR #{pr_number} (Inst: {install_id})")
            
            # Phase 9: Auto-provision Organization and Repository
            db = SessionLocal()
            try:
                # Upsert Organization
                org_data = payload.get("organization") or payload.get("repository", {}).get("owner")
                if org_data:
                    org = db.query(Organization).filter(
                        Organization.github_installation_id == install_id
                    ).first()
                    if not org:
                        org = Organization(
                            github_id=org_data.get("id"),
                            github_installation_id=install_id,
                            installation_id=install_id,
                            login=org_data.get("login"),
                            github_account_login=org_data.get("login")
                        )
                        db.add(org)
                        db.commit()
                        db.refresh(org)
                        print(f"Created Organization: {org.github_account_login}")
                
                # Upsert Repository
                repo_data = payload["repository"]
                repo = db.query(Repository).filter(
                    Repository.github_repo_id == repo_data["id"]
                ).first()
                if not repo:
                    repo = Repository(
                        github_id=repo_data["id"],
                        github_repo_id=repo_data["id"],
                        org_id=org.id if org else None,
                        name=repo_data["name"],
                        full_name=repo_full_name,
                        strictness_level="block",
                        active=True
                    )
                    db.add(repo)
                    db.commit()
                    print(f"Created Repository: {repo.full_name}")
                else:
                    # Reactivate if previously soft-deleted
                    if not repo.active:
                        repo.active = True
                        db.commit()
                        print(f"Reactivated Repository: {repo.full_name}")
            finally:
                db.close()
            
            # Enqueue Job
            job = job_queue.enqueue(
                "releasegate.saas.worker.tasks.run_analysis_job",
                installation_id=install_id,
                repo_slug=repo_full_name,
                pr_number=pr_number,
                commit_sha=head_sha
            )
            
            return {"status": "queued", "job_id": job.id}
    
    # Phase 9: Handle installation events for org/repo provisioning
    elif event_type == "installation" or event_type == "installation_repositories":
        installation = payload.get("installation")
        if not installation:
            return {"status": "ignored", "reason": "no_installation"}
        
        install_id = installation["id"]
        account = installation["account"]
        
        db = SessionLocal()
        try:
            # Upsert Organization
            org = db.query(Organization).filter(
                Organization.github_installation_id == install_id
            ).first()
            if not org:
                org = Organization(
                    github_id=account["id"],
                    github_installation_id=install_id,
                    installation_id=install_id,
                    login=account["login"],
                    github_account_login=account["login"]
                )
                db.add(org)
                db.commit()
                db.refresh(org)
                print(f"Created Organization from installation: {org.github_account_login}")
            
            # Handle repository additions/removals
            if event_type == "installation_repositories":
                action = payload.get("action")
                
                if action == "added":
                    for repo_data in payload.get("repositories_added", []):
                        repo = db.query(Repository).filter(
                            Repository.github_repo_id == repo_data["id"]
                        ).first()
                        if not repo:
                            repo = Repository(
                                github_id=repo_data["id"],
                                github_repo_id=repo_data["id"],
                                org_id=org.id,
                                name=repo_data["name"],
                                full_name=repo_data["full_name"],
                                strictness_level="block",
                                active=True
                            )
                            db.add(repo)
                            print(f"Added Repository: {repo_data['full_name']}")
                    db.commit()
                
                elif action == "removed":
                    for repo_data in payload.get("repositories_removed", []):
                        repo = db.query(Repository).filter(
                            Repository.github_repo_id == repo_data["id"]
                        ).first()
                        if repo:
                            repo.active = False
                            print(f"Soft-deleted Repository: {repo_data['full_name']}")
                    db.commit()
            
            return {"status": "provisioned", "org_id": org.id}
        finally:
            db.close()
            
    return {"status": "ignored"}

# Phase 9: Policy Management Endpoints

@app.post("/orgs/{org_id}/policy")
def set_org_policy(org_id: int, policy: dict):
    """
    Set organization-level default policy configuration.
    """
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        org.default_policy_config = policy
        db.commit()
        return {"status": "updated", "org_id": org_id}
    finally:
        db.close()

@app.get("/orgs/{org_id}/policy")
def get_org_policy(org_id: int):
    """
    Get organization-level default policy configuration.
    """
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        return {
            "org_id": org_id,
            "org_login": org.github_account_login,
            "policy": org.default_policy_config or {}
        }
    finally:
        db.close()

@app.post("/repos/{repo_id}/policy")
def set_repo_policy(repo_id: int, policy: dict):
    """
    Set repository-level policy overrides.
    """
    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        repo.policy_override = policy
        db.commit()
        return {"status": "updated", "repo_id": repo_id}
    finally:
        db.close()

@app.get("/repos/{repo_id}/policy/effective")
def get_effective_policy(repo_id: int):
    """
    Get the effective (merged) policy for a repository.
    """
    db = SessionLocal()
    try:
        effective = resolve_effective_policy(db, repo_id)
        return effective
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        db.close()

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "releasegate-saas-api"}
