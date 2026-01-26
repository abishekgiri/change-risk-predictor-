from fastapi import FastAPI, Request, HTTPException, Depends
from compliancebot.saas.config import SaaSConfig
from compliancebot.saas.worker.queue import job_queue
import hmac
import hashlib
import json

app = FastAPI(title="ComplianceBot SaaS Control Plane")

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
            
            # Enqueue Job
            job = job_queue.enqueue(
                "compliancebot.saas.worker.tasks.run_analysis_job",
                installation_id=install_id,
                repo_slug=repo_full_name,
                pr_number=pr_number,
                commit_sha=head_sha
            )
            
            return {"status": "queued", "job_id": job.id}
            
    return {"status": "ignored"}

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "compliancebot-saas-api"}
