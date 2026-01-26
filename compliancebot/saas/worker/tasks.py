import os
import shutil
import tempfile
import subprocess
import json
from datetime import datetime
from compliancebot.saas.worker.auth import get_installation_token, get_github_client
from compliancebot.saas.db.base import SessionLocal
from compliancebot.saas.db.models import AnalysisRun

def run_analysis_job(installation_id: int, repo_slug: str, pr_number: int, commit_sha: str):
    """
    Main Worker Task:
    1. Auth with GitHub App
    2. Set Status = Pending
    3. Clone Repo (securely)
    4. Run ComplianceBot
    5. Set Status = Success/Failure
    """
    print(f"WORKER: Starting analysis for {repo_slug} PR #{pr_number}")
    db = SessionLocal()
    
    # 1. Auth & Notify GitHub
    try:
        gh = get_github_client(installation_id)
        repo = gh.get_repo(repo_slug)
        # Check Commit Status API
        repo.get_commit(commit_sha).create_status(
            state="pending",
            context="ComplianceBot/SaaS",
            description="Analysis in progress..."
        )
        
        token = get_installation_token(installation_id)
        
        # 2. Prepare Sandbox
        work_dir = tempfile.mkdtemp(prefix=f"saas_run_{pr_number}_")
        
        try:
            # 3. Clone
            clone_url = f"https://x-access-token:{token}@github.com/{repo_slug}.git"
            subprocess.run(["git", "clone", clone_url, "."], cwd=work_dir, check=True, capture_output=True)
            subprocess.run(["git", "checkout", commit_sha], cwd=work_dir, check=True, capture_output=True)
            
            # 4. Run Analysis (subprocess to CLI)
            # We use the CLI directly since we are in the same environment (or container)
            # Enforcing BLOCK mode effectively via check
            
            # Note: In real prod, this runs inside a Docker container.
            # Here, we assume 'compliancebot' is installed in the worker env.
            
            cmd = [
                "compliancebot", "analyze-pr",
                "--repo", repo_slug,
                "--pr", str(pr_number),
                "--token", token, # Pass app token as GITHUB_TOKEN
                "--output", "result.json",
                "--no-bundle" # MVP: don't store bundle yet
            ]
            
            # Run without environment variable enforcement to get raw result JSON
            env = os.environ.copy()
            env["COMPLIANCEBOT_ENFORCEMENT"] = "report_only" 
            
            proc = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True, env=env)
            
            verdict = "UNKNOWN"
            risk_score = 0
            description = "Analysis completed."
            state = "error"
            
            if proc.returncode == 0 and os.path.exists(os.path.join(work_dir, "result.json")):
                with open(os.path.join(work_dir, "result.json")) as f:
                    result = json.load(f)
                    verdict = result.get("control_result", "UNKNOWN")
                    # Fix: handle non-int severity
                    sev = result.get("severity", 0)
                    risk_score = int(sev) if isinstance(sev, int) else 0
                    
                if verdict == "BLOCK":
                    state = "failure"
                    description = f"Blocked: Risk Level {result.get('severity')}"
                elif verdict == "WARN":
                    state = "success" # GitHub 'neutral' not widely supported on status, usually success w/ warning
                    description = f"Warning: Risk Level {result.get('severity')}"
                else: 
                    state = "success"
                    description = "Compliance Checks Passed"
            else:
                print(f"CLI Failed: {proc.stderr}")
                description = "Internal Analysis Error"
                state = "error"

            # 5. Report Final Status
            repo.get_commit(commit_sha).create_status(
                state=state,
                context="ComplianceBot/SaaS",
                description=description
            )
            
            # 6. Audit Log
            run_record = AnalysisRun(
                installation_id=str(installation_id),
                repo_slug=repo_slug,
                pr_number=pr_number,
                commit_sha=commit_sha,
                status="completed",
                verdict=verdict,
                risk_score=risk_score,
                completed_at=datetime.utcnow()
            )
            db.add(run_record)
            db.commit()
            
            print(f"WORKER: Finished {repo_slug} PR #{pr_number} -> {state} ({verdict})")
            
        finally:
            # Cleanup
            shutil.rmtree(work_dir, ignore_errors=True)
            
    except Exception as e:
        print(f"WORKER ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()
