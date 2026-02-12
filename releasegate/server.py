from releasegate.storage.sqlite import save_run
from releasegate.config import (
    GITHUB_TOKEN, WEBHOOK_URL
)
from releasegate.integrations.github_risk import (
    PRRiskInput,
    build_issue_risk_property,
    classify_pr_risk,
    extract_jira_issue_keys,
    score_for_risk_level,
)
import hmac
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
import csv
import io
import zipfile
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from releasegate.security.auth import require_access, tenant_from_request
from releasegate.security.audit import log_security_event
from releasegate.security.api_keys import create_api_key, list_api_keys, revoke_api_key, rotate_api_key
from releasegate.security.checkpoint_keys import list_checkpoint_signing_keys, rotate_checkpoint_signing_key
from releasegate.security.webhook_keys import create_webhook_key, list_webhook_keys
from releasegate.security.types import AuthContext
from releasegate.storage import get_storage_backend

# Load env vars
load_dotenv()


# Initialize App
app = FastAPI(
    title="ComplianceBot Webhook Listener",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
logger = logging.getLogger(__name__)


class CIScoreRequest(BaseModel):
    repo: str
    pr: int
    sha: Optional[str] = None


class ManualOverrideRequest(BaseModel):
    repo: str
    pr_number: Optional[int] = None
    issue_key: Optional[str] = None
    decision_id: Optional[str] = None
    reason: str = Field(min_length=3)
    target_type: str = "pr"
    target_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class PublishPolicyRequest(BaseModel):
    policy_bundle_hash: str
    policy_snapshot: list[dict] = Field(default_factory=list)
    activate: bool = True
    note: Optional[str] = None


class CreateApiKeyRequest(BaseModel):
    name: str
    roles: list[str] = Field(default_factory=lambda: ["operator"])
    scopes: list[str] = Field(default_factory=lambda: ["enforcement:write"])
    tenant_id: Optional[str] = None


class RotateCheckpointSigningKeyRequest(BaseModel):
    key: str = Field(min_length=16)
    tenant_id: Optional[str] = None


class RotateApiKeyRequest(BaseModel):
    tenant_id: Optional[str] = None


class CreateWebhookSigningKeyRequest(BaseModel):
    integration_id: str = Field(min_length=1)
    tenant_id: Optional[str] = None
    rotate_existing: bool = True
    secret: Optional[str] = None


# --- Config ---
# Use user's preferred default
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # For API calls
LEDGER_VERIFY_ON_STARTUP = os.getenv("RELEASEGATE_LEDGER_VERIFY_ON_STARTUP", "false").strip().lower() in {"1", "true", "yes", "on"}
LEDGER_FAIL_ON_CORRUPTION = os.getenv("RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION", "true").strip().lower() in {"1", "true", "yes", "on"}


def _effective_tenant(auth: AuthContext, requested_tenant: Optional[str]) -> str:
    try:
        return tenant_from_request(auth, requested_tenant)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def get_pr_details(repo_full_name: str, pr_number: int) -> Dict:
    """Fetch PR details (title, author, labels) using GitHub API."""
    if not GITHUB_TOKEN:
        return {}

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        print(f"Failed to fetch PR details: {resp.status_code}")
    except Exception as e:
        print(f"Error fetching PR details: {e}")

    return {}


def get_pr_metrics(repo_full_name: str, pr_number: int) -> PRRiskInput:
    """
    Fetch minimal PR counters from GitHub (no diff/file content).
    """
    pr_data = get_pr_details(repo_full_name, pr_number)
    return PRRiskInput(
        changed_files=int(pr_data.get("changed_files", 0) or 0),
        additions=int(pr_data.get("additions", 0) or 0),
        deletions=int(pr_data.get("deletions", 0) or 0),
    )


def post_pr_comment(repo_full_name: str, pr_number: int, body: str):
    """Post a comment to the PR."""
    if not GITHUB_TOKEN:
        return

    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        requests.post(url, json={"body": body}, headers=headers)
        print(f"Posted comment to PR #{pr_number}")
    except Exception as e:
        print(f"Failed to post comment: {e}")


def create_check_run(repo_full_name: str, head_sha: str, score: int, risk_level: str, reasons: list, evidence: list = None):
    """Create a GitHub Check Run."""
    if not GITHUB_TOKEN:
        print("Warning: No GITHUB_TOKEN, skipping check run creation.")
        return

    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    conclusion = "failure" if risk_level == "HIGH" else "success"
    title = f"ComplianceBot CI: {risk_level} severity (Score: {score})"

    summary = "Risk analysis completed.\n\n### Reasons\n" + \
        "\n".join(f"- {r}" for r in reasons)

    if evidence:
        summary += "\n\n### Evidence\n" + "\n".join(f"- {e}" for e in evidence)

    payload = {
        "name": "ComplianceBot CI",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary
        }
    }

    if WEBHOOK_URL:
        payload["details_url"] = WEBHOOK_URL

    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code not in [200, 201]:
            print(f"Failed to create check run: {resp.status_code} - {resp.text}")
        else:
            print(f"Created check run: {title}")
    except Exception as e:
        print(f"Error creating check run: {e}")


@app.post("/ci/score")
def ci_score(
    payload: CIScoreRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    """
    CI Endpoint: Returns metadata-only risk classification for a PR.
    """
    repo_full_name = payload.repo
    pr_number = payload.pr
    print(f"CI Analysis Request: {repo_full_name} #{pr_number}")

    pr_data = get_pr_details(repo_full_name, pr_number)
    metrics = PRRiskInput(
        changed_files=int(pr_data.get("changed_files", 0) or 0),
        additions=int(pr_data.get("additions", 0) or 0),
        deletions=int(pr_data.get("deletions", 0) or 0),
    )

    risk_level = classify_pr_risk(metrics)
    risk_score = score_for_risk_level(risk_level)
    decision = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

    return {
        "score": risk_score,
        "level": risk_level,
        "decision": decision,
        "metrics": {
            "changed_files_count": metrics.changed_files,
            "additions": metrics.additions,
            "deletions": metrics.deletions,
            "total_churn": metrics.total_churn,
        },
    }


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        allow_signature=True,
        rate_profile="webhook",
    ),
):
    payload = await request.body()

    # Handle GitHub ping FIRST
    if x_github_event == "ping":
        return {"msg": "pong"}

    # Verify signature
    if GITHUB_SECRET:
        mac = hmac.new(
            GITHUB_SECRET.encode(),
            msg=payload,
            digestmod=hashlib.sha256
        )
        expected = "sha256=" + mac.hexdigest()

        if not hmac.compare_digest(expected, x_hub_signature_256 or ""):
            raise HTTPException(status_code=401, detail="Invalid signature")

    data = json.loads(payload)

    # Process Pull Request Events
    if x_github_event != "pull_request":
        return {"msg": "Ignored non-PR event"}

    action = data.get("action")
    if action not in ["opened", "synchronize", "reopened", "closed"]:
        return {"msg": f"Ignored PR action: {action}"}

    pr = data.get("pull_request", {})
    repo = data.get("repository", {})

    repo_full_name = repo.get("full_name")
    # DO NOT strip dash here, we need exact name for API calls
    # if repo_full_name:
    # repo_full_name = repo_full_name.strip("-")
    pr_number = pr.get("number")

    if not repo_full_name or not pr_number:
        return {"msg": "Missing repo or pr_number"}

    print(f"Processing PR #{pr_number} for {repo_full_name} ({action})")

    base_sha = pr.get("base", {}).get("sha", "unknown")
    head_sha = pr.get("head", {}).get("sha", "unknown")
    title = pr.get("title", "")
    metrics = PRRiskInput(
        changed_files=int(pr.get("changed_files", 0) or 0),
        additions=int(pr.get("additions", 0) or 0),
        deletions=int(pr.get("deletions", 0) or 0),
    )
    if metrics.changed_files == 0 and metrics.additions == 0 and metrics.deletions == 0:
        metrics = get_pr_metrics(repo_full_name, int(pr_number))

    risk_level = classify_pr_risk(metrics)
    risk_score = score_for_risk_level(risk_level)
    decision = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

    issue_keys = sorted(extract_jira_issue_keys(title, pr.get("body") or ""))
    attached_issue_keys = []
    if issue_keys:
        try:
            from releasegate.integrations.jira.client import JiraClient

            client = JiraClient()
            payload = build_issue_risk_property(
                repo=repo_full_name,
                pr_number=int(pr_number),
                risk_level=risk_level,
                metrics=metrics,
            )
            for issue_key in issue_keys:
                if client.set_issue_property(issue_key, "releasegate_risk", payload):
                    attached_issue_keys.append(issue_key)
        except Exception as e:
            print(f"Warning: Jira risk attach failed: {e}")

    score_data = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "reasons": [f"Heuristic classification from GitHub metadata: {risk_level}"],
    }
    features = {
        "source": "github_metadata",
        "changed_files_count": metrics.changed_files,
        "additions": metrics.additions,
        "deletions": metrics.deletions,
        "total_churn": metrics.total_churn,
        "attached_issue_keys": attached_issue_keys,
    }

    save_run(
        repo=repo_full_name,
        pr_number=int(pr_number),
        base_sha=base_sha,
        head_sha=head_sha,
        score_data=score_data,
        features=features,
    )

    return {
        "status": "processed",
        "result": decision,
        "risk_score": risk_score,
        "severity": risk_level,
        "attached_issue_keys": attached_issue_keys,
        "metrics": features,
    }


@app.get("/")
def health_check():
    return {"status": "ok", "service": "RiskBot Webhook Listener"}


@app.get("/health")
def health():
    storage_status = "ok"
    try:
        get_storage_backend().fetchone("SELECT 1 AS ok")
    except Exception:
        storage_status = "error"
    status_code = 200 if storage_status == "ok" else 503
    payload = {
        "status": "ok" if storage_status == "ok" else "error",
        "service": "RiskBot Webhook Listener",
        "storage": storage_status,
    }
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=payload)
    return payload


@app.on_event("startup")
def verify_ledger_on_startup():
    from releasegate.storage.schema import init_db

    init_db()
    if not LEDGER_VERIFY_ON_STARTUP:
        return
    from releasegate.audit.overrides import verify_all_override_chains

    result = verify_all_override_chains()
    app.state.override_chain_last_verification = result
    if not result.get("valid", True):
        logger.error("Override ledger corruption detected at startup: %s", result)
        if LEDGER_FAIL_ON_CORRUPTION:
            raise RuntimeError("Override ledger corruption detected")
    else:
        logger.info(
            "Override ledger verified at startup: checked_chains=%s",
            result.get("checked_chains", result.get("checked_repos", 0)),
        )


@app.get("/audit/ledger/verify")
def verify_ledger(
    repo: Optional[str] = None,
    pr: Optional[int] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.overrides import verify_all_override_chains, verify_override_chain

    effective_tenant = _effective_tenant(auth, tenant_id)
    if repo:
        result = verify_override_chain(repo=repo, pr=pr, tenant_id=effective_tenant)
        return {"tenant_id": effective_tenant, "repo": repo, **result}
    return verify_all_override_chains(tenant_id=effective_tenant)


def _derive_reason_code(decision: str, message: str, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    msg = (message or "").lower()
    if "override" in msg:
        return "OVERRIDE_APPLIED"
    if "missing issue property `releasegate_risk`" in msg or "missing risk" in msg:
        return "MISSING_RISK_METADATA"
    if "no policies configured" in msg:
        return "NO_POLICIES_MAPPED"
    if "system error" in msg:
        return "SYSTEM_ERROR"
    if decision == "BLOCKED":
        return "POLICY_BLOCKED"
    if decision == "CONDITIONAL":
        return "POLICY_CONDITIONAL"
    if decision == "ERROR":
        return "SYSTEM_ERROR"
    if decision == "SKIPPED":
        return "POLICY_SKIPPED"
    return "POLICY_ALLOWED"


def _bounded_limit(value: int, *, max_allowed: int, field: str = "limit") -> int:
    bounded = int(value)
    if bounded <= 0:
        raise HTTPException(status_code=400, detail=f"{field} must be > 0")
    if bounded > max_allowed:
        raise HTTPException(status_code=400, detail=f"{field} exceeds maximum allowed ({max_allowed})")
    return bounded


def _soc2_records(
    rows: list,
    overrides: Optional[list] = None,
    chain_verified: Optional[bool] = None,
) -> list:
    override_map = {}
    if overrides:
        for ov in overrides:
            d_id = ov.get("decision_id")
            if d_id and d_id not in override_map:
                override_map[d_id] = ov

    records = []
    for r in rows:
        full = {}
        raw_full = r.get("full_decision_json")
        if raw_full:
            try:
                full = json.loads(raw_full) if isinstance(raw_full, str) else (raw_full or {})
            except Exception:
                full = {}

        decision = full.get("release_status") or r.get("release_status") or "UNKNOWN"
        message = full.get("message") or ""
        explicit_reason = full.get("reason_code")
        ov = override_map.get(r.get("decision_id"))

        records.append({
            "tenant_id": r.get("tenant_id") or full.get("tenant_id"),
            "decision_id": r.get("decision_id"),
            "decision": decision,
            "reason_code": _derive_reason_code(decision, message, explicit_reason),
            "human_message": message,
            "actor": full.get("actor_id") or (ov.get("actor") if ov else None),
            "policy_version": full.get("policy_bundle_hash") or r.get("policy_bundle_hash"),
            "inputs_present": full.get("inputs_present") or {},
            "override_id": ov.get("override_id") if ov else None,
            "chain_verified": chain_verified if chain_verified is not None else None,
            "repo": r.get("repo"),
            "pr_number": r.get("pr_number"),
            "created_at": r.get("created_at"),
        })
    return records


@app.get("/audit/export")
def audit_export(
    repo: str,
    format: str = "json",
    limit: int = 200,
    status: Optional[str] = None,
    pr: Optional[int] = None,
    tenant_id: Optional[str] = None,
    include_overrides: bool = False,
    verify_chain: bool = False,
    contract: str = "soc2_v1",
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    """
    Export audit decisions in JSON or CSV.
    """
    from releasegate.audit.reader import AuditReader
    effective_tenant = _effective_tenant(auth, tenant_id)
    limit = _bounded_limit(limit, max_allowed=500, field="limit")
    rows = AuditReader.list_decisions(
        repo=repo,
        limit=limit,
        status=status,
        pr=pr,
        tenant_id=effective_tenant,
    )
    payload = {"decisions": rows}
    overrides = []
    chain_result = None

    include_override_data = include_overrides or contract == "soc2_v1"

    if include_override_data:
        try:
            from releasegate.audit.overrides import list_overrides, verify_override_chain
            overrides = list_overrides(repo=repo, limit=limit, pr=pr, tenant_id=effective_tenant)
            payload["overrides"] = overrides if include_overrides else []
            if verify_chain:
                chain_result = verify_override_chain(repo=repo, pr=pr, tenant_id=effective_tenant)
                payload["override_chain"] = chain_result
        except Exception:
            payload["overrides"] = []

    export_rows = rows
    if contract == "soc2_v1":
        chain_flag = bool(chain_result.get("valid")) if (verify_chain and chain_result is not None) else (False if verify_chain else None)
        export_rows = _soc2_records(rows, overrides=overrides, chain_verified=chain_flag)
        payload = {
            "contract": "soc2_v1",
            "tenant_id": effective_tenant,
            "repo": repo,
            "records": export_rows,
        }
        if verify_chain:
            payload["override_chain"] = chain_result if chain_result is not None else {"valid": False, "checked": 0}

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="audit_export",
        target_type="repo",
        target_id=repo,
        metadata={"format": format.lower(), "contract": contract, "row_count": len(export_rows)},
    )

    if format.lower() == "csv":
        if not export_rows:
            return PlainTextResponse("", media_type="text/csv")
        output = io.StringIO()
        fieldnames = list(export_rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for r in export_rows:
            writer.writerow(r)
        return PlainTextResponse(output.getvalue(), media_type="text/csv")
    return payload


@app.post("/audit/checkpoints/override")
def create_override_checkpoint(
    repo: str,
    cadence: str = "daily",
    pr: Optional[int] = None,
    at: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import create_override_checkpoint as create_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = create_checkpoint(
            repo=repo,
            cadence=cadence,
            pr=pr,
            at=at,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="checkpoint_create",
        target_type="repo",
        target_id=repo,
        metadata={"cadence": cadence, "pr_number": pr},
    )
    return result


@app.get("/audit/checkpoints/override/verify")
def verify_override_checkpoint(
    repo: str,
    period_id: str,
    cadence: str = "daily",
    pr: Optional[int] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import verify_override_checkpoint as verify_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = verify_checkpoint(
            repo=repo,
            cadence=cadence,
            period_id=period_id,
            pr=pr,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result.get("exists", False):
        raise HTTPException(status_code=404, detail=result.get("reason", "Checkpoint not found"))
    return result


@app.get("/policy/simulate")
def simulate_policy_impact(
    repo: str,
    limit: int = 100,
    policy_dir: str = "releasegate/policy/compiled",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.policy.simulation import simulate_policy_impact as run_simulation

    effective_tenant = _effective_tenant(auth, tenant_id)
    limit = _bounded_limit(limit, max_allowed=500, field="limit")
    try:
        return run_simulation(
            repo=repo,
            limit=limit,
            policy_dir=policy_dir,
            tenant_id=effective_tenant,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Policy simulation failed: {exc}") from exc


@app.get("/audit/proof-pack/{decision_id}")
def audit_proof_pack(
    decision_id: str,
    format: str = "json",
    checkpoint_cadence: str = "daily",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["proofpack:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.audit.reader import AuditReader
    from releasegate.audit.overrides import list_overrides, verify_override_chain
    from releasegate.audit.checkpoints import period_id_for_timestamp, verify_override_checkpoint
    from releasegate.audit.proof_packs import record_proof_pack_generation

    effective_tenant = _effective_tenant(auth, tenant_id)
    row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not row:
        raise HTTPException(status_code=404, detail="Decision not found")

    raw = row.get("full_decision_json")
    if not raw:
        raise HTTPException(status_code=422, detail="Decision payload missing full_decision_json")

    try:
        decision_snapshot = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Stored decision payload is invalid: {exc}") from exc

    if not isinstance(decision_snapshot, dict):
        raise HTTPException(status_code=422, detail="Stored decision payload is invalid")

    repo = row.get("repo")
    pr_number = row.get("pr_number")
    created_at = row.get("created_at")

    override_snapshot = None
    chain_proof = None
    checkpoint_proof = None

    if repo:
        overrides = list_overrides(repo=repo, limit=500, pr=pr_number, tenant_id=effective_tenant)
        override_snapshot = next((o for o in overrides if o.get("decision_id") == decision_id), None)
        chain_proof = verify_override_chain(repo=repo, pr=pr_number, tenant_id=effective_tenant)
        try:
            period_id = period_id_for_timestamp(created_at, cadence=checkpoint_cadence)
            checkpoint_proof = verify_override_checkpoint(
                repo=repo,
                cadence=checkpoint_cadence,
                period_id=period_id,
                pr=pr_number,
                tenant_id=effective_tenant,
            )
        except Exception as exc:
            checkpoint_proof = {"exists": False, "valid": False, "reason": str(exc)}

    bundle = {
        "bundle_version": "audit_proof_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "repo": repo,
        "pr_number": pr_number,
        "decision_snapshot": decision_snapshot,
        "policy_snapshot": decision_snapshot.get("policy_bindings", []),
        "input_snapshot": decision_snapshot.get("input_snapshot", {}),
        "override_snapshot": override_snapshot,
        "chain_proof": chain_proof,
        "checkpoint_proof": checkpoint_proof,
    }

    if format.lower() == "json":
        record_proof_pack_generation(
            decision_id=decision_id,
            output_format="json",
            bundle_version=bundle["bundle_version"],
            repo=repo,
            pr_number=pr_number,
            tenant_id=effective_tenant,
        )
        log_security_event(
            tenant_id=effective_tenant,
            principal_id=auth.principal_id,
            auth_method=auth.auth_method,
            action="proof_pack_export",
            target_type="decision",
            target_id=decision_id,
            metadata={"format": "json"},
        )
        return bundle
    if format.lower() != "zip":
        raise HTTPException(status_code=400, detail="Unsupported format (expected json or zip)")

    memory = io.BytesIO()
    with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bundle.json", json.dumps(bundle, indent=2, default=str))
        zf.writestr("decision_snapshot.json", json.dumps(bundle["decision_snapshot"], indent=2, default=str))
        zf.writestr("policy_snapshot.json", json.dumps(bundle["policy_snapshot"], indent=2, default=str))
        zf.writestr("input_snapshot.json", json.dumps(bundle["input_snapshot"], indent=2, default=str))
        zf.writestr("override_snapshot.json", json.dumps(bundle["override_snapshot"], indent=2, default=str))
        zf.writestr("chain_proof.json", json.dumps(bundle["chain_proof"], indent=2, default=str))
        zf.writestr("checkpoint_proof.json", json.dumps(bundle["checkpoint_proof"], indent=2, default=str))
    memory.seek(0)
    record_proof_pack_generation(
        decision_id=decision_id,
        output_format="zip",
        bundle_version=bundle["bundle_version"],
        repo=repo,
        pr_number=pr_number,
        tenant_id=effective_tenant,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="proof_pack_export",
        target_type="decision",
        target_id=decision_id,
        metadata={"format": "zip"},
    )
    return Response(
        content=memory.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="proof-pack-{decision_id}.zip"'},
    )


@app.post("/audit/overrides")
def create_manual_override(
    payload: ManualOverrideRequest,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["override:write"],
        rate_profile="default",
    ),
):
    from releasegate.audit.overrides import record_override

    effective_tenant = _effective_tenant(auth, tenant_id)
    override = record_override(
        repo=payload.repo,
        pr_number=payload.pr_number,
        issue_key=payload.issue_key,
        decision_id=payload.decision_id,
        actor=auth.principal_id,
        reason=payload.reason,
        idempotency_key=payload.idempotency_key,
        tenant_id=effective_tenant,
        target_type=payload.target_type,
        target_id=payload.target_id,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="override_create",
        target_type=payload.target_type,
        target_id=payload.target_id or payload.repo,
        metadata={"repo": payload.repo, "pr_number": payload.pr_number, "decision_id": payload.decision_id},
    )
    return override


@app.post("/policy/publish")
def publish_policy_bundle(
    payload: PublishPolicyRequest,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.audit.policy_bundles import get_policy_bundle, store_policy_bundle

    effective_tenant = _effective_tenant(auth, tenant_id)
    snapshot = payload.policy_snapshot
    if not snapshot:
        existing = get_policy_bundle(tenant_id=effective_tenant, policy_bundle_hash=payload.policy_bundle_hash)
        if not existing:
            raise HTTPException(status_code=404, detail="Policy bundle not found and no policy_snapshot provided")
        snapshot = existing.get("policy_snapshot", [])

    if payload.activate:
        get_storage_backend().execute(
            "UPDATE policy_bundles SET is_active = 0 WHERE tenant_id = ?",
            (effective_tenant,),
        )
    store_policy_bundle(
        tenant_id=effective_tenant,
        policy_bundle_hash=payload.policy_bundle_hash,
        policy_snapshot=snapshot,
        is_active=payload.activate,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_publish",
        target_type="policy_bundle",
        target_id=payload.policy_bundle_hash,
        metadata={"activate": payload.activate, "policy_count": len(snapshot), "note": payload.note},
    )
    return {
        "status": "published",
        "tenant_id": effective_tenant,
        "policy_bundle_hash": payload.policy_bundle_hash,
        "active": payload.activate,
        "policy_count": len(snapshot),
    }


@app.post("/auth/api-keys")
def create_scoped_api_key(
    payload: CreateApiKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    created = create_api_key(
        tenant_id=effective_tenant,
        name=payload.name,
        roles=payload.roles or ["operator"],
        scopes=payload.scopes or ["enforcement:write"],
        created_by=auth.principal_id,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="api_key_create",
        target_type="api_key",
        target_id=created["key_id"],
        metadata={"name": payload.name, "roles": created["roles"], "scopes": created["scopes"]},
    )
    return created


@app.get("/auth/api-keys")
def list_scoped_api_keys(
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "keys": list_api_keys(tenant_id=effective_tenant),
    }


@app.delete("/auth/api-keys/{key_id}")
def revoke_scoped_api_key(
    key_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    revoked = revoke_api_key(tenant_id=effective_tenant, key_id=key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="api_key_revoke",
        target_type="api_key",
        target_id=key_id,
    )
    return {"status": "revoked", "tenant_id": effective_tenant, "key_id": key_id}


@app.post("/auth/api-keys/{key_id}/rotate")
def rotate_scoped_api_key(
    key_id: str,
    payload: RotateApiKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    rotated = rotate_api_key(
        tenant_id=effective_tenant,
        key_id=key_id,
        rotated_by=auth.principal_id,
    )
    if not rotated:
        raise HTTPException(status_code=404, detail="API key not found")
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="api_key_rotate",
        target_type="api_key",
        target_id=rotated["key_id"],
        metadata={"rotated_from_key_id": key_id},
    )
    return rotated


@app.post("/auth/webhook-signing-keys")
def create_scoped_webhook_signing_key(
    payload: CreateWebhookSigningKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    created = create_webhook_key(
        tenant_id=effective_tenant,
        integration_id=payload.integration_id,
        created_by=auth.principal_id,
        raw_secret=payload.secret,
        deactivate_existing=payload.rotate_existing,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="webhook_key_create",
        target_type="webhook_signing_key",
        target_id=created["key_id"],
        metadata={"integration_id": payload.integration_id, "rotate_existing": payload.rotate_existing},
    )
    return created


@app.get("/auth/webhook-signing-keys")
def list_scoped_webhook_signing_keys(
    integration_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "keys": list_webhook_keys(tenant_id=effective_tenant, integration_id=integration_id),
    }


@app.post("/auth/checkpoint-signing-keys/rotate")
def rotate_checkpoint_key(
    payload: RotateCheckpointSigningKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    rotated = rotate_checkpoint_signing_key(
        tenant_id=effective_tenant,
        raw_key=payload.key,
        created_by=auth.principal_id,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="checkpoint_key_rotate",
        target_type="checkpoint_signing_key",
        target_id=rotated["key_id"],
    )
    return rotated


@app.get("/auth/checkpoint-signing-keys")
def list_checkpoint_keys(
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "keys": list_checkpoint_signing_keys(tenant_id=effective_tenant),
    }


@app.post("/decisions/{decision_id}/replay")
def replay_stored_decision(
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    """
    Deterministically replay a stored decision using saved input snapshot + policy bindings.
    """
    from releasegate.audit.reader import AuditReader
    from releasegate.decision.types import Decision
    from releasegate.replay.decision_replay import replay_decision

    row = AuditReader.get_decision(decision_id, tenant_id=_effective_tenant(auth, tenant_id))
    if not row:
        raise HTTPException(status_code=404, detail="Decision not found")

    raw = row.get("full_decision_json")
    if not raw:
        raise HTTPException(status_code=422, detail="Decision payload missing full_decision_json")

    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        decision = Decision.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Stored decision payload is invalid: {exc}") from exc

    try:
        report = replay_decision(decision)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    report["created_at"] = row.get("created_at")
    report["repo"] = row.get("repo")
    report["pr_number"] = row.get("pr_number")
    log_security_event(
        tenant_id=decision.tenant_id,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="decision_replay",
        target_type="decision",
        target_id=decision_id,
        metadata={"repo": report.get("repo"), "pr_number": report.get("pr_number")},
    )
    return report
