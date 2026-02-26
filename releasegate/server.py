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
from fastapi.responses import JSONResponse, PlainTextResponse, Response
import csv
import io
import zipfile
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from releasegate.security.auth import require_access, tenant_from_request
from releasegate.security.audit import log_security_event
from releasegate.security.api_keys import create_api_key, list_api_keys, revoke_api_key, rotate_api_key
from releasegate.security.checkpoint_keys import list_checkpoint_signing_keys, rotate_checkpoint_signing_key
from releasegate.security.webhook_keys import create_webhook_key, list_webhook_keys
from releasegate.integrations.jira.routes import router as jira_router
from releasegate.security.types import AuthContext
from releasegate.audit.idempotency import (
    claim_idempotency,
    complete_idempotency,
    derive_system_idempotency_key,
    wait_for_idempotency_response,
)
from releasegate.decision.hashing import (
    compute_decision_hash,
    compute_input_hash,
    compute_policy_hash_from_bindings,
    compute_replay_hash,
)
from releasegate.attestation.engine import AttestationEngine
from releasegate.attestation.key_manager import AttestationKeyManager
from releasegate.utils.canonical import canonical_json, sha256_json
from releasegate.storage import get_storage_backend
from releasegate.observability.internal_metrics import snapshot as metrics_snapshot
from releasegate.storage.migrations import MIGRATIONS
from releasegate.storage.schema import SCHEMA_VERSION

# Load env vars
load_dotenv()


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging() -> None:
    log_level = (os.getenv("RELEASEGATE_LOG_LEVEL", "INFO") or "INFO").upper()
    level_value = getattr(logging, log_level, logging.INFO)
    log_format = (os.getenv("RELEASEGATE_LOG_FORMAT", "json") or "json").strip().lower()

    root = logging.getLogger()
    root.setLevel(level_value)
    formatter: logging.Formatter
    if log_format == "json":
        formatter = JsonLogFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root.addHandler(handler)
        return

    for handler in root.handlers:
        handler.setFormatter(formatter)


configure_logging()


# Initialize App
app = FastAPI(
    title="ReleaseGate Webhook Listener",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.include_router(jira_router, prefix="/integrations/jira", tags=["jira"])
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
    reason: str
    ttl_seconds: Optional[int] = None
    target_type: str = "pr"
    target_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    override_requested_by: Optional[str] = None
    override_requested_by_email: Optional[str] = None
    override_requested_by_account_id: Optional[str] = None
    pr_author: Optional[str] = None
    pr_author_email: Optional[str] = None
    pr_author_account_id: Optional[str] = None
    separation_of_duties: Dict[str, Any] = Field(default_factory=dict)


class PublishPolicyRequest(BaseModel):
    policy_bundle_hash: str
    policy_snapshot: list[dict] = Field(default_factory=list)
    activate: bool = True
    note: Optional[str] = None


class PolicyReleaseCreateRequest(BaseModel):
    policy_id: str
    target_env: str
    snapshot_id: Optional[str] = None
    policy_hash: Optional[str] = None
    state: str = "DRAFT"
    effective_at: Optional[str] = None
    created_by: Optional[str] = None
    change_ticket: Optional[str] = None
    tenant_id: Optional[str] = None


class PolicyReleasePromoteRequest(BaseModel):
    policy_id: str
    source_env: str
    target_env: str
    state: str = "DRAFT"
    effective_at: Optional[str] = None
    created_by: Optional[str] = None
    change_ticket: Optional[str] = None
    tenant_id: Optional[str] = None


class PolicyReleaseRollbackRequest(BaseModel):
    policy_id: str
    target_env: str
    to_release_id: str
    actor_id: Optional[str] = None
    change_ticket: Optional[str] = None
    tenant_id: Optional[str] = None


class PolicyRegistryCreateRequest(BaseModel):
    scope_type: str
    scope_id: str
    policy_json: Dict[str, Any]
    status: str = "DRAFT"
    rollout_percentage: int = Field(default=100, ge=0, le=100)
    rollout_scope: Optional[str] = None
    created_by: Optional[str] = None
    tenant_id: Optional[str] = None


class PolicyRegistryActivateRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor_id: Optional[str] = None


class SimulateDecisionRequest(BaseModel):
    actor: Optional[str] = None
    issue_key: Optional[str] = None
    transition_id: str
    project_id: Optional[str] = None
    workflow_id: Optional[str] = None
    environment: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    policy_id: Optional[str] = None
    tenant_id: Optional[str] = None


class DeployGateCheckRequest(BaseModel):
    tenant_id: Optional[str] = None
    decision_id: Optional[str] = None
    issue_key: Optional[str] = None
    correlation_id: Optional[str] = None
    deploy_id: Optional[str] = None
    repo: str
    env: str
    commit_sha: Optional[str] = None
    artifact_digest: Optional[str] = None
    policy_overrides: Dict[str, Any] = Field(default_factory=dict)


class IncidentCloseCheckRequest(BaseModel):
    tenant_id: Optional[str] = None
    incident_id: str
    decision_id: Optional[str] = None
    issue_key: Optional[str] = None
    correlation_id: Optional[str] = None
    deploy_id: Optional[str] = None
    repo: Optional[str] = None
    env: Optional[str] = None
    policy_overrides: Dict[str, Any] = Field(default_factory=dict)


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


class VerifyAttestationRequest(BaseModel):
    attestation: Dict[str, Any]


# --- Config ---
# Use user's preferred default
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # For API calls
LEDGER_VERIFY_ON_STARTUP = os.getenv("RELEASEGATE_LEDGER_VERIFY_ON_STARTUP", "false").strip().lower() in {"1", "true", "yes", "on"}
LEDGER_FAIL_ON_CORRUPTION = os.getenv("RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION", "true").strip().lower() in {"1", "true", "yes", "on"}
CANONICALIZATION_VERSION = "releasegate-canonical-json-v1"
HASH_ALGORITHM = "sha256"
GITHUB_API_TIMEOUT_SECONDS = float(os.getenv("RELEASEGATE_GITHUB_API_TIMEOUT_SECONDS", "10"))


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
        resp = requests.get(url, headers=headers, timeout=max(GITHUB_API_TIMEOUT_SECONDS, 0.1))
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Failed to fetch PR details: status_code=%s", resp.status_code)
    except Exception:
        logger.exception("Error fetching PR details")

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
        requests.post(
            url,
            json={"body": body},
            headers=headers,
            timeout=max(GITHUB_API_TIMEOUT_SECONDS, 0.1),
        )
        logger.info("Posted comment to PR #%s", pr_number)
    except Exception:
        logger.exception("Failed to post comment")


def create_check_run(repo_full_name: str, head_sha: str, score: int, risk_level: str, reasons: list, evidence: list = None):
    """Create a GitHub Check Run."""
    if not GITHUB_TOKEN:
        logger.warning("No GITHUB_TOKEN, skipping check run creation")
        return

    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    conclusion = "failure" if risk_level == "HIGH" else "success"
    title = f"ReleaseGate CI: {risk_level} severity (Score: {score})"

    summary = "Risk analysis completed.\n\n### Reasons\n" + \
        "\n".join(f"- {r}" for r in reasons)

    if evidence:
        summary += "\n\n### Evidence\n" + "\n".join(f"- {e}" for e in evidence)

    payload = {
        "name": "ReleaseGate CI",
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
        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=max(GITHUB_API_TIMEOUT_SECONDS, 0.1),
        )
        if resp.status_code not in [200, 201]:
            logger.warning(
                "Failed to create check run: status_code=%s response=%s",
                resp.status_code,
                resp.text,
            )
        else:
            logger.info("Created check run: %s", title)
    except Exception:
        logger.exception("Error creating check run")


@app.post("/ci/score")
def ci_score(
    payload: CIScoreRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    """
    CI Endpoint: Returns metadata-only risk classification for a PR.
    """
    repo_full_name = payload.repo
    pr_number = payload.pr
    logger.info("CI analysis request: repo=%s pr=%s", repo_full_name, pr_number)

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

    logger.info("Processing PR event: repo=%s pr=%s action=%s", repo_full_name, pr_number, action)

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
            logger.warning("Jira risk attach failed: %s", e)

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


@app.get("/keys")
def get_public_keys():
    """
    Returns active public attestation keys.
    Includes both modern and legacy field aliases for compatibility.
    """
    from releasegate.attestation.crypto import load_public_keys_map

    key_map = load_public_keys_map()
    keys = []
    public_keys_by_key_id: Dict[str, str] = {}
    for key_id, public_key in sorted(key_map.items()):
        public_keys_by_key_id[key_id] = public_key
        keys.append(
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key": public_key,
                # legacy aliases
                "kid": key_id,
                "alg": "Ed25519",
                "kty": "OKP",
                "use": "sig",
                "pem": public_key,
            }
        )
    return {
        "issuer": "releasegate",
        "keys": keys,
        "public_keys_by_key_id": public_keys_by_key_id,
    }


@app.get("/.well-known/releasegate-keys.json")
def get_signed_key_manifest():
    from releasegate.attestation.crypto import MissingSigningKeyError
    from releasegate.attestation.key_manifest import get_signed_key_manifest_cached

    try:
        manifest, _ = get_signed_key_manifest_cached()
    except MissingSigningKeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return manifest


@app.get("/.well-known/releasegate-keys.sig")
def get_signed_key_manifest_signature():
    from releasegate.attestation.crypto import MissingSigningKeyError
    from releasegate.attestation.key_manifest import get_signed_key_manifest_cached

    try:
        _, signature = get_signed_key_manifest_cached()
    except MissingSigningKeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return signature


# Alias endpoints for well-known key discovery.
@app.get("/.well-known/releasegate/keys.json")
def get_signed_key_manifest_alias():
    return get_signed_key_manifest()


@app.get("/.well-known/releasegate/keys.sig")
def get_signed_key_manifest_signature_alias():
    return get_signed_key_manifest_signature()


@app.post("/attestations/verify")
def verify_attestation_endpoint(payload: VerifyAttestationRequest):
    """
    Verifies a signed release attestation.
    """
    attestation = payload.attestation
    
    # In a real system, we'd lookup the key by kid.
    # Here we assume we are the issuer and verify with our active key.
    # Or strict verification against a known set.
    private_key, key_id = AttestationKeyManager.load_signing_key()
    public_pem = AttestationKeyManager.get_public_key_pem(private_key)
    
    is_valid = AttestationEngine.verify_attestation(attestation, public_pem)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid signature")

    return {
        "valid": True,
        "attestation_id": attestation.get("attestation_id"),
        "issuer": attestation.get("issuer"),
        "subject": attestation.get("subject"),
         "assertion": attestation.get("assertion")
    }


@app.get("/attestations")
def list_attestations(
    limit: int = 50,
    tenant_id: Optional[str] = None,
    repo: Optional[str] = None,
    since: Optional[str] = None,
):
    from releasegate.audit.attestations import list_release_attestations

    try:
        return list_release_attestations(
            tenant_id=tenant_id,
            repo=repo,
            since=since,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/attestations/{attestation_id}.dsse")
def export_attestation_dsse(attestation_id: str, tenant_id: Optional[str] = None):
    from releasegate.attestation import build_intoto_statement, wrap_dsse
    from releasegate.attestation.crypto import MissingSigningKeyError, current_key_id, load_private_key_from_env
    from releasegate.audit.attestations import get_release_attestation_by_id

    try:
        row = get_release_attestation_by_id(attestation_id=attestation_id, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="attestation not found")

    attestation = row.get("attestation")
    if not isinstance(attestation, dict):
        raise HTTPException(status_code=500, detail="stored attestation payload is invalid")

    try:
        statement = build_intoto_statement(attestation)
        envelope = wrap_dsse(
            statement,
            signing_key=load_private_key_from_env(),
            key_id=current_key_id(),
        )
    except MissingSigningKeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return envelope


@app.get("/attestations/{attestation_id}")
def get_attestation_by_id(attestation_id: str, tenant_id: Optional[str] = None):
    from releasegate.audit.attestations import get_release_attestation_by_id

    try:
        item = get_release_attestation_by_id(
            attestation_id=attestation_id,
            tenant_id=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not item:
        raise HTTPException(status_code=404, detail="attestation not found")
    return {
        "ok": True,
        "item": item,
    }


@app.get("/transparency/latest")
def transparency_latest(limit: int = 50, tenant_id: Optional[str] = None):
    from releasegate.audit.transparency import list_transparency_latest

    try:
        return list_transparency_latest(limit=limit, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/transparency/{attestation_id}")
def transparency_by_attestation_id(attestation_id: str, tenant_id: Optional[str] = None):
    from releasegate.audit.transparency import get_transparency_entry

    try:
        item = get_transparency_entry(attestation_id=attestation_id, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not item:
        raise HTTPException(status_code=404, detail="transparency record not found")
    return {"ok": True, "item": item}


@app.get("/transparency/root/{date_utc}")
def transparency_root_by_date(date_utc: str, tenant_id: Optional[str] = None):
    from releasegate.audit.transparency import get_or_compute_transparency_root

    try:
        root = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not root:
        raise HTTPException(status_code=404, detail="transparency root not found for date")
    etag = sha256_json(root)
    return JSONResponse(
        content=root,
        headers={
            "Cache-Control": "public, max-age=3600",
            "ETag": f"\"{etag}\"",
        },
    )


@app.get("/transparency/proof/{attestation_id}")
def transparency_inclusion_proof(attestation_id: str, tenant_id: Optional[str] = None):
    from releasegate.audit.transparency import get_transparency_inclusion_proof

    try:
        proof = get_transparency_inclusion_proof(attestation_id=attestation_id, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not proof:
        raise HTTPException(status_code=404, detail="transparency inclusion proof not found")
    etag = sha256_json(proof)
    return JSONResponse(
        content=proof,
        headers={
            "Cache-Control": "public, max-age=3600",
            "ETag": f"\"{etag}\"",
        },
    )


@app.get("/")
def health_check():
    return {"status": "ok", "service": "ReleaseGate API"}


def _expected_schema_version() -> str:
    return MIGRATIONS[-1].migration_id if MIGRATIONS else SCHEMA_VERSION


def _readiness_payload() -> tuple[dict, int]:
    payload = {
        "status": "ok",
        "service": "ReleaseGate API",
        "storage": "ok",
        "migrations": {
            "status": "ok",
            "expected": _expected_schema_version(),
            "current": None,
            "updated_at": None,
        },
    }

    try:
        from releasegate.storage.schema import init_db

        current_version = init_db()
        expected_version = payload["migrations"]["expected"]
        get_storage_backend().fetchone("SELECT 1 AS ok")
        state = get_storage_backend().fetchone(
            "SELECT current_version, migration_id, updated_at FROM schema_state WHERE id = 1"
        )
        current_schema = None
        if state:
            current_schema = state.get("migration_id") or state.get("current_version")
            payload["migrations"]["updated_at"] = state.get("updated_at")
        if not current_schema:
            current_schema = current_version
        payload["migrations"]["current"] = current_schema
        if str(current_schema) != str(expected_version):
            payload["status"] = "error"
            payload["migrations"]["status"] = "outdated"
            return payload, 503
    except Exception:
        payload["status"] = "error"
        payload["storage"] = "error"
        payload["migrations"]["status"] = "error"
        return payload, 503
    return payload, 200


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "ReleaseGate API"}


@app.get("/readyz")
def readyz():
    payload, status_code = _readiness_payload()
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=payload)
    return payload


@app.get("/health")
def health():
    payload, status_code = _readiness_payload()
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=payload)
    return payload


def _prometheus_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    snap = metrics_snapshot(include_tenants=True)
    by_tenant = snap.pop("_by_tenant", {}) if isinstance(snap, dict) else {}
    lines = [
        "# HELP releasegate_metric_total ReleaseGate internal counters",
        "# TYPE releasegate_metric_total counter",
        "# HELP releasegate_metric_tenant_total ReleaseGate internal counters by tenant",
        "# TYPE releasegate_metric_tenant_total counter",
    ]
    for metric_name in sorted(snap.keys()):
        lines.append(
            f'releasegate_metric_total{{metric="{_prometheus_label(metric_name)}"}} {int(snap[metric_name])}'
        )
    for tenant in sorted(by_tenant.keys()):
        tenant_metrics = by_tenant.get(tenant) or {}
        for metric_name in sorted(tenant_metrics.keys()):
            lines.append(
                "releasegate_metric_tenant_total"
                + f'{{tenant_id="{_prometheus_label(tenant)}",metric="{_prometheus_label(metric_name)}"}} '
                + f"{int(tenant_metrics[metric_name])}"
            )
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/metrics/tenant/{tenant_id}")
def metrics_for_tenant(
    tenant_id: str,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics_snapshot(tenant_id=effective_tenant),
    }


@app.on_event("startup")
def verify_ledger_on_startup():
    from releasegate.storage.schema import init_db

    init_db()
    if not LEDGER_VERIFY_ON_STARTUP:
        return
    from releasegate.audit.overrides import verify_all_override_chains
    from releasegate.integrations.jira.lock_store import verify_all_lock_chains

    result = verify_all_override_chains()
    app.state.override_chain_last_verification = result
    lock_result = verify_all_lock_chains()
    app.state.jira_lock_chain_last_verification = lock_result
    if not result.get("valid", True):
        logger.error("Override ledger corruption detected at startup: %s", result)
        if LEDGER_FAIL_ON_CORRUPTION:
            raise RuntimeError("Override ledger corruption detected")
    if not lock_result.get("valid", True):
        logger.error("Jira lock ledger corruption detected at startup: %s", lock_result)
        if LEDGER_FAIL_ON_CORRUPTION:
            raise RuntimeError("Jira lock ledger corruption detected")
    else:
        logger.info(
            "Override ledger verified at startup: checked_chains=%s",
            result.get("checked_chains", result.get("checked_repos", 0)),
        )


@app.get("/audit/ledger/verify")
def verify_ledger(
    repo: Optional[str] = None,
    pr: Optional[int] = None,
    chain_id: Optional[str] = None,
    ledger: str = "override",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.overrides import verify_all_override_chains, verify_override_chain
    from releasegate.integrations.jira.lock_store import verify_all_lock_chains, verify_lock_chain

    effective_tenant = _effective_tenant(auth, tenant_id)
    normalized = str(ledger or "override").strip().lower()
    if normalized in {"jira", "jira_lock", "lock"}:
        if chain_id:
            result = verify_lock_chain(tenant_id=effective_tenant, chain_id=chain_id)
            return {"tenant_id": effective_tenant, "chain_id": chain_id, **result}
        return verify_all_lock_chains(tenant_id=effective_tenant)

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


def _decision_hashes_from_snapshot(snapshot: Dict[str, Any]) -> Dict[str, str]:
    input_snapshot = snapshot.get("input_snapshot") or {}
    policy_snapshot = snapshot.get("policy_bindings") or snapshot.get("policy_snapshot") or []
    inputs_present = snapshot.get("inputs_present") or {}
    release_status = str(snapshot.get("release_status") or "UNKNOWN")
    reason_code = snapshot.get("reason_code")
    policy_bundle_hash = str(snapshot.get("policy_bundle_hash") or "")

    input_hash = str(snapshot.get("input_hash") or compute_input_hash(input_snapshot))
    policy_hash = str(snapshot.get("policy_hash") or compute_policy_hash_from_bindings(policy_snapshot))
    decision_hash = str(
        snapshot.get("decision_hash")
        or compute_decision_hash(
            release_status=release_status,
            reason_code=reason_code,
            policy_bundle_hash=policy_bundle_hash,
            inputs_present=inputs_present,
        )
    )
    replay_hash = str(
        snapshot.get("replay_hash")
        or compute_replay_hash(
            input_hash=input_hash,
            policy_hash=policy_hash,
            decision_hash=decision_hash,
        )
    )
    return {
        "input_hash": input_hash,
        "policy_hash": policy_hash,
        "decision_hash": decision_hash,
        "replay_hash": replay_hash,
    }


def _integrity_section(
    *,
    hashes: Dict[str, str],
    ledger_tip_hash: Optional[str] = None,
    ledger_record_id: Optional[str] = None,
    checkpoint_signature: Optional[str] = None,
    signing_key_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "canonicalization": CANONICALIZATION_VERSION,
        "hash_alg": HASH_ALGORITHM,
        "input_hash": hashes.get("input_hash") or "",
        "policy_hash": hashes.get("policy_hash") or "",
        "decision_hash": hashes.get("decision_hash") or "",
        "replay_hash": hashes.get("replay_hash") or "",
        "ledger": {
            "ledger_tip_hash": ledger_tip_hash or "",
            "ledger_record_id": ledger_record_id or "",
        },
        "signatures": {
            "checkpoint_signature": checkpoint_signature or "",
            "signing_key_id": signing_key_id or "",
        },
    }


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
        hashes = _decision_hashes_from_snapshot(full) if full else {
            "input_hash": "",
            "policy_hash": "",
            "decision_hash": "",
            "replay_hash": "",
        }
        checkpoint_signature = ""
        signing_key_id = ""
        if ov:
            checkpoint_signature = ""
            signing_key_id = ""

        records.append({
            "schema_name": "soc2_record",
            "schema_version": "soc2_v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": r.get("tenant_id") or full.get("tenant_id"),
            "ids": {
                "decision_id": r.get("decision_id"),
                "checkpoint_id": "",
                "proof_pack_id": "",
                "policy_bundle_hash": full.get("policy_bundle_hash") or r.get("policy_bundle_hash"),
            },
            "decision_id": r.get("decision_id"),
            "attestation_id": full.get("attestation_id"),
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
            "integrity": _integrity_section(
                hashes=hashes,
                ledger_tip_hash=ov.get("event_hash") if ov else "",
                ledger_record_id=ov.get("override_id") if ov else "",
                checkpoint_signature=checkpoint_signature,
                signing_key_id=signing_key_id,
            ),
        })
    return records


def _attach_attestation_to_rows(rows: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for row in rows:
        copy_row = dict(row)
        attestation_id = None
        raw_full = row.get("full_decision_json")
        if raw_full:
            try:
                full = json.loads(raw_full) if isinstance(raw_full, str) else (raw_full or {})
                attestation_id = full.get("attestation_id")
            except Exception:
                attestation_id = None
        copy_row["attestation_id"] = attestation_id
        enriched.append(copy_row)
    return enriched


def _proof_pack_export_key(
    *,
    tenant_id: str,
    decision_id: str,
    output_format: str,
    checkpoint_cadence: str,
) -> str:
    return derive_system_idempotency_key(
        tenant_id=tenant_id,
        operation="proof_pack_export",
        identity={
            "decision_id": decision_id,
            "format": output_format.lower(),
            "checkpoint_cadence": checkpoint_cadence.lower(),
            "bundle_version": "audit_proof_v1",
        },
    )


def _deterministic_zip_payload(entries: Dict[str, Any]) -> bytes:
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for filename in sorted(entries.keys()):
            payload = entries[filename]
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            info = zipfile.ZipInfo(filename=filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            zf.writestr(info, serialized.encode("utf-8"))
    memory.seek(0)
    return memory.getvalue()


def _deterministic_json_bytes(payload: Any) -> bytes:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return serialized.encode("utf-8")


def _proof_bundle_manifest(
    *,
    decision_id: str,
    proof_pack_id: str,
    export_checksum: str,
    entries: Dict[str, Any],
) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    for filename in sorted(entries.keys()):
        content = _deterministic_json_bytes(entries[filename])
        files.append(
            {
                "filename": filename,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return {
        "schema_name": "proof_bundle_manifest",
        "schema_version": "v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "decision_id": decision_id,
        "proof_pack_id": proof_pack_id,
        "export_checksum": export_checksum,
        "files": files,
    }


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
    rows = _attach_attestation_to_rows(rows)
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
        record_hash_map = {str(r.get("decision_id") or ""): (r.get("integrity") or {}) for r in export_rows}
        aggregated_hashes = {
            "input_hash": sha256_json({k: v.get("input_hash", "") for k, v in record_hash_map.items()}),
            "policy_hash": sha256_json({k: v.get("policy_hash", "") for k, v in record_hash_map.items()}),
            "decision_hash": sha256_json({k: v.get("decision_hash", "") for k, v in record_hash_map.items()}),
            "replay_hash": sha256_json({k: v.get("replay_hash", "") for k, v in record_hash_map.items()}),
        }
        tip_override = overrides[0] if overrides else {}
        payload = {
            "contract": "soc2_v1",
            "schema_name": "soc2_export",
            "schema_version": "soc2_v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": effective_tenant,
            "ids": {
                "decision_id": "",
                "checkpoint_id": "",
                "proof_pack_id": "",
                "policy_bundle_hash": "",
                "repo": repo,
            },
            "integrity": _integrity_section(
                hashes=aggregated_hashes,
                ledger_tip_hash=tip_override.get("event_hash") or "",
                ledger_record_id=tip_override.get("override_id") or "",
            ),
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


@app.get("/audit/search")
def audit_search(
    limit: int = 200,
    repo: Optional[str] = None,
    status: Optional[str] = None,
    pr: Optional[int] = None,
    jira: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    """
    Search audit decisions across repos and/or by external references (e.g. Jira issue key).
    """
    from releasegate.audit.reader import AuditReader

    effective_tenant = _effective_tenant(auth, tenant_id)
    limit = _bounded_limit(limit, max_allowed=500, field="limit")
    rows = AuditReader.search_decisions(
        limit=limit,
        repo=repo,
        status=status,
        pr=pr,
        jira_issue_key=jira,
        tenant_id=effective_tenant,
    )
    rows = _attach_attestation_to_rows(rows)
    return {
        "ok": True,
        "limit": limit,
        "items": rows,
    }


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


@app.get("/audit/checkpoints/override/latest")
def get_latest_override_checkpoint(
    repo: str,
    cadence: str = "daily",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import latest_override_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = latest_override_checkpoint(
            repo=repo,
            cadence=cadence,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return result


@app.post("/audit/checkpoints/jira-lock")
def create_jira_lock_checkpoint(
    chain_id: str,
    cadence: str = "daily",
    at: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import create_jira_lock_checkpoint as create_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = create_checkpoint(
            chain_id=chain_id,
            cadence=cadence,
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
        target_type="jira_lock_chain",
        target_id=chain_id,
        metadata={"cadence": cadence},
    )
    return result


@app.get("/audit/checkpoints/jira-lock/verify")
def verify_jira_lock_checkpoint(
    chain_id: str,
    period_id: str,
    cadence: str = "daily",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import verify_jira_lock_checkpoint as verify_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = verify_checkpoint(
            chain_id=chain_id,
            cadence=cadence,
            period_id=period_id,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result.get("exists", False):
        raise HTTPException(status_code=404, detail=result.get("reason", "Checkpoint not found"))
    return result


@app.get("/audit/checkpoints/jira-lock/latest")
def get_latest_jira_lock_checkpoint(
    chain_id: str,
    cadence: str = "daily",
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.checkpoints import latest_jira_lock_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = latest_jira_lock_checkpoint(
            chain_id=chain_id,
            cadence=cadence,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return result


@app.get("/governance/override-metrics")
def governance_override_metrics(
    tenant_id: Optional[str] = None,
    days: int = 30,
    top_n: int = 10,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.integrations.jira.override_metrics import get_override_metrics_summary

    effective_tenant = _effective_tenant(auth, tenant_id)
    return get_override_metrics_summary(
        tenant_id=effective_tenant,
        days=days,
        top_n=top_n,
    )


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


@app.post("/simulate-decision")
def simulate_decision_endpoint(
    payload: SimulateDecisionRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.policy.registry import simulate_registry_decision

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = simulate_registry_decision(
            tenant_id=effective_tenant,
            actor=payload.actor or auth.principal_id,
            issue_key=payload.issue_key,
            transition_id=payload.transition_id,
            project_id=payload.project_id,
            workflow_id=payload.workflow_id,
            environment=payload.environment,
            context=payload.context,
            policy_id=payload.policy_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


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
    from releasegate.audit.overrides import list_override_chain_segment, list_overrides, verify_override_chain
    from releasegate.audit.checkpoints import (
        load_override_checkpoint,
        period_id_for_timestamp,
        verify_override_checkpoint,
    )
    from releasegate.audit.proof_packs import record_proof_pack_generation

    effective_tenant = _effective_tenant(auth, tenant_id)
    export_key = _proof_pack_export_key(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        output_format=format,
        checkpoint_cadence=checkpoint_cadence,
    )
    claim = claim_idempotency(
        tenant_id=effective_tenant,
        operation="proof_pack_export",
        idem_key=export_key,
        request_payload={
            "decision_id": decision_id,
            "format": format.lower(),
            "checkpoint_cadence": checkpoint_cadence,
        },
    )
    if format.lower() == "json" and claim.state == "replay" and claim.response is not None:
        return claim.response
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=effective_tenant,
            operation="proof_pack_export",
            idem_key=export_key,
        )
        if replayed is not None and format.lower() == "json":
            return replayed
        if replayed is not None and format.lower() == "zip":
            # Keep zip deterministic; we can regenerate bytes for the same export key.
            pass
        else:
            raise HTTPException(status_code=409, detail="Proof pack export is already in progress")

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
    checkpoint_snapshot = None
    ledger_segment = []
    period_id = None

    if repo:
        overrides = list_overrides(repo=repo, limit=500, pr=pr_number, tenant_id=effective_tenant)
        override_snapshot = next((o for o in overrides if o.get("decision_id") == decision_id), None)
        ledger_segment = list_override_chain_segment(
            repo=repo,
            pr=pr_number,
            tenant_id=effective_tenant,
            limit=2000,
        )
        chain_proof = verify_override_chain(repo=repo, pr=pr_number, tenant_id=effective_tenant)
        try:
            period_id = period_id_for_timestamp(created_at, cadence=checkpoint_cadence)
            checkpoint_snapshot = load_override_checkpoint(
                repo=repo,
                cadence=checkpoint_cadence,
                period_id=period_id,
                tenant_id=effective_tenant,
            )
            checkpoint_proof = verify_override_checkpoint(
                repo=repo,
                cadence=checkpoint_cadence,
                period_id=period_id,
                pr=pr_number,
                tenant_id=effective_tenant,
            )
        except Exception as exc:
            checkpoint_proof = {"exists": False, "valid": False, "reason": str(exc)}

    proof_pack_id = record_proof_pack_generation(
        decision_id=decision_id,
        output_format="json" if format.lower() == "json" else "zip",
        bundle_version="audit_proof_v1",
        repo=repo,
        pr_number=pr_number,
        tenant_id=effective_tenant,
        export_key=export_key,
    )
    decision_hashes = _decision_hashes_from_snapshot(decision_snapshot)
    checkpoint_signature = ""
    signing_key_id = ""
    checkpoint_id = ""
    if checkpoint_snapshot:
        checkpoint_signature = (
            (checkpoint_snapshot.get("signature") or {}).get("value")
            or ""
        )
        signing_key_id = (
            (checkpoint_snapshot.get("signature") or {}).get("key_id")
            or ((checkpoint_snapshot.get("integrity") or {}).get("signatures") or {}).get("signing_key_id")
            or ""
        )
        checkpoint_id = (checkpoint_snapshot.get("ids") or {}).get("checkpoint_id") or ""

    ledger_tip_hash = ledger_segment[-1].get("event_hash") if ledger_segment else ""
    ledger_record_id = ledger_segment[-1].get("override_id") if ledger_segment else ""

    from releasegate.evidence.graph import get_decision_evidence_graph, record_proof_pack_evidence

    evidence_graph = get_decision_evidence_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        max_depth=3,
    ) or {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "nodes": [],
        "edges": [],
    }
    replay_request = {
        "method": "POST",
        "endpoint": f"/decisions/{decision_id}/replay",
        "query": {"tenant_id": effective_tenant},
        "body": None,
    }

    bundle = {
        "schema_name": "proof_pack",
        "schema_version": "proof_pack_v1",
        "bundle_version": "audit_proof_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": effective_tenant,
        "ids": {
            "decision_id": decision_id,
            "checkpoint_id": checkpoint_id,
            "proof_pack_id": proof_pack_id,
            "policy_bundle_hash": decision_snapshot.get("policy_bundle_hash") or "",
            "repo": repo or "",
            "pr_number": pr_number if pr_number is not None else "",
            "period_id": period_id or "",
            "checkpoint_cadence": checkpoint_cadence,
        },
        "integrity": _integrity_section(
            hashes=decision_hashes,
            ledger_tip_hash=ledger_tip_hash,
            ledger_record_id=ledger_record_id,
            checkpoint_signature=checkpoint_signature,
            signing_key_id=signing_key_id,
        ),
        "decision_id": decision_id,
        "attestation_id": decision_snapshot.get("attestation_id"),
        "repo": repo,
        "pr_number": pr_number,
        "decision_snapshot": decision_snapshot,
        "policy_snapshot": decision_snapshot.get("policy_bindings", []),
        "input_snapshot": decision_snapshot.get("input_snapshot", {}),
        "override_snapshot": override_snapshot,
        "ledger_segment": ledger_segment,
        "checkpoint_snapshot": checkpoint_snapshot,
        "chain_proof": chain_proof,
        "checkpoint_proof": checkpoint_proof,
        "evidence_graph": evidence_graph,
        "replay_request": replay_request,
    }
    export_checksum = sha256_json(bundle)

    record_proof_pack_evidence(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        proof_pack_id=proof_pack_id,
        output_format="json" if format.lower() == "json" else "zip",
        export_checksum=export_checksum,
        bundle_version="audit_proof_v1",
    )

    if format.lower() == "json":
        log_security_event(
            tenant_id=effective_tenant,
            principal_id=auth.principal_id,
            auth_method=auth.auth_method,
            action="proof_pack_export",
            target_type="decision",
            target_id=decision_id,
            metadata={"format": "json"},
        )
        payload = {
            **bundle,
            "export_checksum": export_checksum,
            "proof_pack_id": proof_pack_id,
        }
        complete_idempotency(
            tenant_id=effective_tenant,
            operation="proof_pack_export",
            idem_key=export_key,
            response_payload=payload,
            resource_type="proof_pack",
            resource_id=proof_pack_id,
        )
        return payload
    if format.lower() != "zip":
        raise HTTPException(status_code=400, detail="Unsupported format (expected json or zip)")

    zip_entries = {
        "bundle.json": bundle,
        "integrity.json": bundle["integrity"],
        "chain_proof.json": bundle["chain_proof"],
        "checkpoint_proof.json": bundle["checkpoint_proof"],
        "checkpoint_snapshot.json": bundle["checkpoint_snapshot"],
        "decision_snapshot.json": bundle["decision_snapshot"],
        "input_snapshot.json": bundle["input_snapshot"],
        "ledger_segment.json": bundle["ledger_segment"],
        "override_snapshot.json": bundle["override_snapshot"],
        "policy_snapshot.json": bundle["policy_snapshot"],
        "evidence_graph.json": bundle["evidence_graph"],
        "replay_request.json": bundle["replay_request"],
    }
    zip_entries["manifest.json"] = _proof_bundle_manifest(
        decision_id=decision_id,
        proof_pack_id=proof_pack_id,
        export_checksum=export_checksum,
        entries=zip_entries,
    )
    zip_bytes = _deterministic_zip_payload(zip_entries)
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="proof_pack_export",
        target_type="decision",
        target_id=decision_id,
        metadata={"format": "zip"},
    )
    complete_idempotency(
        tenant_id=effective_tenant,
        operation="proof_pack_export",
        idem_key=export_key,
        response_payload={"proof_pack_id": proof_pack_id, "export_checksum": export_checksum, "format": "zip"},
        resource_type="proof_pack",
        resource_id=proof_pack_id,
    )
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="proof-pack-{decision_id}.zip"',
            "X-Export-Checksum": export_checksum,
            "X-Export-Id": proof_pack_id,
        },
    )


@app.get("/decisions/{decision_id}/export-proof")
def export_decision_proof_bundle(
    decision_id: str,
    tenant_id: Optional[str] = None,
    checkpoint_cadence: str = "daily",
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["proofpack:read", "checkpoint:read", "policy:read"],
        rate_profile="heavy",
    ),
):
    # Reuse the hardened proof-pack exporter and return a deterministic zip bundle.
    return audit_proof_pack(
        decision_id=decision_id,
        format="zip",
        checkpoint_cadence=checkpoint_cadence,
        tenant_id=tenant_id,
        auth=auth,
    )


@app.post("/audit/overrides")
def create_manual_override(
    payload: ManualOverrideRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["override:write"],
        rate_profile="default",
    ),
):
    from releasegate.audit.overrides import get_active_override, record_override
    from releasegate.integrations.jira.override_validation import ACTION_OVERRIDE, validate_override_request
    from releasegate.governance.actors import normalize_actor_values
    from releasegate.governance.sod import evaluate_separation_of_duties

    effective_tenant = _effective_tenant(auth, tenant_id)
    validation = validate_override_request(
        action=ACTION_OVERRIDE,
        ttl_seconds=payload.ttl_seconds,
        justification=payload.reason,
        actor_roles=auth.roles,
        idempotency_key=idempotency_key,
    )
    if not validation.allowed:
        status_code = 403 if validation.reason_code == "OVERRIDE_ADMIN_REQUIRED" else 400
        raise HTTPException(
            status_code=status_code,
            detail={
                "error_code": validation.reason_code,
                "message": validation.message,
            },
        )

    approver_principals = normalize_actor_values([auth.principal_id])
    requester_principals = normalize_actor_values(
        [
            payload.override_requested_by,
            payload.override_requested_by_email,
            payload.override_requested_by_account_id,
        ]
    )
    pr_author_principals = normalize_actor_values(
        [
            payload.pr_author,
            payload.pr_author_email,
            payload.pr_author_account_id,
        ]
    )
    sod_violation = evaluate_separation_of_duties(
        actors={
            "actor": approver_principals,
            "pr_author": pr_author_principals,
            "override_requested_by": requester_principals,
            "override_approved_by": approver_principals,
        },
        config=payload.separation_of_duties,
    )
    if sod_violation:
        reason_code = str(sod_violation.get("reason_code") or "SOD_CONFLICT")
        message = str(sod_violation.get("message") or "separation-of-duties violation")
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": reason_code,
                "message": f"Override blocked by separation-of-duties policy: {message}",
                "rule": sod_violation.get("rule"),
                "left": sod_violation.get("left"),
                "right": sod_violation.get("right"),
                "conflicting_principals": list(sod_violation.get("conflicting_principals") or []),
            },
        )

    operation = "manual_override_create"
    claim = claim_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idempotency_key,
        request_payload={
            **payload.model_dump(mode="json"),
            "tenant_id": effective_tenant,
        },
    )
    if claim.state == "replay" and claim.response is not None:
        return claim.response
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idempotency_key,
        )
        if replayed is not None:
            return replayed
        raise HTTPException(status_code=409, detail="Override request is already in progress")

    effective_target_type = payload.target_type or "pr"
    effective_target_id = payload.target_id or (
        f"{payload.repo}#{payload.pr_number}" if payload.pr_number is not None else payload.repo
    )
    existing = get_active_override(
        tenant_id=effective_tenant,
        target_type=effective_target_type,
        target_id=effective_target_id,
    )
    if existing is not None:
        same_payload = (
            str(existing.get("reason") or "") == str(payload.reason or "")
            and str(existing.get("actor") or "") == str(auth.principal_id or "")
            and str(existing.get("decision_id") or "") == str(payload.decision_id or "")
        )
        if not same_payload:
            raise HTTPException(
                status_code=409,
                detail="Active override already exists for this target",
            )
        response_payload = {
            **existing,
            "target_type": existing.get("target_type") or effective_target_type,
            "target_id": existing.get("target_id") or effective_target_id,
        }
        existing_decision_id = str(response_payload.get("decision_id") or "")
        if existing_decision_id:
            from releasegate.audit.reader import AuditReader
            att = AuditReader.get_attestation_by_decision(existing_decision_id, tenant_id=effective_tenant)
            response_payload["attestation_id"] = att.get("attestation_id") if att else None
        complete_idempotency(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idempotency_key,
            response_payload=response_payload,
            resource_type="override",
            resource_id=str(response_payload.get("override_id") or ""),
        )
        return response_payload

    override = record_override(
        repo=payload.repo,
        pr_number=payload.pr_number,
        issue_key=payload.issue_key,
        decision_id=payload.decision_id,
        actor=auth.principal_id,
        reason=validation.justification or payload.reason,
        idempotency_key=idempotency_key,
        tenant_id=effective_tenant,
        target_type=effective_target_type,
        target_id=effective_target_id,
        ttl_seconds=validation.ttl_seconds,
        expires_at=validation.expires_at,
        requested_by=auth.principal_id,
        approved_by=auth.principal_id,
    )
    from releasegate.evidence.graph import record_override_evidence

    record_override_evidence(
        tenant_id=effective_tenant,
        decision_id=payload.decision_id,
        override_id=str(override.get("override_id") or ""),
        override_hash=str(override.get("event_hash") or ""),
        issue_key=payload.issue_key,
        repo=payload.repo,
        pr_number=payload.pr_number,
        reason=validation.justification or payload.reason,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="override_create",
        target_type=payload.target_type,
        target_id=payload.target_id or payload.repo,
        metadata={
            "repo": payload.repo,
            "pr_number": payload.pr_number,
            "decision_id": payload.decision_id,
            "ttl_seconds": validation.ttl_seconds,
            "expires_at": validation.expires_at,
        },
    )
    response_payload = {
        **override,
        "idempotency_key": idempotency_key,
        "ttl_seconds": validation.ttl_seconds,
        "expires_at": validation.expires_at,
        "justification": validation.justification,
    }
    if payload.decision_id:
        from releasegate.audit.reader import AuditReader
        att = AuditReader.get_attestation_by_decision(payload.decision_id, tenant_id=effective_tenant)
        response_payload["attestation_id"] = att.get("attestation_id") if att else None
    complete_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idempotency_key,
        response_payload=response_payload,
        resource_type="override",
        resource_id=str(override.get("override_id") or ""),
    )
    return response_payload


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
            "UPDATE policy_bundles SET is_active = ? WHERE tenant_id = ?",
            (False, effective_tenant),
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


@app.post("/policies")
def create_registry_policy_endpoint(
    payload: PolicyRegistryCreateRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import create_registry_policy

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        created = create_registry_policy(
            tenant_id=effective_tenant,
            scope_type=payload.scope_type,
            scope_id=payload.scope_id,
            policy_json=payload.policy_json,
            status=payload.status,
            rollout_percentage=payload.rollout_percentage,
            rollout_scope=payload.rollout_scope,
            created_by=payload.created_by or auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_registry_create",
        target_type="policy_registry",
        target_id=created.get("policy_id"),
        metadata={
            "scope_type": payload.scope_type,
            "scope_id": payload.scope_id,
            "status": created.get("status"),
        },
    )
    return created


@app.get("/policies")
def list_registry_policies_endpoint(
    tenant_id: Optional[str] = None,
    scope_type: Optional[str] = None,
    scope_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import list_registry_policies

    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "policies": list_registry_policies(
            tenant_id=effective_tenant,
            scope_type=scope_type,
            scope_id=scope_id,
            status=status,
            limit=max(1, min(limit, 500)),
        ),
    }


@app.get("/policies/{policy_id}")
def get_registry_policy_endpoint(
    policy_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import get_registry_policy

    effective_tenant = _effective_tenant(auth, tenant_id)
    policy = get_registry_policy(
        tenant_id=effective_tenant,
        policy_id=policy_id,
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@app.post("/policies/{policy_id}/activate")
def activate_registry_policy_endpoint(
    policy_id: str,
    payload: Optional[PolicyRegistryActivateRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import activate_registry_policy

    activate_payload = payload or PolicyRegistryActivateRequest()
    effective_tenant = _effective_tenant(auth, activate_payload.tenant_id)
    try:
        activated = activate_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=activate_payload.actor_id or auth.principal_id,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_registry_activate",
        target_type="policy_registry",
        target_id=policy_id,
        metadata={"scope_type": activated.get("scope_type"), "scope_id": activated.get("scope_id")},
    )
    return activated


@app.post("/policy/releases")
def create_policy_release_endpoint(
    payload: PolicyReleaseCreateRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import create_policy_release

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        created = create_policy_release(
            tenant_id=effective_tenant,
            policy_id=payload.policy_id,
            target_env=payload.target_env,
            snapshot_id=payload.snapshot_id,
            policy_hash=payload.policy_hash,
            state=payload.state,
            effective_at=payload.effective_at,
            created_by=payload.created_by or auth.principal_id,
            change_ticket=payload.change_ticket,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_release_create",
        target_type="policy_release",
        target_id=created.get("release_id"),
        metadata={
            "policy_id": payload.policy_id,
            "target_env": payload.target_env,
            "state": payload.state,
        },
    )
    return created


@app.post("/policy/releases/promote")
def promote_policy_release_endpoint(
    payload: PolicyReleasePromoteRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import promote_policy_release

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        promoted = promote_policy_release(
            tenant_id=effective_tenant,
            policy_id=payload.policy_id,
            source_env=payload.source_env,
            target_env=payload.target_env,
            state=payload.state,
            effective_at=payload.effective_at,
            created_by=payload.created_by or auth.principal_id,
            change_ticket=payload.change_ticket,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_release_promote",
        target_type="policy_release",
        target_id=promoted.get("release_id"),
        metadata={
            "policy_id": payload.policy_id,
            "source_env": payload.source_env,
            "target_env": payload.target_env,
            "state": payload.state,
        },
    )
    return promoted


@app.post("/policy/releases/{release_id}/activate")
def activate_policy_release_endpoint(
    release_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import activate_policy_release

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        activated = activate_policy_release(
            tenant_id=effective_tenant,
            release_id=release_id,
            actor_id=auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_release_activate",
        target_type="policy_release",
        target_id=release_id,
        metadata={"policy_id": activated.get("policy_id"), "target_env": activated.get("target_env")},
    )
    return activated


@app.post("/policy/releases/rollback")
def rollback_policy_release_endpoint(
    payload: PolicyReleaseRollbackRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import rollback_policy_release

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        rolled_back = rollback_policy_release(
            tenant_id=effective_tenant,
            policy_id=payload.policy_id,
            target_env=payload.target_env,
            to_release_id=payload.to_release_id,
            actor_id=payload.actor_id or auth.principal_id,
            change_ticket=payload.change_ticket,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_release_rollback",
        target_type="policy_release",
        target_id=rolled_back.get("release_id"),
        metadata={
            "policy_id": payload.policy_id,
            "target_env": payload.target_env,
            "rollback_to_release_id": payload.to_release_id,
        },
    )
    return rolled_back


@app.post("/policy/releases/scheduler/run")
def run_policy_release_scheduler_endpoint(
    tenant_id: Optional[str] = None,
    now: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import run_policy_release_scheduler

    effective_tenant = _effective_tenant(auth, tenant_id)
    result = run_policy_release_scheduler(
        tenant_id=effective_tenant,
        actor_id=auth.principal_id,
        now=now,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_release_scheduler_run",
        target_type="policy_release",
        target_id="scheduler",
        metadata={"activated_count": result.get("activated_count")},
    )
    return result


@app.get("/policy/releases/active")
def get_active_policy_release_endpoint(
    policy_id: str,
    target_env: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.releases import get_active_policy_release

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = get_active_policy_release(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        target_env=target_env,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Active policy release not found")
    return payload


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
    from releasegate.replay.events import record_replay_event

    effective_tenant = _effective_tenant(auth, tenant_id)
    row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not row:
        raise HTTPException(status_code=404, detail="Decision not found")

    def _build_deterministic_block(report_payload: Dict[str, Any]) -> Dict[str, Any]:
        old = report_payload.get("old") or {}
        new = report_payload.get("new") or {}
        return {
            "match": bool(report_payload.get("match")),
            "old_output": {
                "status": old.get("status"),
                "reason_code": old.get("reason_code"),
            },
            "new_output": {
                "status": new.get("status"),
                "reason_code": new.get("reason_code"),
            },
            "diff": report_payload.get("diff") or [],
            "old_hash": {
                "output_hash": old.get("output_hash"),
                "decision_hash": old.get("decision_hash"),
                "replay_hash": old.get("replay_hash"),
            },
            "new_hash": {
                "output_hash": new.get("output_hash"),
                "decision_hash": new.get("decision_hash"),
                "replay_hash": new.get("replay_hash"),
            },
            "policy_hash": {
                "old": old.get("policy_hash"),
                "new": new.get("policy_hash"),
                "match": bool(report_payload.get("policy_hash_match")),
            },
            "inputs_hash": {
                "old": old.get("input_hash"),
                "new": new.get("input_hash"),
                "match": bool(report_payload.get("input_hash_match")),
            },
        }

    def _record_replay_evidence_safe(
        replay_event: Dict[str, Any],
        diff: List[Dict[str, Any]],
        replay_hash: Optional[str],
    ) -> None:
        try:
            from releasegate.evidence.graph import record_replay_evidence

            record_replay_evidence(
                tenant_id=effective_tenant,
                decision_id=decision_id,
                replay_id=str(replay_event.get("replay_id") or ""),
                match=bool(replay_event.get("match")),
                diff=diff,
                replay_hash=str(replay_hash or ""),
            )
        except Exception:
            # Evidence graph is best effort.
            pass

    def _invalid_stored_state(reason: str, details: str) -> Dict[str, Any]:
        diff_item = {
            "error": "STORED_DECISION_INVALID",
            "reason": str(reason),
            "details": str(details),
        }
        report = {
            "decision_id": decision_id,
            "tenant_id": effective_tenant,
            "match": False,
            "matches_original": False,
            "mismatch_reason": "STORED_DECISION_INVALID",
            "diff": [diff_item],
            "old": {
                "policy_hash": row.get("policy_hash"),
                "engine_version": str(row.get("engine_version") or ""),
                "output_hash": None,
                "status": row.get("release_status"),
                "reason_code": row.get("reason_code"),
                "input_hash": row.get("input_hash"),
                "decision_hash": row.get("decision_hash"),
                "replay_hash": row.get("replay_hash"),
            },
            "new": {
                "policy_hash": None,
                "engine_version": str(row.get("engine_version") or ""),
                "output_hash": None,
                "status": None,
                "reason_code": None,
                "input_hash": None,
                "decision_hash": None,
                "replay_hash": None,
            },
            "policy_hash_match": False,
            "input_hash_match": False,
            "created_at": row.get("created_at"),
            "repo": row.get("repo"),
            "pr_number": row.get("pr_number"),
            "attestation_id": None,
        }
        replay_event = record_replay_event(
            tenant_id=effective_tenant,
            decision_id=decision_id,
            match=False,
            diff=[diff_item],
            old_output_hash=None,
            new_output_hash=None,
            old_policy_hash=row.get("policy_hash"),
            new_policy_hash=None,
            old_input_hash=row.get("input_hash"),
            new_input_hash=None,
            ran_engine_version=str(row.get("engine_version") or ""),
            status="INVALID_STORED_STATE",
        )
        _record_replay_evidence_safe(
            replay_event=replay_event,
            diff=[diff_item],
            replay_hash=None,
        )
        report["replay_id"] = replay_event.get("replay_id")
        report["deterministic"] = _build_deterministic_block(report)
        report["deterministic"]["diff"] = {
            "error": "STORED_DECISION_INVALID",
            "details": str(details),
        }
        report["meta"] = {
            "replay_id": replay_event.get("replay_id"),
            "replayed_at": replay_event.get("created_at"),
            "actor": auth.principal_id,
            "status": replay_event.get("status"),
        }
        log_security_event(
            tenant_id=effective_tenant,
            principal_id=auth.principal_id,
            auth_method=auth.auth_method,
            action="decision_replay",
            target_type="decision",
            target_id=decision_id,
            metadata={
                "repo": report.get("repo"),
                "pr_number": report.get("pr_number"),
                "replay_id": replay_event.get("replay_id"),
                "match": False,
                "status": "INVALID_STORED_STATE",
                "reason": str(reason),
            },
        )
        return report

    raw = row.get("full_decision_json")
    if not raw:
        return _invalid_stored_state("MISSING_FULL_DECISION_JSON", "Decision payload missing full_decision_json")

    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        decision = Decision.model_validate(payload)
    except Exception as exc:
        return _invalid_stored_state("INVALID_DECISION_PAYLOAD", str(exc))

    snapshot_binding = AuditReader.get_decision_with_policy_snapshot(
        decision_id=decision_id,
        tenant_id=effective_tenant,
    )
    if not snapshot_binding:
        return _invalid_stored_state("MISSING_POLICY_SNAPSHOT_BINDING", "Decision policy snapshot binding not found")
    snapshot_wrapper = snapshot_binding.get("snapshot") if isinstance(snapshot_binding, dict) else {}
    policy_snapshot = snapshot_wrapper.get("snapshot") if isinstance(snapshot_wrapper, dict) else None
    if not isinstance(policy_snapshot, dict):
        return _invalid_stored_state("INVALID_POLICY_SNAPSHOT", "Stored policy snapshot payload is invalid")

    try:
        report = replay_decision(
            decision,
            policy_snapshot=policy_snapshot,
            stored_engine_version=str(row.get("engine_version") or ""),
        )
    except ValueError as exc:
        return _invalid_stored_state("INVALID_REPLAY_STATE", str(exc))

    replay_event = record_replay_event(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        match=bool(report.get("match")),
        diff=report.get("diff") or [],
        old_output_hash=(report.get("old") or {}).get("output_hash"),
        new_output_hash=(report.get("new") or {}).get("output_hash"),
        old_policy_hash=(report.get("old") or {}).get("policy_hash"),
        new_policy_hash=(report.get("new") or {}).get("policy_hash"),
        old_input_hash=(report.get("old") or {}).get("input_hash"),
        new_input_hash=(report.get("new") or {}).get("input_hash"),
        ran_engine_version=str(report.get("engine_version_replay") or report.get("engine_version_original") or ""),
        status="COMPLETED",
    )
    _record_replay_evidence_safe(
        replay_event=replay_event,
        diff=report.get("diff") or [],
        replay_hash=str((report.get("new") or {}).get("replay_hash") or report.get("replay_hash_replay") or ""),
    )

    report["created_at"] = row.get("created_at")
    report["repo"] = row.get("repo")
    report["pr_number"] = row.get("pr_number")
    report["attestation_id"] = decision.attestation_id
    report["replay_id"] = replay_event.get("replay_id")
    report["deterministic"] = _build_deterministic_block(report)
    report["meta"] = {
        "replay_id": replay_event.get("replay_id"),
        "replayed_at": replay_event.get("created_at"),
        "actor": auth.principal_id,
        "status": replay_event.get("status"),
    }
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="decision_replay",
        target_type="decision",
        target_id=decision_id,
        metadata={
            "repo": report.get("repo"),
            "pr_number": report.get("pr_number"),
            "replay_id": replay_event.get("replay_id"),
            "match": bool(report.get("match")),
            "status": replay_event.get("status"),
        },
    )
    return report


@app.get("/decisions/{decision_id}/policy-snapshot")
def get_decision_policy_snapshot(
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.reader import AuditReader

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = AuditReader.get_decision_with_policy_snapshot(decision_id, tenant_id=effective_tenant)
    if not payload:
        raise HTTPException(status_code=404, detail="Decision policy snapshot not found")
    return payload


@app.get("/decisions/{decision_id}/policy-snapshot/verify")
def verify_decision_policy_snapshot(
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.audit.reader import AuditReader

    effective_tenant = _effective_tenant(auth, tenant_id)
    report = AuditReader.verify_decision_policy_snapshot(decision_id, tenant_id=effective_tenant)
    if not report.get("exists"):
        raise HTTPException(status_code=404, detail="Decision policy snapshot binding not found")
    return report


@app.get("/decisions/{decision_id}/evidence-graph")
def get_decision_evidence_graph_endpoint(
    decision_id: str,
    tenant_id: Optional[str] = None,
    depth: int = 2,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.evidence.graph import get_decision_evidence_graph

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = get_decision_evidence_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        max_depth=depth,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Evidence graph not found for decision")
    return payload


@app.get("/decisions/{decision_id}/explain")
def explain_decision_endpoint(
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.evidence.graph import explain_decision

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = explain_decision(
        tenant_id=effective_tenant,
        decision_id=decision_id,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Decision evidence explanation not found")
    return payload


@app.post("/gate/deploy/check")
def deploy_gate_check_endpoint(
    payload: DeployGateCheckRequest,
    x_idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.enforcement import evaluate_deploy_gate

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    operation = "deploy_gate_check"
    idem_key = (
        str(x_idempotency_key or "").strip()
        or derive_system_idempotency_key(
            tenant_id=effective_tenant,
            operation=operation,
            identity={
                "decision_id": payload.decision_id,
                "issue_key": payload.issue_key,
                "correlation_id": payload.correlation_id,
                "deploy_id": payload.deploy_id,
                "repo": payload.repo,
                "env": payload.env,
                "commit_sha": payload.commit_sha,
                "artifact_digest": payload.artifact_digest,
                "principal_id": auth.principal_id,
            },
        )
    )
    try:
        claim = claim_idempotency(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
            request_payload={
                **payload.model_dump(mode="json"),
                "tenant_id": effective_tenant,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if claim.state == "replay" and claim.response is not None:
        return claim.response
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
        )
        if replayed is not None:
            return replayed
        raise HTTPException(status_code=409, detail="Deploy gate check is already in progress")

    result = evaluate_deploy_gate(
        tenant_id=effective_tenant,
        decision_id=payload.decision_id,
        issue_key=payload.issue_key,
        correlation_id=payload.correlation_id,
        deploy_id=payload.deploy_id,
        repo=payload.repo,
        env=payload.env,
        commit_sha=payload.commit_sha,
        artifact_digest=payload.artifact_digest,
        policy_overrides=payload.policy_overrides,
    )
    result = {
        **result,
        "idempotency_key": idem_key,
    }
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="deploy_gate_check",
        target_type="deployment",
        target_id=str(payload.deploy_id or payload.correlation_id or payload.repo),
        metadata={
            "result": result.get("status"),
            "reason_code": result.get("reason_code"),
            "repo": payload.repo,
            "env": payload.env,
            "decision_id": result.get("decision_id"),
            "correlation_id": result.get("correlation_id"),
            "idempotency_key": idem_key,
        },
    )
    complete_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idem_key,
        response_payload=result,
        resource_type="deployment",
        resource_id=str(payload.deploy_id or result.get("correlation_id") or payload.repo),
    )
    return result


@app.post("/gate/incident/close-check")
def incident_close_check_endpoint(
    payload: IncidentCloseCheckRequest,
    x_idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.enforcement import evaluate_incident_close_gate

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    operation = "incident_close_gate_check"
    idem_key = (
        str(x_idempotency_key or "").strip()
        or derive_system_idempotency_key(
            tenant_id=effective_tenant,
            operation=operation,
            identity={
                "incident_id": payload.incident_id,
                "decision_id": payload.decision_id,
                "issue_key": payload.issue_key,
                "correlation_id": payload.correlation_id,
                "deploy_id": payload.deploy_id,
                "repo": payload.repo,
                "env": payload.env,
                "principal_id": auth.principal_id,
            },
        )
    )
    try:
        claim = claim_idempotency(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
            request_payload={
                **payload.model_dump(mode="json"),
                "tenant_id": effective_tenant,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if claim.state == "replay" and claim.response is not None:
        return claim.response
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
        )
        if replayed is not None:
            return replayed
        raise HTTPException(status_code=409, detail="Incident close gate check is already in progress")

    result = evaluate_incident_close_gate(
        tenant_id=effective_tenant,
        incident_id=payload.incident_id,
        decision_id=payload.decision_id,
        issue_key=payload.issue_key,
        correlation_id=payload.correlation_id,
        deploy_id=payload.deploy_id,
        repo=payload.repo,
        env=payload.env,
        policy_overrides=payload.policy_overrides,
    )
    result = {
        **result,
        "idempotency_key": idem_key,
    }
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="incident_close_gate_check",
        target_type="incident",
        target_id=str(payload.incident_id),
        metadata={
            "result": result.get("status"),
            "reason_code": result.get("reason_code"),
            "decision_id": result.get("decision_id"),
            "correlation_id": result.get("correlation_id"),
            "deploy_id": payload.deploy_id,
            "idempotency_key": idem_key,
        },
    )
    complete_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idem_key,
        response_payload=result,
        resource_type="incident",
        resource_id=str(payload.incident_id),
    )
    return result


@app.post("/verify")
def verify_release_attestation(
    payload: Dict[str, Any],
):
    from releasegate.attestation.crypto import load_public_keys_map
    from releasegate.attestation.verify import verify_attestation_payload

    attestation = payload.get("attestation") if isinstance(payload.get("attestation"), dict) else payload
    report = verify_attestation_payload(
        attestation,
        public_keys_by_key_id=load_public_keys_map(),
    )
    report["ok"] = bool(
        report.get("schema_valid")
        and report.get("payload_hash_match")
        and report.get("trusted_issuer")
        and report.get("valid_signature")
    )
    return report
