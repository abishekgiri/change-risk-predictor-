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
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from time import monotonic, perf_counter
import requests
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exception_handlers import (
    http_exception_handler as fastapi_http_exception_handler,
    request_validation_exception_handler as fastapi_request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.background import BackgroundTask
import csv
import io
import zipfile
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from releasegate.security.auth import require_access, tenant_from_request
from releasegate.security.audit import log_security_event
from releasegate.security.api_keys import create_api_key, list_api_keys, revoke_api_key, rotate_api_key
from releasegate.security.checkpoint_keys import list_checkpoint_signing_keys, rotate_checkpoint_signing_key
from releasegate.security.webhook_keys import create_webhook_key, list_webhook_keys
from releasegate.tenants.keys import (
    list_tenant_signing_keys,
    revoke_tenant_signing_key,
    rotate_tenant_signing_key,
)
from releasegate.integrations.jira.routes import router as jira_router
from releasegate.security.types import AuthContext
from releasegate.audit.idempotency import (
    cancel_idempotency_claim,
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
from releasegate.quota import (
    QUOTA_KIND_OVERRIDES,
    TenantQuotaExceededError,
    consume_tenant_quota,
    get_tenant_governance_metrics,
    get_tenant_governance_settings,
    update_tenant_governance_settings,
)
from releasegate.security.anomaly_detector import record_anomaly_event
from releasegate.utils.canonical import canonical_json, sha256_json
from releasegate.storage import get_storage_backend
from releasegate.observability.internal_metrics import snapshot as metrics_snapshot
from releasegate.observability.slo_metrics import record_http_request, snapshot as slo_snapshot
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

DEFAULT_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS = 15
_DASHBOARD_OVERVIEW_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}
_DASHBOARD_OVERVIEW_CACHE_LOCK = Lock()
DEFAULT_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS = 30
_DASHBOARD_METRICS_TIMESERIES_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}
_DASHBOARD_METRICS_TIMESERIES_CACHE_LOCK = Lock()


def _releasegate_env() -> str:
    return str(os.getenv("RELEASEGATE_ENV") or "development").strip().lower()


def _is_production_env() -> bool:
    return _releasegate_env() in {"prod", "production"}


def _parse_allowed_origins() -> List[str]:
    raw = str(os.getenv("RELEASEGATE_ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return []
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    deduped: List[str] = []
    for origin in origins:
        if origin not in deduped:
            deduped.append(origin)
    return deduped


ALLOWED_ORIGINS = _parse_allowed_origins()
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-Id"],
    )


@app.middleware("http")
async def _http_slo_tracking_middleware(request: Request, call_next):
    started = perf_counter()
    path = str(request.url.path or "/")
    method = str(request.method or "GET").upper()
    try:
        response = await call_next(request)
    except Exception:
        latency_ms = (perf_counter() - started) * 1000.0
        record_http_request(path=path, method=method, status_code=500, latency_ms=latency_ms)
        raise
    latency_ms = (perf_counter() - started) * 1000.0
    record_http_request(path=path, method=method, status_code=response.status_code, latency_ms=latency_ms)
    return response


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


class PolicyRolloutCreateRequest(BaseModel):
    policy_id: str
    target_env: str
    to_release_id: str
    mode: str = "full"
    canary_percent: Optional[int] = None
    tenant_id: Optional[str] = None
    created_by: Optional[str] = None


class PolicyRolloutPromoteRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor_id: Optional[str] = None


class PolicyRolloutRollbackRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor_id: Optional[str] = None
    rollback_to_release_id: Optional[str] = None


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


class PolicyRegistryStageRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor_id: Optional[str] = None


class PolicyRegistryRollbackRequest(BaseModel):
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
    status_filter: str = "ACTIVE"
    tenant_id: Optional[str] = None


class PolicySimulateRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor: Optional[str] = None
    issue_key: Optional[str] = None
    transition_id: str
    project_id: Optional[str] = None
    workflow_id: Optional[str] = None
    environment: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    policy_json: Optional[Dict[str, Any]] = None
    status_filter: str = "ACTIVE"


class PolicySimulateHistoricalRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    policy_json: Optional[Dict[str, Any]] = None
    time_window_days: int = 30
    transition_id: Optional[str] = None
    project_key: Optional[str] = None
    workflow_id: Optional[str] = None
    environment: Optional[str] = None
    only_protected: bool = False
    max_events: Optional[int] = None
    top_n: int = 10


class PolicyDiffImpactRequest(BaseModel):
    tenant_id: Optional[str] = None
    current_policy_id: Optional[str] = None
    current_policy_version: Optional[int] = None
    current_policy_json: Optional[Dict[str, Any]] = None
    candidate_policy_id: Optional[str] = None
    candidate_policy_version: Optional[int] = None
    candidate_policy_json: Optional[Dict[str, Any]] = None


class PolicyConflictAnalyzeRequest(BaseModel):
    tenant_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_json: Optional[Dict[str, Any]] = None


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


class CorrelationDeploymentRequest(BaseModel):
    tenant_id: Optional[str] = None
    deployment_event_id: str
    repo: str
    environment: str
    service: str
    decision_id: Optional[str] = None
    jira_issue_id: Optional[str] = None
    correlation_id: Optional[str] = None
    commit_sha: Optional[str] = None
    artifact_digest: Optional[str] = None
    risk_eval_id: Optional[str] = None
    risk_evaluated_at: Optional[str] = None
    deployed_at: Optional[str] = None
    source: Optional[str] = None
    jira_ticket_approved: Optional[bool] = None
    jira_ticket_status: Optional[str] = None
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


class CorrelationCreateRequest(BaseModel):
    tenant_id: Optional[str] = None
    correlation_id: Optional[str] = None
    jira_issue_key: Optional[str] = None
    pr_repo: Optional[str] = None
    pr_sha: Optional[str] = None
    deploy_id: Optional[str] = None
    incident_id: Optional[str] = None
    environment: str
    change_ticket_key: Optional[str] = None
    decision_id: Optional[str] = None


class CorrelationAttachRequest(BaseModel):
    tenant_id: Optional[str] = None
    jira_issue_key: Optional[str] = None
    pr_repo: Optional[str] = None
    pr_sha: Optional[str] = None
    deploy_id: Optional[str] = None
    incident_id: Optional[str] = None
    environment: Optional[str] = None
    change_ticket_key: Optional[str] = None
    decision_id: Optional[str] = None


class DeployGateEvaluateRequest(BaseModel):
    tenant_id: Optional[str] = None
    correlation_id: Optional[str] = None
    deploy_id: Optional[str] = None
    environment: str
    change_ticket_key: Optional[str] = None
    decision_id: Optional[str] = None
    issue_key: Optional[str] = None
    repo: Optional[str] = None
    commit_sha: Optional[str] = None
    artifact_digest: Optional[str] = None
    policy_overrides: Dict[str, Any] = Field(default_factory=dict)
    signals: Dict[str, Any] = Field(default_factory=dict)


class IncidentGateEvaluateRequest(BaseModel):
    tenant_id: Optional[str] = None
    incident_id: str
    correlation_id: Optional[str] = None
    close_reason: Optional[str] = None
    decision_id: Optional[str] = None
    issue_key: Optional[str] = None
    deploy_id: Optional[str] = None
    repo: Optional[str] = None
    environment: Optional[str] = None
    policy_overrides: Dict[str, Any] = Field(default_factory=dict)
    signals: Dict[str, Any] = Field(default_factory=dict)


class RecommendationAcknowledgeRequest(BaseModel):
    tenant_id: Optional[str] = None
    recommendation_id: str


class CreateApiKeyRequest(BaseModel):
    name: str
    roles: list[str] = Field(default_factory=lambda: ["operator"])
    scopes: list[str] = Field(default_factory=lambda: ["enforcement:write"])
    tenant_id: Optional[str] = None


class RotateCheckpointSigningKeyRequest(BaseModel):
    key: str = Field(min_length=16)
    kms_key_id: Optional[str] = None
    tenant_id: Optional[str] = None


class RotateTenantSigningKeyRequest(BaseModel):
    tenant_id: Optional[str] = None
    key_id: Optional[str] = None
    private_key: Optional[str] = None
    kms_key_id: Optional[str] = None
    signing_mode: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RevokeTenantSigningKeyRequest(BaseModel):
    tenant_id: Optional[str] = None
    reason: Optional[str] = None


class EmergencyRotateTenantKeyRequest(BaseModel):
    tenant_id: Optional[str] = None
    reason: Optional[str] = None
    compromise_start: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ForceRekeyTenantRequest(BaseModel):
    tenant_id: Optional[str] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ResignCompromisedRequest(BaseModel):
    tenant_id: Optional[str] = None
    limit: int = Field(default=200, ge=1, le=1000)


class TenantGovernanceSettingsRequest(BaseModel):
    max_decisions_per_month: Optional[int] = Field(default=None, ge=0)
    max_anchors_per_day: Optional[int] = Field(default=None, ge=0)
    max_overrides_per_month: Optional[int] = Field(default=None, ge=0)
    quota_enforcement_mode: str = "HARD"


class TenantUnlockRequest(BaseModel):
    reason: Optional[str] = None


class AnchorTickRequest(BaseModel):
    tenant_id: Optional[str] = None


class DailyIndependentCheckpointPublishRequest(BaseModel):
    tenant_id: Optional[str] = None
    provider: Optional[str] = None
    publish_anchor: bool = True


class RotateApiKeyRequest(BaseModel):
    tenant_id: Optional[str] = None


class CreateWebhookSigningKeyRequest(BaseModel):
    integration_id: str = Field(min_length=1)
    tenant_id: Optional[str] = None
    rotate_existing: bool = True
    secret: Optional[str] = None


class VerifyAttestationRequest(BaseModel):
    attestation: Dict[str, Any]


class SignalAttestRequest(BaseModel):
    tenant_id: Optional[str] = None
    signal_type: str = Field(min_length=1)
    signal_source: str = Field(min_length=1)
    subject_type: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    computed_at: str
    expires_at: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    signal_hash: Optional[str] = None
    sig_alg: Optional[str] = None
    signature: Optional[str] = None
    key_id: Optional[str] = None


class GovernanceExportRequest(BaseModel):
    tenant_id: Optional[str] = None
    type: str = Field(min_length=1)
    year: int
    quarter: Optional[int] = None


class DashboardTrendPoint(BaseModel):
    date_utc: str
    value: float = 0.0


class DashboardOverrideRateTrendPoint(BaseModel):
    date_utc: str
    value: float = 0.0
    override_count: int = 0
    decision_count: int = 0


class DashboardDriftPayload(BaseModel):
    current: float = 0.0
    breakdown: Optional[Dict[str, Any]] = None


class DashboardOverviewData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    window_days: int = 30
    integrity_score: float = 0.0
    integrity_trend: List[DashboardTrendPoint] = Field(default_factory=list)
    drift_index: float = 0.0
    drift_trend: List[DashboardTrendPoint] = Field(default_factory=list)
    override_rate: float = 0.0
    override_rate_trend: List[DashboardOverrideRateTrendPoint] = Field(default_factory=list)
    drift: DashboardDriftPayload = Field(default_factory=DashboardDriftPayload)
    active_strict_modes: List[Dict[str, Any]] = Field(default_factory=list)
    recent_blocked: List[Dict[str, Any]] = Field(default_factory=list)
    debug_timing_ms: Optional[Dict[str, float]] = None


class DashboardIntegrityTrendPoint(BaseModel):
    date_utc: str
    integrity_score: float = 0.0
    drift_index: float = 0.0
    override_rate: float = 0.0
    override_count: int = 0
    decision_count: int = 0
    blocked_count: int = 0
    drift_breakdown: Optional[Dict[str, Any]] = None
    override_abuse_index: float = 0.0


class DashboardIntegrityData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    window_days: int = 30
    trend: List[DashboardIntegrityTrendPoint] = Field(default_factory=list)


class DashboardAlertsData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    window_days: int = 30
    current_override_abuse_index: float = 0.0
    alerts: List[Dict[str, Any]] = Field(default_factory=list)


class DashboardBlockedData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    items: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class DashboardStrictModesData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    items: List[Dict[str, Any]] = Field(default_factory=list)


class DashboardDecisionExplainData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    decision_id: str
    decision: Dict[str, Any] = Field(default_factory=dict)
    snapshot_binding: Dict[str, Any] = Field(default_factory=dict)
    evaluation_tree: Dict[str, Any] = Field(default_factory=dict)
    signals: List[Dict[str, Any]] = Field(default_factory=list)
    risk: Dict[str, Any] = Field(default_factory=dict)
    evidence_links: List[Dict[str, Any]] = Field(default_factory=list)
    replay: Dict[str, Any] = Field(default_factory=dict)


class DashboardPolicyDiffData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: Optional[str] = None
    report_id: Optional[str] = None
    report_trace_id: Optional[str] = None
    overall: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    threshold_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    condition_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    role_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    sod_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    active_policy: Dict[str, Any] = Field(default_factory=dict)
    staged_policy: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    strengthening_signals: List[Dict[str, Any]] = Field(default_factory=list)
    legacy_summary: Dict[str, Any] = Field(default_factory=dict)


class DashboardOverridesBreakdownRow(BaseModel):
    key: str
    count: int = 0
    workflows: int = 0
    rules: int = 0
    actors: int = 0
    last_seen: Optional[str] = None
    sample_override_ids: List[str] = Field(default_factory=list)


class DashboardOverridesBreakdownData(BaseModel):
    trace_id: Optional[str] = None
    tenant: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    group_by: str = "actor"
    total_overrides: int = 0
    rows: List[DashboardOverridesBreakdownRow] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class DashboardMetricsSeriesPoint(BaseModel):
    t: str
    value: float = 0.0
    numerator: Optional[int] = None
    denominator: Optional[int] = None


class DashboardMetricsTimeseriesData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    metric: str
    display_name: str
    unit: str
    higher_is_better: bool = False
    description: str = ""
    bucket: str = "day"
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    series: List[DashboardMetricsSeriesPoint] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class DashboardMetricSummaryPoint(BaseModel):
    display_name: str
    unit: str
    higher_is_better: bool = False
    value: float = 0.0
    previous: Optional[float] = None
    delta: Optional[float] = None
    sample_size: int = 0


class DashboardMetricsSummaryData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    window_days: int = 30
    metrics: Dict[str, DashboardMetricSummaryPoint] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class DashboardMetricDecisionItem(BaseModel):
    decision_id: str
    created_at: str
    decision_status: str
    reason_code: str = ""
    jira_issue_id: str = ""
    workflow_id: str = ""
    transition_id: str = ""
    actor: str = ""
    environment: str = ""
    project_key: str = ""
    policy_hash: str = ""
    explainer_path: str = ""


class DashboardMetricsDrilldownData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    metric: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    limit: int = 50
    items: List[DashboardMetricDecisionItem] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class CustomerSuccessRiskTrendPoint(BaseModel):
    t: str
    value: float
    decision_count: int = 0


class CustomerSuccessReleaseStabilityPoint(BaseModel):
    t: str
    value: float
    block_rate: float = 0.0
    override_rate: float = 0.0
    blocked_count: int = 0
    override_count: int = 0
    decision_count: int = 0


class DashboardCustomerSuccessRiskTrendData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    window_days: int = 30
    risk_index: List[CustomerSuccessRiskTrendPoint] = Field(default_factory=list)
    risk_delta_30d: float = 0.0
    org_risk_reduction: float = 0.0
    release_stability: List[CustomerSuccessReleaseStabilityPoint] = Field(default_factory=list)
    release_stability_delta: float = 0.0

    model_config = ConfigDict(populate_by_name=True)


class CustomerSuccessTopOverrideUser(BaseModel):
    user: str
    overrides: int
    share: float
    last_override_at: Optional[str] = None


class DashboardCustomerSuccessOverrideAnalysisData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    window_days: int = 30
    total_overrides: int = 0
    total_decisions: int = 0
    top_users: List[CustomerSuccessTopOverrideUser] = Field(default_factory=list)
    override_concentration_index: float = 0.0
    policy_weakening_signal: bool = False
    override_rate_baseline: float = 0.0
    override_rate_recent: float = 0.0

    model_config = ConfigDict(populate_by_name=True)


class CustomerSuccessRegressionItem(BaseModel):
    policy_change_id: str
    policy_id: str
    event_type: str
    changed_at: str
    integrity_before: float
    integrity_after: float
    integrity_drop: float
    integrity_drop_ratio: float
    correlation_window_hours: int
    affected_workflows: List[str] = Field(default_factory=list)
    policy_diff_path: str = "/policies/diff"
    decisions_path: str = "/observability?metric=block_frequency"


class DashboardCustomerSuccessRegressionReportData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    from_ts: str = Field(alias="from")
    to_ts: str = Field(alias="to")
    window_days: int = 30
    threshold_drop: float = 0.0
    total_policy_changes: int = 0
    regressions_detected: int = 0
    regressions: List[CustomerSuccessRegressionItem] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class DashboardErrorDetail(BaseModel):
    code: str = Field(description="Stable canonical dashboard error code.")
    error_code: str = Field(description="Detailed service error code. Defaults to canonical code.")
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(
        description="Client-facing request correlation identifier; equals top-level trace_id for dashboard responses."
    )


class DashboardErrorResponse(BaseModel):
    generated_at: str
    trace_id: str = Field(description="Distributed request correlation identifier.")
    error: DashboardErrorDetail


class DashboardOverviewResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardOverviewData


class DashboardIntegrityResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardIntegrityData


class DashboardAlertsResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardAlertsData


class DashboardBlockedResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardBlockedData


class DashboardStrictModesResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardStrictModesData


class DashboardDecisionExplainResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardDecisionExplainData


class DashboardPolicyDiffResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardPolicyDiffData


class DashboardOverridesBreakdownResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardOverridesBreakdownData


class DashboardMetricsTimeseriesResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardMetricsTimeseriesData


class DashboardMetricsSummaryResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardMetricsSummaryData


class DashboardMetricsDrilldownResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardMetricsDrilldownData


class DashboardCustomerSuccessRiskTrendResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardCustomerSuccessRiskTrendData


class DashboardCustomerSuccessOverrideAnalysisResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardCustomerSuccessOverrideAnalysisData


class DashboardCustomerSuccessRegressionReportResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardCustomerSuccessRegressionReportData


class OnboardingConfigData(BaseModel):
    tenant_id: str
    jira_instance_id: Optional[str] = None
    project_keys: List[str] = Field(default_factory=list)
    workflow_ids: List[str] = Field(default_factory=list)
    transition_ids: List[str] = Field(default_factory=list)
    mode: str = "simulation"
    canary_pct: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class OnboardingStatusData(BaseModel):
    tenant_id: str
    onboarding_completed: bool = False
    config: OnboardingConfigData


class OnboardingStatusResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: OnboardingStatusData


class OnboardingSetupRequest(BaseModel):
    tenant_id: Optional[str] = None
    jira_instance_id: Optional[str] = None
    project_keys: List[str] = Field(default_factory=list)
    workflow_ids: List[str] = Field(default_factory=list)
    transition_ids: List[str] = Field(default_factory=list)
    mode: str = "simulation"
    canary_pct: Optional[int] = None


class OnboardingSetupResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: OnboardingStatusData


class OnboardingActivationRequest(BaseModel):
    tenant_id: Optional[str] = None
    mode: str = "simulation"
    canary_pct: Optional[int] = None


class OnboardingActivationRollbackRequest(BaseModel):
    tenant_id: Optional[str] = None


class OnboardingActivationData(BaseModel):
    tenant_id: str
    mode: str = "simulation"
    canary_pct: Optional[int] = None
    applied: bool = False
    updated_at: Optional[str] = None


class OnboardingActivationResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: OnboardingActivationData


class OnboardingActivationRollbackData(BaseModel):
    status: str = "rolled_back"
    activation: OnboardingActivationData


class OnboardingActivationRollbackResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: OnboardingActivationRollbackData


class OnboardingActivationHistoryEntry(BaseModel):
    history_id: int
    mode: str = "simulation"
    canary_pct: Optional[int] = None
    updated_at: Optional[str] = None
    recorded_at: Optional[str] = None


class OnboardingActivationHistoryData(BaseModel):
    tenant_id: str
    limit: int = 20
    current: OnboardingActivationData
    items: List[OnboardingActivationHistoryEntry] = Field(default_factory=list)


class OnboardingActivationHistoryResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: OnboardingActivationHistoryData


class SimulationRunRequest(BaseModel):
    tenant_id: Optional[str] = None
    lookback_days: int = 30


class SimulationResultData(BaseModel):
    tenant_id: str
    lookback_days: int = 30
    total_transitions: int = 0
    allowed: int = 0
    blocked: int = 0
    blocked_pct: float = 0.0
    override_required: int = 0
    risk_distribution: Dict[str, int] = Field(default_factory=lambda: {"low": 0, "medium": 0, "high": 0})
    ran_at: Optional[str] = None
    has_run: bool = False


class SimulationRunResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: SimulationResultData


class DashboardTenantRoleAssignmentEntry(BaseModel):
    actor_id: str
    roles: List[str] = Field(default_factory=list)
    assigned_by: Optional[str] = None
    last_assigned_at: Optional[str] = None


class DashboardTenantInfoData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    name: str
    plan: str
    region: str
    status: str = "active"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None
    roles: List[DashboardTenantRoleAssignmentEntry] = Field(default_factory=list)
    limits: Dict[str, Any] = Field(default_factory=dict)


class DashboardTenantCreateRequest(BaseModel):
    tenant_id: Optional[str] = None
    name: Optional[str] = None
    plan: str = "enterprise"
    region: str = "us-east"


class DashboardTenantLockRequest(BaseModel):
    tenant_id: Optional[str] = None
    status: str = "locked"
    reason: Optional[str] = None


class DashboardTenantUnlockRequest(BaseModel):
    tenant_id: Optional[str] = None
    reason: Optional[str] = None


class DashboardTenantRoleAssignRequest(BaseModel):
    tenant_id: Optional[str] = None
    actor_id: str
    role: str
    action: str = "assign"


class DashboardTenantKeyRotateRequest(BaseModel):
    tenant_id: Optional[str] = None
    rotate_signing_key: bool = True
    rotate_api_key: bool = True
    api_key_id: Optional[str] = None


class DashboardTenantKeyRotateData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    rotated_signing_key_id: Optional[str] = None
    rotated_api_key_id: Optional[str] = None
    api_key_created: bool = False


class DashboardBillingUsageData(BaseModel):
    trace_id: Optional[str] = None
    tenant_id: str
    plan: str
    status: str = "active"
    decisions_this_month: int = 0
    decision_limit: Optional[int] = None
    decision_usage_pct: Optional[float] = None
    overrides_this_month: int = 0
    override_limit: Optional[int] = None
    override_usage_pct: Optional[float] = None
    storage_mb: float = 0.0
    storage_limit_mb: Optional[int] = None
    storage_usage_pct: Optional[float] = None
    simulation_runs: int = 0
    simulation_history_days_limit: int = 0


class DashboardTenantInfoResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardTenantInfoData


class DashboardTenantKeyRotateResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardTenantKeyRotateData


class DashboardBillingUsageResponse(BaseModel):
    generated_at: str
    trace_id: str
    data: DashboardBillingUsageData


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
def get_public_keys(tenant_id: Optional[str] = None):
    """
    Returns active public attestation keys.
    Includes both modern and legacy field aliases for compatibility.
    """
    from releasegate.attestation.crypto import load_public_keys_map

    effective_tenant = str(tenant_id or "").strip() or None
    key_map = load_public_keys_map(tenant_id=effective_tenant)
    key_status_map: Dict[str, str] = {}
    if effective_tenant:
        try:
            for row in list_tenant_signing_keys(effective_tenant):
                key_id = str(row.get("key_id") or "").strip()
                if not key_id:
                    continue
                key_status_map[key_id] = str(row.get("status") or "").upper()
        except Exception:
            key_status_map = {}
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
                "status": key_status_map.get(key_id) or "ACTIVE",
            }
        )
    return {
        "issuer": "releasegate",
        "tenant_id": effective_tenant,
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
    from releasegate.attestation import build_intoto_statement
    from releasegate.attestation.crypto import MissingSigningKeyError, sign_message_for_tenant
    from releasegate.attestation.dsse import wrap_dsse_with_signer
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
        signing_tenant = str(row.get("tenant_id") or tenant_id or "").strip() or None
        envelope = wrap_dsse_with_signer(
            statement,
            signer=lambda message: sign_message_for_tenant(
                signing_tenant,
                message,
                purpose="attestation_dsse_export",
                actor="system:attestation",
            ),
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


@app.post("/transparency/root/{date_utc}/anchor")
def anchor_transparency_root_endpoint(
    date_utc: str,
    provider: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["proofpack:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.anchoring.roots import anchor_transparency_root

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        anchored = anchor_transparency_root(
            date_utc=date_utc,
            tenant_id=effective_tenant,
            provider_name=provider,
        )
    except TenantQuotaExceededError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="quota_bypass_attempt",
                operation="anchor_transparency_root",
                details=exc.to_http_detail(),
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(status_code=429, detail=exc.to_http_detail()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"external anchor failed: {exc}") from exc
    if not anchored:
        raise HTTPException(status_code=404, detail="transparency root not found for date")
    return {"ok": True, "anchor": anchored}


@app.get("/transparency/root/{date_utc}/anchors")
def transparency_root_anchors_by_date(
    date_utc: str,
    limit: int = 20,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["proofpack:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.anchoring.roots import list_root_anchors

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        items = list_root_anchors(tenant_id=effective_tenant, date_utc=date_utc, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "date_utc": date_utc,
        "count": len(items),
        "items": items,
    }


@app.post("/anchors/checkpoints/daily/{date_utc}/publish")
def publish_independent_daily_checkpoint(
    date_utc: str,
    payload: Optional[DailyIndependentCheckpointPublishRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["checkpoint:read", "proofpack:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.anchoring.independent_checkpoints import create_independent_daily_checkpoint

    body = payload or DailyIndependentCheckpointPublishRequest()
    effective_tenant = _effective_tenant(auth, body.tenant_id)
    try:
        checkpoint = create_independent_daily_checkpoint(
            date_utc=date_utc,
            tenant_id=effective_tenant,
            publish_anchor=bool(body.publish_anchor),
            provider_name=body.provider,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"failed to publish independent checkpoint: {exc}") from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="independent_checkpoint_publish",
        target_type="checkpoint",
        target_id=str((checkpoint.get("ids") or {}).get("checkpoint_id") or date_utc),
        metadata={
            "date_utc": date_utc,
            "created": bool(checkpoint.get("created")),
            "provider": str(((checkpoint.get("external_anchor") or {}).get("provider") or "")),
        },
    )
    return checkpoint


@app.get("/anchors/checkpoints/daily/{date_utc}")
def get_independent_daily_checkpoint_endpoint(
    date_utc: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read", "proofpack:read"],
        rate_profile="default",
    ),
):
    from releasegate.anchoring.independent_checkpoints import get_independent_daily_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        payload = get_independent_daily_checkpoint(
            date_utc=date_utc,
            tenant_id=effective_tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not payload:
        raise HTTPException(status_code=404, detail="independent daily checkpoint not found")
    return payload


@app.get("/anchors/checkpoints/daily/{date_utc}/verify")
def verify_independent_daily_checkpoint_endpoint(
    date_utc: str,
    require_anchor: bool = True,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read", "proofpack:read"],
        rate_profile="default",
    ),
):
    from releasegate.anchoring.independent_checkpoints import verify_independent_daily_checkpoint

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        report = verify_independent_daily_checkpoint(
            date_utc=date_utc,
            tenant_id=effective_tenant,
            require_anchor=require_anchor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not report.get("exists"):
        raise HTTPException(status_code=404, detail="independent daily checkpoint not found")
    return report


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


@app.head("/")
def health_check_head():
    return Response(status_code=200)


def _expected_schema_version() -> str:
    return MIGRATIONS[-1].migration_id if MIGRATIONS else SCHEMA_VERSION


def _required_runtime_tables() -> list[str]:
    return [
        "governance_insights",
        "governance_recommendations",
        "cross_system_correlations",
    ]


def _missing_runtime_tables() -> list[str]:
    storage = get_storage_backend()
    backend = (os.getenv("RELEASEGATE_STORAGE_BACKEND") or "sqlite").strip().lower()
    missing: list[str] = []
    for table_name in _required_runtime_tables():
        if backend == "postgres":
            row = storage.fetchone(
                """
                SELECT 1 AS ok
                FROM information_schema.tables
                WHERE table_schema = ANY (current_schemas(false))
                  AND table_name = ?
                LIMIT 1
                """,
                (table_name,),
            )
        else:
            row = storage.fetchone(
                """
                SELECT 1 AS ok
                FROM sqlite_master
                WHERE type = 'table' AND name = ?
                LIMIT 1
                """,
                (table_name,),
            )
        if not row:
            missing.append(table_name)
    return missing


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
        expected_version = payload["migrations"]["expected"]
        get_storage_backend().fetchone("SELECT 1 AS ok")
        state = get_storage_backend().fetchone(
            "SELECT current_version, migration_id, updated_at FROM schema_state WHERE id = 1"
        )
        if not state:
            payload["status"] = "error"
            payload["storage"] = "error"
            payload["migrations"]["status"] = "missing"
            payload["migrations"]["detail"] = "schema_state row not found; run migrations before serving traffic"
            return payload, 503
        current_schema = state.get("migration_id") or state.get("current_version")
        payload["migrations"]["updated_at"] = state.get("updated_at")
        payload["migrations"]["current"] = current_schema
        if str(current_schema) != str(expected_version):
            payload["status"] = "error"
            payload["migrations"]["status"] = "outdated"
            return payload, 503
        missing_tables = _missing_runtime_tables()
        if missing_tables:
            payload["status"] = "error"
            payload["storage"] = "error"
            payload["migrations"]["status"] = "incomplete"
            payload["migrations"]["missing_tables"] = missing_tables
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
    slo = slo_snapshot()
    by_tenant = snap.pop("_by_tenant", {}) if isinstance(snap, dict) else {}
    lines = [
        "# HELP releasegate_metric_total ReleaseGate internal counters",
        "# TYPE releasegate_metric_total counter",
        "# HELP releasegate_metric_tenant_total ReleaseGate internal counters by tenant",
        "# TYPE releasegate_metric_tenant_total counter",
        "# HELP releasegate_http_requests_total HTTP requests processed by the API process",
        "# TYPE releasegate_http_requests_total counter",
        "# HELP releasegate_http_errors_5xx_total HTTP 5xx responses observed by the API process",
        "# TYPE releasegate_http_errors_5xx_total counter",
        "# HELP releasegate_http_error_rate_5xx_ratio HTTP 5xx error ratio observed by the API process",
        "# TYPE releasegate_http_error_rate_5xx_ratio gauge",
        "# HELP releasegate_http_latency_ms_p95 API p95 latency in milliseconds (process-local sample)",
        "# TYPE releasegate_http_latency_ms_p95 gauge",
        "# HELP releasegate_uptime_seconds API process uptime in seconds",
        "# TYPE releasegate_uptime_seconds gauge",
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
    lines.append(f"releasegate_http_requests_total {int(slo.get('http_requests_total') or 0)}")
    lines.append(f"releasegate_http_errors_5xx_total {int(slo.get('http_errors_5xx_total') or 0)}")
    lines.append(f"releasegate_http_error_rate_5xx_ratio {float(slo.get('http_error_rate_5xx') or 0.0)}")
    lines.append(f"releasegate_http_latency_ms_p95 {float(slo.get('latency_ms_p95') or 0.0)}")
    lines.append(f"releasegate_uptime_seconds {float(slo.get('uptime_seconds') or 0.0)}")
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/internal/slo")
def slo_metrics(
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    _ = auth
    payload = slo_snapshot()
    payload["targets"] = {
        "p95_latency_ms": 500.0,
        "error_rate_5xx": 0.001,
        "uptime_ratio": 0.999,
    }
    return payload


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


@app.post("/signals/attest")
def attest_signal_endpoint(
    payload: SignalAttestRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.signals.attestation import attest_signal

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        record = attest_signal(
            tenant_id=effective_tenant,
            signal_type=payload.signal_type,
            signal_source=payload.signal_source,
            subject_type=payload.subject_type,
            subject_id=payload.subject_id,
            computed_at=payload.computed_at,
            expires_at=payload.expires_at,
            payload=payload.payload,
            signal_hash=payload.signal_hash,
            sig_alg=payload.sig_alg,
            signature=payload.signature,
            key_id=payload.key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "signal_id": record.get("signal_id"),
        "signal_hash": record.get("signal_hash"),
        "signal_type": record.get("signal_type"),
        "subject_type": record.get("subject_type"),
        "subject_id": record.get("subject_id"),
        "computed_at": record.get("computed_at"),
        "expires_at": record.get("expires_at"),
    }


@app.get("/signals/latest")
def latest_signal_attestation_endpoint(
    signal_type: str,
    subject_type: str,
    subject_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.signals.attestation import get_latest_signal_attestation

    effective_tenant = _effective_tenant(auth, tenant_id)
    item = get_latest_signal_attestation(
        tenant_id=effective_tenant,
        signal_type=signal_type,
        subject_type=subject_type,
        subject_id=subject_id,
    )
    if not item:
        raise HTTPException(status_code=404, detail="Signal attestation not found")
    return {"ok": True, "tenant_id": effective_tenant, "item": item}


@app.get("/internal/metrics/anchor")
def anchor_metrics(
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.anchoring.metrics import get_anchor_health

    effective_tenant = _effective_tenant(auth, tenant_id)
    report = get_anchor_health(tenant_id=effective_tenant)
    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "anchor": report,
    }


@app.post("/internal/anchor/tick")
def anchor_tick(
    payload: AnchorTickRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["policy:write"],
        rate_profile="heavy",
    ),
):
    from releasegate.anchoring.anchor_scheduler import tick

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    report = tick(tenant_id=effective_tenant)
    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "report": report,
    }


@app.on_event("startup")
def verify_ledger_on_startup():
    from releasegate.anchoring.anchor_scheduler import scheduler_status, start_anchor_scheduler
    from releasegate.crypto.kms_client import ensure_kms_runtime_policy
    from releasegate.governance.dashboard_metrics import warm_dashboard_rollups_for_startup
    from releasegate.saas.tenants import warm_known_tenant_rows_for_startup
    from releasegate.storage.schema import init_db

    _validate_startup_environment()
    ensure_kms_runtime_policy()
    init_db()
    try:
        tenant_row_warmup = warm_known_tenant_rows_for_startup()
        app.state.tenant_row_warmup = tenant_row_warmup
        logger.info(
            "Tenant row warmup complete: discovered=%s warmed=%s failed=%s",
            tenant_row_warmup.get("tenants_discovered"),
            tenant_row_warmup.get("tenants_warmed"),
            tenant_row_warmup.get("tenants_failed"),
        )
    except Exception:
        logger.exception("Tenant row warmup failed at startup")
    try:
        warmup_report = warm_dashboard_rollups_for_startup()
        app.state.dashboard_rollup_warmup = warmup_report
        logger.info(
            "Dashboard rollup warmup complete: discovered=%s warmed=%s failed=%s",
            warmup_report.get("tenants_discovered"),
            warmup_report.get("tenants_warmed"),
            warmup_report.get("tenants_failed"),
        )
    except Exception:
        logger.exception("Dashboard rollup warmup failed at startup")
    app.state.anchor_scheduler = start_anchor_scheduler()
    app.state.anchor_scheduler_status = scheduler_status()
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


@app.on_event("shutdown")
def stop_background_workers():
    from releasegate.anchoring.anchor_scheduler import stop_anchor_scheduler

    app.state.anchor_scheduler = stop_anchor_scheduler()


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


def _validate_startup_environment() -> None:
    if _is_production_env():
        required_for_production = [
            "RELEASEGATE_INTERNAL_SERVICE_KEY",
            "RELEASEGATE_ALLOWED_ORIGINS",
            "RELEASEGATE_JWT_SECRET",
            "RELEASEGATE_KEY_ENCRYPTION_SECRET",
        ]
        missing_for_production = [
            name for name in required_for_production if not str(os.getenv(name) or "").strip()
        ]
        if missing_for_production:
            raise RuntimeError(
                "Missing required production environment variables: "
                + ", ".join(missing_for_production)
            )

        if not ALLOWED_ORIGINS:
            raise RuntimeError(
                "RELEASEGATE_ALLOWED_ORIGINS must include at least one origin in production."
            )
    else:
        if not str(os.getenv("RELEASEGATE_INTERNAL_SERVICE_KEY") or "").strip():
            logger.warning(
                "RELEASEGATE_INTERNAL_SERVICE_KEY is not set; internal service authentication will be disabled."
            )


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
    graph_hash: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "canonicalization": CANONICALIZATION_VERSION,
        "hash_alg": HASH_ALGORITHM,
        "input_hash": hashes.get("input_hash") or "",
        "policy_hash": hashes.get("policy_hash") or "",
        "decision_hash": hashes.get("decision_hash") or "",
        "replay_hash": hashes.get("replay_hash") or "",
        "graph_hash": graph_hash or "",
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


def _gate_required_actions(reason_code: Optional[str]) -> list[str]:
    code = str(reason_code or "").strip().upper()
    mapping = {
        "DEPLOY_JIRA_ISSUE_REQUIRED": ["Attach a valid Jira issue key before production deployment."],
        "DECISION_REQUIRED_FOR_PROD": ["Obtain an approved ReleaseGate decision for this production change."],
        "POLICY_RELEASE_MISSING": ["Activate a policy release for the target environment."],
        "POLICY_NOT_LOADED": ["Verify policy control-plane/cache availability and retry."],
        "PROVIDER_TIMEOUT": ["Resolve upstream policy provider timeout or retry with healthy dependencies."],
        "PROVIDER_ERROR": ["Restore provider health and retry gate evaluation."],
        "POSTMORTEM_REQUIRED": ["Include a postmortem or closure rationale before incident close."],
        "DEPLOY_LINK_REQUIRED": ["Attach deployment linkage (deploy_id or correlation_id)."],
        "CORRELATION_ID_MISSING": ["Provide a correlation_id or enable deterministic correlation derivation."],
    }
    return list(mapping.get(code) or [])


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


@app.get("/audit/checkpoints/{checkpoint_id}/proof")
def get_independent_checkpoint_proof_endpoint(
    checkpoint_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["checkpoint:read", "proofpack:read"],
        rate_profile="default",
    ),
):
    from releasegate.anchoring.independent_checkpoints import (
        get_independent_daily_checkpoint_by_id,
        verify_independent_daily_checkpoint,
    )

    effective_tenant = _effective_tenant(auth, tenant_id)
    checkpoint = get_independent_daily_checkpoint_by_id(
        checkpoint_id=checkpoint_id,
        tenant_id=effective_tenant,
    )
    if not checkpoint:
        raise HTTPException(status_code=404, detail="independent checkpoint not found")
    payload = checkpoint.get("payload") if isinstance(checkpoint.get("payload"), dict) else {}
    verification = verify_independent_daily_checkpoint(
        date_utc=str(payload.get("date_utc") or ""),
        tenant_id=effective_tenant,
        require_anchor=True,
    )
    return {
        "tenant_id": effective_tenant,
        "checkpoint_id": checkpoint_id,
        "checkpoint": checkpoint,
        "verification": verification,
        "chain_segment": {
            "checkpoint_hash": ((checkpoint.get("integrity") or {}).get("checkpoint_hash") if isinstance(checkpoint.get("integrity"), dict) else None),
            "prev_checkpoint_hash": payload.get("prev_checkpoint_hash"),
            "ledger_root": payload.get("ledger_root"),
            "ledger_size": payload.get("ledger_size"),
        },
    }


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


def _dashboard_trace_id(request: Request) -> str:
    supplied = str(request.headers.get("X-Request-Id") or "").strip()
    if supplied:
        return supplied[:128]
    return uuid.uuid4().hex


def _dashboard_generated_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dashboard_error_code(status_code: int) -> str:
    if status_code == 401:
        return "AUTH_REQUIRED"
    if status_code == 403:
        return "FORBIDDEN"
    if status_code == 404:
        return "NOT_FOUND"
    if status_code == 409:
        return "CONFLICT"
    if status_code in {400, 422}:
        return "VALIDATION_ERROR"
    return "INTERNAL"


def _dashboard_error_subcode(detail: Any, default_code: str) -> str:
    if isinstance(detail, dict):
        existing = str(detail.get("error_code") or "").strip()
        if existing:
            return existing
    return default_code


def _dashboard_error_message(detail: Any, status_code: int) -> str:
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    if isinstance(detail, dict):
        message = str(detail.get("message") or "").strip()
        if message:
            return message
        if "error_code" in detail and len(detail.keys()) == 1:
            return f"Dashboard request failed with {status_code}"
        serialized = json.dumps(detail, separators=(",", ":"), ensure_ascii=False)
        return serialized if serialized else f"Dashboard request failed with {status_code}"
    return f"Dashboard request failed with {status_code}"


def _dashboard_error_response(
    *,
    request: Request,
    status_code: int,
    detail: Any,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    trace_id = _dashboard_trace_id(request)
    canonical_code = _dashboard_error_code(status_code)
    detailed_code = _dashboard_error_subcode(detail, canonical_code)
    payload = {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "error": {
            "code": canonical_code,
            "error_code": detailed_code,
            "message": _dashboard_error_message(detail, status_code),
            "details": detail if isinstance(detail, dict) else {},
            "request_id": trace_id,
        },
    }
    response_headers = dict(headers or {})
    response_headers["X-Request-Id"] = trace_id
    response_headers["Cache-Control"] = "private, no-store"
    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers=response_headers,
    )


def _dashboard_error_models() -> Dict[int, Dict[str, Any]]:
    return {
        400: {"model": DashboardErrorResponse},
        401: {"model": DashboardErrorResponse},
        403: {"model": DashboardErrorResponse},
        404: {"model": DashboardErrorResponse},
        409: {"model": DashboardErrorResponse},
        422: {"model": DashboardErrorResponse},
        500: {"model": DashboardErrorResponse},
    }


def _dashboard_response(
    *,
    response: Response,
    trace_id: str,
    cache_control: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = cache_control
    data = dict(payload)
    existing_trace_id = data.get("trace_id")
    if existing_trace_id and str(existing_trace_id) != str(trace_id):
        data["report_trace_id"] = existing_trace_id
    data["trace_id"] = trace_id
    generated_at = data.get("generated_at")
    if not generated_at:
        generated_at = _dashboard_generated_at()
    return {
        "generated_at": generated_at,
        "trace_id": trace_id,
        "data": data,
    }


def _dashboard_json_response(
    *,
    trace_id: str,
    cache_control: str,
    payload: Dict[str, Any],
) -> JSONResponse:
    envelope = _dashboard_response(
        response=Response(),
        trace_id=trace_id,
        cache_control=cache_control,
        payload=payload,
    )
    return JSONResponse(
        content=jsonable_encoder(envelope),
        headers={
            "X-Request-Id": trace_id,
            "Cache-Control": cache_control,
        },
    )


def _dashboard_overview_cache_ttl_seconds() -> int:
    raw = str(
        os.getenv(
            "RELEASEGATE_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS",
            str(DEFAULT_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS),
        )
        or str(DEFAULT_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS)
    ).strip()
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS
    return max(0, parsed)


def _dashboard_overview_cache_key(*, tenant_id: str, window_days: int, blocked_limit: int) -> str:
    return f"{tenant_id}:{int(window_days)}:{int(blocked_limit)}"


def clear_dashboard_overview_cache(*, tenant_id: Optional[str] = None) -> None:
    with _DASHBOARD_OVERVIEW_CACHE_LOCK:
        if tenant_id is None:
            _DASHBOARD_OVERVIEW_CACHE.clear()
            return
        prefix = f"{tenant_id}:"
        for key in [key for key in _DASHBOARD_OVERVIEW_CACHE if key.startswith(prefix)]:
            _DASHBOARD_OVERVIEW_CACHE.pop(key, None)


def _read_dashboard_overview_cache(*, tenant_id: str, window_days: int, blocked_limit: int) -> Optional[Dict[str, Any]]:
    ttl_seconds = _dashboard_overview_cache_ttl_seconds()
    if ttl_seconds <= 0:
        return None
    cache_key = _dashboard_overview_cache_key(
        tenant_id=tenant_id,
        window_days=window_days,
        blocked_limit=blocked_limit,
    )
    now = monotonic()
    with _DASHBOARD_OVERVIEW_CACHE_LOCK:
        cached = _DASHBOARD_OVERVIEW_CACHE.get(cache_key)
        if not cached:
            return None
        expires_at, payload = cached
        if expires_at <= now:
            _DASHBOARD_OVERVIEW_CACHE.pop(cache_key, None)
            return None
        return deepcopy(payload)


def _write_dashboard_overview_cache(
    *,
    tenant_id: str,
    window_days: int,
    blocked_limit: int,
    payload: Dict[str, Any],
) -> None:
    ttl_seconds = _dashboard_overview_cache_ttl_seconds()
    if ttl_seconds <= 0:
        return
    cache_key = _dashboard_overview_cache_key(
        tenant_id=tenant_id,
        window_days=window_days,
        blocked_limit=blocked_limit,
    )
    with _DASHBOARD_OVERVIEW_CACHE_LOCK:
        _DASHBOARD_OVERVIEW_CACHE[cache_key] = (
            monotonic() + float(ttl_seconds),
            deepcopy(payload),
        )


def _dashboard_metrics_timeseries_cache_ttl_seconds() -> int:
    raw = str(
        os.getenv(
            "RELEASEGATE_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS",
            str(DEFAULT_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS),
        )
        or str(DEFAULT_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS)
    ).strip()
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS
    return max(0, parsed)


def _dashboard_metrics_timeseries_cache_key(
    *,
    tenant_id: str,
    metric: str,
    from_ts: Optional[str],
    to_ts: Optional[str],
    window_days: int,
    bucket: str,
) -> str:
    return "|".join(
        (
            tenant_id,
            str(metric or ""),
            str(from_ts or ""),
            str(to_ts or ""),
            str(int(window_days)),
            str(bucket or ""),
        )
    )


def clear_dashboard_metrics_timeseries_cache() -> None:
    with _DASHBOARD_METRICS_TIMESERIES_CACHE_LOCK:
        _DASHBOARD_METRICS_TIMESERIES_CACHE.clear()


def _read_dashboard_metrics_timeseries_cache(
    *,
    tenant_id: str,
    metric: str,
    from_ts: Optional[str],
    to_ts: Optional[str],
    window_days: int,
    bucket: str,
) -> Optional[Dict[str, Any]]:
    ttl_seconds = _dashboard_metrics_timeseries_cache_ttl_seconds()
    if ttl_seconds <= 0:
        return None
    cache_key = _dashboard_metrics_timeseries_cache_key(
        tenant_id=tenant_id,
        metric=metric,
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
        bucket=bucket,
    )
    now = monotonic()
    with _DASHBOARD_METRICS_TIMESERIES_CACHE_LOCK:
        cached = _DASHBOARD_METRICS_TIMESERIES_CACHE.get(cache_key)
        if not cached:
            return None
        expires_at, payload = cached
        if expires_at <= now:
            _DASHBOARD_METRICS_TIMESERIES_CACHE.pop(cache_key, None)
            return None
        return deepcopy(payload)


def _write_dashboard_metrics_timeseries_cache(
    *,
    tenant_id: str,
    metric: str,
    from_ts: Optional[str],
    to_ts: Optional[str],
    window_days: int,
    bucket: str,
    payload: Dict[str, Any],
) -> None:
    ttl_seconds = _dashboard_metrics_timeseries_cache_ttl_seconds()
    if ttl_seconds <= 0:
        return
    cache_key = _dashboard_metrics_timeseries_cache_key(
        tenant_id=tenant_id,
        metric=metric,
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
        bucket=bucket,
    )
    with _DASHBOARD_METRICS_TIMESERIES_CACHE_LOCK:
        _DASHBOARD_METRICS_TIMESERIES_CACHE[cache_key] = (
            monotonic() + float(ttl_seconds),
            deepcopy(payload),
        )


def _audit_dashboard_read(
    *,
    auth: AuthContext,
    tenant_id: str,
    action: str,
    endpoint: str,
    trace_id: str,
    params: Dict[str, Any],
) -> None:
    try:
        log_security_event(
            tenant_id=tenant_id,
            principal_id=str(auth.principal_id or "system"),
            auth_method="api",
            action=action,
            target_type="dashboard",
            target_id=endpoint,
            metadata={
                "trace_id": trace_id,
                "endpoint": endpoint,
                "params": params,
            },
        )
    except Exception:
        logger.exception("Failed to write dashboard read audit event: action=%s", action)


@app.exception_handler(HTTPException)
async def releasegate_http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/dashboard/"):
        header_map = dict(exc.headers or {})
        return _dashboard_error_response(
            request=request,
            status_code=int(exc.status_code),
            detail=exc.detail,
            headers=header_map,
        )
    return await fastapi_http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def releasegate_request_validation_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/dashboard/"):
        return _dashboard_error_response(
            request=request,
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "validation_errors": exc.errors(),
            },
        )
    return await fastapi_request_validation_exception_handler(request, exc)


@app.get(
    "/dashboard/overview",
    responses=_dashboard_error_models(),
)
def dashboard_overview_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    tenant_id: Optional[str] = None,
    window_days: int = 30,
    blocked_limit: int = 25,
    include_debug_timing: bool = False,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import get_dashboard_overview

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    endpoint_started = perf_counter()
    debug_requested = bool(include_debug_timing and auth.auth_method == "internal_service")
    payload: Optional[Dict[str, Any]] = None
    if not debug_requested:
        payload = _read_dashboard_overview_cache(
            tenant_id=effective_tenant,
            window_days=window_days,
            blocked_limit=blocked_limit,
        )
    try:
        if payload is None:
            payload = get_dashboard_overview(
                tenant_id=effective_tenant,
                window_days=window_days,
                blocked_limit=blocked_limit,
                include_debug_timing=debug_requested,
            )
            if not debug_requested:
                _write_dashboard_overview_cache(
                    tenant_id=effective_tenant,
                    window_days=window_days,
                    blocked_limit=blocked_limit,
                    payload=payload,
                )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_started = perf_counter()
    background_tasks.add_task(
        _audit_dashboard_read,
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_OVERVIEW",
        endpoint="/dashboard/overview",
        trace_id=trace_id,
        params={
            "window_days": int(window_days),
            "blocked_limit": int(blocked_limit),
        },
    )
    audit_ms = round((perf_counter() - audit_started) * 1000.0, 3)
    endpoint_total_ms = round((perf_counter() - endpoint_started) * 1000.0, 3)
    if debug_requested:
        debug_timing = payload.setdefault("debug_timing_ms", {})
        debug_timing["audit_dashboard_read"] = audit_ms
        debug_timing["total_endpoint"] = endpoint_total_ms
    if debug_requested or endpoint_total_ms >= 500.0:
        logger.info(
            "Dashboard overview timings trace_id=%s tenant_id=%s total_ms=%.3f breakdown=%s",
            trace_id,
            effective_tenant,
            endpoint_total_ms,
            payload.get("debug_timing_ms") or {"audit_dashboard_read": audit_ms},
        )
    dashboard_response = _dashboard_json_response(
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=payload,
    )
    if debug_requested:
        dashboard_response.headers["X-Overview-Timing-Total-Ms"] = str(endpoint_total_ms)
    return dashboard_response


@app.get(
    "/dashboard/integrity",
    response_model=DashboardIntegrityResponse,
    responses=_dashboard_error_models(),
)
def dashboard_integrity_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    window_days: int = 30,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import list_integrity_trend

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        trend = list_integrity_trend(
            tenant_id=effective_tenant,
            window_days=window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_INTEGRITY",
        endpoint="/dashboard/integrity",
        trace_id=trace_id,
        params={"window_days": int(window_days)},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload={
        "tenant_id": effective_tenant,
        "window_days": int(window_days),
        "trend": trend,
        },
    )


@app.get(
    "/dashboard/alerts",
    response_model=DashboardAlertsResponse,
    responses=_dashboard_error_models(),
)
def dashboard_alerts_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    window_days: int = 30,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import list_dashboard_alerts

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = list_dashboard_alerts(
            tenant_id=effective_tenant,
            window_days=window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_ALERTS",
        endpoint="/dashboard/alerts",
        trace_id=trace_id,
        params={"window_days": int(window_days)},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload=payload,
    )


@app.get(
    "/dashboard/overrides/breakdown",
    response_model=DashboardOverridesBreakdownResponse,
    responses=_dashboard_error_models(),
)
def dashboard_overrides_breakdown_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    group_by: str = "actor",
    limit: int = 25,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import get_dashboard_overrides_breakdown

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_dashboard_overrides_breakdown(
            tenant_id=effective_tenant,
            from_ts=from_ts,
            to_ts=to_ts,
            group_by=group_by,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_OVERRIDES_BREAKDOWN",
        endpoint="/dashboard/overrides/breakdown",
        trace_id=trace_id,
        params={
            "from": from_ts,
            "to": to_ts,
            "group_by": str(group_by or "actor"),
            "limit": int(limit),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload=payload,
    )


@app.get(
    "/dashboard/metrics/timeseries",
    response_model=DashboardMetricsTimeseriesResponse,
    responses=_dashboard_error_models(),
)
def dashboard_metrics_timeseries_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    tenant_id: Optional[str] = None,
    metric: str = "integrity_score",
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    bucket: str = "day",
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import get_metrics_timeseries

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = _read_dashboard_metrics_timeseries_cache(
        tenant_id=effective_tenant,
        metric=metric,
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
        bucket=bucket,
    )
    try:
        if payload is None:
            payload = get_metrics_timeseries(
                tenant_id=effective_tenant,
                metric=metric,
                from_ts=from_ts,
                to_ts=to_ts,
                window_days=window_days,
                bucket=bucket,
            )
            _write_dashboard_metrics_timeseries_cache(
                tenant_id=effective_tenant,
                metric=metric,
                from_ts=from_ts,
                to_ts=to_ts,
                window_days=window_days,
                bucket=bucket,
                payload=payload,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(
        _audit_dashboard_read,
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_METRICS_TIMESERIES",
        endpoint="/dashboard/metrics/timeseries",
        trace_id=trace_id,
        params={
            "metric": str(metric or "integrity_score"),
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
            "bucket": str(bucket or "day"),
        },
    )
    return _dashboard_json_response(
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=payload,
    )


@app.get(
    "/dashboard/metrics/summary",
    response_model=DashboardMetricsSummaryResponse,
    responses=_dashboard_error_models(),
)
def dashboard_metrics_summary_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import get_metrics_summary

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_metrics_summary(
            tenant_id=effective_tenant,
            from_ts=from_ts,
            to_ts=to_ts,
            window_days=window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_METRICS_SUMMARY",
        endpoint="/dashboard/metrics/summary",
        trace_id=trace_id,
        params={
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=payload,
    )


@app.get(
    "/dashboard/metrics/drilldown",
    response_model=DashboardMetricsDrilldownResponse,
    responses=_dashboard_error_models(),
)
def dashboard_metrics_drilldown_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    metric: str = "block_frequency",
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    limit: int = 50,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import get_metrics_drilldown

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_metrics_drilldown(
            tenant_id=effective_tenant,
            metric=metric,
            from_ts=from_ts,
            to_ts=to_ts,
            window_days=window_days,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_METRICS_DRILLDOWN",
        endpoint="/dashboard/metrics/drilldown",
        trace_id=trace_id,
        params={
            "metric": str(metric or "block_frequency"),
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
            "limit": int(limit),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=15",
        payload=payload,
    )


@app.get(
    "/dashboard/customer_success/risk_trend",
    response_model=DashboardCustomerSuccessRiskTrendResponse,
    responses=_dashboard_error_models(),
)
def dashboard_customer_success_risk_trend_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.customer_success import get_customer_success_risk_trend

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_customer_success_risk_trend(
            tenant_id=effective_tenant,
            from_ts=from_ts,
            to_ts=to_ts,
            window_days=window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_CUSTOMER_SUCCESS_RISK_TREND",
        endpoint="/dashboard/customer_success/risk_trend",
        trace_id=trace_id,
        params={
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload=payload,
    )


@app.get(
    "/dashboard/customer_success/override_analysis",
    response_model=DashboardCustomerSuccessOverrideAnalysisResponse,
    responses=_dashboard_error_models(),
)
def dashboard_customer_success_override_analysis_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    top_users_limit: int = 10,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.customer_success import get_customer_success_override_analysis

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_customer_success_override_analysis(
            tenant_id=effective_tenant,
            from_ts=from_ts,
            to_ts=to_ts,
            window_days=window_days,
            top_users_limit=top_users_limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_CUSTOMER_SUCCESS_OVERRIDE_ANALYSIS",
        endpoint="/dashboard/customer_success/override_analysis",
        trace_id=trace_id,
        params={
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
            "top_users_limit": int(top_users_limit),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload=payload,
    )


@app.get(
    "/dashboard/customer_success/regression_report",
    response_model=DashboardCustomerSuccessRegressionReportResponse,
    responses=_dashboard_error_models(),
)
def dashboard_customer_success_regression_report_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    window_days: int = 30,
    correlation_window_hours: int = 48,
    drop_threshold: float = 10.0,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.customer_success import get_customer_success_regression_report

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        payload = get_customer_success_regression_report(
            tenant_id=effective_tenant,
            from_ts=from_ts,
            to_ts=to_ts,
            window_days=window_days,
            correlation_window_hours=correlation_window_hours,
            drop_threshold=drop_threshold,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_CUSTOMER_SUCCESS_REGRESSION_REPORT",
        endpoint="/dashboard/customer_success/regression_report",
        trace_id=trace_id,
        params={
            "from": from_ts,
            "to": to_ts,
            "window_days": int(window_days),
            "correlation_window_hours": int(correlation_window_hours),
            "drop_threshold": float(drop_threshold),
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=60",
        payload=payload,
    )


@app.get("/governance/recommendations")
def governance_recommendations_endpoint(
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 25,
    lookback_days: int = 30,
    refresh: bool = False,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.recommendations.engine import get_or_generate_recommendations

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = get_or_generate_recommendations(
        tenant_id=effective_tenant,
        lookback_days=max(1, min(int(lookback_days or 30), 365)),
        force_refresh=bool(refresh),
        status=status,
        limit=_bounded_limit(limit, max_allowed=200, field="limit"),
    )
    return payload


@app.post("/governance/recommendations/ack")
def governance_recommendations_ack_endpoint(
    payload: RecommendationAcknowledgeRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.recommendations.engine import acknowledge_recommendation

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        recommendation = acknowledge_recommendation(
            tenant_id=effective_tenant,
            recommendation_id=payload.recommendation_id,
            actor_id=auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "recommendation": recommendation,
    }


@app.get(
    "/dashboard/tenant/info",
    response_model=DashboardTenantInfoResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_info_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.saas.tenants import get_tenant_profile

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = get_tenant_profile(tenant_id=effective_tenant)
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_TENANT_INFO",
        endpoint="/dashboard/tenant/info",
        trace_id=trace_id,
        params={},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=payload,
    )


@app.post(
    "/dashboard/tenant/create",
    response_model=DashboardTenantInfoResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_create_endpoint(
    request: Request,
    response: Response,
    payload: DashboardTenantCreateRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.saas.tenants import create_tenant_profile

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        tenant_payload = create_tenant_profile(
            tenant_id=effective_tenant,
            name=payload.name,
            plan=payload.plan,
            region=payload.region,
            actor_id=auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="dashboard_tenant_create_or_update",
        target_type="tenant_profile",
        target_id=effective_tenant,
        metadata={"plan": payload.plan, "region": payload.region},
    )

    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=tenant_payload,
    )


@app.post(
    "/dashboard/tenant/lock",
    response_model=DashboardTenantInfoResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_lock_endpoint(
    request: Request,
    response: Response,
    payload: DashboardTenantLockRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
        allow_locked=True,
    ),
):
    from releasegate.saas.tenants import set_tenant_status

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        tenant_payload = set_tenant_status(
            tenant_id=effective_tenant,
            status=payload.status,
            reason=payload.reason,
            actor_id=auth.principal_id,
            source="dashboard_tenant_lock",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="dashboard_tenant_status_set",
        target_type="tenant_security_state",
        target_id=effective_tenant,
        metadata={"status": payload.status, "reason": payload.reason},
    )

    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=tenant_payload,
    )


@app.post(
    "/dashboard/tenant/unlock",
    response_model=DashboardTenantInfoResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_unlock_endpoint(
    request: Request,
    response: Response,
    payload: DashboardTenantUnlockRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
        allow_locked=True,
    ),
):
    from releasegate.saas.tenants import set_tenant_status

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    tenant_payload = set_tenant_status(
        tenant_id=effective_tenant,
        status="active",
        reason=payload.reason,
        actor_id=auth.principal_id,
        source="dashboard_tenant_unlock",
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="dashboard_tenant_unlock",
        target_type="tenant_security_state",
        target_id=effective_tenant,
        metadata={"reason": payload.reason},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=tenant_payload,
    )


@app.post(
    "/dashboard/tenant/role_assign",
    response_model=DashboardTenantInfoResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_role_assign_endpoint(
    request: Request,
    response: Response,
    payload: DashboardTenantRoleAssignRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.saas.tenants import assign_tenant_role

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        tenant_payload = assign_tenant_role(
            tenant_id=effective_tenant,
            actor_id=payload.actor_id,
            role=payload.role,
            action=payload.action,
            assigned_by=auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="dashboard_tenant_role_assignment",
        target_type="tenant_role_assignment",
        target_id=payload.actor_id,
        metadata={"role": payload.role, "action": payload.action},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=tenant_payload,
    )


@app.post(
    "/dashboard/tenant/key_rotate",
    response_model=DashboardTenantKeyRotateResponse,
    responses=_dashboard_error_models(),
)
def dashboard_tenant_key_rotate_endpoint(
    request: Request,
    response: Response,
    payload: DashboardTenantKeyRotateRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.saas.tenants import rotate_tenant_keys

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        rotation_payload = rotate_tenant_keys(
            tenant_id=effective_tenant,
            actor_id=auth.principal_id,
            rotate_signing_key=payload.rotate_signing_key,
            rotate_api_key_enabled=payload.rotate_api_key,
            api_key_id=payload.api_key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="dashboard_tenant_keys_rotate",
        target_type="tenant_keys",
        target_id=effective_tenant,
        metadata={
            "rotate_signing_key": payload.rotate_signing_key,
            "rotate_api_key": payload.rotate_api_key,
            "rotated_signing_key_id": rotation_payload.get("rotated_signing_key_id"),
            "rotated_api_key_id": rotation_payload.get("rotated_api_key_id"),
            "api_key_created": bool(rotation_payload.get("api_key_created")),
        },
    )

    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=rotation_payload,
    )


@app.get(
    "/dashboard/billing/usage",
    response_model=DashboardBillingUsageResponse,
    responses=_dashboard_error_models(),
)
def dashboard_billing_usage_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.saas.quotas import get_billing_usage

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    usage_payload = get_billing_usage(tenant_id=effective_tenant)
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_BILLING_USAGE",
        endpoint="/dashboard/billing/usage",
        trace_id=trace_id,
        params={},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=usage_payload,
    )


@app.get(
    "/dashboard/blocked",
    response_model=DashboardBlockedResponse,
    responses=_dashboard_error_models(),
)
def dashboard_blocked_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import list_recent_blocked_decisions_page

    effective_tenant = _effective_tenant(auth, tenant_id)
    bounded_limit = _bounded_limit(limit, max_allowed=100, field="limit")
    trace_id = _dashboard_trace_id(request)
    try:
        page = list_recent_blocked_decisions_page(
            tenant_id=effective_tenant,
            limit=bounded_limit,
            cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_BLOCKED",
        endpoint="/dashboard/blocked",
        trace_id=trace_id,
        params={
            "limit": int(bounded_limit),
            "cursor": str(cursor or "") or None,
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=10",
        payload={
        "tenant_id": effective_tenant,
        "items": page.get("items") if isinstance(page.get("items"), list) else [],
        "next_cursor": page.get("next_cursor"),
        },
    )


@app.get(
    "/dashboard/strict-modes",
    response_model=DashboardStrictModesResponse,
    responses=_dashboard_error_models(),
)
def dashboard_strict_modes_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.dashboard_metrics import list_active_strict_modes

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = {
        "tenant_id": effective_tenant,
        "items": list_active_strict_modes(tenant_id=effective_tenant),
    }
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_STRICT_MODES",
        endpoint="/dashboard/strict-modes",
        trace_id=trace_id,
        params={},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, max-age=30",
        payload=payload,
    )


@app.get(
    "/dashboard/decisions/{decision_id}/explainer",
    response_model=DashboardDecisionExplainResponse,
    responses=_dashboard_error_models(),
)
def dashboard_decision_explainer_endpoint(
    request: Request,
    response: Response,
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.decision_explainer import build_decision_explainer

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = build_decision_explainer(
        tenant_id=effective_tenant,
        decision_id=decision_id,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="decision_not_found")
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_DECISION_EXPLAIN",
        endpoint="/dashboard/decisions/{decision_id}/explainer",
        trace_id=trace_id,
        params={"decision_id": decision_id},
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=payload,
    )


@app.post(
    "/dashboard/policies/diff",
    response_model=DashboardPolicyDiffResponse,
    responses=_dashboard_error_models(),
)
def dashboard_policy_diff_endpoint(
    request: Request,
    response: Response,
    payload: PolicyDiffImpactRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.governance.policy_diff_visual import build_policy_diff_visual
    from releasegate.policy.diff_impact import build_policy_impact_diff

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        raw = build_policy_impact_diff(
            tenant_id=effective_tenant,
            current_policy_id=payload.current_policy_id,
            current_policy_version=payload.current_policy_version,
            current_policy_json=payload.current_policy_json,
            candidate_policy_id=payload.candidate_policy_id,
            candidate_policy_version=payload.candidate_policy_version,
            candidate_policy_json=payload.candidate_policy_json,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    trace_id = _dashboard_trace_id(request)
    response_payload = build_policy_diff_visual(raw)
    _audit_dashboard_read(
        auth=auth,
        tenant_id=effective_tenant,
        action="DASHBOARD_READ_POLICY_DIFF",
        endpoint="/dashboard/policies/diff",
        trace_id=trace_id,
        params={
            "current_policy_id": payload.current_policy_id,
            "current_policy_version": payload.current_policy_version,
            "candidate_policy_id": payload.candidate_policy_id,
            "candidate_policy_version": payload.candidate_policy_version,
        },
    )
    return _dashboard_response(
        response=response,
        trace_id=trace_id,
        cache_control="private, no-store",
        payload=response_payload,
    )


@app.post("/internal/dashboard/rollups/backfill")
def dashboard_rollups_backfill_endpoint(
    days: int = 30,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="heavy",
    ),
):
    from releasegate.governance.dashboard_metrics import backfill_rollups

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        result = backfill_rollups(
            tenant_id=effective_tenant,
            days=days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        **result,
    }


@app.get("/onboarding/status", response_model=OnboardingStatusResponse)
def onboarding_status_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import get_onboarding_status

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = get_onboarding_status(tenant_id=effective_tenant)
    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": payload,
    }


@app.post("/onboarding/setup", response_model=OnboardingSetupResponse)
def onboarding_setup_endpoint(
    request: Request,
    response: Response,
    payload: OnboardingSetupRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import save_onboarding_config

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        status_payload = save_onboarding_config(
            tenant_id=effective_tenant,
            jira_instance_id=payload.jira_instance_id,
            project_keys=payload.project_keys,
            workflow_ids=payload.workflow_ids,
            transition_ids=payload.transition_ids,
            mode=payload.mode,
            canary_pct=payload.canary_pct,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": status_payload,
    }


@app.get("/onboarding/activation", response_model=OnboardingActivationResponse)
def onboarding_activation_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import get_onboarding_activation

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    payload = get_onboarding_activation(tenant_id=effective_tenant)
    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": payload,
    }


@app.post("/onboarding/activation", response_model=OnboardingActivationResponse)
def onboarding_activation_update_endpoint(
    request: Request,
    response: Response,
    payload: OnboardingActivationRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import save_onboarding_activation

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        activation_payload = save_onboarding_activation(
            tenant_id=effective_tenant,
            mode=payload.mode,
            canary_pct=payload.canary_pct,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="onboarding_activation_apply",
        target_type="onboarding",
        target_id=effective_tenant,
        metadata={
            "mode": activation_payload.get("mode"),
            "canary_pct": activation_payload.get("canary_pct"),
        },
    )

    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": activation_payload,
    }


@app.get("/onboarding/activation/history", response_model=OnboardingActivationHistoryResponse)
def onboarding_activation_history_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    limit: int = 20,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import get_onboarding_activation_history

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        history_payload = get_onboarding_activation_history(
            tenant_id=effective_tenant,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": history_payload,
    }


@app.post("/onboarding/activation/rollback", response_model=OnboardingActivationRollbackResponse)
def onboarding_activation_rollback_endpoint(
    request: Request,
    response: Response,
    payload: OnboardingActivationRollbackRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["policy:write"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.service import rollback_onboarding_activation

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        activation_payload = rollback_onboarding_activation(tenant_id=effective_tenant)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="onboarding_activation_rollback",
        target_type="onboarding",
        target_id=effective_tenant,
        metadata={
            "mode": (activation_payload.get("activation") or {}).get("mode"),
            "canary_pct": (activation_payload.get("activation") or {}).get("canary_pct"),
            "status": activation_payload.get("status"),
        },
    )

    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": activation_payload,
    }


@app.post("/simulation/run", response_model=SimulationRunResponse)
def simulation_run_endpoint(
    request: Request,
    response: Response,
    payload: SimulationRunRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="heavy",
    ),
):
    from releasegate.onboarding.simulation import run_historical_simulation
    from releasegate.saas.plans import get_plan_tier
    from releasegate.saas.tenants import get_tenant_profile

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    trace_id = _dashboard_trace_id(request)
    profile = get_tenant_profile(tenant_id=effective_tenant)
    plan = get_plan_tier(profile.get("plan"))
    if int(payload.lookback_days) > int(plan.simulation_history_days):
        raise HTTPException(
            status_code=400,
            detail=f"lookback_days exceeds plan limit ({plan.simulation_history_days} days for {plan.name})",
        )
    try:
        result = run_historical_simulation(
            tenant_id=effective_tenant,
            lookback_days=payload.lookback_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="onboarding_simulation_run",
        target_type="onboarding",
        target_id=effective_tenant,
        metadata={
            "lookback_days": int(result.get("lookback_days") or payload.lookback_days),
            "total_transitions": int(result.get("total_transitions") or 0),
            "blocked": int(result.get("blocked") or 0),
            "override_required": int(result.get("override_required") or 0),
        },
    )

    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": result,
    }


@app.get("/simulation/last", response_model=SimulationRunResponse)
def simulation_last_endpoint(
    request: Request,
    response: Response,
    tenant_id: Optional[str] = None,
    lookback_days: int = 30,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        allow_internal_service=True,
        rate_profile="default",
    ),
):
    from releasegate.onboarding.simulation import get_last_historical_simulation

    effective_tenant = _effective_tenant(auth, tenant_id)
    trace_id = _dashboard_trace_id(request)
    try:
        result = get_last_historical_simulation(
            tenant_id=effective_tenant,
            lookback_days=lookback_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    response.headers["X-Request-Id"] = trace_id
    response.headers["Cache-Control"] = "private, no-store"
    return {
        "generated_at": _dashboard_generated_at(),
        "trace_id": trace_id,
        "data": result,
    }


@app.get("/governance/decisions")
def governance_decision_archive(
    tenant_id: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    decision_status: Optional[str] = None,
    risk_min: Optional[float] = None,
    risk_max: Optional[float] = None,
    risk_band: Optional[str] = None,
    override_used: Optional[bool] = None,
    workflow_id: Optional[str] = None,
    transition_id: Optional[str] = None,
    actor: Optional[str] = None,
    environment: Optional[str] = None,
    project_key: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.governance.governance_query import DecisionArchiveFilters, search_decisions

    effective_tenant = _effective_tenant(auth, tenant_id)
    bounded_limit = _bounded_limit(limit, max_allowed=500, field="limit")
    try:
        payload = search_decisions(
            tenant_id=effective_tenant,
            filters=DecisionArchiveFilters(
                from_ts=from_ts,
                to_ts=to_ts,
                decision_status=decision_status,
                risk_min=risk_min,
                risk_max=risk_max,
                risk_band=risk_band,
                override_used=override_used,
                workflow_id=workflow_id,
                transition_id=transition_id,
                actor=actor,
                environment=environment,
                project_key=project_key,
            ),
            limit=bounded_limit,
            cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "tenant_id": effective_tenant,
        "results": payload.get("results") or [],
        "next_cursor": payload.get("next_cursor"),
        "truncated": bool(payload.get("truncated")),
    }


@app.get("/governance/decisions/{decision_id}/graph")
def governance_decision_graph(
    decision_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.governance.audit_graph import build_decision_graph

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = build_decision_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Decision graph not found")
    return payload


@app.post("/governance/export")
def governance_export_bundle(
    payload: GovernanceExportRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.governance.governance_export import (
        build_governance_export,
        cleanup_export_artifact,
    )

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        artifact = build_governance_export(
            tenant_id=effective_tenant,
            export_type=payload.type,
            year=payload.year,
            quarter=payload.quarter,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="governance_export",
        target_type="tenant_governance_export",
        target_id=effective_tenant,
        metadata={
            "type": str(payload.type).lower(),
            "year": payload.year,
            "quarter": payload.quarter,
            "archive_name": artifact.archive_name,
        },
    )

    return FileResponse(
        path=artifact.archive_path,
        media_type="application/zip",
        filename=artifact.archive_name,
        background=BackgroundTask(cleanup_export_artifact, artifact.temp_dir),
        headers={
            "X-Export-Version": str(artifact.manifest.get("export_version") or ""),
            "X-Range-Start": str(artifact.manifest.get("range_start") or ""),
            "X-Range-End-Exclusive": str(artifact.manifest.get("range_end_exclusive") or ""),
        },
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


@app.post("/policies/simulate")
def simulate_policy_endpoint(
    payload: PolicySimulateRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.policy.simulate_service import simulate_policy_decision

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = simulate_policy_decision(
            tenant_id=effective_tenant,
            actor=payload.actor or auth.principal_id,
            issue_key=payload.issue_key,
            transition_id=payload.transition_id,
            project_id=payload.project_id,
            workflow_id=payload.workflow_id,
            environment=payload.environment,
            context=payload.context,
            policy_id=payload.policy_id,
            policy_version=payload.policy_version,
            policy_json=payload.policy_json,
            status_filter=payload.status_filter,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_simulate",
        target_type="policy_registry",
        target_id=str(payload.policy_id or "resolved"),
        metadata={
            "simulation_id": result.get("simulation_id"),
            "status": result.get("status"),
            "allow": result.get("allow"),
            "policy_version": payload.policy_version,
        },
    )
    return result


@app.post("/policies/simulate-historical")
def simulate_historical_policy_endpoint(
    payload: PolicySimulateHistoricalRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="heavy",
    ),
):
    from releasegate.policy.historical_simulation import simulate_historical_policy_impact

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = simulate_historical_policy_impact(
            tenant_id=effective_tenant,
            actor=payload.actor or auth.principal_id,
            policy_id=payload.policy_id,
            policy_version=payload.policy_version,
            policy_json=payload.policy_json,
            time_window_days=payload.time_window_days,
            transition_id=payload.transition_id,
            project_key=payload.project_key,
            workflow_id=payload.workflow_id,
            environment=payload.environment,
            only_protected=payload.only_protected,
            max_events=payload.max_events,
            top_n=payload.top_n,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_simulate_historical",
        target_type="policy_registry",
        target_id=str(payload.policy_id or "candidate"),
        metadata={
            "simulation_id": result.get("simulation_id"),
            "policy_version": payload.policy_version,
            "time_window_days": payload.time_window_days,
            "scanned_events": result.get("scanned_events"),
            "simulated_events": result.get("simulated_events"),
            "would_block_count": result.get("would_block_count"),
            "override_delta": result.get("override_delta"),
            "truncated": result.get("truncated"),
        },
    )
    return result


@app.post("/policies/diff-impact")
def policy_diff_impact_endpoint(
    payload: PolicyDiffImpactRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.diff_impact import build_policy_impact_diff

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = build_policy_impact_diff(
            tenant_id=effective_tenant,
            current_policy_id=payload.current_policy_id,
            current_policy_version=payload.current_policy_version,
            current_policy_json=payload.current_policy_json,
            candidate_policy_id=payload.candidate_policy_id,
            candidate_policy_version=payload.candidate_policy_version,
            candidate_policy_json=payload.candidate_policy_json,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_diff_impact",
        target_type="policy_registry",
        target_id=str(payload.candidate_policy_id or "candidate"),
        metadata={
            "report_id": result.get("report_id"),
            "overall": result.get("overall"),
            "warning_count": ((result.get("summary") or {}).get("warning_count")),
            "strengthening_count": ((result.get("summary") or {}).get("strengthening_count")),
        },
    )
    return result


@app.post("/simulate-decision")
def simulate_decision_endpoint(
    payload: SimulateDecisionRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
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
            status_filter=payload.status_filter,
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
    independent_checkpoint = None
    transparency_merkle_proof = None
    approvals_snapshot: Dict[str, Any] = {}
    ledger_segment = []
    period_id = None
    external_anchor = None
    anchor_date = ""

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

    raw_approvals = decision_snapshot.get("approvals")
    if isinstance(raw_approvals, dict):
        approvals_snapshot = dict(raw_approvals)
    elif isinstance(raw_approvals, list):
        approvals_snapshot = {"items": raw_approvals}
    else:
        input_snapshot = decision_snapshot.get("input_snapshot")
        if isinstance(input_snapshot, dict):
            for key in ("approvals", "approval_snapshot", "approval_events"):
                value = input_snapshot.get(key)
                if isinstance(value, dict):
                    approvals_snapshot = dict(value)
                    break
                if isinstance(value, list):
                    approvals_snapshot = {"items": value}
                    break

    attestation_id = str(decision_snapshot.get("attestation_id") or "").strip()
    if attestation_id:
        try:
            from releasegate.audit.transparency import get_transparency_inclusion_proof

            transparency_merkle_proof = get_transparency_inclusion_proof(
                attestation_id=attestation_id,
                tenant_id=effective_tenant,
            )
        except Exception:
            transparency_merkle_proof = None

    if isinstance(created_at, str):
        anchor_date = created_at[:10]
    elif isinstance(created_at, datetime):
        anchor_date = created_at.astimezone(timezone.utc).date().isoformat()

    try:
        from releasegate.anchoring.roots import get_root_anchor_for_date

        if anchor_date:
            external_anchor = get_root_anchor_for_date(
                date_utc=anchor_date,
                tenant_id=effective_tenant,
            )
    except Exception:
        external_anchor = None

    if anchor_date:
        try:
            from releasegate.anchoring.independent_checkpoints import get_independent_daily_checkpoint

            independent_checkpoint = get_independent_daily_checkpoint(
                date_utc=anchor_date,
                tenant_id=effective_tenant,
            )
        except Exception:
            independent_checkpoint = None

    external_anchor_reference = {}
    if isinstance(independent_checkpoint, dict):
        anchor_payload = independent_checkpoint.get("external_anchor")
        if isinstance(anchor_payload, dict):
            external_anchor_reference = {
                "provider": str(anchor_payload.get("provider") or ""),
                "external_ref": str(anchor_payload.get("external_ref") or ""),
                "date_utc": anchor_date,
            }
    if not external_anchor_reference and isinstance(external_anchor, dict):
        external_anchor_reference = {
            "provider": str(external_anchor.get("provider") or ""),
            "external_ref": str(
                external_anchor.get("external_ref")
                or external_anchor.get("anchor_id")
                or ""
            ),
            "date_utc": str(external_anchor.get("date_utc") or anchor_date or ""),
        }

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

    from releasegate.evidence.graph import build_decision_compliance_graph, record_proof_pack_evidence

    replay_request = {
        "method": "POST",
        "endpoint": f"/decisions/{decision_id}/replay",
        "query": {"tenant_id": effective_tenant},
        "body": None,
    }
    evidence_graph = build_decision_compliance_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        max_depth=3,
        decision_snapshot=decision_snapshot,
        override_snapshot=override_snapshot,
        checkpoint_snapshot=checkpoint_snapshot,
        chain_proof=chain_proof,
        replay_request=replay_request,
        proof_pack_id=proof_pack_id,
        external_anchor_snapshot=external_anchor if external_anchor else external_anchor_reference,
    )
    graph_hash = str(evidence_graph.get("graph_hash") or "")

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
            graph_hash=graph_hash,
        ),
        "decision_id": decision_id,
        "attestation_id": decision_snapshot.get("attestation_id"),
        "repo": repo,
        "pr_number": pr_number,
        "decision_snapshot": decision_snapshot,
        "policy_snapshot": decision_snapshot.get("policy_bindings", []),
        "approvals_snapshot": approvals_snapshot,
        "input_snapshot": decision_snapshot.get("input_snapshot", {}),
        "override_snapshot": override_snapshot,
        "override_history": ledger_segment,
        "ledger_segment": ledger_segment,
        "checkpoint_snapshot": checkpoint_snapshot,
        "independent_checkpoint": independent_checkpoint,
        "chain_proof": chain_proof,
        "checkpoint_proof": checkpoint_proof,
        "merkle_proof": transparency_merkle_proof,
        "external_anchor": external_anchor,
        "external_anchor_ref": external_anchor_reference,
        "evidence_graph": evidence_graph,
        "replay_request": replay_request,
    }
    export_checksum = sha256_json(bundle)
    in_toto_statement = None
    dsse_envelope = None
    dsse_error = None
    try:
        from releasegate.attestation import build_proof_pack_statement
        from releasegate.attestation.crypto import (
            MissingSigningKeyError,
            sign_message_for_tenant,
        )
        from releasegate.attestation.dsse import wrap_dsse_with_signer

        in_toto_statement = build_proof_pack_statement(bundle, export_checksum=export_checksum)
        try:
            dsse_envelope = wrap_dsse_with_signer(
                in_toto_statement,
                signer=lambda message: sign_message_for_tenant(
                    effective_tenant,
                    message,
                    purpose="proof_pack_dsse_signing",
                    actor="system:proof_pack",
                ),
            )
        except MissingSigningKeyError as exc:
            dsse_error = {"error_code": "MISSING_SIGNING_KEY", "message": str(exc)}
    except Exception as exc:
        dsse_error = {"error_code": "DSSE_BUILD_FAILED", "message": str(exc)}

    record_proof_pack_evidence(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        proof_pack_id=proof_pack_id,
        output_format="json" if format.lower() == "json" else "zip",
        export_checksum=export_checksum,
        checkpoint_id=checkpoint_id or None,
        checkpoint_hash=str(
            ((checkpoint_snapshot or {}).get("integrity") or {}).get("checkpoint_hash")
            or (checkpoint_snapshot or {}).get("checkpoint_hash")
            or ""
        )
        or None,
        graph_hash=graph_hash or None,
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
        if isinstance(in_toto_statement, dict):
            payload["in_toto_statement"] = in_toto_statement
        if isinstance(dsse_envelope, dict):
            payload["dsse_envelope"] = dsse_envelope
        if isinstance(dsse_error, dict):
            payload["dsse_error"] = dsse_error
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
        "approvals.json": bundle["approvals_snapshot"],
        "chain_proof.json": bundle["chain_proof"],
        "checkpoint_proof.json": bundle["checkpoint_proof"],
        "checkpoint_snapshot.json": bundle["checkpoint_snapshot"],
        "independent_checkpoint.json": bundle["independent_checkpoint"],
        "decision_snapshot.json": bundle["decision_snapshot"],
        "input_snapshot.json": bundle["input_snapshot"],
        "ledger_segment.json": bundle["ledger_segment"],
        "override_history.json": bundle["override_history"],
        "merkle_proof.json": bundle["merkle_proof"],
        "override_snapshot.json": bundle["override_snapshot"],
        "policy_snapshot.json": bundle["policy_snapshot"],
        "external_anchor.json": bundle["external_anchor"],
        "external_anchor_ref.json": bundle["external_anchor_ref"],
        "evidence_graph.json": bundle["evidence_graph"],
        "replay_request.json": bundle["replay_request"],
    }
    if isinstance(in_toto_statement, dict):
        zip_entries["in_toto_statement.json"] = in_toto_statement
    if isinstance(dsse_envelope, dict):
        zip_entries["dsse_envelope.json"] = dsse_envelope
    if isinstance(dsse_error, dict):
        zip_entries["dsse_error.json"] = dsse_error
    independent_sig = (
        (bundle.get("independent_checkpoint") or {}).get("signature")
        if isinstance(bundle.get("independent_checkpoint"), dict)
        else {}
    )
    if isinstance(independent_sig, dict):
        public_key = str(independent_sig.get("public_key") or "").strip()
        if public_key:
            zip_entries["checkpoint_public_key.json"] = {
                "algorithm": str(independent_sig.get("algorithm") or "").strip().lower(),
                "key_id": str(independent_sig.get("key_id") or "").strip(),
                "public_key": public_key,
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


@app.get("/decisions/{decision_id}/proof-bundle")
def export_decision_proof_bundle_alias(
    decision_id: str,
    tenant_id: Optional[str] = None,
    checkpoint_cadence: str = "daily",
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["proofpack:read", "checkpoint:read", "policy:read"],
        rate_profile="heavy",
    ),
):
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
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="failed_override_attempt",
                operation="manual_override_create",
                details={
                    "reason_code": validation.reason_code,
                    "status_code": status_code,
                },
                actor=auth.principal_id,
            )
        except Exception:
            pass
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
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="failed_override_attempt",
                operation="manual_override_create",
                details={
                    "reason_code": reason_code,
                    "status_code": 403,
                    "sod_rule": sod_violation.get("rule"),
                },
                actor=auth.principal_id,
            )
        except Exception:
            pass
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
        if isinstance(claim.response, dict) and claim.response.get("_error_status_code"):
            raise HTTPException(
                status_code=int(claim.response.get("_error_status_code") or 400),
                detail=claim.response.get("detail"),
            )
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
            try:
                record_anomaly_event(
                    tenant_id=effective_tenant,
                    signal_type="failed_override_attempt",
                    operation="manual_override_create",
                    details={
                        "reason_code": "ACTIVE_OVERRIDE_EXISTS",
                        "status_code": 409,
                        "target_type": effective_target_type,
                    },
                    actor=auth.principal_id,
                )
            except Exception:
                pass
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

    try:
        consume_tenant_quota(
            tenant_id=effective_tenant,
            quota_kind=QUOTA_KIND_OVERRIDES,
            amount=1,
        )
    except TenantQuotaExceededError as exc:
        cancel_idempotency_claim(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idempotency_key,
        )
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="quota_bypass_attempt",
                operation=operation,
                details=exc.to_http_detail(),
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(status_code=429, detail=exc.to_http_detail()) from exc

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
    from releasegate.policy.registry import PolicyConflictError, create_registry_policy

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
    except PolicyConflictError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_create",
                details={
                    "error_code": exc.code,
                    "scope_type": exc.scope_type,
                    "scope_id": exc.scope_id,
                    "stage": exc.stage,
                },
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": exc.code,
                "scope_type": exc.scope_type,
                "scope_id": exc.scope_id,
                "stage": exc.stage,
                "conflicts": exc.conflicts,
            },
        ) from exc
    except ValueError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_create",
                details={"error": str(exc)},
                actor=auth.principal_id,
            )
        except Exception:
            pass
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


@app.get("/policies/{policy_id}/conflicts")
def analyze_registry_policy_conflicts_endpoint(
    policy_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.conflict_engine import analyze_policy_conflicts
    from releasegate.policy.registry import get_registry_policy

    effective_tenant = _effective_tenant(auth, tenant_id)
    policy = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy_json = policy.get("policy_json") if isinstance(policy.get("policy_json"), dict) else {}
    analysis = analyze_policy_conflicts(policy_json)
    return {
        "tenant_id": effective_tenant,
        "policy_id": policy_id,
        "policy_hash": policy.get("policy_hash"),
        "analysis": analysis,
    }


@app.post("/policies/conflicts/analyze")
def analyze_policy_conflicts_endpoint(
    payload: PolicyConflictAnalyzeRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.conflict_engine import analyze_policy_conflicts
    from releasegate.policy.registry import get_registry_policy

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    policy_json = payload.policy_json if isinstance(payload.policy_json, dict) else None
    policy_hash = None
    policy_id = payload.policy_id

    if policy_json is None:
        if not policy_id:
            raise HTTPException(status_code=400, detail="policy_id or policy_json is required")
        policy = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        policy_json = policy.get("policy_json") if isinstance(policy.get("policy_json"), dict) else {}
        policy_hash = policy.get("policy_hash")

    analysis = analyze_policy_conflicts(policy_json)
    return {
        "tenant_id": effective_tenant,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "analysis": analysis,
    }


@app.get("/policies/{policy_id}/events")
def list_registry_policy_events_endpoint(
    policy_id: str,
    tenant_id: Optional[str] = None,
    limit: int = 100,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.policy.store import list_registry_events

    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "policy_id": policy_id,
        "events": list_registry_events(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            limit=max(1, min(limit, 500)),
        ),
    }


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
    from releasegate.policy.registry import PolicyConflictError, activate_registry_policy

    activate_payload = payload or PolicyRegistryActivateRequest()
    effective_tenant = _effective_tenant(auth, activate_payload.tenant_id)
    try:
        activated = activate_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=activate_payload.actor_id or auth.principal_id,
        )
    except PolicyConflictError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_activate",
                details={
                    "error_code": exc.code,
                    "scope_type": exc.scope_type,
                    "scope_id": exc.scope_id,
                    "stage": exc.stage,
                },
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": exc.code,
                "scope_type": exc.scope_type,
                "scope_id": exc.scope_id,
                "stage": exc.stage,
                "conflicts": exc.conflicts,
            },
        ) from exc
    except ValueError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_activate",
                details={"error": str(exc)},
                actor=auth.principal_id,
            )
        except Exception:
            pass
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


@app.post("/policies/{policy_id}/stage")
def stage_registry_policy_endpoint(
    policy_id: str,
    payload: Optional[PolicyRegistryStageRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import PolicyConflictError, stage_registry_policy

    stage_payload = payload or PolicyRegistryStageRequest()
    effective_tenant = _effective_tenant(auth, stage_payload.tenant_id)
    try:
        staged = stage_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=stage_payload.actor_id or auth.principal_id,
        )
    except PolicyConflictError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_stage",
                details={
                    "error_code": exc.code,
                    "scope_type": exc.scope_type,
                    "scope_id": exc.scope_id,
                    "stage": exc.stage,
                },
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": exc.code,
                "scope_type": exc.scope_type,
                "scope_id": exc.scope_id,
                "stage": exc.stage,
                "conflicts": exc.conflicts,
            },
        ) from exc
    except ValueError as exc:
        try:
            record_anomaly_event(
                tenant_id=effective_tenant,
                signal_type="policy_tamper_attempt",
                operation="policy_registry_stage",
                details={"error": str(exc)},
                actor=auth.principal_id,
            )
        except Exception:
            pass
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_registry_stage",
        target_type="policy_registry",
        target_id=policy_id,
        metadata={"scope_type": staged.get("scope_type"), "scope_id": staged.get("scope_id")},
    )
    return staged


@app.post("/policies/{policy_id}/rollback")
def rollback_registry_policy_endpoint(
    policy_id: str,
    payload: Optional[PolicyRegistryRollbackRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.policy.registry import rollback_registry_policy

    rollback_payload = payload or PolicyRegistryRollbackRequest()
    effective_tenant = _effective_tenant(auth, rollback_payload.tenant_id)
    try:
        restored = rollback_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=rollback_payload.actor_id or auth.principal_id,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_registry_rollback",
        target_type="policy_registry",
        target_id=policy_id,
        metadata={"restored_policy_id": restored.get("policy_id")},
    )
    return restored


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
    rollout_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import resolve_effective_policy_release

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = resolve_effective_policy_release(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        target_env=target_env,
        rollout_key=rollout_key,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Active policy release not found")
    return payload


@app.post("/policy/rollouts")
def create_policy_rollout_endpoint(
    payload: PolicyRolloutCreateRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import create_policy_rollout

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        created = create_policy_rollout(
            tenant_id=effective_tenant,
            policy_id=payload.policy_id,
            target_env=payload.target_env,
            to_release_id=payload.to_release_id,
            mode=payload.mode,
            canary_percent=payload.canary_percent,
            created_by=payload.created_by or auth.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_rollout_create",
        target_type="policy_rollout",
        target_id=created.get("rollout_id"),
        metadata={
            "policy_id": created.get("policy_id"),
            "target_env": created.get("target_env"),
            "mode": created.get("mode"),
            "state": created.get("state"),
            "canary_percent": created.get("canary_percent"),
        },
    )
    return created


@app.post("/policy/rollouts/{rollout_id}/promote")
def promote_policy_rollout_endpoint(
    rollout_id: str,
    payload: Optional[PolicyRolloutPromoteRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import promote_policy_rollout

    promote_payload = payload or PolicyRolloutPromoteRequest()
    effective_tenant = _effective_tenant(auth, promote_payload.tenant_id)
    try:
        promoted = promote_policy_rollout(
            tenant_id=effective_tenant,
            rollout_id=rollout_id,
            actor_id=promote_payload.actor_id or auth.principal_id,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_rollout_promote",
        target_type="policy_rollout",
        target_id=rollout_id,
        metadata={"policy_id": promoted.get("policy_id"), "target_env": promoted.get("target_env")},
    )
    return promoted


@app.post("/policy/rollouts/{rollout_id}/rollback")
def rollback_policy_rollout_control_endpoint(
    rollout_id: str,
    payload: Optional[PolicyRolloutRollbackRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import rollback_policy_rollout

    rollback_payload = payload or PolicyRolloutRollbackRequest()
    effective_tenant = _effective_tenant(auth, rollback_payload.tenant_id)
    try:
        rolled_back = rollback_policy_rollout(
            tenant_id=effective_tenant,
            rollout_id=rollout_id,
            actor_id=rollback_payload.actor_id or auth.principal_id,
            rollback_to_release_id=rollback_payload.rollback_to_release_id,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="policy_rollout_rollback",
        target_type="policy_rollout",
        target_id=rollout_id,
        metadata={
            "policy_id": rolled_back.get("policy_id"),
            "target_env": rolled_back.get("target_env"),
            "rollback_to_release_id": rolled_back.get("rollback_to_release_id"),
        },
    )
    return rolled_back


@app.get("/policy/rollouts/{rollout_id}")
def get_policy_rollout_endpoint(
    rollout_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import get_policy_rollout

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = get_policy_rollout(tenant_id=effective_tenant, rollout_id=rollout_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Policy rollout not found")
    return payload


@app.get("/policy/rollouts")
def list_policy_rollouts_endpoint(
    policy_id: Optional[str] = None,
    target_env: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 50,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.rollout.rollout_service import list_policy_rollouts

    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "items": list_policy_rollouts(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            target_env=target_env,
            state=state,
            limit=max(1, min(limit, 500)),
        ),
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
        kms_key_id=payload.kms_key_id,
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


@app.post("/tenants/{tenant_id}/rotate-key")
def rotate_tenant_attestation_key(
    tenant_id: str,
    payload: RotateTenantSigningKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    requested_tenant = payload.tenant_id or tenant_id
    if payload.tenant_id and str(payload.tenant_id).strip() != str(tenant_id).strip():
        raise HTTPException(status_code=400, detail="tenant_id mismatch between path and payload")
    effective_tenant = _effective_tenant(auth, requested_tenant)
    try:
        rotated = rotate_tenant_signing_key(
            tenant_id=effective_tenant,
            created_by=auth.principal_id,
            raw_private_key=payload.private_key,
            key_id=payload.key_id,
            kms_key_id=payload.kms_key_id,
            signing_mode=payload.signing_mode,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_signing_key_rotate",
        target_type="tenant_signing_key",
        target_id=str(rotated.get("key_id") or ""),
    )
    return rotated


@app.get("/tenants/{tenant_id}/signing-keys")
def list_tenant_attestation_keys(
    tenant_id: str,
    auth: AuthContext = require_access(
        roles=["admin", "auditor"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return {
        "tenant_id": effective_tenant,
        "keys": list_tenant_signing_keys(tenant_id=effective_tenant),
    }


@app.post("/tenants/{tenant_id}/signing-keys/{key_id}/revoke")
def revoke_tenant_attestation_key(
    tenant_id: str,
    key_id: str,
    payload: RevokeTenantSigningKeyRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        rate_profile="default",
    ),
):
    requested_tenant = payload.tenant_id or tenant_id
    if payload.tenant_id and str(payload.tenant_id).strip() != str(tenant_id).strip():
        raise HTTPException(status_code=400, detail="tenant_id mismatch between path and payload")
    effective_tenant = _effective_tenant(auth, requested_tenant)
    try:
        revoked = revoke_tenant_signing_key(
            tenant_id=effective_tenant,
            key_id=key_id,
            revoked_by=auth.principal_id,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_signing_key_revoke",
        target_type="tenant_signing_key",
        target_id=key_id,
        metadata={"reason": payload.reason or ""},
    )
    return revoked


@app.get("/tenants/{tenant_id}/key-access-log")
def list_tenant_key_access_log(
    tenant_id: str,
    key_id: Optional[str] = None,
    operation: Optional[str] = None,
    limit: int = 100,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["checkpoint:read"],
        rate_profile="default",
    ),
):
    from releasegate.security.key_access import list_key_access_logs

    effective_tenant = _effective_tenant(auth, tenant_id)
    items = list_key_access_logs(
        tenant_id=effective_tenant,
        key_id=key_id,
        operation=operation,
        limit=limit,
    )
    return {
        "tenant_id": effective_tenant,
        "count": len(items),
        "items": items,
    }


@app.get("/tenants/{tenant_id}/governance-settings")
def get_tenant_governance_settings_endpoint(
    tenant_id: str,
    auth: AuthContext = require_access(
        roles=["admin", "auditor"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return get_tenant_governance_settings(tenant_id=effective_tenant)


@app.put("/tenants/{tenant_id}/governance-settings")
def update_tenant_governance_settings_endpoint(
    tenant_id: str,
    payload: TenantGovernanceSettingsRequest,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    updated = update_tenant_governance_settings(
        tenant_id=effective_tenant,
        max_decisions_per_month=payload.max_decisions_per_month,
        max_anchors_per_day=payload.max_anchors_per_day,
        max_overrides_per_month=payload.max_overrides_per_month,
        quota_enforcement_mode=payload.quota_enforcement_mode,
        updated_by=auth.principal_id,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_governance_settings_update",
        target_type="tenant_governance_settings",
        target_id=effective_tenant,
        metadata={
            "max_decisions_per_month": updated.get("max_decisions_per_month"),
            "max_anchors_per_day": updated.get("max_anchors_per_day"),
            "max_overrides_per_month": updated.get("max_overrides_per_month"),
            "quota_enforcement_mode": updated.get("quota_enforcement_mode"),
        },
    )
    return updated


@app.post("/tenants/{tenant_id}/unlock")
def unlock_tenant_endpoint(
    tenant_id: str,
    payload: Optional[TenantUnlockRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
        allow_locked=True,
    ),
):
    from releasegate.security.security_state_service import set_tenant_security_state

    effective_tenant = _effective_tenant(auth, tenant_id)
    req = payload or TenantUnlockRequest()
    result = set_tenant_security_state(
        tenant_id=effective_tenant,
        to_state="normal",
        reason=req.reason or "manual_unlock",
        source="admin_unlock_endpoint",
        actor=auth.principal_id,
        metadata={"path": "/tenants/{tenant_id}/unlock"},
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_unlock",
        target_type="tenant_security_state",
        target_id=effective_tenant,
        metadata={"reason": req.reason or "manual_unlock"},
    )
    return result


@app.get("/tenants/{tenant_id}/governance-metrics")
def tenant_governance_metrics_endpoint(
    tenant_id: str,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    effective_tenant = _effective_tenant(auth, tenant_id)
    return get_tenant_governance_metrics(tenant_id=effective_tenant)


@app.get("/tenants/{tenant_id}/governance-integrity")
def tenant_governance_integrity_endpoint(
    tenant_id: str,
    window_days: int = 90,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.governance.integrity import get_tenant_governance_integrity

    effective_tenant = _effective_tenant(auth, tenant_id)
    try:
        payload = get_tenant_governance_integrity(
            tenant_id=effective_tenant,
            window_days=window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return payload


@app.post("/tenants/{tenant_id}/emergency-rotate")
def emergency_rotate_tenant_key_endpoint(
    tenant_id: str,
    payload: EmergencyRotateTenantKeyRequest,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.tenants.compromise import emergency_rotate_tenant_signing_key

    requested_tenant = payload.tenant_id or tenant_id
    if payload.tenant_id and str(payload.tenant_id).strip() != str(tenant_id).strip():
        raise HTTPException(status_code=400, detail="tenant_id mismatch between path and payload")
    effective_tenant = _effective_tenant(auth, requested_tenant)
    operation = "tenant_emergency_rotate"
    idem_key = (
        str(idempotency_key or "").strip()
        or derive_system_idempotency_key(
            tenant_id=effective_tenant,
            operation=operation,
            identity={
                "tenant_id": effective_tenant,
                "reason": payload.reason,
                "compromise_start": payload.compromise_start,
                "principal_id": auth.principal_id,
            },
        )
    )
    claim = claim_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idem_key,
        request_payload={
            **payload.model_dump(mode="json"),
            "tenant_id": effective_tenant,
        },
    )
    def _replay_or_raise(replayed: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if replayed is None:
            return None
        if isinstance(replayed, dict) and replayed.get("_error_status_code"):
            raise HTTPException(
                status_code=int(replayed.get("_error_status_code") or 400),
                detail=str(replayed.get("detail") or "Emergency rotate request failed"),
            )
        return replayed

    if claim.state == "replay":
        replayed = _replay_or_raise(claim.response)
        if replayed is not None:
            return replayed
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
        )
        replayed = _replay_or_raise(replayed)
        if replayed is not None:
            return replayed
        raise HTTPException(status_code=409, detail="Emergency rotate request is already in progress")
    try:
        report = emergency_rotate_tenant_signing_key(
            tenant_id=effective_tenant,
            actor_id=auth.principal_id,
            reason=payload.reason,
            compromise_start=payload.compromise_start,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        error_payload = {
            "_error_status_code": 400,
            "detail": str(exc),
            "idempotency_key": idem_key,
        }
        complete_idempotency(
            tenant_id=effective_tenant,
            operation=operation,
            idem_key=idem_key,
            response_payload=error_payload,
            resource_type="tenant_key_compromise_event",
            resource_id="",
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_signing_key_emergency_rotate",
        target_type="tenant_signing_key",
        target_id=str(report.get("replacement_key_id") or ""),
        metadata={
            "revoked_key_id": report.get("revoked_key_id"),
            "event_id": report.get("event_id"),
            "affected_count": report.get("affected_count"),
        },
    )
    report = {
        **report,
        "idempotency_key": idem_key,
    }
    complete_idempotency(
        tenant_id=effective_tenant,
        operation=operation,
        idem_key=idem_key,
        response_payload=report,
        resource_type="tenant_key_compromise_event",
        resource_id=str(report.get("event_id") or ""),
    )
    return report


@app.get("/tenants/{tenant_id}/compromise-report")
def tenant_compromise_report_endpoint(
    tenant_id: str,
    limit: int = 20,
    auth: AuthContext = require_access(
        roles=["admin", "auditor"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.tenants.compromise import build_compromise_report

    effective_tenant = _effective_tenant(auth, tenant_id)
    return build_compromise_report(
        tenant_id=effective_tenant,
        limit=max(1, min(limit, 500)),
    )


@app.post("/tenants/{tenant_id}/re-sign")
def tenant_bulk_resign_endpoint(
    tenant_id: str,
    payload: Optional[ResignCompromisedRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="heavy",
    ),
):
    from releasegate.tenants.compromise import bulk_resign_compromised_attestations

    req = payload or ResignCompromisedRequest()
    requested_tenant = req.tenant_id or tenant_id
    if req.tenant_id and str(req.tenant_id).strip() != str(tenant_id).strip():
        raise HTTPException(status_code=400, detail="tenant_id mismatch between path and payload")
    effective_tenant = _effective_tenant(auth, requested_tenant)
    try:
        result = bulk_resign_compromised_attestations(
            tenant_id=effective_tenant,
            actor_id=auth.principal_id,
            limit=req.limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_attestation_bulk_resign",
        target_type="tenant",
        target_id=effective_tenant,
        metadata={"resigned_count": result.get("resigned_count")},
    )
    return result


@app.post("/tenants/{tenant_id}/force-rekey")
def force_rekey_tenant_endpoint(
    tenant_id: str,
    payload: Optional[ForceRekeyTenantRequest] = None,
    auth: AuthContext = require_access(
        roles=["admin"],
        scopes=["policy:write"],
        rate_profile="default",
    ),
):
    from releasegate.tenants.compromise import force_rekey_tenant

    req = payload or ForceRekeyTenantRequest()
    requested_tenant = req.tenant_id or tenant_id
    if req.tenant_id and str(req.tenant_id).strip() != str(tenant_id).strip():
        raise HTTPException(status_code=400, detail="tenant_id mismatch between path and payload")
    effective_tenant = _effective_tenant(auth, requested_tenant)
    rotated = force_rekey_tenant(
        tenant_id=effective_tenant,
        actor_id=auth.principal_id,
        reason=req.reason,
        metadata=req.metadata,
    )
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="tenant_signing_key_force_rekey",
        target_type="tenant_signing_key",
        target_id=str(rotated.get("key_id") or ""),
    )
    return rotated


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
    from releasegate.integrations.jira.decision_linkage import get_decision_linkage, is_protected_status

    effective_tenant = _effective_tenant(auth, tenant_id)
    row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not row:
        raise HTTPException(status_code=404, detail="Decision not found")

    def _linkage_snapshot() -> Optional[Dict[str, Any]]:
        try:
            link = get_decision_linkage(tenant_id=effective_tenant, decision_id=decision_id)
        except Exception:
            return None
        if not link:
            return None
        target_status = str(link.get("target_status") or "")
        return {
            "protected": bool(is_protected_status(target_status)),
            "context_hash": str(link.get("context_hash") or ""),
            "expires_at": link.get("expires_at"),
            "consumed": bool(link.get("consumed")),
            "consumed_at": link.get("consumed_at"),
            "consumed_by_request_id": link.get("consumed_by_request_id"),
            "bound_fields": {
                "jira_issue_id": link.get("jira_issue_id"),
                "transition_id": link.get("transition_id"),
                "actor": link.get("actor"),
                "source_status": link.get("source_status"),
                "target_status": target_status,
            },
        }

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
            "linkage": _linkage_snapshot(),
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
    report["linkage"] = _linkage_snapshot()
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


@app.post("/correlation/deployments/authorize")
def authorize_correlation_deployment_endpoint(
    payload: CorrelationDeploymentRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.contracts import evaluate_and_record_deployment_correlation

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = evaluate_and_record_deployment_correlation(
            tenant_id=effective_tenant,
            deployment_event_id=payload.deployment_event_id,
            repo=payload.repo,
            environment=payload.environment,
            service=payload.service,
            decision_id=payload.decision_id,
            jira_issue_id=payload.jira_issue_id,
            correlation_id=payload.correlation_id,
            commit_sha=payload.commit_sha,
            artifact_digest=payload.artifact_digest,
            risk_eval_id=payload.risk_eval_id,
            risk_evaluated_at=payload.risk_evaluated_at,
            deployed_at=payload.deployed_at,
            source=payload.source,
            jira_ticket_approved=payload.jira_ticket_approved,
            jira_ticket_status=payload.jira_ticket_status,
            policy_overrides=payload.policy_overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="correlation_deployment_authorize",
        target_type="deployment",
        target_id=payload.deployment_event_id,
        metadata={
            "verdict": result.get("contract_verdict"),
            "allow": result.get("allow"),
            "reason_code": result.get("reason_code"),
            "decision_id": result.get("decision_id"),
            "jira_issue_id": result.get("jira_issue_id"),
            "environment": result.get("environment"),
            "service": result.get("service"),
            "violations": result.get("violations"),
            "strict": result.get("strict"),
        },
    )
    return result


@app.post("/correlation/deployments/ingest")
def ingest_correlation_deployment_endpoint(
    payload: CorrelationDeploymentRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.contracts import evaluate_and_record_deployment_correlation

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        result = evaluate_and_record_deployment_correlation(
            tenant_id=effective_tenant,
            deployment_event_id=payload.deployment_event_id,
            repo=payload.repo,
            environment=payload.environment,
            service=payload.service,
            decision_id=payload.decision_id,
            jira_issue_id=payload.jira_issue_id,
            correlation_id=payload.correlation_id,
            commit_sha=payload.commit_sha,
            artifact_digest=payload.artifact_digest,
            risk_eval_id=payload.risk_eval_id,
            risk_evaluated_at=payload.risk_evaluated_at,
            deployed_at=payload.deployed_at,
            source=payload.source,
            jira_ticket_approved=payload.jira_ticket_approved,
            jira_ticket_status=payload.jira_ticket_status,
            policy_overrides=payload.policy_overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="correlation_deployment_ingest",
        target_type="deployment",
        target_id=payload.deployment_event_id,
        metadata={
            "verdict": result.get("contract_verdict"),
            "allow": result.get("allow"),
            "reason_code": result.get("reason_code"),
            "decision_id": result.get("decision_id"),
            "jira_issue_id": result.get("jira_issue_id"),
            "environment": result.get("environment"),
            "service": result.get("service"),
            "violations": result.get("violations"),
            "strict": result.get("strict"),
        },
    )
    return result


@app.get("/correlation/deployments/{deployment_event_id}")
def get_correlation_deployment_endpoint(
    deployment_event_id: str,
    tenant_id: Optional[str] = None,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.contracts import get_deployment_correlation_link

    effective_tenant = _effective_tenant(auth, tenant_id)
    payload = get_deployment_correlation_link(
        tenant_id=effective_tenant,
        deployment_event_id=deployment_event_id,
    )
    if not payload:
        raise HTTPException(status_code=404, detail="Deployment correlation link not found")
    return payload


@app.post("/correlations")
def create_correlation_record_endpoint(
    payload: CorrelationCreateRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.governance.correlation import create_correlation_record

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        record = create_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=payload.correlation_id,
            payload=payload.model_dump(mode="json"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="correlation_record_create",
        target_type="correlation",
        target_id=str(record.get("correlation_id") or ""),
        metadata={
            "environment": record.get("environment"),
            "jira_issue_key": record.get("jira_issue_key"),
            "deploy_id": record.get("deploy_id"),
            "incident_id": record.get("incident_id"),
        },
    )
    return record


@app.post("/correlations/{correlation_id}/attach")
def attach_correlation_record_endpoint(
    correlation_id: str,
    payload: CorrelationAttachRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.governance.correlation import update_correlation_record

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    try:
        record = update_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=correlation_id,
            payload=payload.model_dump(mode="json"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="correlation_record_attach",
        target_type="correlation",
        target_id=str(record.get("correlation_id") or correlation_id),
        metadata={
            "environment": record.get("environment"),
            "jira_issue_key": record.get("jira_issue_key"),
            "deploy_id": record.get("deploy_id"),
            "incident_id": record.get("incident_id"),
        },
    )
    return record


@app.post("/gates/deploy/evaluate")
def evaluate_deploy_gate_endpoint(
    payload: DeployGateEvaluateRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.enforcement import evaluate_deploy_gate
    from releasegate.governance.correlation import find_correlation_record, get_correlation_record

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    correlation_record = None
    if payload.correlation_id:
        correlation_record = get_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=payload.correlation_id,
        )
    elif payload.deploy_id:
        correlation_record = find_correlation_record(
            tenant_id=effective_tenant,
            deploy_id=payload.deploy_id,
        )

    resolved_env = str(
        payload.environment
        or (correlation_record or {}).get("environment")
        or ""
    ).strip().lower()
    if not resolved_env:
        raise HTTPException(status_code=400, detail="environment is required")

    resolved_issue_key = str(
        payload.issue_key
        or (correlation_record or {}).get("jira_issue_key")
        or ""
    ).strip()
    if resolved_env in {"prod", "production"} and not resolved_issue_key:
        return {
            "allow": False,
            "status": "BLOCKED",
            "reason_code": "DEPLOY_JIRA_ISSUE_REQUIRED",
            "reason": "Production deployment requires a valid jira_issue_key.",
            "decision_id": payload.decision_id,
            "correlation_id": payload.correlation_id or (correlation_record or {}).get("correlation_id"),
            "required_actions": _gate_required_actions("DEPLOY_JIRA_ISSUE_REQUIRED"),
        }

    resolved_decision_id = str(
        payload.decision_id
        or (correlation_record or {}).get("decision_id")
        or ""
    ).strip()
    strict_enabled = bool(
        (payload.policy_overrides or {}).get("strict_fail_closed")
        if (payload.policy_overrides or {}).get("strict_fail_closed") is not None
        else True
    )
    if strict_enabled and resolved_env in {"prod", "production"} and not resolved_decision_id:
        return {
            "allow": False,
            "status": "BLOCKED",
            "reason_code": "DECISION_REQUIRED_FOR_PROD",
            "reason": "Strict production gate requires an approved ReleaseGate decision.",
            "decision_id": None,
            "correlation_id": payload.correlation_id or (correlation_record or {}).get("correlation_id"),
            "required_actions": _gate_required_actions("DECISION_REQUIRED_FOR_PROD"),
        }

    resolved_repo = str(payload.repo or (correlation_record or {}).get("pr_repo") or "").strip()
    resolved_commit_sha = str(payload.commit_sha or (correlation_record or {}).get("pr_sha") or "").strip() or None
    if not resolved_repo:
        raise HTTPException(status_code=400, detail="repo is required for deploy gate evaluation")

    result = evaluate_deploy_gate(
        tenant_id=effective_tenant,
        decision_id=resolved_decision_id or None,
        issue_key=resolved_issue_key or None,
        correlation_id=payload.correlation_id or (correlation_record or {}).get("correlation_id"),
        deploy_id=payload.deploy_id or (correlation_record or {}).get("deploy_id"),
        repo=resolved_repo,
        env=resolved_env,
        commit_sha=resolved_commit_sha,
        artifact_digest=payload.artifact_digest,
        policy_overrides=payload.policy_overrides,
    )
    result = dict(result)
    result["required_actions"] = _gate_required_actions(result.get("reason_code"))
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="gate_deploy_evaluate",
        target_type="deployment",
        target_id=str(payload.deploy_id or result.get("correlation_id") or resolved_repo),
        metadata={
            "allow": result.get("allow"),
            "reason_code": result.get("reason_code"),
            "decision_id": result.get("decision_id"),
            "correlation_id": result.get("correlation_id"),
        },
    )
    return result


@app.post("/gates/incident/evaluate")
def evaluate_incident_gate_endpoint(
    payload: IncidentGateEvaluateRequest,
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        rate_profile="default",
    ),
):
    from releasegate.correlation.enforcement import evaluate_incident_close_gate
    from releasegate.governance.correlation import find_correlation_record, get_correlation_record

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    correlation_record = None
    if payload.correlation_id:
        correlation_record = get_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=payload.correlation_id,
        )
    if correlation_record is None:
        correlation_record = find_correlation_record(
            tenant_id=effective_tenant,
            incident_id=payload.incident_id,
        )

    requires_postmortem = bool(
        (payload.policy_overrides or {}).get("incident_close_requires_postmortem")
    )
    close_reason = str(payload.close_reason or "").strip()
    if requires_postmortem and not close_reason:
        return {
            "allow": False,
            "status": "BLOCKED",
            "reason_code": "POSTMORTEM_REQUIRED",
            "reason": "Incident close requires postmortem evidence.",
            "decision_id": payload.decision_id,
            "correlation_id": payload.correlation_id or (correlation_record or {}).get("correlation_id"),
            "required_actions": _gate_required_actions("POSTMORTEM_REQUIRED"),
        }

    result = evaluate_incident_close_gate(
        tenant_id=effective_tenant,
        incident_id=payload.incident_id,
        decision_id=payload.decision_id or (correlation_record or {}).get("decision_id"),
        issue_key=payload.issue_key or (correlation_record or {}).get("jira_issue_key"),
        correlation_id=payload.correlation_id or (correlation_record or {}).get("correlation_id"),
        deploy_id=payload.deploy_id or (correlation_record or {}).get("deploy_id"),
        repo=payload.repo or (correlation_record or {}).get("pr_repo"),
        env=payload.environment or (correlation_record or {}).get("environment"),
        policy_overrides=payload.policy_overrides,
    )
    result = dict(result)
    result["required_actions"] = _gate_required_actions(result.get("reason_code"))
    log_security_event(
        tenant_id=effective_tenant,
        principal_id=auth.principal_id,
        auth_method=auth.auth_method,
        action="gate_incident_evaluate",
        target_type="incident",
        target_id=str(payload.incident_id),
        metadata={
            "allow": result.get("allow"),
            "reason_code": result.get("reason_code"),
            "decision_id": result.get("decision_id"),
            "correlation_id": result.get("correlation_id"),
        },
    )
    return result


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
    from releasegate.governance.strict_mode import resolve_strict_fail_closed

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    strict_fail_closed = resolve_strict_fail_closed(
        policy_overrides=payload.policy_overrides,
        fallback=True,
    )
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

    try:
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
    except Exception as exc:
        if not strict_fail_closed:
            raise HTTPException(status_code=500, detail=f"Deploy gate evaluation failed: {exc}") from exc
        result = {
            "allow": False,
            "status": "BLOCKED",
            "reason_code": "SYSTEM_FAILURE",
            "reason": "BLOCKED: deploy gate system failure in strict mode.",
            "tenant_id": effective_tenant,
            "decision_id": payload.decision_id,
            "issue_key": payload.issue_key,
            "correlation_id": payload.correlation_id,
            "repo": payload.repo,
            "pr_number": None,
            "commit_sha": payload.commit_sha,
            "env": payload.env,
        }
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
    from releasegate.governance.strict_mode import resolve_strict_fail_closed

    effective_tenant = _effective_tenant(auth, payload.tenant_id)
    strict_fail_closed = resolve_strict_fail_closed(
        policy_overrides=payload.policy_overrides,
        fallback=True,
    )
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

    try:
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
    except Exception as exc:
        if not strict_fail_closed:
            raise HTTPException(status_code=500, detail=f"Incident gate evaluation failed: {exc}") from exc
        result = {
            "allow": False,
            "status": "BLOCKED",
            "reason_code": "SYSTEM_FAILURE",
            "reason": "BLOCKED: incident gate system failure in strict mode.",
            "tenant_id": effective_tenant,
            "decision_id": payload.decision_id,
            "issue_key": payload.issue_key,
            "correlation_id": payload.correlation_id,
            "repo": payload.repo,
            "pr_number": None,
            "commit_sha": None,
            "env": payload.env,
        }
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
    from releasegate.tenants.compromise import get_latest_attestation_resignature, is_attestation_compromised
    from releasegate.tenants.keys import KEY_STATUS_REVOKED, get_tenant_signing_public_keys_with_status

    attestation = payload.get("attestation") if isinstance(payload.get("attestation"), dict) else payload
    tenant_hint = str((attestation or {}).get("tenant_id") or payload.get("tenant_id") or "").strip() or None
    public_keys = load_public_keys_map(tenant_id=tenant_hint, include_revoked=True)
    report = verify_attestation_payload(
        attestation,
        public_keys_by_key_id=public_keys,
    )
    statuses: Dict[str, Dict[str, Any]] = {}
    if tenant_hint:
        try:
            statuses = get_tenant_signing_public_keys_with_status(
                tenant_id=tenant_hint,
                include_verify_only=True,
                include_revoked=True,
            )
        except Exception as exc:
            logger.warning("Failed to check key revocation status for tenant_id=%s: %s", tenant_hint, exc)
            raise HTTPException(status_code=503, detail="Failed to verify key status.") from exc

    def _key_is_revoked(key_id: str) -> bool:
        normalized = str(key_id or "").strip()
        if not normalized:
            return False
        return str((statuses.get(normalized) or {}).get("status") or "").upper() == KEY_STATUS_REVOKED

    key_id = str(report.get("key_id") or "").strip()
    key_revoked = _key_is_revoked(key_id)
    compromise = {"compromised": False, "event_id": None}
    attestation_id = str((attestation or {}).get("attestation_id") or "").strip()
    if not attestation_id and isinstance(attestation, dict):
        signature_obj = attestation.get("signature") or {}
        signed_payload_hash = str(signature_obj.get("signed_payload_hash") or "").strip().lower()
        if ":" in signed_payload_hash:
            algo, digest = signed_payload_hash.split(":", 1)
            if algo.strip() == "sha256":
                signed_payload_hash = digest.strip()
        if len(signed_payload_hash) == 64 and all(ch in "0123456789abcdef" for ch in signed_payload_hash):
            attestation_id = signed_payload_hash
    if tenant_hint and attestation_id:
        try:
            compromise = is_attestation_compromised(tenant_id=tenant_hint, attestation_id=attestation_id)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Attestation compromise status check failed",
            ) from exc
    report["key_revoked"] = bool(key_revoked)
    report["compromised"] = bool(compromise.get("compromised"))
    report["compromise_event_id"] = compromise.get("event_id")
    report["signature_valid"] = bool(report.get("valid_signature"))
    report["ok"] = bool(
        report.get("schema_valid")
        and report.get("payload_hash_match")
        and report.get("trusted_issuer")
        and report.get("valid_signature")
    )
    report["accepted"] = bool(report["ok"] and not report["key_revoked"] and not report["compromised"])

    superseding_resign = None
    if tenant_hint and attestation_id:
        try:
            superseding_resign = get_latest_attestation_resignature(
                tenant_id=tenant_hint,
                attestation_id=attestation_id,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Attestation re-signature check failed",
            ) from exc
    superseding_available = isinstance(superseding_resign, dict) and bool(superseding_resign)
    superseding_signature_valid = False
    superseding_key_id = ""
    superseding_key_revoked = False
    superseding_accepted = False
    superseding_attestation_id = ""
    superseding_report: Dict[str, Any] = {}
    if superseding_available:
        superseding_attestation = superseding_resign.get("attestation")
        if isinstance(superseding_attestation, dict):
            superseding_report = verify_attestation_payload(
                superseding_attestation,
                public_keys_by_key_id=public_keys,
            )
            superseding_signature_valid = bool(superseding_report.get("valid_signature"))
            superseding_key_id = str(superseding_report.get("key_id") or superseding_resign.get("new_key_id") or "").strip()
            superseding_key_revoked = _key_is_revoked(superseding_key_id)
            superseding_accepted = bool(
                superseding_report.get("schema_valid")
                and superseding_report.get("payload_hash_match")
                and superseding_report.get("trusted_issuer")
                and superseding_report.get("valid_signature")
                and not superseding_key_revoked
            )
            superseding_attestation_id = str(superseding_resign.get("attestation_id") or attestation_id or "").strip()
        else:
            superseding_available = False

    report["superseded_by_resignature"] = bool(superseding_available)
    report["superseding_resign_id"] = (superseding_resign or {}).get("resign_id") if superseding_available else None
    report["superseding_attestation_id"] = superseding_attestation_id or None
    report["superseding_key_id"] = superseding_key_id or None
    report["superseding_signature_valid"] = bool(superseding_signature_valid)
    report["superseding_key_revoked"] = bool(superseding_key_revoked)
    report["superseding_accepted"] = bool(superseding_accepted)
    report["accepted_effective"] = bool(report["accepted"] or superseding_accepted)
    if tenant_hint and not report["signature_valid"]:
        try:
            record_anomaly_event(
                tenant_id=tenant_hint,
                signal_type="signature_verification_failed",
                operation="verify_attestation",
                details={
                    "key_id": report.get("key_id"),
                    "schema_valid": bool(report.get("schema_valid")),
                    "payload_hash_match": bool(report.get("payload_hash_match")),
                    "trusted_issuer": bool(report.get("trusted_issuer")),
                },
            )
        except Exception:
            pass
    return report
