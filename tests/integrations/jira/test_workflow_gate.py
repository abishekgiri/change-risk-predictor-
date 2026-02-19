import pytest
import os
import requests
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from releasegate.integrations.jira.types import TransitionCheckRequest
from releasegate.integrations.jira.client import JiraDependencyTimeout
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.decision.types import Decision, EnforcementTargets, DecisionType

@pytest.fixture
def base_request():
    return TransitionCheckRequest(
        issue_key="TEST-1",
        transition_id="31",
        source_status="Open",
        target_status="Ready",
        actor_account_id="user-1",
        environment="PRODUCTION",
        project_key="TEST",
        issue_type="Story"
    )

def test_resolve_policies_fail_open(base_request):
    """Test that missing config returns empty list (Allow)."""
    gate = WorkflowGate()
    # Simulate missing transition map.
    with patch.object(gate, "_load_transition_map", return_value=None):
        policies = gate._resolve_policies(base_request)
        assert policies == []

def test_compute_key_stability(base_request):
    """Test idempotency key generation."""
    gate = WorkflowGate()
    k1 = gate._compute_key(base_request)
    k2 = gate._compute_key(base_request)
    assert k1 == k2
    
    # Change status -> New key
    base_request.target_status = "Done"
    k3 = gate._compute_key(base_request)
    assert k1 != k3

    # Delivery/idempotency keys must not change canonical evaluation key.
    base_request.context_overrides = {"idempotency_key": "req-1"}
    k4 = gate._compute_key(base_request)
    base_request.context_overrides = {"idempotency_key": "req-2"}
    k5 = gate._compute_key(base_request)
    assert k4 == k5

    # Changing canonical transition inputs must change the key.
    base_request.context_overrides = {"repo": "abishekgiri/change-risk-predictor-", "pr_number": 27}
    k6 = gate._compute_key(base_request)
    base_request.context_overrides = {"repo": "abishekgiri/change-risk-predictor-", "pr_number": 28}
    k7 = gate._compute_key(base_request)
    assert k6 != k7


def test_build_decision_id_is_deterministic(base_request):
    gate = WorkflowGate()
    eval_key = gate._compute_key(base_request)

    d1 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
    )
    d2 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
    )
    assert d1.decision_id == d2.decision_id
    assert len(d1.decision_id) == 64


def test_build_decision_id_ignores_evaluation_suffix(base_request):
    gate = WorkflowGate()
    eval_key = gate._compute_key(base_request)
    d = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=f"{eval_key}:evaluated",
    )
    d_base = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
    )
    assert d.decision_id == d_base.decision_id


def test_build_decision_id_changes_when_policy_hash_changes(base_request):
    gate = WorkflowGate()
    eval_key = gate._compute_key(base_request)
    d1 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
        policy_hash="hash-a",
    )
    d2 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
        policy_hash="hash-b",
    )
    assert d1.decision_id != d2.decision_id


def test_build_decision_id_changes_when_pr_number_changes(base_request):
    gate = WorkflowGate()
    eval_key = gate._compute_key(base_request)
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 27,
    }
    d1 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
    )
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 28,
    }
    d2 = gate._build_decision(
        base_request,
        release_status=DecisionType.ALLOWED,
        message="ok",
        evaluation_key=eval_key,
    )
    assert d1.decision_id != d2.decision_id

@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_flow_allowed(MockRecorder, MockEngine, base_request):
    """Test full allowed flow."""
    gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})
    
    # Mock Engine Result (ComplianceRunResult structure)
    mock_run_result = MagicMock()
    mock_policy_result = MagicMock()
    mock_policy_result.policy_id = "SEC-PR-001"
    mock_policy_result.status = "COMPLIANT" # or allowed
    mock_run_result.results = [mock_policy_result]
    
    MockEngine.return_value.evaluate.return_value = mock_run_result
    
    # Mock Recorder to return a Decision
    mock_decision = Decision(
        decision_id="uuid-1",
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="ctx-1",
        message="All good",
        policy_bundle_hash="abc",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    # Mock Policy Resolve
    with patch.object(gate, '_resolve_policies', return_value=["SEC-PR-001"]):
        resp = gate.check_transition(base_request)
        
    assert resp.allow is True
    assert resp.status == "ALLOWED"

@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_prod_conditional_block(MockRecorder, MockEngine, base_request):
    """Test that CONDITIONAL becomes BLOCKED in PROD."""
    gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "HIGH"})
    
    # Mock Engine Result
    mock_run_result = MagicMock()
    mock_policy_result = MagicMock()
    mock_policy_result.policy_id = "SEC-PR-001"
    mock_policy_result.status = "WARN" # maps to CONDITIONAL
    mock_policy_result.violations = ["Need approval"]
    mock_run_result.results = [mock_policy_result]

    MockEngine.return_value.evaluate.return_value = mock_run_result

    # Mock Recorder returning CONDITIONAL decision
    mock_decision = Decision(
        decision_id="uuid-2",
        timestamp=datetime.now(timezone.utc),
        release_status="CONDITIONAL",
        context_id="ctx-2",
        message="Needs approval",
        policy_bundle_hash="abc",
        requirements={}, 
        unlock_conditions=["Need approval"],
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    # Mock Client
    gate.client.post_comment_deduped = MagicMock()

    with patch.object(gate, '_resolve_policies', return_value=["SEC-PR-001"]):
        resp = gate.check_transition(base_request)
        
    # Should upgrade to BLOCKED
    assert resp.allow is False
    assert resp.status == "BLOCKED" 
    # Should have posted comment
    gate.client.post_comment_deduped.assert_called_once()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_skips_when_risk_metadata_missing(MockRecorder, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(return_value={})

    mock_decision = Decision(
        decision_id="uuid-skip",
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id="ctx-skip",
        message="SKIPPED: missing issue property `releasegate_risk`",
        policy_bundle_hash="abc",
        unlock_conditions=["Run GitHub PR classification to attach `releasegate_risk` on this issue."],
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    resp = gate.check_transition(base_request)
    assert resp.allow is True
    assert resp.status == "SKIPPED"
    assert "missing issue property" in resp.reason


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_uses_ci_score_fallback_when_risk_metadata_missing(MockRecorder, base_request):
    with patch.dict(
        os.environ,
        {
            "RELEASEGATE_STRICT_MODE": "false",
            "GITHUB_TOKEN": "test-github-token",
        },
    ):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 27,
    }
    gate.client.get_issue_property = MagicMock(return_value={})
    gate.client.set_issue_property = MagicMock(return_value=True)

    mock_ci_response = MagicMock(status_code=200)
    mock_ci_response.json.return_value = {"changed_files": 9, "additions": 120, "deletions": 21}

    mock_decision = Decision(
        decision_id="uuid-ci-fallback",
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id="ctx-ci-fallback",
        message="SKIPPED: no policies configured for this transition",
        policy_bundle_hash="abc",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.integrations.jira.workflow_gate.requests.get", return_value=mock_ci_response), patch.object(
        gate, "_resolve_policies", return_value=[]
    ):
        resp = gate.check_transition(base_request)

    assert resp.status == "SKIPPED"
    assert "no policies configured" in resp.reason
    gate.client.set_issue_property.assert_called_once()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_strict_mode_blocks_when_risk_missing(MockRecorder, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={})

    mock_decision = Decision(
        decision_id="uuid-strict",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-strict",
        message="BLOCKED: missing issue property `releasegate_risk` (strict mode)",
        policy_bundle_hash="abc",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_skips_when_no_policies_mapped(MockRecorder, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})

    mock_decision = Decision(
        decision_id="uuid-nopol",
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id="ctx-nopol",
        message="SKIPPED: no policies configured for this transition",
        policy_bundle_hash="abc",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch.object(gate, "_resolve_policies", return_value=[]):
        resp = gate.check_transition(base_request)
    assert resp.allow is True
    assert resp.status == "SKIPPED"


@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_skips_when_policy_mapping_invalid(MockRecorder, MockEngine, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})

    mock_run_result = MagicMock()
    only_loaded = MagicMock()
    only_loaded.policy_id = "VALID-1"
    only_loaded.status = "COMPLIANT"
    mock_run_result.results = [only_loaded]
    mock_run_result.metadata = {"policy_hash": "hash-1"}
    MockEngine.return_value.evaluate.return_value = mock_run_result

    mock_decision = Decision(
        decision_id="uuid-invalid-map",
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id="ctx-invalid-map",
        message="SKIPPED: invalid policy references: UNKNOWN-1",
        policy_bundle_hash="hash-1",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch.object(gate, "_resolve_policies", return_value=["UNKNOWN-1"]):
        resp = gate.check_transition(base_request)
    assert resp.allow is True
    assert resp.status == "SKIPPED"
    assert "invalid policy references" in resp.reason


@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_multiple_policies_block_wins(MockRecorder, MockEngine, base_request):
    gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "HIGH"})
    gate.client.post_comment_deduped = MagicMock()

    mock_run_result = MagicMock()
    warn_policy = MagicMock()
    warn_policy.policy_id = "SEC-PR-003"
    warn_policy.status = "WARN"
    warn_policy.violations = ["Need one approval"]
    block_policy = MagicMock()
    block_policy.policy_id = "SEC-PR-001"
    block_policy.status = "BLOCK"
    block_policy.violations = ["Need security approval"]
    mock_run_result.results = [warn_policy, block_policy]
    mock_run_result.metadata = {"policy_hash": "hash-multi"}
    MockEngine.return_value.evaluate.return_value = mock_run_result

    mock_decision = Decision(
        decision_id="uuid-multi",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-multi",
        message="Policy Check (Open -> Ready): BLOCKED",
        policy_bundle_hash="hash-multi",
        unlock_conditions=["Need one approval", "Need security approval"],
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch.object(gate, "_resolve_policies", return_value=["SEC-PR-003", "SEC-PR-001"]):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_override_present_allows(MockRecorder, base_request):
    gate = WorkflowGate()
    base_request.context_overrides = {"override": True, "override_reason": "Emergency approved"}

    mock_decision = Decision(
        decision_id="uuid-override",
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="ctx-override",
        message="Override applied: Emergency approved",
        policy_bundle_hash="hash-o",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.audit.overrides.record_override") as mock_record_override:
        resp = gate.check_transition(base_request)

    assert resp.allow is True
    assert resp.status == "ALLOWED"
    mock_record_override.assert_called_once()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_override_requires_justification(MockRecorder, base_request):
    gate = WorkflowGate()
    base_request.context_overrides = {
        "override": True,
        "override_justification_required": True,
    }

    mock_decision = Decision(
        decision_id="uuid-override-missing-justification",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-override-missing-justification",
        message="BLOCKED: override justification is required",
        policy_bundle_hash="hash-o",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.audit.overrides.record_override") as mock_record_override:
        resp = gate.check_transition(base_request)

    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "justification is required" in resp.reason
    mock_record_override.assert_not_called()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_override_expired_blocks(MockRecorder, base_request):
    gate = WorkflowGate()
    base_request.context_overrides = {
        "override": True,
        "override_reason": "Expired emergency approval",
        "override_expires_at": "2000-01-01T00:00:00Z",
    }

    mock_decision = Decision(
        decision_id="uuid-override-expired",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-override-expired",
        message="BLOCKED: override expired at 2000-01-01T00:00:00+00:00",
        policy_bundle_hash="hash-o",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.audit.overrides.record_override") as mock_record_override:
        resp = gate.check_transition(base_request)

    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "override expired at" in resp.reason
    mock_record_override.assert_not_called()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_override_pr_author_cannot_self_approve(MockRecorder, base_request):
    gate = WorkflowGate()
    base_request.context_overrides = {
        "override": True,
        "override_reason": "Emergency approved",
        "pr_author_account_id": base_request.actor_account_id,
    }

    mock_decision = Decision(
        decision_id="uuid-override-sod-pr-author",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-override-sod-pr-author",
        message="BLOCKED: separation-of-duties violation (PR author cannot approve override)",
        policy_bundle_hash="hash-o",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.audit.overrides.record_override") as mock_record_override:
        resp = gate.check_transition(base_request)

    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "PR author cannot approve override" in resp.reason
    mock_record_override.assert_not_called()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_override_requestor_cannot_self_approve(MockRecorder, base_request):
    gate = WorkflowGate()
    base_request.context_overrides = {
        "override": True,
        "override_reason": "Emergency approved",
        "override_requested_by_account_id": base_request.actor_account_id,
    }

    mock_decision = Decision(
        decision_id="uuid-override-sod-requestor",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-override-sod-requestor",
        message="BLOCKED: separation-of-duties violation (override requestor cannot self-approve)",
        policy_bundle_hash="hash-o",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch("releasegate.audit.overrides.record_override") as mock_record_override:
        resp = gate.check_transition(base_request)

    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "override requestor cannot self-approve" in resp.reason
    mock_record_override.assert_not_called()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_strict_mode_blocks_when_no_policies_mapped(MockRecorder, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})

    mock_decision = Decision(
        decision_id="uuid-nopol-strict",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-nopol-strict",
        message="BLOCKED: no policies configured for this transition (strict mode)",
        policy_bundle_hash="abc",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch.object(gate, "_resolve_policies", return_value=[]):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"


@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_strict_mode_blocks_invalid_policy_mapping(MockRecorder, MockEngine, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})

    mock_run_result = MagicMock()
    mock_run_result.results = []
    MockEngine.return_value.evaluate.return_value = mock_run_result

    mock_decision = Decision(
        decision_id="uuid-invalid-map-strict",
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="ctx-invalid-map-strict",
        message="BLOCKED: invalid policy references: UNKNOWN-STRICT (strict mode)",
        policy_bundle_hash="hash-1",
        enforcement_targets=EnforcementTargets(repository="r", ref="h")
    )
    MockRecorder.record_with_context.return_value = mock_decision

    with patch.object(gate, "_resolve_policies", return_value=["UNKNOWN-STRICT"]):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "invalid policy references" in resp.reason


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_strict_mode_blocks_on_risk_fetch_error(MockRecorder, base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(side_effect=RuntimeError("jira unavailable"))

    with patch.object(gate, "_record_with_timeout", side_effect=lambda decision, **_: decision):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert "failed to fetch issue property" in resp.reason


def test_gate_strict_blocks_when_policy_map_missing(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    with patch.object(gate, "_load_transition_map", return_value=None), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "POLICY_MISSING"


def test_gate_strict_blocks_when_policy_resolution_invalid(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()

    def _resolve_with_invalid(_request):
        gate._policy_resolution_issue = {
            "reason_code": "POLICY_INVALID",
            "message": "BLOCKED: transition policy map is invalid",
            "unlock_conditions": ["Fix jira_transition_map.yaml validation errors before retrying transition."],
            "error_code": "TRANSITION_MAP_LOAD_FAILED",
        }
        return []

    with patch.object(gate, "_resolve_policies", side_effect=_resolve_with_invalid), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "POLICY_INVALID"


def test_gate_policy_registry_timeout_permissive_returns_skipped(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    with patch.object(gate, "_resolve_policies", side_effect=TimeoutError("policy registry timed out")), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is True
    assert resp.status == "SKIPPED"
    assert "dependency timeout" in resp.reason


def test_gate_policy_registry_timeout_strict_blocks(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    with patch.object(gate, "_resolve_policies", side_effect=TimeoutError("policy registry timed out")), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "DEPENDENCY_TIMEOUT"
    assert "dependency timeout" in resp.reason


def test_gate_jira_timeout_in_permissive_mode_is_skipped(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(side_effect=JiraDependencyTimeout("jira timed out"))
    with patch.object(gate, "_resolve_policies", return_value=["SEC-PR-001"]), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is True
    assert resp.status == "SKIPPED"
    assert "dependency timeout" in resp.reason


def test_gate_prod_without_mapping_blocks_fail_closed(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "false"}):
        gate = WorkflowGate()
    base_request.environment = "PRODUCTION"
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})
    with patch.object(gate, "_resolve_policies", return_value=[]), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "POLICY_MISSING"
    assert "no policies configured" in resp.reason.lower()


def test_gate_strict_blocks_when_role_map_missing(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})
    with patch.object(gate, "_resolve_policies", return_value=["SEC-PR-001"]), patch.object(
        gate, "_load_role_map", return_value=None
    ), patch.object(gate, "_record_with_timeout", side_effect=lambda decision, **_: decision):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "JIRA_ROLE_MAPPING_MISSING"
    assert "role mapping unavailable" in resp.reason.lower()


def test_gate_strict_blocks_when_required_signal_missing(base_request):
    with patch.dict(
        os.environ,
        {
            "RELEASEGATE_STRICT_MODE": "true",
            "RELEASEGATE_STRICT_REQUIRED_SIGNALS": "releasegate_risk,risk_score",
        },
    ):
        gate = WorkflowGate()
        base_request.environment = "STAGING"
        gate.client.get_issue_property = MagicMock(return_value={"releasegate_risk": "LOW"})
        with patch.object(gate, "_resolve_policies", return_value=["SEC-PR-001"]), patch.object(
            gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
        ):
            resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "SIGNAL_MISSING:risk_score"
    assert "required signal missing" in resp.reason.lower()


def test_gate_strict_blocks_when_risk_fallback_fetch_fails(base_request):
    with patch.dict(
        os.environ,
        {"RELEASEGATE_STRICT_MODE": "true", "GITHUB_TOKEN": "test-github-token"},
    ):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 27,
    }
    gate.client.get_issue_property = MagicMock(return_value={})
    with patch("releasegate.integrations.jira.workflow_gate.requests.get", side_effect=requests.RequestException("boom")), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "GITHUB_UNAVAILABLE"
    assert "dependency unavailable" in resp.reason.lower()


def test_gate_strict_blocks_when_risk_scoring_fails(base_request):
    with patch.dict(
        os.environ,
        {"RELEASEGATE_STRICT_MODE": "true", "GITHUB_TOKEN": "test-github-token"},
    ):
        gate = WorkflowGate()
    base_request.environment = "PRODUCTION"
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 27,
    }
    gate.client.get_issue_property = MagicMock(return_value={})
    ok_pr = MagicMock(status_code=200)
    ok_pr.json.return_value = {"changed_files": 3, "additions": 10, "deletions": 1}
    with patch("releasegate.integrations.jira.workflow_gate.requests.get", return_value=ok_pr), patch(
        "releasegate.integrations.jira.workflow_gate.classify_pr_risk",
        side_effect=RuntimeError("model load failed"),
    ), patch.object(gate, "_record_with_timeout", side_effect=lambda decision, **_: decision):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "RISK_SCORING_FAILED"
    assert "model load failed" in resp.reason.lower()


def test_gate_strict_blocks_when_repo_or_pr_not_found(base_request):
    with patch.dict(
        os.environ,
        {"RELEASEGATE_STRICT_MODE": "true", "GITHUB_TOKEN": "test-github-token"},
    ):
        gate = WorkflowGate()
    base_request.environment = "STAGING"
    base_request.context_overrides = {
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 999999,
    }
    with patch(
        "releasegate.integrations.jira.workflow_gate.requests.get",
        return_value=MagicMock(status_code=404),
    ), patch.object(gate, "_record_with_timeout", side_effect=lambda decision, **_: decision):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "REPO_OR_PR_NOT_FOUND"
    assert "not found" in resp.reason.lower()


def test_gate_strict_blocks_when_project_not_allowed_for_tenant(base_request):
    with patch.dict(
        os.environ,
        {
            "RELEASEGATE_STRICT_MODE": "true",
            "RELEASEGATE_ALLOWED_PROJECTS_TENANT_TEST": "OTHER",
            "GITHUB_TOKEN": "test-github-token",
        },
    ):
        gate = WorkflowGate()
        base_request.environment = "STAGING"
        base_request.context_overrides = {
            "repo": "abishekgiri/change-risk-predictor-",
            "pr_number": 27,
        }
        with patch("releasegate.integrations.jira.workflow_gate.requests.get") as mock_get, patch.object(
            gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
        ):
            resp = gate.check_transition(base_request)
        mock_get.assert_not_called()
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "PROJECT_NOT_ALLOWED"
    assert "project" in resp.reason.lower()


def test_gate_strict_blocks_when_repo_not_allowed_for_tenant(base_request):
    with patch.dict(
        os.environ,
        {
            "RELEASEGATE_STRICT_MODE": "true",
            "RELEASEGATE_ALLOWED_REPOS_DEFAULT": "abishekgiri/another-repo",
            "RELEASEGATE_ALLOWED_REPOS_TENANT_TEST": "abishekgiri/another-repo",
            "GITHUB_TOKEN": "test-github-token",
        },
    ):
        gate = WorkflowGate()
        base_request.environment = "STAGING"
        base_request.context_overrides = {
            "repo": "abishekgiri/change-risk-predictor-",
            "pr_number": 27,
        }
        with patch("releasegate.integrations.jira.workflow_gate.requests.get") as mock_get, patch.object(
            gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
        ):
            resp = gate.check_transition(base_request)
        mock_get.assert_not_called()
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "REPO_NOT_ALLOWED"
    assert "not allowed" in resp.reason.lower()


def test_gate_jira_timeout_in_strict_mode_blocks(base_request):
    with patch.dict(os.environ, {"RELEASEGATE_STRICT_MODE": "true"}):
        gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(side_effect=JiraDependencyTimeout("jira timed out"))
    with patch.object(gate, "_resolve_policies", return_value=["SEC-PR-001"]), patch.object(
        gate, "_record_with_timeout", side_effect=lambda decision, **_: decision
    ):
        resp = gate.check_transition(base_request)
    assert resp.allow is False
    assert resp.status == "BLOCKED"
    assert resp.reason_code == "DEPENDENCY_TIMEOUT"
    assert "dependency timeout" in resp.reason
