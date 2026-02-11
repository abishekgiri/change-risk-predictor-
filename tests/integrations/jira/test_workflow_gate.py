import pytest
import os
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from releasegate.integrations.jira.types import TransitionCheckRequest
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.decision.types import Decision, EnforcementTargets

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
    # Mock resolve to check logic (or create temp file)
    with patch("builtins.open", side_effect=FileNotFoundError):
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

@patch("releasegate.engine.ComplianceEngine")
@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_flow_allowed(MockRecorder, MockEngine, base_request):
    """Test full allowed flow."""
    gate = WorkflowGate()
    gate.client.get_issue_property = MagicMock(return_value={"risk_level": "LOW"})
    
    # Mock Engine Result (ComplianceRunResult structure)
    mock_run_result = MagicMock()
    mock_policy_result = MagicMock()
    mock_policy_result.policy_id = "p1"
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
    with patch.object(gate, '_resolve_policies', return_value=["p1"]):
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
    mock_policy_result.policy_id = "p1"
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

    with patch.object(gate, '_resolve_policies', return_value=["p1"]):
        resp = gate.check_transition(base_request)
        
    # Should upgrade to BLOCKED
    assert resp.allow is False
    assert resp.status == "BLOCKED" 
    # Should have posted comment
    gate.client.post_comment_deduped.assert_called_once()


@patch("releasegate.integrations.jira.workflow_gate.AuditRecorder")
def test_gate_skips_when_risk_metadata_missing(MockRecorder, base_request):
    gate = WorkflowGate()
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
    gate = WorkflowGate()
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
    gate = WorkflowGate()
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
    warn_policy.policy_id = "P-WARN"
    warn_policy.status = "WARN"
    warn_policy.violations = ["Need one approval"]
    block_policy = MagicMock()
    block_policy.policy_id = "P-BLOCK"
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

    with patch.object(gate, "_resolve_policies", return_value=["P-WARN", "P-BLOCK"]):
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
