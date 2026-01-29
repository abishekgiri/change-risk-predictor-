import pytest
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
