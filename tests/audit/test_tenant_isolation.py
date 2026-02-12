import uuid
from datetime import datetime, timezone

from releasegate.audit.overrides import get_active_override, record_override, verify_override_chain
from releasegate.audit.reader import AuditReader
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets


def _decision(repo: str, pr_number: int, tenant_id: str, evaluation_key: str) -> Decision:
    return Decision(
        tenant_id=tenant_id,
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: tenant test",
        policy_bundle_hash="tenant-hash",
        evaluation_key=evaluation_key,
        actor_id="tenant-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["TEN-1"]},
        ),
    )


def test_audit_decisions_are_scoped_by_tenant():
    repo = f"tenant-repo-{uuid.uuid4().hex[:8]}"
    pr_number = 11
    shared_eval_key = f"{repo}:{pr_number}:shared-key"

    d1 = _decision(repo, pr_number, tenant_id="tenant-alpha", evaluation_key=shared_eval_key)
    d2 = _decision(repo, pr_number, tenant_id="tenant-beta", evaluation_key=shared_eval_key)

    AuditRecorder.record_with_context(d1, repo=repo, pr_number=pr_number, tenant_id="tenant-alpha")
    AuditRecorder.record_with_context(d2, repo=repo, pr_number=pr_number, tenant_id="tenant-beta")

    rows_alpha = AuditReader.list_decisions(repo=repo, limit=20, tenant_id="tenant-alpha")
    rows_beta = AuditReader.list_decisions(repo=repo, limit=20, tenant_id="tenant-beta")

    alpha_ids = {row["decision_id"] for row in rows_alpha}
    beta_ids = {row["decision_id"] for row in rows_beta}

    assert d1.decision_id in alpha_ids
    assert d2.decision_id not in alpha_ids
    assert d2.decision_id in beta_ids
    assert d1.decision_id not in beta_ids


def test_override_chains_are_scoped_by_tenant():
    repo = f"tenant-chain-{uuid.uuid4().hex[:8]}"

    record_override(
        repo=repo,
        pr_number=1,
        issue_key="TEN-1",
        decision_id="d-1",
        actor="actor-1",
        reason="reason-1",
        tenant_id="tenant-alpha",
    )
    record_override(
        repo=repo,
        pr_number=1,
        issue_key="TEN-1",
        decision_id="d-2",
        actor="actor-2",
        reason="reason-2",
        tenant_id="tenant-beta",
    )

    alpha = verify_override_chain(repo=repo, tenant_id="tenant-alpha")
    beta = verify_override_chain(repo=repo, tenant_id="tenant-beta")

    assert alpha["valid"] is True
    assert beta["valid"] is True
    assert alpha["checked"] == 1
    assert beta["checked"] == 1


def test_get_active_override_by_target_is_tenant_scoped():
    repo = f"tenant-active-{uuid.uuid4().hex[:8]}"
    pr_number = 33
    target_id = f"{repo}#{pr_number}"
    record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="TEN-33",
        decision_id="d-alpha",
        actor="alpha",
        reason="r-alpha",
        tenant_id="tenant-alpha",
        target_type="pr",
        target_id=target_id,
    )
    record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="TEN-33",
        decision_id="d-beta",
        actor="beta",
        reason="r-beta",
        tenant_id="tenant-beta",
        target_type="pr",
        target_id=target_id,
    )
    active_alpha = get_active_override(tenant_id="tenant-alpha", target_type="pr", target_id=target_id)
    active_beta = get_active_override(tenant_id="tenant-beta", target_type="pr", target_id=target_id)

    assert active_alpha["decision_id"] == "d-alpha"
    assert active_beta["decision_id"] == "d-beta"
