import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.policy.simulation import simulate_policy_impact


def _record_decision(repo: str, pr_number: int, status: str, risk_level: str) -> Decision:
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status=status,
        context_id=f"jira-{repo}-{pr_number}",
        message=f"{status}: test",
        policy_bundle_hash="sim-v1",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="sim-user",
        reason_code="SIM_TEST",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": risk_level},
                "labels": [],
            },
            "policies_requested": ["SIM-001"],
        },
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["SIM-1"]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)


def _write_sim_policy(policy_dir: Path) -> None:
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy = {
        "policy_id": "SIM-001",
        "name": "Block high risk",
        "scope": "pull_request",
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "HIGH"},
        ],
        "enforcement": {"result": "BLOCK", "message": "High risk blocked"},
    }
    (policy_dir / "SIM-001.yaml").write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


def test_policy_simulation_reports_impact(tmp_path):
    repo = f"sim-{uuid.uuid4().hex[:8]}"
    _record_decision(repo=repo, pr_number=1, status="ALLOWED", risk_level="LOW")
    _record_decision(repo=repo, pr_number=2, status="ALLOWED", risk_level="HIGH")

    policy_dir = tmp_path / "compiled"
    _write_sim_policy(policy_dir)

    report = simulate_policy_impact(
        repo=repo,
        limit=10,
        policy_dir=str(policy_dir),
    )

    assert report["repo"] == repo
    assert report["policy_count"] == 1
    assert report["total_rows"] == 2
    assert report["simulated_rows"] == 2
    assert report["unsimulated_rows"] == 0
    assert report["changed_count"] == 1
    assert report["would_newly_block"] == 1
    assert report["would_unblock"] == 0
    assert report["simulated_counts"]["BLOCKED"] == 1
