#!/usr/bin/env python3
"""
Golden demo harness:
attach risk -> block transition -> override -> export proof pack -> verify -> replay -> simulate
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, Dict

from releasegate.audit.checkpoints import create_override_checkpoint
from releasegate.audit.overrides import list_overrides
from releasegate.audit.reader import AuditReader
from releasegate.decision.types import Decision
from releasegate.integrations.github_risk import (
    PRRiskInput,
    build_issue_risk_property,
    classify_pr_risk,
)
from releasegate.integrations.jira.types import TransitionCheckRequest
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.policy.simulation import simulate_policy_impact
from releasegate.replay.decision_replay import replay_decision
from releasegate.storage.migrate import migrate


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "golden"
OUT_DIR = ROOT / "out" / "golden"
OUT_DIR_REL = "out/golden"
INPUT_FIXTURE = FIXTURES / "input_snapshot.json"
TRANSITION_MAP = FIXTURES / "jira_transition_map.yaml"
ROLE_MAP = FIXTURES / "jira_role_map.yaml"


class GoldenFailure(RuntimeError):
    pass


class InMemoryIssuePropertyStore:
    def __init__(self) -> None:
        self._properties: Dict[tuple[str, str], Dict[str, Any]] = {}

    def set_issue_property(self, issue_key: str, prop_key: str, value: Dict[str, Any]) -> bool:
        self._properties[(issue_key, prop_key)] = dict(value or {})
        return True

    def get_issue_property(self, issue_key: str, prop_key: str) -> Dict[str, Any]:
        return dict(self._properties.get((issue_key, prop_key), {}))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _run_cli(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "releasegate.cli", *cmd],
        cwd=str(ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise GoldenFailure(
            f"CLI command failed ({' '.join(cmd)}): rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def _parse_json_payload(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise GoldenFailure("Expected JSON output but received empty stdout")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise GoldenFailure(f"Expected JSON object in stdout, got: {text[:200]}")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise GoldenFailure(f"Failed to parse JSON output: {exc}") from exc


def _read_decision(decision_id: str, tenant_id: str) -> Decision:
    row = AuditReader.get_decision(decision_id, tenant_id=tenant_id)
    if not row:
        raise GoldenFailure(f"Decision not found: {decision_id}")
    raw = row.get("full_decision_json")
    if not raw:
        raise GoldenFailure(f"Decision {decision_id} has no full_decision_json")
    payload = json.loads(raw) if isinstance(raw, str) else raw
    return Decision.model_validate(payload)


def _run_quiet(fn, *args, **kwargs):
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        return fn(*args, **kwargs)


def _request_from_fixture(fixture: Dict[str, Any], *, tenant_id: str, delivery_id: str, override: bool = False) -> TransitionCheckRequest:
    transition = fixture["transition"]
    actor = fixture["actor"]
    override_cfg = fixture.get("override", {})
    context_overrides: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "repo": fixture["repo"],
        "pr_number": fixture["pr_number"],
        "delivery_id": delivery_id,
        "idempotency_key": delivery_id,
        "jira_groups": ["release-operators"],
        "jira_project_roles": ["Developers"],
    }
    if override:
        context_overrides.update(
            {
                "override": True,
                "override_reason": override_cfg.get("reason", "Override approved"),
                "override_justification_required": bool(override_cfg.get("justification_required", True)),
            }
        )
    return TransitionCheckRequest(
        issue_key=fixture["issue_key"],
        transition_id=str(transition["id"]),
        transition_name=str(transition["name"]),
        source_status=str(transition["source_status"]),
        target_status=str(transition["target_status"]),
        actor_account_id=str(actor["account_id"]),
        actor_email=str(actor["email"]),
        environment=str(transition["environment"]),
        project_key=str(transition["project_key"]),
        issue_type=str(transition["issue_type"]),
        tenant_id=tenant_id,
        context_overrides=context_overrides,
    )


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Deterministic local defaults for the golden path.
    os.environ.setdefault("RELEASEGATE_STORAGE_BACKEND", "sqlite")
    os.environ.setdefault("RELEASEGATE_STRICT_MODE", "true")
    os.environ.setdefault("RELEASEGATE_TENANT_ID", "golden-demo")
    os.environ.setdefault("COMPLIANCE_DB_PATH", str(OUT_DIR / "releasegate_golden.db"))
    os.environ.setdefault("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "golden-demo-checkpoint-signing-key")
    os.environ.setdefault("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID", "golden-demo-key")

    tenant_id = os.environ["RELEASEGATE_TENANT_ID"]
    fixture = json.loads(INPUT_FIXTURE.read_text(encoding="utf-8"))

    migrate()

    property_store = InMemoryIssuePropertyStore()

    # Step A: attach risk metadata
    metrics = fixture["risk_metrics"]
    risk_input = PRRiskInput(
        changed_files=int(metrics["changed_files_count"]),
        additions=int(metrics["additions"]),
        deletions=int(metrics["deletions"]),
    )
    risk_level = classify_pr_risk(risk_input)
    risk_payload = build_issue_risk_property(
        repo=fixture["repo"],
        pr_number=int(fixture["pr_number"]),
        risk_level=risk_level,
        metrics=risk_input,
    )
    if not property_store.set_issue_property(fixture["issue_key"], "releasegate_risk", risk_payload):
        raise GoldenFailure("Failed to attach releasegate_risk metadata")
    _write_json(OUT_DIR / "risk_metadata.json", risk_payload)
    print(
        "Risk attached \u2705"
        f" (issue={fixture['issue_key']}, pr={fixture['pr_number']}, level={risk_payload.get('releasegate_risk')})"
    )

    gate = WorkflowGate()
    gate.policy_map_path = str(TRANSITION_MAP)
    gate.role_map_path = str(ROLE_MAP)
    gate.client.get_issue_property = property_store.get_issue_property  # type: ignore[assignment]
    gate.client.set_issue_property = property_store.set_issue_property  # type: ignore[assignment]

    # Step B: transition block
    block_req = _request_from_fixture(
        fixture,
        tenant_id=tenant_id,
        delivery_id="golden-block-event-v1",
        override=False,
    )
    block_resp = _run_quiet(gate.check_transition, block_req)
    if block_resp.status != "BLOCKED" or block_resp.allow:
        raise GoldenFailure(f"Expected BLOCKED transition, got status={block_resp.status} allow={block_resp.allow}")
    blocked_decision = _read_decision(block_resp.decision_id, tenant_id=tenant_id)
    _write_json(OUT_DIR / "transition_block_response.json", block_resp.model_dump(mode="json"))
    print(
        "Transition blocked \u2705"
        f" (decision_id={block_resp.decision_id}, reason_code={blocked_decision.reason_code})"
    )

    # Step C: override with justification
    override_req = _request_from_fixture(
        fixture,
        tenant_id=tenant_id,
        delivery_id="golden-override-event-v1",
        override=True,
    )
    override_resp = _run_quiet(gate.check_transition, override_req)
    if override_resp.status not in {"ALLOWED", "CONDITIONAL"} or not override_resp.allow:
        raise GoldenFailure(f"Expected ALLOWED/CONDITIONAL override decision, got {override_resp.status}")
    override_decision = _read_decision(override_resp.decision_id, tenant_id=tenant_id)
    overrides = list_overrides(
        repo=fixture["repo"],
        pr=int(fixture["pr_number"]),
        tenant_id=tenant_id,
        limit=100,
    )
    override_event = next((row for row in overrides if row.get("decision_id") == override_resp.decision_id), None)
    if not override_event:
        raise GoldenFailure("Override ledger entry not found for override decision")
    _write_json(OUT_DIR / "transition_override_response.json", override_resp.model_dump(mode="json"))
    _write_json(OUT_DIR / "override_event.json", override_event)
    print(
        "Override recorded \u2705"
        f" (override_id={override_event.get('override_id')}, actor={override_event.get('actor')})"
    )

    # Step D: checkpoint + proof pack export
    checkpoint = create_override_checkpoint(
        repo=fixture["repo"],
        pr=int(fixture["pr_number"]),
        cadence="daily",
        tenant_id=tenant_id,
    )
    _write_json(OUT_DIR / "checkpoint.json", checkpoint)
    proof_pack_path = OUT_DIR / "proof_pack.json"
    proof_pack_decision_id = block_resp.decision_id
    _run_cli(
        [
            "proof-pack",
            "--decision-id",
            proof_pack_decision_id,
            "--tenant",
            tenant_id,
            "--format",
            "json",
            "--checkpoint-cadence",
            "daily",
            "--output",
            str(proof_pack_path),
        ]
    )
    proof_pack = json.loads(proof_pack_path.read_text(encoding="utf-8"))
    print(
        "Proof pack exported \u2705"
        f" (decision_id={proof_pack_decision_id}, proof_pack_id={proof_pack.get('proof_pack_id')}, checksum={proof_pack.get('export_checksum')})"
    )

    # Step E: offline verification
    verify_proc = _run_cli(
        [
            "verify-proof-pack",
            str(proof_pack_path),
            "--format",
            "json",
            "--signing-key",
            os.environ["RELEASEGATE_CHECKPOINT_SIGNING_KEY"],
        ]
    )
    verify_report = _parse_json_payload(verify_proc.stdout)
    _write_json(OUT_DIR / "verify_report.json", verify_report)
    if not verify_report.get("ok"):
        raise GoldenFailure(f"Proof-pack verification failed: {verify_report.get('error_code')}")
    print("Proof pack verified \u2705")

    # Step F: deterministic replay
    replay_report = _run_quiet(replay_decision, blocked_decision)
    _write_json(OUT_DIR / "replay_report.json", replay_report)
    if not replay_report.get("matches_original"):
        raise GoldenFailure(f"Replay mismatch: {replay_report.get('mismatch_reason')}")
    print("Replay matches original \u2705")

    # Step G: policy simulation impact
    simulation_report = _run_quiet(
        simulate_policy_impact,
        repo=fixture["repo"],
        limit=100,
        policy_dir="releasegate/policy/compiled",
        tenant_id=tenant_id,
    )
    _write_json(OUT_DIR / "simulation_report.json", simulation_report)
    print(
        "Simulation impact \u2705"
        f" (simulated_rows={simulation_report.get('simulated_rows')}, changed_count={simulation_report.get('changed_count')})"
    )

    summary = {
        "pass": True,
        "final_status": "PASS",
        "decision_id": proof_pack_decision_id,
        "tenant_id": tenant_id,
        "issue_key": fixture["issue_key"],
        "repo": fixture["repo"],
        "pr_number": fixture["pr_number"],
        "blocked_decision_id": block_resp.decision_id,
        "override_decision_id": override_resp.decision_id,
        "override_id": override_event.get("override_id"),
        "reason_code": blocked_decision.reason_code,
        "proof_pack_decision_id": proof_pack_decision_id,
        "proof_pack_id": proof_pack.get("proof_pack_id"),
        "export_checksum": proof_pack.get("export_checksum"),
        "matches_original": replay_report.get("matches_original"),
        "simulation_changed_count": simulation_report.get("changed_count"),
        "output_dir": OUT_DIR_REL,
        "artifacts_dir": OUT_DIR_REL,
    }
    _write_json(OUT_DIR / "summary.json", summary)
    print(f"Artifacts written to {OUT_DIR_REL}")
    print("\n\u2705 PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GoldenFailure as exc:
        print(f"\u274c FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
