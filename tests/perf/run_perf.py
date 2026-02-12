from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class PerfStats:
    count: int
    total_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    ops_per_sec: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "total_ms": round(self.total_ms, 3),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "max_ms": round(self.max_ms, 3),
            "ops_per_sec": round(self.ops_per_sec, 3),
        }


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ranked = sorted(values)
    index = int(round((len(ranked) - 1) * (p / 100.0)))
    return ranked[min(max(index, 0), len(ranked) - 1)]


def _measure(samples: List[float]) -> PerfStats:
    total_ms = sum(samples)
    total_seconds = total_ms / 1000.0 if total_ms > 0 else 1e-9
    return PerfStats(
        count=len(samples),
        total_ms=total_ms,
        p50_ms=_percentile(samples, 50),
        p95_ms=_percentile(samples, 95),
        p99_ms=_percentile(samples, 99),
        max_ms=max(samples) if samples else 0.0,
        ops_per_sec=(len(samples) / total_seconds) if samples else 0.0,
    )


def _timed_loop(count: int, fn: Callable[[int], None]) -> List[float]:
    samples_ms: List[float] = []
    for idx in range(count):
        start = perf_counter()
        fn(idx)
        elapsed_ms = (perf_counter() - start) * 1000.0
        samples_ms.append(elapsed_ms)
    return samples_ms


def _warmup(fn: Callable[[], None], runs: int = 1) -> None:
    for _ in range(max(0, runs)):
        fn()


def _policy_hash(policy: dict) -> str:
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bindings_hash(bindings: list[dict]) -> str:
    material = []
    for binding in sorted(bindings, key=lambda row: row.get("policy_id", "")):
        material.append(
            {
                "policy_id": binding.get("policy_id"),
                "policy_version": binding.get("policy_version"),
                "policy_hash": binding.get("policy_hash"),
            }
        )
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_fixture(tenant_id: str) -> Dict[str, Any]:
    from fastapi.testclient import TestClient

    from releasegate.audit.checkpoints import create_override_checkpoint
    from releasegate.audit.overrides import record_override
    from releasegate.audit.recorder import AuditRecorder
    from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
    from releasegate.server import app
    from tests.auth_helpers import jwt_headers

    client = TestClient(app)
    repo = f"perf-{uuid.uuid4().hex[:8]}"
    pr_number = 101
    policy = {
        "policy_id": "PERF-001",
        "version": "1.0.0",
        "name": "Perf policy",
        "scope": "pull_request",
        "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "HIGH"}],
        "enforcement": {"result": "BLOCK", "message": "blocked for perf fixture"},
    }
    binding = PolicyBinding(
        policy_id="PERF-001",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy),
        policy=policy,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="BLOCKED: perf fixture",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="perf-user",
        reason_code="POLICY_BLOCKED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "HIGH"},
                "labels": [],
            },
            "policies_requested": ["PERF-001"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PERF-1"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)
    record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="PERF-1",
        decision_id=stored.decision_id,
        actor="perf-manager",
        reason="perf fixture",
        tenant_id=tenant_id,
    )
    create_override_checkpoint(
        repo=repo,
        cadence="daily",
        pr=pr_number,
        tenant_id=tenant_id,
        signing_key=os.environ["RELEASEGATE_CHECKPOINT_SIGNING_KEY"],
    )

    proof = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"format": "json", "tenant_id": tenant_id},
        headers=jwt_headers(
            tenant_id=tenant_id,
            scopes=["proofpack:read", "checkpoint:read", "policy:read"],
        ),
    )
    proof.raise_for_status()
    proof_bundle = proof.json()
    return {
        "tenant_id": tenant_id,
        "repo": repo,
        "pr_number": pr_number,
        "decision_id": stored.decision_id,
        "decision_snapshot": proof_bundle["decision_snapshot"],
        "input_snapshot": proof_bundle["input_snapshot"],
        "policy_snapshot": proof_bundle["policy_snapshot"],
        "proof_bundle": proof_bundle,
        "client": client,
    }


def run_perf(count: int, tenant_id: str) -> Dict[str, Any]:
    from releasegate.decision.hashing import (
        compute_decision_hash,
        compute_input_hash,
        compute_policy_hash_from_bindings,
        compute_replay_hash,
    )
    from releasegate.decision.types import Decision
    from releasegate.engine import ComplianceEngine
    from releasegate.replay.decision_replay import replay_decision
    from tests.auth_helpers import jwt_headers

    fixture = _build_fixture(tenant_id=tenant_id)
    decision = Decision.model_validate(fixture["decision_snapshot"])
    input_snapshot = fixture["input_snapshot"]
    policy_snapshot = fixture["policy_snapshot"]
    raw_signal_map = dict(input_snapshot.get("signal_map") or {})
    signal_map = {
        **raw_signal_map,
        "files_changed": list(raw_signal_map.get("files_changed") or []),
        "total_churn": int(raw_signal_map.get("total_churn") or 0),
        "commit_count": int(raw_signal_map.get("commit_count") or 0),
        "labels": list(raw_signal_map.get("labels") or []),
        "critical_paths": list(raw_signal_map.get("critical_paths") or []),
        "dependency_changes": list(raw_signal_map.get("dependency_changes") or []),
        "secrets_findings": list(raw_signal_map.get("secrets_findings") or []),
        "licenses": list(raw_signal_map.get("licenses") or []),
        "diff": raw_signal_map.get("diff") or {},
    }
    base_client = fixture["client"]
    decision_id = fixture["decision_id"]

    with contextlib.redirect_stdout(io.StringIO()):
        _warmup(lambda: replay_decision(decision), runs=1)
        replay_samples = _timed_loop(count, lambda _i: replay_decision(decision))
    hash_samples = _timed_loop(
        count,
        lambda _i: (
            compute_input_hash(input_snapshot),
            compute_policy_hash_from_bindings(policy_snapshot),
            compute_decision_hash(
                release_status=str(decision.release_status.value),
                reason_code=decision.reason_code,
                policy_bundle_hash=str(decision.policy_bundle_hash),
                inputs_present=decision.inputs_present,
            ),
            compute_replay_hash(
                input_hash=decision.input_hash or compute_input_hash(input_snapshot),
                policy_hash=decision.policy_hash or decision.policy_bundle_hash,
                decision_hash=decision.decision_hash
                or compute_decision_hash(
                    release_status=str(decision.release_status.value),
                    reason_code=decision.reason_code,
                    policy_bundle_hash=str(decision.policy_bundle_hash),
                    inputs_present=decision.inputs_present,
                ),
            ),
        ),
    )
    evaluator = ComplianceEngine({"tenant_id": tenant_id})
    with contextlib.redirect_stdout(io.StringIO()):
        _warmup(lambda: evaluator.evaluate(dict(signal_map)), runs=1)
        evaluator_samples = _timed_loop(count, lambda _i: evaluator.evaluate(dict(signal_map)))

    simulation_engine = ComplianceEngine({"tenant_id": tenant_id})

    def _simulate(i: int) -> None:
        risk_level = "HIGH" if i % 3 == 0 else "MEDIUM" if i % 3 == 1 else "LOW"
        simulation_engine.evaluate(
            {
                **signal_map,
                "risk": {"level": risk_level},
                "total_churn": int(signal_map.get("total_churn", 0)) + (i % 50),
                "labels": [f"perf-{i % 5}"],
            }
        )

    with contextlib.redirect_stdout(io.StringIO()):
        _warmup(lambda: _simulate(0), runs=1)
        simulation_samples = _timed_loop(count, _simulate)

    def _export(_i: int) -> None:
        response = base_client.get(
            f"/audit/proof-pack/{decision_id}",
            params={"format": "json", "tenant_id": tenant_id},
            headers=jwt_headers(
                tenant_id=tenant_id,
                scopes=["proofpack:read", "checkpoint:read", "policy:read"],
            ),
        )
        if response.status_code != 200:
            raise RuntimeError(f"proof-pack export failed with status {response.status_code}: {response.text}")

    _warmup(lambda: _export(0), runs=1)
    export_samples = _timed_loop(count, _export)

    return {
        "decision_replay_1k": {
            "summary": _measure(replay_samples).as_dict(),
            "breakdown": {
                "hashing_only": _measure(hash_samples).as_dict(),
                "policy_eval_only": _measure(evaluator_samples).as_dict(),
            },
        },
        "policy_simulation_1k": {
            "summary": _measure(simulation_samples).as_dict(),
            "simulation_strategy": "same policy set, varied input snapshots",
        },
        "proof_pack_export_1k": {
            "summary": _measure(export_samples).as_dict(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ReleaseGate Phase 7 perf runner")
    parser.add_argument("--count", type=int, default=1000, help="Iterations per benchmark")
    parser.add_argument("--tenant", default="tenant-perf", help="Tenant id used for fixtures")
    parser.add_argument(
        "--results-dir",
        default="tests/perf/results",
        help="Directory for JSON benchmark reports",
    )
    parser.add_argument(
        "--db-path",
        help="Optional sqlite DB path for isolated perf run (default: temp file)",
    )
    args = parser.parse_args()

    db_path = Path(args.db_path) if args.db_path else Path(tempfile.mkdtemp(prefix="releasegate_perf_")) / "perf.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.environ["DB_PATH"] = str(db_path)
    os.environ["COMPLIANCE_DB_PATH"] = str(db_path)
    os.environ["RELEASEGATE_TENANT_ID"] = args.tenant
    os.environ.setdefault("RELEASEGATE_JWT_SECRET", "test-jwt-secret")
    os.environ.setdefault("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "perf-signing-secret")
    os.environ.setdefault("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID", "perf-key")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_TENANT_HEAVY", "50000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_IP_HEAVY", "50000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT", "50000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_IP_DEFAULT", "50000")
    os.environ.setdefault(
        "RELEASEGATE_CHECKPOINT_STORE_DIR",
        str(Path(tempfile.mkdtemp(prefix="releasegate_perf_ckpt_"))),
    )

    bench = run_perf(count=args.count, tenant_id=args.tenant)
    report = {
        "schema_version": "perf_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bench_name": "releasegate_phase7_perf",
        "count": args.count,
        "warmup_runs": 1,
        "tenant_id": args.tenant,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "db_path": str(db_path),
        },
        "benchmarks": bench,
    }

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / f"perf_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(f"\nWrote perf report: {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
