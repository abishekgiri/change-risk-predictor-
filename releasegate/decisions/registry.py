"""ReleaseGate Decision Registry — Phase 7 System of Record Authority.

This module owns:
  - Human-readable decision ID format  (rg_dec_YYYYMMDD_uuid8)
  - Governance declaration for CI/CD deploys (non-Jira path)
  - Full audit graph trace  (decision → checkpoint → external anchor)
  - Authority report        (coverage, completeness, standalone-audit test)
  - Decision verification   (replay_hash reconstruction check)

The decision_id stored in ``audit_decisions`` is a UUID.  All public APIs
here accept both the UUID form and the human-readable ``rg_dec_…`` form.

Decision ID format
------------------
    rg_dec_<YYYYMMDD>_<first-8-hex-chars-of-uuid-without-dashes>

Example:
    rg_dec_20260416_ab3f7e21
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def format_rg_decision_id(decision_id: str, created_at: str) -> str:
    """Return the human-readable rg_dec_YYYYMMDD_uuid8 form."""
    date_part = created_at[:10].replace("-", "")          # "2026-04-16" → "20260416"
    uuid_part = decision_id.replace("-", "")[:8]          # strip dashes, take first 8
    return f"rg_dec_{date_part}_{uuid_part}"


def parse_rg_decision_id(rg_id: str) -> Optional[tuple[str, str]]:
    """Extract (date_str, uuid_prefix) from an rg_dec_… ID.

    Returns None if the string is not a valid rg_dec_… ID or if the UUID
    prefix is not exactly 8 hex characters (prevents empty-prefix LIKE '%%' queries).
    """
    if not rg_id.startswith("rg_dec_"):
        return None
    parts = rg_id.split("_")
    if len(parts) < 4:
        return None
    date_raw = parts[2]   # "20260416"
    uuid_prefix = parts[3]
    if len(uuid_prefix) != 8:
        return None
    # Convert "20260416" → "2026-04-16" for SQL date prefix matching
    date_str = f"{date_raw[:4]}-{date_raw[4:6]}-{date_raw[6:8]}"
    return date_str, uuid_prefix


# ---------------------------------------------------------------------------
# Database lookups
# ---------------------------------------------------------------------------

def resolve_decision_row(rg_id: str, tenant_id: str, storage: Any) -> Optional[Dict[str, Any]]:
    """Look up an audit_decisions row by rg_dec_… ID or plain UUID."""
    if rg_id.startswith("rg_dec_"):
        parsed = parse_rg_decision_id(rg_id)
        if not parsed:
            return None
        date_str, uuid_prefix = parsed
        # Narrow by date prefix first to prevent full-table scans and eliminate
        # any risk of an empty LIKE pattern matching the wrong row.
        row = storage.fetchone(
            """SELECT * FROM audit_decisions
               WHERE tenant_id = ? AND created_at LIKE ? AND decision_id LIKE ?
               ORDER BY created_at DESC LIMIT 1""",
            (tenant_id, f"{date_str}%", f"{uuid_prefix}%"),
        )
    else:
        row = storage.fetchone(
            "SELECT * FROM audit_decisions WHERE tenant_id = ? AND decision_id = ? LIMIT 1",
            (tenant_id, rg_id),
        )
    return row


def _parse_full_json(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("full_decision_json") or "{}"
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Governance declaration (non-Jira CI/CD path)
# ---------------------------------------------------------------------------

def declare_deploy_decision(
    *,
    tenant_id: str,
    repo: str,
    environment: str,
    actor_id: str = "ci",
    sha: Optional[str] = None,
    pr_number: Optional[int] = None,
    jira_issue_key: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Declare a governance decision for a deploy.

    This is the authoritative "get me a decision ID" endpoint for CI/CD
    pipelines that are not driven by a Jira transition.  The decision is
    recorded to ``audit_decisions`` with all four integrity hashes and is
    immediately covered by the next checkpoint cycle.

    Evaluation logic (in priority order):
    1. Signal freshness — BLOCKED if risk signal is older than policy max_age or absent.
    2. Active policy release — if a policy release is active for this tenant+environment,
       run the full policy engine against available signals; any BLOCK enforcement blocks.
    3. ALLOWED if all checks pass.

    Returns a dict with:
      rg_decision_id, decision_id, status, reason_code, message, rg_id_url
    """
    from releasegate.decision.types import (
        Decision, DecisionType, EnforcementTargets, ExternalKeys, PolicyBinding,
    )
    from releasegate.audit.recorder import AuditRecorder
    from releasegate.governance.signal_freshness import (
        evaluate_risk_signal_freshness,
        resolve_signal_freshness_policy,
    )
    from releasegate.storage.base import get_storage_backend

    storage = get_storage_backend()
    now = datetime.now(timezone.utc)
    overrides = policy_overrides or {}

    # 1. Load latest risk signal age for this tenant + repo
    sig_row = storage.fetchone(
        "SELECT MAX(computed_at) as latest FROM audit_decisions WHERE tenant_id = ? AND repo = ?",
        (tenant_id, repo),
    )
    signal_age_seconds: Optional[float] = None
    if sig_row and sig_row.get("latest"):
        try:
            latest = datetime.fromisoformat(str(sig_row["latest"]))
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=timezone.utc)
            signal_age_seconds = (now - latest).total_seconds()
        except Exception:
            pass

    # 2. Evaluate signal freshness
    freshness_policy = resolve_signal_freshness_policy(
        policy_overrides=overrides.get("signals"),
        strict_enabled=True,
    )
    fr = evaluate_risk_signal_freshness(
        computed_at=sig_row.get("latest") if sig_row else None,
        policy=freshness_policy,
    )
    signal_stale: bool = bool(fr.get("stale", True))
    reason_code = fr.get("reason_code") or "SIGNAL_STALE"
    max_age_s = int(freshness_policy.get("max_age_seconds") or 3600)

    # 3. Determine initial verdict from signal freshness
    if signal_stale:
        status = DecisionType.BLOCKED
        if not sig_row or not sig_row.get("latest"):
            reason_code = "NO_RISK_SIGNAL"
            message = (
                f"Deploy BLOCKED: no risk signal found for {repo}. "
                "Run a risk evaluation before deploying."
            )
        else:
            age_h = round((signal_age_seconds or 0) / 3600, 1)
            message = (
                f"Deploy BLOCKED: risk signal for {repo} is {age_h}h old "
                f"(max {max_age_s // 3600}h). Re-evaluate before deploying."
            )
    else:
        status = DecisionType.ALLOWED
        reason_code = "SIGNAL_FRESH"
        age_h = round((signal_age_seconds or 0) / 3600, 1)
        message = (
            f"Deploy ALLOWED: risk signal for {repo} is fresh ({age_h}h old)."
        )

    # 4. Run active policy release (full policy engine) if one is configured.
    # This enforces mandatory approvals, security scan thresholds, and any
    # custom rules the tenant has activated — not just signal freshness.
    if status == DecisionType.ALLOWED:
        try:
            from releasegate.policy.releases import get_active_policy_release
            from releasegate.engine_core.evaluator import evaluate_policy
            from releasegate.engine_core.evaluate import check_condition

            policy_release = get_active_policy_release(
                tenant_id=tenant_id,
                policy_id="deploy-gate",
                target_env=environment,
            )
            if policy_release:
                snapshot = policy_release.get("snapshot") or {}
                policies = snapshot.get("policies") or []
                signals: Dict[str, Any] = {
                    "signal_fresh": not signal_stale,
                    "signal_age_hours": round((signal_age_seconds or 0) / 3600, 2),
                    "repo": repo,
                    "environment": environment,
                    "actor": actor_id,
                }
                signals.update(overrides.get("signals", {}))
                for pol in policies:
                    try:
                        result = evaluate_policy(pol, signals, check_condition=check_condition)
                        if result.triggered and str(result.status).upper() in ("BLOCK", "BLOCKED"):
                            status = DecisionType.BLOCKED
                            reason_code = f"POLICY_BLOCK:{result.policy_id}"
                            message = (
                                f"Deploy BLOCKED by policy '{result.policy_id}': "
                                + "; ".join(result.violations or ["policy triggered"])
                            )
                            break
                    except Exception as pol_err:
                        logger.warning("Policy evaluation error for %s: %s", pol, pol_err)
        except Exception as policy_err:
            # Fail-closed: if the policy engine itself errors, block the deploy
            logger.error("Policy engine unavailable during declare: %s", policy_err)
            status = DecisionType.BLOCKED
            reason_code = "POLICY_ENGINE_ERROR"
            message = "Deploy BLOCKED: policy engine unavailable (fail-closed)."

    # 4. Build Decision object
    context_id = str(uuid.uuid4())
    eval_key_raw = f"{repo}:{sha or 'HEAD'}:{environment}:{now.isoformat()}:{tenant_id}"
    evaluation_key = hashlib.sha256(eval_key_raw.encode()).hexdigest()

    decision = Decision(
        timestamp=now,
        release_status=status,
        context_id=context_id,
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref=sha or "HEAD",
            external=ExternalKeys(jira=[jira_issue_key] if jira_issue_key else []),
        ),
        actor_id=actor_id,
        message=message,
        reason_code=reason_code,
        inputs_present={
            "risk_signal": sig_row is not None and bool(sig_row.get("latest")),
            "signal_fresh": not signal_stale,
        },
        input_snapshot={
            "repo": repo,
            "environment": environment,
            "sha": sha,
            "actor": actor_id,
            "pr_number": pr_number,
            "jira_issue_key": jira_issue_key,
            "signal_age_seconds": signal_age_seconds,
            "signal_max_age_seconds": max_age_s,
        },
        policy_bindings=[
            PolicyBinding(
                policy_id="deploy-gate-signal-freshness-v1",
                policy_version="1.0",
                policy_hash=hashlib.sha256(
                    f"deploy-gate:{tenant_id}:{max_age_s}".encode()
                ).hexdigest()[:16],
                tenant_id=tenant_id,
                policy={
                    "type": "signal_freshness",
                    "max_age_seconds": max_age_s,
                    "fail_closed": True,
                },
            )
        ],
        policy_bundle_hash=hashlib.sha256(
            f"deploy-gate-v1:{tenant_id}".encode()
        ).hexdigest()[:8],
        evaluation_key=evaluation_key,
        tenant_id=tenant_id,
    )

    # 5. Record (attaches hashes + persists)
    AuditRecorder.record_with_context(
        decision, repo=repo, pr_number=pr_number, tenant_id=tenant_id
    )

    rg_id = format_rg_decision_id(decision.decision_id, now.isoformat())
    return {
        "rg_decision_id": rg_id,
        "decision_id": decision.decision_id,
        "tenant_id": tenant_id,
        "status": str(decision.release_status),
        "reason_code": reason_code,
        "message": message,
        "allowed": status == DecisionType.ALLOWED,
        "repo": repo,
        "environment": environment,
        "created_at": now.isoformat(),
        "signal_age_seconds": signal_age_seconds,
        "hashes": {
            "input_hash": decision.input_hash,
            "policy_hash": decision.policy_hash,
            "decision_hash": decision.decision_hash,
            "replay_hash": decision.replay_hash,
        },
    }


# ---------------------------------------------------------------------------
# Audit graph trace
# ---------------------------------------------------------------------------

def trace_decision(
    rg_id: str,
    tenant_id: str,
    storage: Any,
) -> Dict[str, Any]:
    """Return a full audit graph trace for a decision.

    Chain:
        decision → covering checkpoint → external anchor

    Each step includes all hashes needed for offline verification.
    """
    row = resolve_decision_row(rg_id, tenant_id, storage)
    if not row:
        return {"ok": False, "error": "Decision not found"}

    full_json = _parse_full_json(row)
    created_at = str(row.get("created_at") or "")
    decision_id = str(row.get("decision_id") or "")

    # ── Step 1: Decision node ──────────────────────────────────────────────
    decision_node: Dict[str, Any] = {
        "rg_decision_id": format_rg_decision_id(decision_id, created_at),
        "decision_id": decision_id,
        "tenant_id": tenant_id,
        "repo": row.get("repo"),
        "status": row.get("release_status"),
        "reason_code": full_json.get("reason_code"),
        "message": full_json.get("message"),
        "actor": full_json.get("actor_id"),
        "created_at": created_at,
        "hashes": {
            "input_hash": row.get("input_hash"),
            "policy_hash": row.get("policy_hash"),
            "decision_hash": row.get("decision_hash"),
            "replay_hash": row.get("replay_hash"),
        },
        "inputs_present": full_json.get("inputs_present", {}),
        "input_snapshot": full_json.get("input_snapshot", {}),
        "policy_bindings": [
            {
                "policy_id": b.get("policy_id"),
                "policy_version": b.get("policy_version"),
                "policy_hash": b.get("policy_hash"),
            }
            for b in (full_json.get("policy_bindings") or [])
        ],
    }

    # ── Step 2: Covering checkpoint ────────────────────────────────────────
    checkpoint_node: Optional[Dict[str, Any]] = None
    checkpoint_root_hash: Optional[str] = None
    try:
        cp_row = storage.fetchone(
            """SELECT * FROM audit_checkpoints
               WHERE tenant_id = ?
                 AND created_at >= ?
               ORDER BY created_at ASC LIMIT 1""",
            (tenant_id, created_at),
        )
        if cp_row:
            checkpoint_root_hash = str(cp_row.get("root_hash") or "")
            checkpoint_node = {
                "checkpoint_id": cp_row.get("checkpoint_id"),
                "root_hash": checkpoint_root_hash,
                "cadence": cp_row.get("cadence"),
                "period_id": cp_row.get("period_id"),
                "period_end": str(cp_row.get("period_end") or ""),
                "event_count": cp_row.get("event_count"),
                "signature_algorithm": cp_row.get("signature_algorithm"),
                "signature_value": (cp_row.get("signature_value") or "")[:16] + "…",
                "created_at": str(cp_row.get("created_at") or ""),
                "covers_decision": True,
            }
    except Exception:
        logger.debug("checkpoint trace failed for decision %s", decision_id, exc_info=True)

    # ── Step 3: External anchor ────────────────────────────────────────────
    anchor_node: Optional[Dict[str, Any]] = None
    try:
        if checkpoint_root_hash:
            anc_row = storage.fetchone(
                """SELECT * FROM anchor_jobs
                   WHERE tenant_id = ? AND root_hash = ?
                   ORDER BY confirmed_at DESC NULLS LAST LIMIT 1""",
                (tenant_id, checkpoint_root_hash),
            )
            if anc_row:
                anchor_node = {
                    "job_id": anc_row.get("job_id"),
                    "root_hash": anc_row.get("root_hash"),
                    "status": anc_row.get("status"),
                    "external_anchor_id": anc_row.get("external_anchor_id"),
                    "date_utc": anc_row.get("date_utc"),
                    "submitted_at": str(anc_row.get("submitted_at") or ""),
                    "confirmed_at": str(anc_row.get("confirmed_at") or ""),
                }
    except Exception:
        # Try NULLS LAST alternative for SQLite
        try:
            if checkpoint_root_hash:
                anc_row = storage.fetchone(
                    """SELECT * FROM anchor_jobs
                       WHERE tenant_id = ? AND root_hash = ?
                       ORDER BY confirmed_at DESC LIMIT 1""",
                    (tenant_id, checkpoint_root_hash),
                )
                if anc_row:
                    anchor_node = {
                        "job_id": anc_row.get("job_id"),
                        "root_hash": anc_row.get("root_hash"),
                        "status": anc_row.get("status"),
                        "external_anchor_id": anc_row.get("external_anchor_id"),
                        "date_utc": anc_row.get("date_utc"),
                        "submitted_at": str(anc_row.get("submitted_at") or ""),
                        "confirmed_at": str(anc_row.get("confirmed_at") or ""),
                    }
        except Exception:
            logger.debug("anchor trace failed", exc_info=True)

    # ── Completeness assessment ────────────────────────────────────────────
    checkpointed = checkpoint_node is not None
    anchored = anchor_node is not None and (anchor_node.get("status") in ("CONFIRMED", "confirmed"))
    replay_verifiable = bool(
        row.get("input_hash")
        and row.get("policy_hash")
        and row.get("decision_hash")
        and row.get("replay_hash")
    )

    return {
        "ok": True,
        "rg_decision_id": decision_node["rg_decision_id"],
        "decision": decision_node,
        "checkpoint": checkpoint_node,
        "anchor": anchor_node,
        "completeness": {
            "decision_recorded": True,
            "hashes_complete": replay_verifiable,
            "checkpointed": checkpointed,
            "externally_anchored": anchored,
            "standalone_auditable": checkpointed and replay_verifiable,
        },
        "verification_command": (
            f"python -m releasegate.cli verify-decision --id {decision_node['rg_decision_id']}"
        ),
    }


# ---------------------------------------------------------------------------
# Decision verification (replay_hash reconstruction)
# ---------------------------------------------------------------------------

def verify_decision(
    rg_id: str,
    tenant_id: str,
    storage: Any,
) -> Dict[str, Any]:
    """Verify a decision's replay_hash by reconstructing it from stored parts.

    This proves the decision record has not been tampered with:
    replay_hash = SHA256(input_hash + policy_hash + decision_hash)
    """
    row = resolve_decision_row(rg_id, tenant_id, storage)
    if not row:
        return {"ok": False, "verified": False, "error": "Decision not found"}

    input_hash   = str(row.get("input_hash") or "")
    policy_hash  = str(row.get("policy_hash") or "")
    decision_hash = str(row.get("decision_hash") or "")
    stored_replay = str(row.get("replay_hash") or "")

    if not all([input_hash, policy_hash, decision_hash, stored_replay]):
        return {
            "ok": True,
            "verified": False,
            "error": "One or more hashes missing — decision predates hash chaining",
        }

    computed_replay = hashlib.sha256(
        (input_hash + policy_hash + decision_hash).encode()
    ).hexdigest()

    match = computed_replay == stored_replay
    return {
        "ok": True,
        "verified": match,
        "rg_decision_id": format_rg_decision_id(
            str(row.get("decision_id") or ""),
            str(row.get("created_at") or ""),
        ),
        "stored_replay_hash": stored_replay,
        "computed_replay_hash": computed_replay,
        "tamper_evidence": "CLEAN" if match else "MISMATCH — possible tampering detected",
    }


# ---------------------------------------------------------------------------
# Authority report
# ---------------------------------------------------------------------------

def authority_report(
    tenant_id: str,
    storage: Any,
    days: int = 30,
) -> Dict[str, Any]:
    """Compute the authority metrics for a tenant.

    Tests whether ReleaseGate can serve as the sole audit source:
    - Decision coverage (% of known deploys with a decision ID)
    - Checkpoint coverage (% of decisions inside a signed checkpoint)
    - External anchor coverage (% of checkpoints with external anchor)
    - Verification sample (spot-check N random decisions)
    - Per-repo coverage breakdown
    """
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()

    # 1. Total decisions in window
    total_row = storage.fetchone(
        "SELECT COUNT(*) as cnt FROM audit_decisions WHERE tenant_id = ? AND created_at >= ?",
        (tenant_id, cutoff),
    )
    total_decisions = int((total_row.get("cnt") or 0) if total_row else 0)

    # 2. Decisions covered by a checkpoint.
    # Use period_end (the authoritative close-of-cycle boundary) rather than
    # created_at so decisions near the checkpoint boundary are counted correctly.
    try:
        latest_cp_row = storage.fetchone(
            "SELECT MAX(period_end) as latest FROM audit_checkpoints WHERE tenant_id = ?",
            (tenant_id,),
        )
        latest_cp = latest_cp_row.get("latest") if latest_cp_row else None
        if latest_cp:
            covered_row = storage.fetchone(
                """SELECT COUNT(*) as cnt FROM audit_decisions
                   WHERE tenant_id = ? AND created_at >= ? AND created_at <= ?""",
                (tenant_id, cutoff, latest_cp),
            )
            covered_by_checkpoint = int((covered_row.get("cnt") or 0) if covered_row else 0)
        else:
            covered_by_checkpoint = 0
    except Exception:
        covered_by_checkpoint = 0

    checkpoint_coverage_pct = (
        round(covered_by_checkpoint / total_decisions * 100, 1) if total_decisions > 0 else 0.0
    )

    # 3. External anchor coverage
    try:
        anchored_row = storage.fetchone(
            """SELECT COUNT(*) as cnt FROM anchor_jobs
               WHERE tenant_id = ? AND status = 'CONFIRMED'
                 AND created_at >= ?""",
            (tenant_id, cutoff),
        )
        anchored_checkpoints = int((anchored_row.get("cnt") or 0) if anchored_row else 0)
        total_cp_row = storage.fetchone(
            "SELECT COUNT(*) as cnt FROM audit_checkpoints WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, cutoff),
        )
        total_checkpoints = int((total_cp_row.get("cnt") or 0) if total_cp_row else 0)
        anchor_coverage_pct = (
            round(anchored_checkpoints / total_checkpoints * 100, 1) if total_checkpoints > 0 else 0.0
        )
    except Exception:
        anchored_checkpoints = 0
        total_checkpoints = 0
        anchor_coverage_pct = 0.0

    # 4. Verification sample — spot-check up to 5 recent decisions
    verification_results: List[Dict[str, Any]] = []
    try:
        sample_rows = storage.fetchall(
            """SELECT decision_id, created_at, input_hash, policy_hash, decision_hash, replay_hash
               FROM audit_decisions
               WHERE tenant_id = ? AND created_at >= ?
               ORDER BY created_at DESC LIMIT 5""",
            (tenant_id, cutoff),
        )
        for s in (sample_rows or []):
            ih = str(s.get("input_hash") or "")
            ph = str(s.get("policy_hash") or "")
            dh = str(s.get("decision_hash") or "")
            stored = str(s.get("replay_hash") or "")
            if ih and ph and dh and stored:
                computed = hashlib.sha256((ih + ph + dh).encode()).hexdigest()
                verification_results.append({
                    "rg_decision_id": format_rg_decision_id(
                        str(s.get("decision_id") or ""),
                        str(s.get("created_at") or ""),
                    ),
                    "verified": computed == stored,
                })
    except Exception:
        logger.debug("verification sample failed", exc_info=True)

    all_verified = all(v["verified"] for v in verification_results) if verification_results else True

    # 5. Per-repo coverage
    repo_coverage: List[Dict[str, Any]] = []
    try:
        repo_rows = storage.fetchall(
            """SELECT repo, COUNT(*) as decisions,
                      SUM(CASE WHEN release_status = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
                      SUM(CASE WHEN release_status = 'ALLOWED' THEN 1 ELSE 0 END) as allowed
               FROM audit_decisions
               WHERE tenant_id = ? AND created_at >= ?
               GROUP BY repo ORDER BY decisions DESC LIMIT 20""",
            (tenant_id, cutoff),
        )
        for r in (repo_rows or []):
            repo_coverage.append({
                "repo": r.get("repo"),
                "decisions": int(r.get("decisions") or 0),
                "blocked": int(r.get("blocked") or 0),
                "allowed": int(r.get("allowed") or 0),
            })
    except Exception:
        pass

    # 6. Authority verdict
    passes_authority_test = (
        total_decisions > 0
        and checkpoint_coverage_pct >= 80.0
        and all_verified
    )

    return {
        "ok": True,
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "window_days": days,
        "decisions": {
            "total": total_decisions,
            "covered_by_checkpoint": covered_by_checkpoint,
            "checkpoint_coverage_pct": checkpoint_coverage_pct,
        },
        "checkpoints": {
            "total": total_checkpoints,
            "externally_anchored": anchored_checkpoints,
            "anchor_coverage_pct": anchor_coverage_pct,
        },
        "verification_sample": {
            "checked": len(verification_results),
            "all_passed": all_verified,
            "results": verification_results,
        },
        "repo_coverage": repo_coverage,
        "authority_test": {
            "passed": passes_authority_test,
            "verdict": (
                "AUTHORITATIVE — ReleaseGate is the system of record for releases in this tenant."
                if passes_authority_test
                else "NOT YET AUTHORITATIVE — increase checkpoint coverage and/or add more decisions."
            ),
        },
    }
