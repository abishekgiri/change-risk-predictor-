import argparse
import sys
import os
import json
import yaml
from datetime import datetime, timedelta, timezone

from releasegate.storage.base import resolve_tenant_id

def _parse_age_seconds(value: str) -> int:
    """
    Parses a compact duration like '30s', '10m', '12h', '7d' into seconds.
    """
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError("duration is empty")
    unit = text[-1]
    num = text[:-1]
    if unit not in {"s", "m", "h", "d"}:
        raise ValueError("duration must end with s/m/h/d")
    if not num.isdigit():
        raise ValueError("duration must start with an integer")
    n = int(num)
    if n <= 0:
        raise ValueError("duration must be > 0")
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="releasegate")
    sub = p.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze-pr", help="Analyze a PR and output decision.")
    analyze_p.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    analyze_p.add_argument("--pr", required=True, help="PR number")
    analyze_p.add_argument("--token", help="GitHub token (optional, else uses GITHUB_TOKEN env)")
    analyze_p.add_argument("--config", default="releasegate.yaml", help="Path to config yaml")
    analyze_p.add_argument("--output", help="Write JSON result to file")
    analyze_p.add_argument("--format", default="json", choices=["json", "text"])
    analyze_p.add_argument("--post-comment", action="store_true", help="Post PR comment")
    analyze_p.add_argument("--create-check", action="store_true", help="Create GitHub check run")
    analyze_p.add_argument("--no-bundle", action="store_true", help="(ignored) compatibility flag")
    analyze_p.add_argument("--tenant", help="Tenant/org identifier for attestation metadata")
    analyze_p.add_argument("--emit-attestation", help="Write signed release attestation JSON to file")
    analyze_p.add_argument("--emit-dsse", help="Write DSSE wrapped in-toto statement JSON to file")
    analyze_p.add_argument(
        "--dsse-signing-mode",
        default="ed25519",
        choices=["ed25519", "sigstore"],
        help="How to sign the DSSE payload (default: ed25519). Sigstore mode uses cosign to produce a bundle.",
    )
    analyze_p.add_argument(
        "--dsse-sigstore-bundle",
        help="Output path for Sigstore bundle JSON when --dsse-signing-mode=sigstore (default: <emit-dsse>.sigstore.bundle.json)",
    )

    eval_p = sub.add_parser("evaluate", help="Evaluate policies for a change (PR/release).")
    eval_p.add_argument("--repo", required=True)
    eval_p.add_argument("--pr", required=True)
    eval_p.add_argument("--format", default="text", choices=["text", "json"])
    eval_p.add_argument("--environment", choices=["PRODUCTION", "STAGING", "DEV", "UNKNOWN"], default="UNKNOWN")
    eval_p.add_argument("--include-context", action="store_true", help="Include full context in output")
    eval_p.add_argument("--enforce", action="store_true", help="Execute enforcement actions")
    eval_p.add_argument("--no-audit", action="store_true", help="Skip writing to audit log")
    eval_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    
    # Enforce Command (Retroactive)
    enforce_p = sub.add_parser("enforce", help="Enforce a previous decision")
    enforce_p.add_argument("--decision-id", required=True)
    enforce_p.add_argument("--dry-run", action="store_true", help="Plan actions but do not execute")
    enforce_p.add_argument("--tenant", required=True, help="Tenant/org identifier")

    # Audit Command
    audit_p = sub.add_parser("audit", help="Query audit logs.")
    audit_sub = audit_p.add_subparsers(dest="audit_cmd", required=True)
    
    # audit list
    audit_list = audit_sub.add_parser("list", help="List recent decisions")
    audit_list.add_argument("--repo", required=True)
    audit_list.add_argument("--limit", type=int, default=20)
    audit_list.add_argument("--status", choices=["ALLOWED", "BLOCKED", "CONDITIONAL", "SKIPPED", "ERROR"])
    audit_list.add_argument("--pr", type=int)
    audit_list.add_argument("--tenant", required=True, help="Tenant/org identifier")
    
    # audit show
    audit_show = audit_sub.add_parser("show", help="Show full decision details")
    audit_show.add_argument("--decision-id", required=True)
    audit_show.add_argument("--tenant", required=True, help="Tenant/org identifier")

    lint_p = sub.add_parser("lint-policies", help="Validate compiled policy schema and lint policy logic.")
    lint_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    lint_p.add_argument("--format", default="text", choices=["text", "json"])
    lint_p.add_argument(
        "--no-schema-strict",
        action="store_true",
        help="Allow invalid policy files to be skipped (lint still runs on valid files).",
    )

    jira_validate_p = sub.add_parser(
        "validate-jira-config",
        help="Validate Jira transition/role mapping config and optional Jira connectivity.",
    )
    jira_validate_p.add_argument(
        "--transition-map",
        default="releasegate/integrations/jira/jira_transition_map.yaml",
        help="Path to jira_transition_map.yaml",
    )
    jira_validate_p.add_argument(
        "--role-map",
        default="releasegate/integrations/jira/jira_role_map.yaml",
        help="Path to jira_role_map.yaml",
    )
    jira_validate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    jira_validate_p.add_argument("--check-jira", action="store_true", help="Validate mappings against live Jira metadata")
    jira_validate_p.add_argument("--format", default="text", choices=["text", "json"])

    bundle_validate_p = sub.add_parser(
        "validate-policy-bundle",
        help="Deploy-time guard: validate compiled policy bundle load + lint.",
    )
    bundle_validate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    bundle_validate_p.add_argument("--format", default="text", choices=["text", "json"])
    bundle_validate_p.add_argument(
        "--no-schema-strict",
        action="store_true",
        help="Allow invalid policy files to be skipped while validating policy bundle.",
    )

    checkpoint_p = sub.add_parser("checkpoint-override", help="Create signed override-ledger root checkpoint.")
    checkpoint_p.add_argument("--repo", required=True)
    checkpoint_p.add_argument("--cadence", default="daily", choices=["daily", "weekly"])
    checkpoint_p.add_argument("--pr", type=int)
    checkpoint_p.add_argument("--at", help="ISO timestamp for checkpoint cutoff (default: now)")
    checkpoint_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    checkpoint_p.add_argument("--format", default="text", choices=["text", "json"])

    simulate_p = sub.add_parser("simulate-policies", help="Run what-if simulation over recent decisions.")
    simulate_p.add_argument("--repo", required=True)
    simulate_p.add_argument("--limit", type=int, default=100)
    simulate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    simulate_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    simulate_p.add_argument("--format", default="text", choices=["text", "json"])

    export_root_p = sub.add_parser("export-root", help="Export signed daily transparency Merkle root.")
    export_root_p.add_argument("--date", required=True, help="UTC date in YYYY-MM-DD")
    export_root_p.add_argument("--out", required=True, help="Output path for signed root JSON")
    export_root_p.add_argument("--tenant", help="Tenant/org identifier (optional)")
    export_root_p.add_argument("--format", default="text", choices=["text", "json"])

    verify_inclusion_p = sub.add_parser(
        "verify-inclusion",
        help="Verify transparency inclusion proof from file or by attestation id.",
    )
    inclusion_src = verify_inclusion_p.add_mutually_exclusive_group(required=True)
    inclusion_src.add_argument("--proof-file", help="Path to inclusion proof JSON payload")
    inclusion_src.add_argument("--attestation-id", help="Attestation id to resolve proof from local storage")
    verify_inclusion_p.add_argument("--tenant", help="Tenant/org identifier")
    verify_inclusion_p.add_argument("--format", default="text", choices=["text", "json"])

    proof_p = sub.add_parser("proof-pack", help="Export audit evidence bundle for a decision.")
    proof_p.add_argument("--decision-id", required=True)
    proof_p.add_argument("--format", default="json", choices=["json", "zip"])
    proof_p.add_argument("--checkpoint-cadence", default="daily", choices=["daily", "weekly"])
    proof_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    proof_p.add_argument("--output", help="Output file path (required for zip)")

    verify_proof_pack_p = sub.add_parser(
        "verify-proof-pack",
        help="Verify proof-pack artifact integrity offline.",
    )
    verify_proof_pack_p.add_argument("file", help="Path to proof-pack JSON or ZIP file")
    verify_proof_pack_p.add_argument("--format", default="text", choices=["text", "json"])
    verify_proof_pack_p.add_argument("--signing-key", help="Checkpoint signing key for verification (HMAC)")
    verify_proof_pack_p.add_argument("--key-file", help="Path to trusted key file/key map for verification")

    verify_attestation_p = sub.add_parser(
        "verify-attestation",
        help="Verify signed release attestation offline.",
    )
    verify_attestation_p.add_argument("file", help="Path to release attestation JSON file")
    verify_attestation_p.add_argument("--format", default="text", choices=["text", "json"])
    verify_attestation_p.add_argument("--key-file", help="Path to trusted Ed25519 public key file or key-id map")

    verify_dsse_p = sub.add_parser(
        "verify-dsse",
        help="Verify DSSE wrapped in-toto statement offline.",
    )
    verify_dsse_p.add_argument("--dsse", required=True, help="Path to DSSE JSON envelope")
    verify_dsse_p.add_argument("--format", default="text", choices=["text", "json"])
    verify_dsse_p.add_argument("--key-file", help="Path to trusted Ed25519 public key file or key-id map")
    verify_dsse_p.add_argument("--key", dest="key_file", help="Alias for --key-file")
    verify_dsse_p.add_argument("--keys-url", help="Fetch public key map from an HTTP endpoint (optional)")
    verify_dsse_p.add_argument("--require-keyid", help="Require DSSE signature keyid to match this value")
    verify_dsse_p.add_argument(
        "--require-signers",
        help="Comma-separated list of key ids that must have valid signatures in the envelope",
    )
    verify_dsse_p.add_argument("--max-age", help="Require attestation issued_at to be newer than this (e.g. 7d, 12h)")
    verify_dsse_p.add_argument("--require-repo", help="Require predicate.subject.repo to match this value")
    verify_dsse_p.add_argument("--require-commit", help="Require predicate.subject.commit_sha to match this value")
    verify_dsse_p.add_argument(
        "--sigstore-bundle",
        help="Verify DSSE payload using a Sigstore bundle (cosign bundle JSON) instead of an Ed25519 key map.",
    )
    verify_dsse_p.add_argument(
        "--sigstore-identity",
        help="Expected certificate identity for Sigstore verification (cosign --certificate-identity).",
    )
    verify_dsse_p.add_argument(
        "--sigstore-issuer",
        help="Expected OIDC issuer for Sigstore verification (cosign --certificate-oidc-issuer).",
    )

    log_dsse_p = sub.add_parser(
        "log-dsse",
        help="Append a DSSE envelope summary line to an append-only JSONL log.",
    )
    log_dsse_p.add_argument("--dsse", required=True, help="Path to DSSE JSON envelope")
    log_dsse_p.add_argument("--log", required=True, help="Path to attestations.log JSONL file")
    log_dsse_p.add_argument("--format", default="json", choices=["json", "text"])

    verify_log_p = sub.add_parser(
        "verify-log",
        help="Verify that a DSSE envelope matches an entry in an attestations.log JSONL file.",
    )
    verify_log_p.add_argument("--dsse", required=True, help="Path to DSSE JSON envelope")
    verify_log_p.add_argument("--log", required=True, help="Path to attestations.log JSONL file")
    verify_log_p.add_argument("--format", default="json", choices=["json", "text"])

    proofpack_v1_p = sub.add_parser(
        "proofpack",
        help="Create deterministic proofpack v1 zip artifact.",
    )
    proofpack_v1_p.add_argument("--decision-id", required=True)
    proofpack_v1_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    proofpack_v1_p.add_argument("--out", required=True, help="Output path for proofpack.zip")
    proofpack_v1_p.add_argument(
        "--include-timestamp",
        action="store_true",
        help="Include RFC3161 timestamp token when configured.",
    )
    proofpack_v1_p.add_argument("--tsa-url", help="RFC3161 TSA URL override")
    proofpack_v1_p.add_argument("--tsa-timeout-seconds", type=int, default=10)
    proofpack_v1_p.add_argument("--format", default="text", choices=["text", "json"])

    verify_pack_p = sub.add_parser(
        "verify-pack",
        help="Verify deterministic proofpack v1 artifact.",
    )
    verify_pack_p.add_argument("file", help="Path to proofpack zip")
    verify_pack_p.add_argument("--format", default="text", choices=["text", "json"])
    verify_pack_p.add_argument("--key-file", help="Path to trusted Ed25519 public key file or key-id map")
    verify_pack_p.add_argument("--expected-hash", help="Expected proofpack sha256 hash (sha256:<hex> or <hex>)")
    verify_pack_p.add_argument("--tsa-ca-bundle", help="CA bundle for RFC3161 timestamp verification")

    sub.add_parser("db-migrate", help="Apply forward-only DB migrations.")
    sub.add_parser("db-migration-status", help="Show applied DB migrations.")
    sub.add_parser("version", help="Print version.")
    return p

def main() -> int:
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
        
    p = build_parser()
    args = p.parse_args()
    if hasattr(args, "tenant") and getattr(args, "tenant", None):
        os.environ["RELEASEGATE_TENANT_ID"] = args.tenant

    if args.cmd == "version":
        print("releasegate 0.1.0")
        return 0

    if args.cmd == "db-migrate":
        from releasegate.storage.migrate import migrate

        current = migrate()
        print(json.dumps({"status": "ok", "schema_version": current}, indent=2))
        return 0

    if args.cmd == "db-migration-status":
        from releasegate.storage.migrate import migration_status

        print(json.dumps(migration_status(), indent=2))
        return 0

    if args.cmd == "analyze-pr":
        # Set token if provided
        if args.token:
            os.environ["GITHUB_TOKEN"] = args.token

        # Load config (optional thresholds)
        config = {}
        if args.config and os.path.exists(args.config):
            try:
                with open(args.config, "r") as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Failed to load config {args.config}: {e}", file=sys.stderr)

        from releasegate.reporting import (
            build_compliance_report,
            exit_code_for_verdict,
            resolve_enforcement_mode,
            write_json_report_atomic,
        )
        from releasegate.utils.canonical import sha256_json

        enforcement_mode = resolve_enforcement_mode(config)
        tenant_id = resolve_tenant_id(getattr(args, "tenant", None), allow_none=True) or "default"

        try:
            from releasegate.server import get_pr_details, get_pr_metrics, post_pr_comment, create_check_run
        except Exception as e:
            errors = [f"IMPORT_GITHUB_HELPERS_FAILED: {e}"]
            artifact_failed = bool(args.emit_attestation or args.emit_dsse)
            report = build_compliance_report(
                repo=args.repo,
                pr_number=int(args.pr),
                head_sha=None,
                base_sha=None,
                tenant_id=tenant_id,
                control_result="BLOCK",
                risk_score=None,
                risk_level="UNKNOWN",
                reasons=[],
                reason_codes=[],
                metrics={
                    "changed_files_count": None,
                    "additions": None,
                    "deletions": None,
                    "total_churn": None,
                },
                dependency_provenance={},
                attached_issue_keys=[],
                policy_hash=sha256_json({}),
                policy_resolution_hash=sha256_json({}),
                policy_scope=[],
                enforcement_mode=enforcement_mode,
                decision_id="unknown",
                attestation_id=None,
                signed_payload_hash=None,
                dsse_path=args.emit_dsse if getattr(args, "emit_dsse", None) else None,
                dsse_sigstore_bundle_path=None,
                artifacts_sha256_path="releasegate.artifacts.sha256",
                errors=errors,
            )

            if args.output:
                try:
                    write_json_report_atomic(args.output, report)
                except Exception as write_err:
                    print(f"Error writing output {args.output}: {write_err}", file=sys.stderr)
                    return 1

            if args.format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print("Decision: BLOCK")
                print("Risk: UNKNOWN")
                for err in errors:
                    print(f" - {err}")

            exit_code = exit_code_for_verdict(enforcement_mode, report.get("verdict"))
            if artifact_failed:
                exit_code = 1
            return exit_code

        from releasegate.integrations.github_risk import (
            build_issue_risk_property,
            classify_pr_risk,
            extract_jira_issue_keys,
            score_for_risk_level,
        )

        pr_number = int(args.pr)
        artifact_failed = False
        errors: list[str] = []

        # Defaults (kept fail-closed)
        commit_sha = ""
        base_sha = None
        control_result = "BLOCK"
        risk_level = "UNKNOWN"
        risk_score: Optional[float] = None
        reasons: list[str] = []
        reason_codes: list[str] = []
        dependency_provenance: dict = {}
        attached_issue_keys: list[str] = []
        policy_scope: list[str] = []
        policy_resolution_hash = sha256_json({})
        policy_hash = policy_resolution_hash
        decision_id = "unknown"
        attestation_id: Optional[str] = None
        signed_payload_hash: Optional[str] = None
        dsse_path: Optional[str] = args.emit_dsse if getattr(args, "emit_dsse", None) else None
        dsse_sigstore_bundle_path: Optional[str] = None
        artifacts_sha256_path: Optional[str] = "releasegate.artifacts.sha256"

        metrics_payload = {
            "changed_files_count": None,
            "additions": None,
            "deletions": None,
            "total_churn": None,
        }

        try:
            pr_data = get_pr_details(args.repo, pr_number)
            metrics = get_pr_metrics(args.repo, pr_number)
            commit_sha = str((pr_data.get("head") or {}).get("sha") or "")
            base_sha = str((pr_data.get("base") or {}).get("sha") or "") or None

            github_risk = config.get("github_risk", {}) if isinstance(config, dict) else {}
            risk_level = classify_pr_risk(
                metrics,
                high_changed_files=int(github_risk.get("high_changed_files", 20)),
                medium_additions=int(github_risk.get("medium_additions", 300)),
                high_total_churn=int(github_risk.get("high_total_churn", 800)),
            )
            risk_score = float(score_for_risk_level(risk_level))
            control_result = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

            reasons = [f"Heuristic classification from GitHub metadata: {risk_level}"]
            if risk_level == "HIGH":
                reason_codes.append("RISK_HIGH_HEURISTIC")
            elif risk_level == "MEDIUM":
                reason_codes.append("RISK_MEDIUM_HEURISTIC")
            else:
                reason_codes.append("RISK_LOW_HEURISTIC")

            env_name = str(os.getenv("RELEASEGATE_ENVIRONMENT") or "DEV")
            resolved_policy = {}
            try:
                from releasegate.policy.inheritance import resolve_policy_inheritance

                inheritance_cfg = config.get("policy_inheritance", {}) if isinstance(config, dict) else {}
                org_policy = inheritance_cfg.get("org_policy") if isinstance(inheritance_cfg, dict) else {}
                repo_policies = inheritance_cfg.get("repo_policies") if isinstance(inheritance_cfg, dict) else {}
                repo_policy = repo_policies.get(args.repo) if isinstance(repo_policies, dict) else {}
                env_policies = inheritance_cfg.get("environment_policies") if isinstance(inheritance_cfg, dict) else {}
                resolved = resolve_policy_inheritance(
                    org_policy=org_policy if isinstance(org_policy, dict) else {},
                    repo_policy=repo_policy if isinstance(repo_policy, dict) else {},
                    environment=env_name,
                    environment_policies=env_policies if isinstance(env_policies, dict) else None,
                )
                resolved_policy = resolved.get("resolved_policy", {}) if isinstance(resolved, dict) else {}
                policy_scope = list(resolved.get("policy_scope") or [])
                policy_resolution_hash = str(resolved.get("policy_resolution_hash") or policy_resolution_hash)
                policy_hash = policy_resolution_hash
            except Exception as e:
                errors.append(f"POLICY_INHERITANCE_FAILED: {e}")
                resolved_policy = {}
                policy_scope = []
                policy_resolution_hash = sha256_json({})
                policy_hash = policy_resolution_hash

            dp_cfg = resolved_policy.get("dependency_provenance") if isinstance(resolved_policy, dict) else {}
            lockfile_required = bool((dp_cfg or {}).get("lockfile_required", False))

            try:
                from releasegate.ingestion.providers.github_provider import GitHubProvider
                from releasegate.signals.dependency_provenance import build_dependency_provenance_signal

                dp_provider = GitHubProvider(config if isinstance(config, dict) else {})
                dependency_provenance = build_dependency_provenance_signal(
                    provider=dp_provider,
                    repo=args.repo,
                    ref=commit_sha or None,
                    lockfile_required=lockfile_required,
                )
            except Exception:
                from releasegate.signals.dependency_provenance import build_dependency_provenance_signal

                dependency_provenance = build_dependency_provenance_signal(
                    provider=None,
                    repo=args.repo,
                    ref=commit_sha or None,
                    lockfile_required=lockfile_required,
                )

            dependency_provenance = dependency_provenance if isinstance(dependency_provenance, dict) else {}
            if not dependency_provenance.get("satisfied", True):
                for code in dependency_provenance.get("reason_codes", []):
                    if code not in reason_codes:
                        reason_codes.append(code)
                if "LOCKFILE_REQUIRED_MISSING" in dependency_provenance.get("reason_codes", []):
                    reasons.append("LOCKFILE_REQUIRED_MISSING: policy requires at least one lockfile at PR head.")
                control_result = "BLOCK"

            dependency_provenance_signal = dependency_provenance
            dependency_provenance = dependency_provenance_signal

            issue_keys = sorted(extract_jira_issue_keys(pr_data.get("title"), pr_data.get("body")))
            if issue_keys:
                try:
                    from releasegate.integrations.jira.client import JiraClient

                    jc = JiraClient()
                    payload = build_issue_risk_property(
                        repo=args.repo,
                        pr_number=pr_number,
                        risk_level=risk_level,
                        metrics=metrics,
                    )
                    for key in issue_keys:
                        if jc.set_issue_property(key, "releasegate_risk", payload):
                            attached_issue_keys.append(key)
                except Exception as e:
                    errors.append(f"JIRA_PROPERTY_ATTACH_FAILED: {e}")

            metrics_payload = {
                "changed_files_count": metrics.changed_files,
                "additions": metrics.additions,
                "deletions": metrics.deletions,
                "total_churn": metrics.total_churn,
            }

            dependency_provenance = dependency_provenance if isinstance(dependency_provenance, dict) else {}

            try:
                from releasegate.attestation import (
                    build_attestation_from_bundle,
                    build_bundle_from_analysis_result,
                    build_intoto_statement,
                    wrap_dsse,
                )
                from releasegate.attestation.crypto import current_key_id, load_private_key_from_env
                from releasegate.audit.attestations import record_release_attestation

                bundle_timestamp = str(
                    pr_data.get("updated_at")
                    or pr_data.get("created_at")
                    or "1970-01-01T00:00:00Z"
                )

                signals_payload: dict = {
                    "metrics": metrics_payload,
                    "dependency_provenance": dependency_provenance,
                }

                if str(os.getenv("GITHUB_ACTIONS") or "").lower() == "true":
                    source_ref = str(os.getenv("GITHUB_REF") or "").strip()
                    if source_ref:
                        signals_payload["source_ref"] = source_ref
                    workflow_run = {
                        k: v
                        for k, v in {
                            "provider": "github-actions",
                            "repository": str(os.getenv("GITHUB_REPOSITORY") or "").strip(),
                            "workflow": str(os.getenv("GITHUB_WORKFLOW") or "").strip(),
                            "run_id": str(os.getenv("GITHUB_RUN_ID") or "").strip(),
                            "run_attempt": str(os.getenv("GITHUB_RUN_ATTEMPT") or "").strip(),
                            "actor": str(os.getenv("GITHUB_ACTOR") or "").strip(),
                            "job": str(os.getenv("GITHUB_JOB") or "").strip(),
                            "ref": str(os.getenv("GITHUB_REF") or "").strip(),
                            "sha": str(os.getenv("GITHUB_SHA") or "").strip(),
                        }.items()
                        if v
                    }
                    if workflow_run:
                        signals_payload["workflow_run"] = workflow_run

                bundle = build_bundle_from_analysis_result(
                    tenant_id=tenant_id,
                    repo=args.repo,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    policy_hash=policy_hash,
                    policy_version="1.0.0",
                    policy_bundle_hash=policy_hash,
                    risk_score=float(risk_score or 0.0),
                    decision=control_result,
                    reason_codes=reason_codes or reasons,
                    signals=signals_payload,
                    engine_version=os.getenv("RELEASEGATE_ENGINE_VERSION", "2.0.0"),
                    timestamp=bundle_timestamp,
                    policy_scope=policy_scope,
                    policy_resolution_hash=policy_resolution_hash,
                )
                decision_id = bundle.decision_id

                try:
                    attestation = build_attestation_from_bundle(bundle)
                    signature = attestation.get("signature") if isinstance(attestation, dict) else {}
                    if isinstance(signature, dict):
                        signed_payload_hash = signature.get("signed_payload_hash")

                    attestation_id = record_release_attestation(
                        decision_id=bundle.decision_id,
                        tenant_id=tenant_id,
                        repo=args.repo,
                        pr_number=pr_number,
                        attestation=attestation,
                    )

                    if args.emit_attestation:
                        with open(args.emit_attestation, "w", encoding="utf-8") as f:
                            json.dump(attestation, f, indent=2)

                    if args.emit_dsse:
                        statement = build_intoto_statement(attestation)
                        dsse_mode = str(getattr(args, "dsse_signing_mode", "") or "ed25519").strip().lower()
                        if dsse_mode == "sigstore":
                            from releasegate.attestation.dsse import wrap_dsse_sigstore

                            bundle_out = str(getattr(args, "dsse_sigstore_bundle", "") or "").strip()
                            if not bundle_out:
                                bundle_out = f"{args.emit_dsse}.sigstore.bundle.json"
                            dsse_sigstore_bundle_path = bundle_out
                            dsse_envelope = wrap_dsse_sigstore(statement, bundle_path=bundle_out)
                        else:
                            dsse_envelope = wrap_dsse(
                                statement,
                                signing_key=load_private_key_from_env(),
                                key_id=current_key_id(),
                            )
                        with open(args.emit_dsse, "w", encoding="utf-8") as f:
                            json.dump(dsse_envelope, f, indent=2)
                except Exception as e:
                    errors.append(f"ATTESTATION_GENERATION_FAILED: {e}")
                    if args.emit_attestation or args.emit_dsse:
                        artifact_failed = True
            except Exception as e:
                errors.append(f"ATTESTATION_PIPELINE_FAILED: {e}")
                if args.emit_attestation or args.emit_dsse:
                    artifact_failed = True

            report = build_compliance_report(
                repo=args.repo,
                pr_number=pr_number,
                head_sha=commit_sha or None,
                base_sha=base_sha,
                tenant_id=tenant_id,
                control_result=control_result,
                risk_score=risk_score,
                risk_level=risk_level,
                reasons=reasons,
                reason_codes=reason_codes,
                metrics=metrics_payload,
                dependency_provenance=dependency_provenance,
                attached_issue_keys=attached_issue_keys,
                policy_hash=policy_hash,
                policy_resolution_hash=policy_resolution_hash,
                policy_scope=policy_scope,
                enforcement_mode=enforcement_mode,
                decision_id=decision_id,
                attestation_id=attestation_id,
                signed_payload_hash=signed_payload_hash,
                dsse_path=dsse_path,
                dsse_sigstore_bundle_path=dsse_sigstore_bundle_path,
                artifacts_sha256_path=artifacts_sha256_path,
                errors=errors,
            )

            if args.output:
                write_json_report_atomic(args.output, report)

            if args.format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(f"Decision: {control_result}")
                print(f"Risk: {risk_level} ({risk_score})")
                if reasons:
                    print("Reasons:")
                    for r in reasons:
                        print(f" - {r}")
                if errors:
                    print("Errors:")
                    for err in errors:
                        print(f" - {err}")

            # Optional PR comment/check
            if args.post_comment and args.repo and pr_number:
                comment_body = (
                    f"## {control_result} Compliance Check\n\n"
                    f"**Severity**: {risk_level} ({risk_score})\n\n"
                    + ("\n".join(f"- {r}" for r in reasons) if reasons else "_No policy violations found._")
                )
                try:
                    post_pr_comment(args.repo, pr_number, comment_body)
                except Exception as e:
                    print(f"Warning: Failed to post comment: {e}", file=sys.stderr)

            if args.create_check and args.repo and pr_number:
                try:
                    create_check_run(
                        args.repo,
                        pr_data.get("head", {}).get("sha", ""),
                        risk_score,
                        risk_level,
                        reasons,
                        evidence=None
                    )
                except Exception as e:
                    print(f"Warning: Failed to create check run: {e}", file=sys.stderr)

            exit_code = exit_code_for_verdict(enforcement_mode, report.get("verdict"))
            if artifact_failed:
                exit_code = 1
            return exit_code
        except Exception as e:
            errors.append(f"ANALYSIS_FAILED: {e}")
            if args.emit_attestation or args.emit_dsse:
                artifact_failed = True

            report = build_compliance_report(
                repo=args.repo,
                pr_number=pr_number,
                head_sha=commit_sha or None,
                base_sha=base_sha,
                tenant_id=tenant_id,
                control_result="BLOCK",
                risk_score=None,
                risk_level="UNKNOWN",
                reasons=[],
                reason_codes=[],
                metrics=metrics_payload,
                dependency_provenance={},
                attached_issue_keys=[],
                policy_hash=policy_hash,
                policy_resolution_hash=policy_resolution_hash,
                policy_scope=policy_scope,
                enforcement_mode=enforcement_mode,
                decision_id=decision_id,
                attestation_id=None,
                signed_payload_hash=None,
                dsse_path=dsse_path,
                dsse_sigstore_bundle_path=None,
                artifacts_sha256_path=artifacts_sha256_path,
                errors=errors,
            )

            if args.output:
                try:
                    write_json_report_atomic(args.output, report)
                except Exception as write_err:
                    print(f"Error writing output {args.output}: {write_err}", file=sys.stderr)
                    return 1

            if args.format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print("Decision: BLOCK")
                print("Risk: UNKNOWN")
                if errors:
                    print("Errors:")
                    for err in errors:
                        print(f" - {err}")

            exit_code = exit_code_for_verdict(enforcement_mode, report.get("verdict"))
            if artifact_failed:
                exit_code = 1
            return exit_code

    if args.cmd == "evaluate":
        try:
            from releasegate.context.builder import ContextBuilder
            from releasegate.context.types import EvaluationContext
            
            # TODO: Fetch real user/change details from GitHub API if --repo/--pr provided
            # For Phase 10 Step 2, we demo the Builder working with mock data (but structured correctly)
            
            # In real implementation:
            # pr_data = github_client.get_pr(args.repo, args.pr)
            
            ctx = (ContextBuilder()
                   # .with_pr_data(pr_data) # Future
                   .with_actor(user_id="mock-user", login="mock-user", role="Engineer", team="Product")
                   .with_change(
                       repo=args.repo, 
                       change_id=args.pr, 
                       files=["TODO: fetch files"], 
                       change_type="PR",
                       author_login="mock-user",
                       head_sha="a1b2c3d4e5f678901234567890abcdef12345678" # Mock SHA for demo
                    )
                   .with_environment(args.environment)
                   .check_change_window()
                   .build())

            # Load and Evaluate Policies
            from releasegate.policy.loader import PolicyLoader
            from releasegate.policy.evaluator import PolicyEvaluator
            
            loader = PolicyLoader()
            policies = loader.load_policies()
            if args.format != "json":
                print(f"Loaded policies: {len(policies)} from {loader.policy_dir}", file=sys.stderr)
            
            evaluator = PolicyEvaluator()
            result = evaluator.evaluate(ctx, policies)

            # Create Canonical Decision (in-memory candidate)
            from releasegate.decision.factory import DecisionFactory
            new_decision = DecisionFactory.create(ctx, result, policies)
            
            # 2. Check for Idempotency (Have we made this exact decision before?)
            from releasegate.audit.reader import AuditReader
            existing_data = AuditReader.get_decision_by_evaluation_key(
                new_decision.evaluation_key,
                tenant_id=resolve_tenant_id(args.tenant),
            )
            
            if existing_data:
                # Reuse the existing decision
                from releasegate.decision.types import Decision
                
                decision_dict = json.loads(existing_data["full_decision_json"])
                decision = Decision(**decision_dict)
                is_new = False
            else:
                decision = new_decision
                is_new = True

            if args.format == "json":
                # Decision model has explicit schema, perfect for JSON
                print(decision.model_dump_json())
            else:
                print(f"Decision ID: {decision.decision_id}")
                if not is_new:
                     print(f"(Reused existing decision from {decision.timestamp})")
                     
                print(f"Context ID: {decision.context_id}")
                print(f"Status: {decision.release_status}")
                print(f"Message: {decision.message}")
                
                if decision.release_status == "BLOCKED":
                    print(f"Blocking Policies: {', '.join(decision.blocking_policies)}")
                    
                if decision.unlock_conditions:
                    print("Unlock Conditions:")
                    for cond in decision.unlock_conditions:
                        print(f"  - {cond}")
                
                if args.include_context:
                    print("\nFull Context:")
                    print(ctx.model_dump_json(indent=2))
            
            # Enforcement Execution
            if args.enforce:
                if args.format != "json":
                    print("\n[Enforcement] Planning actions...")
                
                from releasegate.enforcement.planner import EnforcementPlanner
                from releasegate.enforcement.runner import EnforcementRunner
                
                actions = EnforcementPlanner.plan(decision)
                runner = EnforcementRunner()
                results = runner.run(actions)
                
                if args.format != "json":
                     for res in results:
                         print(f"[{res.status}] {res.action.action_type} -> {res.detail}")

            # Audit Logging (Default: ON)
            # Only record if it's NEW and auditing is enabled
            if is_new and not args.no_audit:
                try:
                    from releasegate.audit.recorder import AuditRecorder
                    # Attempt to extract Repo/PR from context
                    repo = ctx.change.repository
                    # Try to parse PR number safely
                    try:
                        pr_number = int(ctx.change.change_id)
                    except:
                        pr_number = None
                        
                    AuditRecorder.record_with_context(decision, repo, pr_number)
                    if args.format != "json":
                        print(f"[Audit] Recorded decision {decision.decision_id}")
                except Exception as e:
                    print(f"[Audit] Failed to record: {e}", file=sys.stderr)
            elif not is_new and not args.no_audit and args.format != "json":
                # Only print this in text mode
                print(f"[Audit] Decision {decision.decision_id} already recorded.")

        except Exception as e:
            print(f"Error building context: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 1
            
        return 0

    if args.cmd == "enforce":
        try:
            from releasegate.audit.reader import AuditReader
            from releasegate.enforcement.planner import EnforcementPlanner
            from releasegate.enforcement.runner import EnforcementRunner
            from releasegate.decision.types import Decision
            tenant_id = resolve_tenant_id(args.tenant)
            
            # 1. Fetch Decision
            data = AuditReader.get_decision(args.decision_id, tenant_id=tenant_id)
            if not data:
                print(f"Error: Decision {args.decision_id} not found.", file=sys.stderr)
                return 1
                
            # Parse canonical JSON back to Decision object
            # Note: We depend on pydantic to parse the JSON string stored in DB
            decision_dict = json.loads(data["full_decision_json"])
            decision = Decision(**decision_dict)
            
            # 2. Plan
            actions = EnforcementPlanner.plan(decision)
            
            if args.dry_run:
                print(f"Planned Actions for Decision {args.decision_id}:")
                print(json.dumps([a.model_dump(mode='json') for a in actions], indent=2))
                return 0
            
            # 3. Execute
            print(f"Executing enforcement for decision {args.decision_id}...")
            runner = EnforcementRunner()
            results = runner.run(actions)
            
            for res in results:
                print(f"[{res.status}] {res.action.action_type} -> {res.detail}")
                
        except Exception as e:
            print(f"Enforcement error: {e}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "audit":
        from releasegate.audit.reader import AuditReader
        
        if args.audit_cmd == "list":
            tenant_id = resolve_tenant_id(args.tenant)
            rows = AuditReader.list_decisions(
                repo=args.repo,
                limit=args.limit,
                status=args.status,
                pr=args.pr,
                tenant_id=tenant_id,
            )
            print(json.dumps(rows, indent=2, default=str)) # Simple JSON output for list
            
        elif args.audit_cmd == "show":
            row = AuditReader.get_decision(args.decision_id, tenant_id=resolve_tenant_id(args.tenant))
            if row:
                # Try to parse the inner JSON for pretty printing
                try:
                    row["full_decision_json"] = json.loads(row["full_decision_json"])
                except:
                    pass
                print(json.dumps(row, indent=2, default=str))
            else:
                print("Decision not found.", file=sys.stderr)
                return 1
        return 0

    if args.cmd == "lint-policies":
        from releasegate.policy.lint import lint_compiled_policies, format_lint_report

        report = lint_compiled_policies(
            policy_dir=args.policy_dir,
            strict_schema=not args.no_schema_strict,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_lint_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "validate-policy-bundle":
        from releasegate.policy.lint import lint_compiled_policies, format_lint_report

        report = lint_compiled_policies(
            policy_dir=args.policy_dir,
            strict_schema=not args.no_schema_strict,
        )
        report = {
            **report,
            "validation_profile": "deploy_bundle_v1",
        }
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_lint_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "validate-jira-config":
        from releasegate.integrations.jira.validate import (
            format_jira_validation_report,
            validate_jira_config_files,
        )

        report = validate_jira_config_files(
            transition_map_path=args.transition_map,
            role_map_path=args.role_map,
            policy_dir=args.policy_dir,
            check_jira=args.check_jira,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_jira_validation_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "checkpoint-override":
        from releasegate.audit.checkpoints import create_override_checkpoint

        tenant_id = resolve_tenant_id(args.tenant)
        result = create_override_checkpoint(
            repo=args.repo,
            cadence=args.cadence,
            pr=args.pr,
            at=args.at,
            tenant_id=tenant_id,
        )
        if args.format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            payload = result.get("payload", {})
            print(f"Checkpoint created: {result.get('path')}")
            print(f"Tenant: {payload.get('tenant_id')}")
            print(f"Repo: {payload.get('repo')}")
            print(f"Cadence: {payload.get('cadence')}")
            print(f"Period: {payload.get('period_id')}")
            print(f"Root Hash: {payload.get('root_hash')}")
            print(f"Events: {payload.get('event_count')}")
        return 0

    if args.cmd == "simulate-policies":
        from releasegate.policy.simulation import simulate_policy_impact

        tenant_id = resolve_tenant_id(args.tenant)
        report = simulate_policy_impact(
            repo=args.repo,
            limit=args.limit,
            policy_dir=args.policy_dir,
            tenant_id=tenant_id,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            print(f"Tenant: {report.get('tenant_id')}")
            print(f"Repo: {report.get('repo')}")
            print(f"Policy Dir: {report.get('policy_dir')}")
            print(f"Policy Hash: {report.get('policy_hash')}")
            print(f"Total Decisions: {report.get('total_rows')}")
            print(f"Simulated: {report.get('simulated_rows')}  Unsimulated: {report.get('unsimulated_rows')}")
            print(f"Changed: {report.get('changed_count')}")
            print(f"Would Newly Block: {report.get('would_newly_block')}")
            print(f"Would Unblock: {report.get('would_unblock')}")
        return 0

    if args.cmd == "export-root":
        from releasegate.attestation.crypto import MissingRootSigningKeyError
        from releasegate.audit.root_export import export_daily_root_to_path

        try:
            signed = export_daily_root_to_path(
                date_utc=args.date,
                out_path=args.out,
                tenant_id=getattr(args, "tenant", None),
            )
            if not signed:
                payload = {
                    "ok": False,
                    "error_code": "NO_ROOT_FOR_DATE",
                    "date_utc": args.date,
                    "out": args.out,
                }
                if args.format == "json":
                    print(json.dumps(payload, indent=2))
                else:
                    print(f"No transparency root available for date {args.date}", file=sys.stderr)
                return 2
            payload = {
                "ok": True,
                "date_utc": signed.get("date_utc"),
                "leaf_count": signed.get("leaf_count"),
                "root_hash": signed.get("root_hash"),
                "out": args.out,
                "signature": signed.get("signature"),
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print(f"Exported signed root: {args.out}")
                print(f"Date: {payload['date_utc']}")
                print(f"Leaf count: {payload['leaf_count']}")
                print(f"Root hash: {payload['root_hash']}")
            return 0
        except MissingRootSigningKeyError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Failed to export root: {exc}", file=sys.stderr)
            return 1

    if args.cmd == "verify-inclusion":
        from releasegate.attestation.sdk import verify_inclusion_proof
        from releasegate.audit.transparency import get_transparency_inclusion_proof

        payload = None
        if args.proof_file:
            try:
                with open(args.proof_file, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception as exc:
                error = {
                    "ok": False,
                    "error_code": "PROOF_FILE_INVALID",
                    "error": str(exc),
                }
                if args.format == "json":
                    print(json.dumps(error, indent=2))
                else:
                    print(f"verification: FAIL\\nerror: {error['error_code']}", file=sys.stderr)
                return 3
        else:
            try:
                tenant_id = resolve_tenant_id(getattr(args, "tenant", None))
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            payload = get_transparency_inclusion_proof(
                attestation_id=str(args.attestation_id),
                tenant_id=tenant_id,
            )
            if not payload:
                error = {
                    "ok": False,
                    "error_code": "PROOF_NOT_FOUND",
                    "attestation_id": args.attestation_id,
                }
                if args.format == "json":
                    print(json.dumps(error, indent=2))
                else:
                    print("verification: FAIL\\nerror: PROOF_NOT_FOUND", file=sys.stderr)
                return 3

        ok = bool(verify_inclusion_proof(payload))
        result = {
            "ok": ok,
            "attestation_id": payload.get("attestation_id") if isinstance(payload, dict) else None,
            "root_hash": payload.get("root_hash") if isinstance(payload, dict) else None,
            "leaf_hash": payload.get("leaf_hash") if isinstance(payload, dict) else None,
            "date_utc": payload.get("date_utc") if isinstance(payload, dict) else None,
        }
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"verification: {'OK' if ok else 'FAIL'}")
            if result.get("attestation_id"):
                print(f"attestation_id: {result['attestation_id']}")
            if result.get("root_hash"):
                print(f"root_hash: {result['root_hash']}")
        return 0 if ok else 2

    if args.cmd == "proof-pack":
        from releasegate.audit.checkpoints import (
            load_override_checkpoint,
            period_id_for_timestamp,
            verify_override_checkpoint,
        )
        from releasegate.audit.overrides import list_override_chain_segment, list_overrides, verify_override_chain
        from releasegate.audit.reader import AuditReader
        from releasegate.audit.proof_packs import record_proof_pack_generation
        from releasegate.decision.hashing import (
            compute_decision_hash,
            compute_input_hash,
            compute_policy_hash_from_bindings,
            compute_replay_hash,
        )
        from releasegate.utils.canonical import sha256_json

        tenant_id = resolve_tenant_id(args.tenant)

        row = AuditReader.get_decision(args.decision_id, tenant_id=tenant_id)
        if not row:
            print("Decision not found.", file=sys.stderr)
            return 1

        raw = row.get("full_decision_json")
        if not raw:
            print("Decision payload missing full_decision_json.", file=sys.stderr)
            return 1

        decision_snapshot = json.loads(raw) if isinstance(raw, str) else raw
        repo = row.get("repo")
        pr_number = row.get("pr_number")
        created_at = row.get("created_at")

        override_snapshot = None
        chain_proof = None
        checkpoint_proof = None
        checkpoint_snapshot = None
        ledger_segment = []
        period_id = ""
        if repo:
            overrides = list_overrides(repo=repo, limit=500, pr=pr_number, tenant_id=tenant_id)
            override_snapshot = next((o for o in overrides if o.get("decision_id") == args.decision_id), None)
            ledger_segment = list_override_chain_segment(
                repo=repo,
                pr=pr_number,
                tenant_id=tenant_id,
                limit=2000,
            )
            chain_proof = verify_override_chain(repo=repo, pr=pr_number, tenant_id=tenant_id)
            period_id = period_id_for_timestamp(created_at, cadence=args.checkpoint_cadence)
            checkpoint_snapshot = load_override_checkpoint(
                repo=repo,
                cadence=args.checkpoint_cadence,
                period_id=period_id,
                tenant_id=tenant_id,
            )
            checkpoint_proof = verify_override_checkpoint(
                repo=repo,
                cadence=args.checkpoint_cadence,
                period_id=period_id,
                pr=pr_number,
                tenant_id=tenant_id,
            )

        input_hash = decision_snapshot.get("input_hash") or compute_input_hash(decision_snapshot.get("input_snapshot", {}))
        policy_hash = decision_snapshot.get("policy_hash") or compute_policy_hash_from_bindings(
            decision_snapshot.get("policy_bindings") or decision_snapshot.get("policy_snapshot") or []
        )
        decision_hash = decision_snapshot.get("decision_hash") or compute_decision_hash(
            release_status=str(decision_snapshot.get("release_status") or "UNKNOWN"),
            reason_code=decision_snapshot.get("reason_code"),
            policy_bundle_hash=str(decision_snapshot.get("policy_bundle_hash") or ""),
            inputs_present=decision_snapshot.get("inputs_present") or {},
        )
        replay_hash = decision_snapshot.get("replay_hash") or compute_replay_hash(
            input_hash=input_hash,
            policy_hash=policy_hash,
            decision_hash=decision_hash,
        )
        checkpoint_signature = ""
        signing_key_id = ""
        checkpoint_id = ""
        if checkpoint_snapshot:
            checkpoint_signature = ((checkpoint_snapshot.get("signature") or {}).get("value") or "")
            signing_key_id = ((checkpoint_snapshot.get("signature") or {}).get("key_id") or "")
            checkpoint_id = ((checkpoint_snapshot.get("ids") or {}).get("checkpoint_id") or "")

        proof_pack_id = record_proof_pack_generation(
            decision_id=args.decision_id,
            output_format=args.format.lower(),
            bundle_version="audit_proof_v1",
            repo=repo,
            pr_number=pr_number,
            tenant_id=tenant_id,
        )

        bundle = {
            "schema_name": "proof_pack",
            "schema_version": "proof_pack_v1",
            "bundle_version": "audit_proof_v1",
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ids": {
                "decision_id": args.decision_id,
                "checkpoint_id": checkpoint_id,
                "proof_pack_id": proof_pack_id,
                "policy_bundle_hash": decision_snapshot.get("policy_bundle_hash") or "",
                "repo": repo or "",
                "pr_number": pr_number if pr_number is not None else "",
                "period_id": period_id,
                "checkpoint_cadence": args.checkpoint_cadence,
            },
            "integrity": {
                "canonicalization": "releasegate-canonical-json-v1",
                "hash_alg": "sha256",
                "input_hash": input_hash,
                "policy_hash": policy_hash,
                "decision_hash": decision_hash,
                "replay_hash": replay_hash,
                "ledger": {
                    "ledger_tip_hash": ledger_segment[-1].get("event_hash") if ledger_segment else "",
                    "ledger_record_id": ledger_segment[-1].get("override_id") if ledger_segment else "",
                },
                "signatures": {
                    "checkpoint_signature": checkpoint_signature,
                    "signing_key_id": signing_key_id,
                },
            },
            "decision_id": args.decision_id,
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
        }
        export_checksum = sha256_json(bundle)
        bundle["export_checksum"] = export_checksum
        bundle["proof_pack_id"] = proof_pack_id

        if args.format == "json":
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(bundle, f, indent=2, default=str)
            print(json.dumps(bundle, indent=2, default=str))
            return 0

        if not args.output:
            print("--output is required for zip format", file=sys.stderr)
            return 1

        import io
        import zipfile

        memory = io.BytesIO()
        with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bundle.json", json.dumps(bundle, indent=2, default=str))
            zf.writestr("integrity.json", json.dumps(bundle["integrity"], indent=2, default=str))
            zf.writestr("decision_snapshot.json", json.dumps(bundle["decision_snapshot"], indent=2, default=str))
            zf.writestr("policy_snapshot.json", json.dumps(bundle["policy_snapshot"], indent=2, default=str))
            zf.writestr("input_snapshot.json", json.dumps(bundle["input_snapshot"], indent=2, default=str))
            zf.writestr("override_snapshot.json", json.dumps(bundle["override_snapshot"], indent=2, default=str))
            zf.writestr("ledger_segment.json", json.dumps(bundle["ledger_segment"], indent=2, default=str))
            zf.writestr("chain_proof.json", json.dumps(bundle["chain_proof"], indent=2, default=str))
            zf.writestr("checkpoint_proof.json", json.dumps(bundle["checkpoint_proof"], indent=2, default=str))
            zf.writestr("checkpoint_snapshot.json", json.dumps(bundle["checkpoint_snapshot"], indent=2, default=str))
        memory.seek(0)
        with open(args.output, "wb") as f:
            f.write(memory.getvalue())
        print(f"Wrote proof pack: {args.output}")
        return 0

    if args.cmd == "verify-proof-pack":
        from releasegate.audit.proof_pack_verify import (
            ProofPackFileError,
            format_verification_summary,
            verify_proof_pack_file,
        )

        try:
            report = verify_proof_pack_file(
                args.file,
                signing_key=args.signing_key,
                key_file=args.key_file,
            )
        except ProofPackFileError as exc:
            payload = {
                "ok": False,
                "error_code": "PROOF_PACK_FILE_INVALID",
                "error_message": str(exc),
                "file": args.file,
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print(f"verification: FAIL\nerror_code: {payload['error_code']}\nerror_message: {payload['error_message']}")
            return 3

        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_verification_summary(report))
        return 0 if report.get("ok") else 2

    if args.cmd == "verify-attestation":
        from releasegate.attestation.crypto import load_public_keys_map
        from releasegate.attestation.verify import verify_attestation_payload

        try:
            with open(args.file, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            error = {
                "ok": False,
                "schema_valid": False,
                "payload_hash_match": False,
                "trusted_issuer": False,
                "valid_signature": False,
                "errors": [f"FILE_INVALID: {exc}"],
            }
            if args.format == "json":
                print(json.dumps(error, indent=2))
            else:
                print("verification: FAIL")
                print(f"error: {error['errors'][0]}")
            return 3

        key_map = load_public_keys_map(key_file=args.key_file)
        report = verify_attestation_payload(payload, public_keys_by_key_id=key_map)
        report["ok"] = bool(
            report.get("schema_valid")
            and report.get("payload_hash_match")
            and report.get("trusted_issuer")
            and report.get("valid_signature")
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(
                "\n".join(
                    [
                        f"schema_valid: {'OK' if report.get('schema_valid') else 'FAIL'}",
                        f"payload_hash_match: {'OK' if report.get('payload_hash_match') else 'FAIL'}",
                        f"trusted_issuer: {'OK' if report.get('trusted_issuer') else 'FAIL'}",
                        f"valid_signature: {'OK' if report.get('valid_signature') else 'FAIL'}",
                        f"errors: {', '.join(report.get('errors') or []) if report.get('errors') else 'none'}",
                    ]
                )
            )
        return 0 if report.get("ok") else 2

    if args.cmd == "verify-dsse":
        from releasegate.attestation.crypto import load_public_keys_map
        from releasegate.attestation.dsse import verify_dsse_signatures
        from releasegate.attestation.intoto import PREDICATE_TYPE_RELEASEGATE_V1, STATEMENT_TYPE_V1

        try:
            with open(args.dsse, "r", encoding="utf-8") as f:
                envelope = json.load(f)
        except Exception as exc:
            payload = {
                "ok": False,
                "error_code": "DSSE_FILE_INVALID",
                "error_message": str(exc),
                "file": args.dsse,
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print("verification: FAIL")
                print(f"error_code: {payload['error_code']}")
                print(f"error_message: {payload['error_message']}")
            return 3

        key_id = None
        signature_key_ids: list[str] = []
        signatures = envelope.get("signatures") if isinstance(envelope, dict) else None
        if isinstance(signatures, list):
            for entry in signatures:
                if isinstance(entry, dict):
                    kid = str(entry.get("keyid") or "").strip()
                    if kid:
                        signature_key_ids.append(kid)
        if signature_key_ids:
            key_id = signature_key_ids[0]

        require_key_id = str(getattr(args, "require_keyid", "") or "").strip() or None
        if require_key_id and require_key_id not in signature_key_ids:
            report = {
                "ok": False,
                "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                "key_id": key_id,
                "error_code": "KEYID_PIN_MISMATCH",
            }
            if args.format == "json":
                print(json.dumps(report, indent=2))
            else:
                print("verification: FAIL")
                print(f"error_code: {report['error_code']}")
                if report.get("payload_type") is not None:
                    print(f"payloadType: {report.get('payload_type')}")
                if report.get("key_id") is not None:
                    print(f"keyid: {report.get('key_id')}")
            return 2

        require_signers_raw = str(getattr(args, "require_signers", "") or "").strip()
        require_signers = [s.strip() for s in require_signers_raw.split(",") if s.strip()] if require_signers_raw else []
        missing_required = [s for s in require_signers if s not in signature_key_ids]
        if missing_required:
            report = {
                "ok": False,
                "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                "key_id": key_id,
                "error_code": "SIGNERS_MISSING",
                "missing_signers": missing_required,
            }
            if args.format == "json":
                print(json.dumps(report, indent=2))
            else:
                print("verification: FAIL")
                print(f"error_code: {report['error_code']}")
                print(f"missing_signers: {', '.join(missing_required)}")
            return 2

        key_map = None
        if getattr(args, "sigstore_bundle", None):
            from releasegate.attestation.dsse import verify_dsse_sigstore

            sig_ok, statement, error = verify_dsse_sigstore(
                envelope,
                bundle_path=str(args.sigstore_bundle),
                certificate_identity=str(getattr(args, "sigstore_identity", "") or "").strip() or None,
                certificate_oidc_issuer=str(getattr(args, "sigstore_issuer", "") or "").strip() or None,
            )
            signature_results = [
                {
                    "keyid": key_id,
                    "ok": bool(sig_ok),
                    "error_code": (error if not sig_ok else None),
                }
            ]
            valid_key_ids = [str(key_id)] if sig_ok and key_id else []
            signature_ok = bool(valid_key_ids) and not error
            # If Sigstore verification is selected, skip Ed25519 key-map verification.
        elif args.key_file:
            try:
                key_text = open(args.key_file, "r", encoding="utf-8").read().strip()
            except Exception as exc:
                payload = {
                    "ok": False,
                    "error_code": "KEY_FILE_INVALID",
                    "error_message": str(exc),
                    "file": args.key_file,
                }
                if args.format == "json":
                    print(json.dumps(payload, indent=2))
                else:
                    print("verification: FAIL")
                    print(f"error_code: {payload['error_code']}")
                    print(f"error_message: {payload['error_message']}")
                return 3

            if key_text.startswith("{"):
                try:
                    parsed = json.loads(key_text)
                except Exception as exc:
                    payload = {
                        "ok": False,
                        "error_code": "KEY_MAP_INVALID",
                        "error_message": str(exc),
                        "file": args.key_file,
                    }
                    if args.format == "json":
                        print(json.dumps(payload, indent=2))
                    else:
                        print("verification: FAIL")
                        print(f"error_code: {payload['error_code']}")
                        print(f"error_message: {payload['error_message']}")
                    return 3
                if not isinstance(parsed, dict):
                    payload = {
                        "ok": False,
                        "error_code": "KEY_MAP_INVALID",
                        "error_message": "key map must be a JSON object",
                        "file": args.key_file,
                    }
                    if args.format == "json":
                        print(json.dumps(payload, indent=2))
                    else:
                        print("verification: FAIL")
                        print(f"error_code: {payload['error_code']}")
                        print(f"error_message: {payload['error_message']}")
                    return 3
                key_map = {str(k): str(v).strip() for k, v in parsed.items() if isinstance(v, str) and v.strip()}
                for required in [require_key_id] + require_signers:
                    if required and required not in key_map:
                        report = {
                            "ok": False,
                            "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                            "key_id": key_id,
                            "error_code": "KEYID_NOT_FOUND",
                            "missing_key_id": required,
                        }
                        if args.format == "json":
                            print(json.dumps(report, indent=2))
                        else:
                            print("verification: FAIL")
                            print(f"error_code: {report['error_code']}")
                            print(f"missing_key_id: {required}")
                        return 2
                if key_id and key_id not in key_map:
                    report = {
                        "ok": False,
                        "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                        "key_id": key_id,
                        "error_code": "KEYID_NOT_FOUND",
                    }
                    if args.format == "json":
                        print(json.dumps(report, indent=2))
                    else:
                        print("verification: FAIL")
                        print(f"error_code: {report['error_code']}")
                        if report.get("payload_type") is not None:
                            print(f"payloadType: {report.get('payload_type')}")
                        if report.get("key_id") is not None:
                            print(f"keyid: {report.get('key_id')}")
                    return 2
            else:
                if not key_id:
                    report = {
                        "ok": False,
                        "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                        "key_id": None,
                        "error_code": "MISSING_KEY_ID",
                    }
                    if args.format == "json":
                        print(json.dumps(report, indent=2))
                    else:
                        print("verification: FAIL")
                        print(f"error_code: {report.get('error_code')}")
                    return 3
                key_map = {str(key_id): key_text}
        elif getattr(args, "keys_url", None):
            import requests

            try:
                resp = requests.get(str(args.keys_url), timeout=10)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:
                error_payload = {
                    "ok": False,
                    "error_code": "KEY_URL_INVALID",
                    "error_message": str(exc),
                    "url": str(args.keys_url),
                }
                if args.format == "json":
                    print(json.dumps(error_payload, indent=2))
                else:
                    print("verification: FAIL")
                    print(f"error_code: {error_payload['error_code']}")
                    print(f"error_message: {error_payload['error_message']}")
                return 3

            candidate_map: dict = {}
            if isinstance(payload, dict):
                public_map = payload.get("public_keys_by_key_id")
                if isinstance(public_map, dict):
                    candidate_map = {str(k): str(v).strip() for k, v in public_map.items() if isinstance(v, str) and v.strip()}
                elif isinstance(payload.get("keys"), list):
                    for entry in payload.get("keys") or []:
                        if not isinstance(entry, dict):
                            continue
                        kid = str(entry.get("key_id") or entry.get("kid") or "").strip()
                        pem = str(entry.get("public_key_pem") or entry.get("public_key") or entry.get("pem") or "").strip()
                        if kid and pem:
                            candidate_map[kid] = pem
                elif payload and all(isinstance(v, str) for v in payload.values()):
                    candidate_map = {str(k): str(v).strip() for k, v in payload.items() if isinstance(v, str) and v.strip()}

            if not candidate_map:
                error_payload = {
                    "ok": False,
                    "error_code": "KEY_URL_EMPTY",
                    "url": str(args.keys_url),
                }
                if args.format == "json":
                    print(json.dumps(error_payload, indent=2))
                else:
                    print("verification: FAIL")
                    print(f"error_code: {error_payload['error_code']}")
                return 3

            key_map = candidate_map
            for required in [require_key_id] + require_signers:
                if required and required not in key_map:
                    report = {
                        "ok": False,
                        "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
                        "key_id": key_id,
                        "error_code": "KEYID_NOT_FOUND",
                        "missing_key_id": required,
                    }
                    if args.format == "json":
                        print(json.dumps(report, indent=2))
                    else:
                        print("verification: FAIL")
                        print(f"error_code: {report['error_code']}")
                        print(f"missing_key_id: {required}")
                    return 2
        else:
            key_map = load_public_keys_map(key_file=None)

        if getattr(args, "sigstore_bundle", None):
            # Sigstore branch already computed statement/signature_results/signature_ok above.
            pass
        else:
            statement, signature_results, error = verify_dsse_signatures(envelope, key_map)
            valid_key_ids = [
                str(entry.get("keyid") or "")
                for entry in (signature_results or [])
                if isinstance(entry, dict) and entry.get("ok") is True and str(entry.get("keyid") or "").strip()
            ]
            signature_ok = bool(valid_key_ids) and not error
        if require_key_id and require_key_id not in valid_key_ids:
            signature_ok = False
            error = "REQUIRED_KEYID_INVALID"
        if signature_ok and require_signers:
            missing_valid = [s for s in require_signers if s not in valid_key_ids]
            if missing_valid:
                signature_ok = False
                error = "REQUIRED_SIGNER_INVALID"

        report: dict = {
            "ok": False,
            "payload_type": envelope.get("payloadType") if isinstance(envelope, dict) else None,
            "key_id": key_id,
            "error_code": error,
            "key_ids": signature_key_ids,
            "valid_key_ids": valid_key_ids,
        }

        subject_name = None
        subject_digest_sha256 = None
        predicate_type = None
        statement_type = None
        attestation_id = None
        conformance_errors: list[str] = []
        predicate = None
        predicate_repo = ""
        predicate_commit_sha = ""
        signed_payload_hash = ""
        predicate_issued_at = ""

        if isinstance(statement, dict):
            statement_type = statement.get("_type")
            predicate_type = statement.get("predicateType")
            subject = statement.get("subject")
            if isinstance(subject, list) and subject and isinstance(subject[0], dict):
                subject_name = subject[0].get("name")
                digest = subject[0].get("digest")
                if isinstance(digest, dict):
                    subject_digest_sha256 = digest.get("sha256")

            predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else None
            if not isinstance(predicate, dict):
                conformance_errors.append("PREDICATE_MISSING")
            else:
                predicate_subject = predicate.get("subject") if isinstance(predicate.get("subject"), dict) else {}
                predicate_repo = str(predicate_subject.get("repo") or "").strip()
                predicate_commit_sha = str(predicate_subject.get("commit_sha") or "").strip()

                signature = predicate.get("signature") if isinstance(predicate.get("signature"), dict) else {}
                signed_payload_hash = str(signature.get("signed_payload_hash") or "").strip()
                predicate_issued_at = str(predicate.get("issued_at") or "").strip()
                if signed_payload_hash:
                    if ":" in signed_payload_hash:
                        signed_payload_hash = signed_payload_hash.split(":", 1)[1]
                    signed_payload_hash = signed_payload_hash.strip().lower()
                    if len(signed_payload_hash) == 64:
                        attestation_id = signed_payload_hash

            if statement_type != STATEMENT_TYPE_V1:
                conformance_errors.append("STATEMENT_TYPE_MISMATCH")
            if predicate_type != PREDICATE_TYPE_RELEASEGATE_V1:
                conformance_errors.append("PREDICATE_TYPE_MISMATCH")
            if not (isinstance(subject, list) and subject and isinstance(subject[0], dict)):
                conformance_errors.append("SUBJECT_MISSING")
            else:
                if predicate_repo and predicate_commit_sha:
                    expected_subject_name = f"git+https://github.com/{predicate_repo}@{predicate_commit_sha}"
                    if subject_name != expected_subject_name:
                        conformance_errors.append("SUBJECT_NAME_MISMATCH")
                else:
                    conformance_errors.append("PREDICATE_SUBJECT_MISSING")

                require_repo = str(getattr(args, "require_repo", "") or "").strip()
                if require_repo:
                    if not predicate_repo:
                        conformance_errors.append("REPO_MISSING")
                    elif predicate_repo != require_repo:
                        conformance_errors.append("REPO_MISMATCH")

                require_commit = str(getattr(args, "require_commit", "") or "").strip()
                if require_commit:
                    if not predicate_commit_sha:
                        conformance_errors.append("COMMIT_MISSING")
                    elif predicate_commit_sha != require_commit:
                        conformance_errors.append("COMMIT_MISMATCH")

                max_age_raw = str(getattr(args, "max_age", "") or "").strip()
                if max_age_raw:
                    try:
                        max_age_seconds = _parse_age_seconds(max_age_raw)
                    except Exception:
                        conformance_errors.append("MAX_AGE_INVALID")
                    else:
                        issued_raw = str(predicate_issued_at or "").strip()
                        if not issued_raw:
                            conformance_errors.append("ISSUED_AT_MISSING")
                        else:
                            ts = issued_raw
                            if ts.endswith("Z"):
                                ts = f"{ts[:-1]}+00:00"
                            try:
                                issued_dt = datetime.fromisoformat(ts)
                                if issued_dt.tzinfo is None:
                                    issued_dt = issued_dt.replace(tzinfo=timezone.utc)
                                else:
                                    issued_dt = issued_dt.astimezone(timezone.utc)
                            except Exception:
                                conformance_errors.append("ISSUED_AT_INVALID")
                            else:
                                if datetime.now(timezone.utc) - issued_dt > timedelta(seconds=max_age_seconds):
                                    conformance_errors.append("ATTESTATION_TOO_OLD")

                if not signed_payload_hash:
                    conformance_errors.append("SIGNED_PAYLOAD_HASH_MISSING")
                elif len(str(signed_payload_hash)) != 64:
                    conformance_errors.append("SIGNED_PAYLOAD_HASH_INVALID")

                if not attestation_id:
                    conformance_errors.append("ATTESTATION_ID_MISSING")
                if not subject_digest_sha256:
                    conformance_errors.append("SUBJECT_DIGEST_MISSING")
                if attestation_id and subject_digest_sha256:
                    if str(subject_digest_sha256).strip().lower() != attestation_id:
                        conformance_errors.append("SUBJECT_DIGEST_MISMATCH")

        report.update(
            {
                "statement_type": statement_type,
                "predicate_type": predicate_type,
                "subject_name": subject_name,
                "subject_digest_sha256": subject_digest_sha256,
                "attestation_id": attestation_id,
                "errors": ([str(error)] if error else []) + conformance_errors,
            }
        )

        report["ok"] = bool(signature_ok and not error and not conformance_errors)
        if report["ok"] is True:
            report["error_code"] = None
        elif report.get("error_code") is None and conformance_errors:
            report["error_code"] = conformance_errors[0]

        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            if report.get("ok"):
                print("verification: OK")
            else:
                print("verification: FAIL")
                if report.get("error_code"):
                    print(f"error_code: {report.get('error_code')}")
            if report.get("payload_type") is not None:
                print(f"payloadType: {report.get('payload_type')}")
            if report.get("key_id") is not None:
                print(f"keyid: {report.get('key_id')}")
            if report.get("subject_name") is not None:
                print(f"subject.name: {report.get('subject_name')}")
            if report.get("subject_digest_sha256") is not None:
                print(f"subject.digest.sha256: {report.get('subject_digest_sha256')}")
            if report.get("predicate_type") is not None:
                print(f"predicateType: {report.get('predicate_type')}")
            if report.get("attestation_id") is not None:
                print(f"attestation_id: {report.get('attestation_id')}")

        if report.get("ok"):
            return 0

        # Distinguish format errors from signature/key failures.
        verification_errors = {
            "SIGNATURE_INVALID",
            "UNKNOWN_KEY_ID",
            "SIGNATURE_LEN_INVALID",
            "KEYID_PIN_MISMATCH",
            "KEYID_NOT_FOUND",
            "REQUIRED_KEYID_INVALID",
            "REQUIRED_SIGNER_INVALID",
            "SIGNERS_MISSING",
            "SIGSTORE_SIGNATURE_INVALID",
        }
        return 2 if str(report.get("error_code") or "") in verification_errors else 3

    if args.cmd == "log-dsse":
        import base64

        from releasegate.audit.attestation_index import (
            append_attestation_index_entry,
            build_attestation_index_entry,
        )

        try:
            envelope = json.load(open(args.dsse, "r", encoding="utf-8"))
        except Exception as exc:
            payload = {"ok": False, "error_code": "DSSE_FILE_INVALID", "error_message": str(exc)}
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print("log: FAIL")
                print(f"error_code: {payload['error_code']}")
                print(f"error_message: {payload['error_message']}")
            return 3

        try:
            payload_bytes = base64.b64decode(str(envelope.get("payload") or "").encode("ascii"), validate=True)
            statement = json.loads(payload_bytes.decode("utf-8"))
            if not isinstance(statement, dict):
                raise ValueError("payload must decode to a JSON object")
        except Exception as exc:
            payload = {"ok": False, "error_code": "DSSE_PAYLOAD_INVALID", "error_message": str(exc)}
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print("log: FAIL")
                print(f"error_code: {payload['error_code']}")
                print(f"error_message: {payload['error_message']}")
            return 3

        entry = build_attestation_index_entry(envelope=envelope, statement=statement)
        append_attestation_index_entry(log_path=args.log, entry=entry)

        out = {"ok": True, "entry": entry, "log": args.log}
        if args.format == "json":
            print(json.dumps(out, indent=2))
        else:
            print("log: OK")
            print(f"log: {args.log}")
            if entry.get("attestation_id"):
                print(f"attestation_id: {entry.get('attestation_id')}")
            if entry.get("dsse_sha256"):
                print(f"dsse_sha256: {entry.get('dsse_sha256')}")
        return 0

    if args.cmd == "verify-log":
        import base64

        from releasegate.audit.attestation_index import (
            build_attestation_index_entry,
            compute_dsse_sha256,
        )

        try:
            envelope = json.load(open(args.dsse, "r", encoding="utf-8"))
        except Exception as exc:
            payload = {"ok": False, "error_code": "DSSE_FILE_INVALID", "error_message": str(exc)}
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print("verification: FAIL")
                print(f"error_code: {payload['error_code']}")
                print(f"error_message: {payload['error_message']}")
            return 3

        expected_hash = compute_dsse_sha256(envelope)
        expected_id = None
        try:
            payload_bytes = base64.b64decode(str(envelope.get("payload") or "").encode("ascii"), validate=True)
            statement = json.loads(payload_bytes.decode("utf-8"))
            if isinstance(statement, dict):
                expected = build_attestation_index_entry(envelope=envelope, statement=statement)
                expected_id = str(expected.get("attestation_id") or "").strip() or None
        except Exception:
            # If the payload is corrupted, fall back to DSSE envelope hash matching.
            expected_id = None

        try:
            with open(args.log, "r", encoding="utf-8") as f:
                lines = list(f)
        except Exception as exc:
            payload = {"ok": False, "error_code": "LOG_FILE_INVALID", "error_message": str(exc)}
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print("verification: FAIL")
                print(f"error_code: {payload['error_code']}")
                print(f"error_message: {payload['error_message']}")
            return 3

        match = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            if str(row.get("dsse_sha256") or "").strip() != expected_hash:
                continue
            if expected_id is not None and str(row.get("attestation_id") or "").strip() != expected_id:
                continue
            match = True
            break

        payload = {
            "ok": bool(match),
            "attestation_id": expected_id,
            "dsse_sha256": expected_hash,
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2))
        else:
            print("verification: OK" if match else "verification: FAIL")
            print(f"attestation_id: {expected_id}")
            print(f"dsse_sha256: {expected_hash}")
        return 0 if match else 2

    if args.cmd == "proofpack":
        from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_decision
        from releasegate.audit.attestations import record_release_attestation
        from releasegate.audit.proofpack_v1 import write_proofpack_v1_zip
        from releasegate.audit.rfc3161 import (
            RFC3161Error,
            default_rfc3161_tsa_url,
            is_rfc3161_enabled,
            mint_rfc3161_artifact,
        )
        from releasegate.audit.reader import AuditReader
        from releasegate.decision.types import Decision, DecisionType

        tenant_id = resolve_tenant_id(args.tenant)
        row = AuditReader.get_decision(args.decision_id, tenant_id=tenant_id)
        if not row:
            print("Decision not found.", file=sys.stderr)
            return 1

        raw = row.get("full_decision_json")
        if not raw:
            print("Decision payload missing full_decision_json.", file=sys.stderr)
            return 1

        decision_snapshot = json.loads(raw) if isinstance(raw, str) else raw
        decision_model = Decision(**decision_snapshot)
        repo = str(row.get("repo") or decision_model.enforcement_targets.repository or "")
        pr_number = row.get("pr_number")
        engine_version = str(row.get("engine_version") or decision_model.policy_bundle_hash or "unknown")

        attestation_row = AuditReader.get_attestation_by_decision(args.decision_id, tenant_id=tenant_id)
        if attestation_row and isinstance(attestation_row.get("attestation"), dict):
            attestation = dict(attestation_row["attestation"])
            attestation_id = str(attestation_row.get("attestation_id") or "")
        else:
            bundle = build_bundle_from_decision(
                decision_model,
                repo=repo,
                pr_number=pr_number,
                engine_version=engine_version,
            )
            attestation = build_attestation_from_bundle(bundle)
            attestation_id = record_release_attestation(
                decision_id=args.decision_id,
                tenant_id=tenant_id,
                repo=repo,
                pr_number=pr_number,
                attestation=attestation,
            )

        signature_text = str(((attestation.get("signature") or {}).get("signature_bytes")) or "")
        if not signature_text:
            print("Attestation signature is missing; cannot build deterministic proofpack.", file=sys.stderr)
            return 1

        status = decision_model.release_status
        allow_block = "BLOCK" if status in {DecisionType.BLOCKED, DecisionType.ERROR} else "ALLOW"
        inputs_payload = {
            "repo": repo,
            "pr_number": pr_number,
            "commit_sha": ((attestation.get("subject") or {}).get("commit_sha") or ""),
            "policy_hash": decision_model.policy_hash,
            "policy_bundle_hash": decision_model.policy_bundle_hash,
            "input_snapshot": decision_model.input_snapshot,
        }
        decision_payload = {
            "decision_id": decision_model.decision_id,
            "decision": allow_block,
            "release_status": str(status.value if hasattr(status, "value") else status),
            "reason_code": decision_model.reason_code,
            "message": decision_model.message,
            "decision_hash": decision_model.decision_hash,
            "replay_hash": decision_model.replay_hash,
        }

        inclusion = None
        receipt = None

        timestamp_metadata = None
        rfc3161_token = None
        if args.include_timestamp or is_rfc3161_enabled():
            tsa_url = str(args.tsa_url or default_rfc3161_tsa_url()).strip()
            signed_hash = str(((attestation.get("signature") or {}).get("signed_payload_hash")) or "").strip()
            if not tsa_url:
                print(
                    "RFC3161 timestamping requested but TSA URL is missing "
                    "(--tsa-url or RELEASEGATE_RFC3161_TSA_URL).",
                    file=sys.stderr,
                )
                return 1
            try:
                timestamp_metadata, rfc3161_token = mint_rfc3161_artifact(
                    payload_hash=signed_hash,
                    tsa_url=tsa_url,
                    timeout_seconds=max(1, int(args.tsa_timeout_seconds)),
                )
            except RFC3161Error as exc:
                print(f"Failed to mint RFC3161 timestamp token: {exc}", file=sys.stderr)
                return 1

        result = write_proofpack_v1_zip(
            out_path=args.out,
            attestation=attestation,
            signature_text=signature_text,
            inputs=inputs_payload,
            decision=decision_payload,
            created_by=str(attestation.get("engine_version") or engine_version),
            receipt=receipt,
            inclusion_proof=inclusion,
            timestamp_metadata=timestamp_metadata,
            rfc3161_token=rfc3161_token,
        )
        payload = {
            "ok": True,
            "decision_id": args.decision_id,
            "attestation_id": attestation_id,
            **result,
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2))
        else:
            print(f"Wrote proofpack: {args.out}")
            print(f"proofpack_hash: {payload['proofpack_hash']}")
            print(f"attestation_id: {attestation_id}")
        return 0

    if args.cmd == "verify-pack":
        from releasegate.audit.proofpack_v1 import verify_proofpack_v1_file

        report = verify_proofpack_v1_file(
            args.file,
            key_file=args.key_file,
            tsa_ca_bundle=args.tsa_ca_bundle,
        )
        if report.get("ok") and args.expected_hash:
            expected = str(args.expected_hash).strip().lower()
            actual = str(report.get("proofpack_hash") or "").strip().lower()
            if expected.startswith("sha256:"):
                expected = expected.split(":", 1)[1]
            if actual.startswith("sha256:"):
                actual = actual.split(":", 1)[1]
            if expected != actual:
                report = {
                    "ok": False,
                    "error_code": "PROOFPACK_HASH_MISMATCH",
                    "details": {
                        "expected": f"sha256:{expected}",
                        "actual": f"sha256:{actual}",
                    },
                }
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            if report.get("ok"):
                print("verification: OK")
                print(f"proofpack_version: {report.get('proofpack_version')}")
                print(f"proofpack_hash: {report.get('proofpack_hash')}")
                if report.get("timestamp_verified") is True:
                    print("rfc3161_timestamp: OK")
            else:
                print("verification: FAIL")
                print(f"error_code: {report.get('error_code')}")
        return 0 if report.get("ok") else 2

    return 2

if __name__ == "__main__":
    sys.exit(main())
