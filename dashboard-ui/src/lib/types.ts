export type Severity = "high" | "medium" | "low";

export interface TrendPoint {
  date_utc: string;
  integrity_score: number;
  drift_index: number;
  override_rate: number;
  override_count: number;
  decision_count: number;
  blocked_count: number;
  drift_breakdown?: Record<string, unknown> | null;
  override_abuse_index?: number;
}

export interface StrictModeItem {
  mode: string;
  scope_type: string;
  scope_id: string;
  enabled: boolean;
  reason?: string | null;
  last_changed_by?: string | null;
  last_changed_at?: string | null;
}

export interface BlockedDecisionItem {
  decision_id: string;
  created_at: string;
  decision_status: string;
  reason_code: string;
  subject_ref: string;
  workflow: string;
  transition: string;
  explainer_path: string;
}

export interface DashboardOverview {
  trace_id: string;
  tenant_id: string;
  integrity_score: number;
  integrity_trend: Array<{ date_utc: string; value: number }>;
  drift_index: number;
  drift_trend: Array<{ date_utc: string; value: number }>;
  override_rate: number;
  override_rate_trend: Array<{ date_utc: string; value: number; override_count: number; decision_count: number }>;
  drift: { current: number; breakdown: Record<string, unknown> | null };
  active_strict_modes: StrictModeItem[];
  recent_blocked: BlockedDecisionItem[];
}

export interface DashboardIntegrity {
  trace_id: string;
  tenant_id: string;
  window_days: number;
  trend: TrendPoint[];
}

export interface DashboardAlerts {
  trace_id: string;
  tenant_id: string;
  window_days: number;
  current_override_abuse_index: number;
  alerts: Array<{
    date_utc: string;
    severity: Severity;
    code: string;
    title: string;
    details: Record<string, unknown>;
  }>;
}

export interface DecisionExplainer {
  trace_id: string;
  tenant_id: string;
  decision_id: string;
  decision: {
    decision_id: string;
    created_at: string;
    outcome: "BLOCK" | "ALLOW";
    blocked_because?: string | null;
    reason_code?: string | null;
    jira_issue_id?: string | null;
    workflow_id?: string | null;
    transition_id?: string | null;
    actor?: string | null;
    environment?: string | null;
    status?: string | null;
    repo?: string | null;
    pr_number?: number | null;
    project_key?: string | null;
  };
  snapshot_binding: {
    policy_hash?: string | null;
    snapshot_hash?: string | null;
    decision_hash?: string | null;
    policy_resolution_hash?: string | null;
    signal_bundle_hash?: string | null;
    binding_verified?: boolean | null;
  };
  evaluation_tree: {
    nodes: Array<Record<string, unknown>>;
    edges: Array<Record<string, unknown>>;
  };
  signals: Array<{
    name: string;
    value: unknown;
    source: string | null;
    confidence: number | null;
    captured_at: string | null;
  }>;
  risk: {
    score: number;
    components: Array<{
      name: string;
      value: unknown;
      weight: number | null;
      notes: string | null;
    }>;
  };
  evidence_links: Array<{
    type: string;
    id: string;
    label: string;
    path: string | null;
  }>;
  approval_freshness?: {
    enforced?: boolean;
    max_age_seconds?: number | null;
    active_count?: number;
    expired_count?: number;
    expired_actor_ids?: string[];
  };
  replay: {
    path: string;
    token: string;
    expires_at: string | null;
  };
}

export interface PolicyDiffResponse {
  trace_id: string;
  report_trace_id?: string;
  overall: string;
  summary: {
    has_changes: boolean;
    change_count: number;
    severity_counts: Record<Severity, number>;
    summary_bullets: string[];
    warning_count?: number;
    strengthening_count?: number;
    rule_change_count?: number;
    risk_threshold_change_count?: number;
  };
  threshold_deltas: Array<Record<string, unknown> & { severity: Severity }>;
  condition_deltas: Array<Record<string, unknown> & { severity: Severity }>;
  role_deltas: Array<Record<string, unknown> & { severity: Severity }>;
  sod_deltas: Array<Record<string, unknown> & { severity: Severity }>;
}

export type OverridesGroupBy = "actor" | "workflow" | "rule";

export interface OverrideBreakdownRow {
  key: string;
  count: number;
  workflows: number;
  rules: number;
  actors: number;
  last_seen: string | null;
  sample_override_ids: string[];
}

export interface DashboardOverridesBreakdown {
  trace_id: string;
  tenant: string;
  from: string;
  to: string;
  group_by: OverridesGroupBy;
  total_overrides: number;
  rows: OverrideBreakdownRow[];
}

export type ObservabilityMetric =
  | "integrity_score"
  | "drift_index"
  | "override_rate"
  | "block_frequency";

export interface MetricsSeriesPoint {
  t: string;
  value: number;
  numerator?: number;
  denominator?: number;
}

export interface DashboardMetricsTimeseries {
  trace_id: string;
  tenant_id: string;
  metric: ObservabilityMetric;
  display_name: string;
  unit: string;
  higher_is_better: boolean;
  description: string;
  bucket: "day" | "hour";
  from: string;
  to: string;
  series: MetricsSeriesPoint[];
}

export interface DashboardMetricSummaryPoint {
  display_name: string;
  unit: string;
  higher_is_better: boolean;
  value: number;
  previous: number | null;
  delta: number | null;
  sample_size: number;
}

export interface DashboardMetricsSummary {
  trace_id: string;
  tenant_id: string;
  from: string;
  to: string;
  window_days: number;
  metrics: Record<ObservabilityMetric, DashboardMetricSummaryPoint>;
}

export interface DashboardMetricsDrilldownItem {
  decision_id: string;
  created_at: string;
  decision_status: string;
  reason_code: string;
  jira_issue_id: string;
  workflow_id: string;
  transition_id: string;
  actor: string;
  environment: string;
  project_key: string;
  policy_hash: string;
  explainer_path: string;
}

export interface DashboardMetricsDrilldown {
  trace_id: string;
  tenant_id: string;
  metric: ObservabilityMetric;
  from: string;
  to: string;
  limit: number;
  items: DashboardMetricsDrilldownItem[];
}

export interface CustomerSuccessRiskPoint {
  t: string;
  value: number;
  decision_count: number;
}

export interface CustomerSuccessReleaseStabilityPoint {
  t: string;
  value: number;
  block_rate: number;
  override_rate: number;
  blocked_count: number;
  override_count: number;
  decision_count: number;
}

export interface DashboardCustomerSuccessRiskTrend {
  trace_id: string;
  tenant_id: string;
  from: string;
  to: string;
  window_days: number;
  risk_index: CustomerSuccessRiskPoint[];
  risk_delta_30d: number;
  org_risk_reduction: number;
  release_stability: CustomerSuccessReleaseStabilityPoint[];
  release_stability_delta: number;
}

export interface CustomerSuccessOverrideUser {
  user: string;
  overrides: number;
  share: number;
  last_override_at: string | null;
}

export interface DashboardCustomerSuccessOverrideAnalysis {
  trace_id: string;
  tenant_id: string;
  from: string;
  to: string;
  window_days: number;
  total_overrides: number;
  total_decisions: number;
  top_users: CustomerSuccessOverrideUser[];
  override_concentration_index: number;
  policy_weakening_signal: boolean;
  override_rate_baseline: number;
  override_rate_recent: number;
}

export interface CustomerSuccessRegressionItem {
  policy_change_id: string;
  policy_id: string;
  event_type: string;
  changed_at: string;
  integrity_before: number;
  integrity_after: number;
  integrity_drop: number;
  integrity_drop_ratio: number;
  correlation_window_hours: number;
  affected_workflows: string[];
  policy_diff_path: string;
  decisions_path: string;
}

export interface DashboardCustomerSuccessRegressionReport {
  trace_id: string;
  tenant_id: string;
  from: string;
  to: string;
  window_days: number;
  threshold_drop: number;
  total_policy_changes: number;
  regressions_detected: number;
  regressions: CustomerSuccessRegressionItem[];
}

export interface GovernanceRecommendation {
  recommendation_id: string;
  recommendation_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  status: "OPEN" | "ACKED" | "RESOLVED";
  title: string;
  message: string;
  playbook: string;
  context: Record<string, unknown>;
  acked_by: string | null;
  acked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface GovernanceRecommendationsResponse {
  tenant_id: string;
  generated_at: string | null;
  lookback_days: number;
  insight: Record<string, unknown>;
  recommendations: GovernanceRecommendation[];
}

export type OnboardingMode = "simulation" | "canary" | "strict";

export interface JiraProject {
  project_key: string;
  name: string;
  project_id?: string | null;
}

export interface JiraWorkflow {
  workflow_id: string;
  workflow_name: string;
  project_keys: string[];
}

export interface JiraWorkflowTransition {
  transition_id: string;
  transition_name: string;
  workflow_id: string;
  workflow_name: string;
  project_keys: string[];
}

export interface OnboardingConfig {
  tenant_id: string;
  jira_instance_id: string | null;
  project_keys: string[];
  workflow_ids: string[];
  transition_ids: string[];
  mode: OnboardingMode;
  canary_pct: number | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface OnboardingStatus {
  tenant_id: string;
  onboarding_completed: boolean;
  config: OnboardingConfig;
}

export interface OnboardingActivation {
  tenant_id: string;
  mode: OnboardingMode;
  canary_pct: number | null;
  applied: boolean;
  updated_at: string | null;
}

export interface OnboardingActivationHistoryEntry {
  history_id: number;
  mode: OnboardingMode;
  canary_pct: number | null;
  updated_at: string | null;
  recorded_at: string | null;
}

export interface OnboardingActivationHistory {
  tenant_id: string;
  limit: number;
  current: OnboardingActivation;
  items: OnboardingActivationHistoryEntry[];
}

export interface OnboardingActivationRollback {
  status: "rolled_back";
  activation: OnboardingActivation;
}

export interface SimulationResult {
  tenant_id: string;
  lookback_days: number;
  total_transitions: number;
  allowed: number;
  blocked: number;
  blocked_pct: number;
  override_required: number;
  starter_pack: string;
  insights: {
    high_risk_releases: number;
    missing_approvals: number;
    unmapped_transitions: number;
  };
  summary: string | null;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
  };
  ran_at: string | null;
  has_run: boolean;
}

export type TenantStatus = "active" | "locked" | "throttled";
export type TenantPlan = "starter" | "growth" | "enterprise";
export type TenantRole = "owner" | "admin" | "operator" | "auditor" | "viewer";

export interface TenantRoleAssignment {
  actor_id: string;
  roles: TenantRole[];
  assigned_by: string | null;
  last_assigned_at: string | null;
}

export interface TenantInfo {
  trace_id?: string;
  tenant_id: string;
  name: string;
  plan: TenantPlan;
  region: string;
  status: TenantStatus;
  created_at: string | null;
  updated_at: string | null;
  updated_by: string | null;
  roles: TenantRoleAssignment[];
  limits: {
    plan: TenantPlan;
    decision_limit_month: number | null;
    override_limit_month: number | null;
    simulation_history_days: number;
    storage_limit_mb: number | null;
    blocked_list_limit: number;
    quota_enforcement_mode: string;
  };
}

export interface TenantKeyRotationResult {
  trace_id?: string;
  tenant_id: string;
  rotated_signing_key_id: string | null;
  rotated_api_key_id: string | null;
  api_key_created: boolean;
}

export interface BillingUsage {
  trace_id?: string;
  tenant_id: string;
  plan: TenantPlan;
  status: TenantStatus;
  decisions_this_month: number;
  decision_limit: number | null;
  decision_usage_pct: number | null;
  overrides_this_month: number;
  override_limit: number | null;
  override_usage_pct: number | null;
  storage_mb: number;
  storage_limit_mb: number | null;
  storage_usage_pct: number | null;
  simulation_runs: number;
  simulation_history_days_limit: number;
}

export interface JiraProjectsDiscoveryResponse {
  tenant_id: string;
  source: string;
  items: JiraProject[];
}

export interface JiraWorkflowsDiscoveryResponse {
  tenant_id: string;
  project_key: string | null;
  source: string;
  items: JiraWorkflow[];
}

export interface JiraTransitionsDiscoveryResponse {
  tenant_id: string;
  workflow_id: string;
  project_key: string | null;
  source: string;
  items: JiraWorkflowTransition[];
}

// ---------------------------------------------------------------------------
// Policy Control Plane
// ---------------------------------------------------------------------------

export type PolicyScopeType = "org" | "project" | "workflow" | "transition";
export type PolicyStatus = "DRAFT" | "STAGED" | "ACTIVE" | "ARCHIVED" | "DEPRECATED";

export interface RegistryPolicy {
  tenant_id: string;
  policy_id: string;
  scope_type: PolicyScopeType;
  scope_id: string;
  version: number;
  status: PolicyStatus;
  policy_hash: string;
  policy_json: Record<string, unknown>;
  lint_errors: LintIssue[];
  lint_warnings: LintIssue[];
  rollout_percentage: number;
  rollout_scope: string | null;
  created_at: string;
  created_by: string | null;
  activated_at: string | null;
  activated_by: string | null;
  archived_at: string | null;
  supersedes_policy_id: string | null;
}

export interface PolicyListResponse {
  tenant_id: string;
  policies: RegistryPolicy[];
}

export interface LintIssue {
  severity: "ERROR" | "WARNING";
  code: string;
  message: string;
  policy_id?: string | null;
  source_file?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface LintResult {
  ok: boolean;
  error_count: number;
  warning_count: number;
  issues: LintIssue[];
}

export interface ConflictSummary {
  contradiction_count: number;
  shadowed_rule_count: number;
  coverage_gap_count: number;
  warning_count: number;
}

export interface ConflictAnalysis {
  ok: boolean;
  contradictions: LintIssue[];
  shadowed_rules: LintIssue[];
  coverage_gaps: LintIssue[];
  warnings: LintIssue[];
  summary: ConflictSummary;
  lint: LintResult;
}

export interface PolicyConflictResponse {
  tenant_id: string;
  policy_id: string;
  policy_hash: string;
  analysis: ConflictAnalysis;
}

export interface PolicyRegistryEvent {
  event_id?: string;
  event_type: string;
  policy_id: string;
  actor_id?: string | null;
  created_at: string;
  metadata?: Record<string, unknown>;
}

export interface PolicyEventsResponse {
  tenant_id: string;
  policy_id: string;
  events: PolicyRegistryEvent[];
}

export interface PolicySimulationRequest {
  tenant_id?: string;
  actor?: string;
  issue_key?: string;
  transition_id: string;
  project_id?: string;
  workflow_id?: string;
  environment?: string;
  context?: Record<string, unknown>;
  policy_id?: string;
  policy_version?: number;
  policy_json?: Record<string, unknown>;
  status_filter?: string;
}

export interface PolicySimulationResult {
  simulation_id: string;
  trace_id: string;
  enforced: boolean;
  tenant_id: string;
  allow: boolean;
  status: "ALLOWED" | "BLOCKED" | "CONDITIONAL";
  reason_codes: string[];
  policy_hash: string;
  effective_policy_hash: string;
  component_policy_ids: string[];
  component_lineage: Record<string, { policy_id: string; version: number; scope_id: string; policy_hash: string }>;
  resolution_conflicts: Record<string, unknown>[];
  effective_policy_json: Record<string, unknown>;
  matched_rule?: Record<string, unknown> | null;
  warnings: Record<string, unknown>[];
  coverage_gaps: Record<string, unknown>[];
  shadowed_rules: Record<string, unknown>[];
  conflicts: Record<string, unknown>[];
  conflict_summary: Record<string, unknown>;
  actor?: string | null;
  issue_key?: string | null;
  transition_id: string;
  project_id?: string | null;
  workflow_id?: string | null;
  environment?: string | null;
}

export interface HistoricalSimulationRequest {
  tenant_id?: string;
  policy_id?: string;
  policy_version?: number;
  policy_json?: Record<string, unknown>;
  time_window_days?: number;
  transition_id?: string;
  project_key?: string;
  workflow_id?: string;
  environment?: string;
  only_protected?: boolean;
  max_events?: number;
  top_n?: number;
}

export interface HistoricalSimulationResult {
  simulation_id: string;
  trace_id: string;
  enforced: boolean;
  tenant_id: string;
  time_window_days: number;
  window_start: string;
  window_end: string;
  policy_ref: {
    policy_id: string;
    policy_version: number | null;
    policy_hash: string;
    source: string;
  };
  scanned_events: number;
  simulated_events: number;
  skipped_events: number;
  would_block_count: number;
  would_allow_count: number;
  unchanged_count: number;
  override_delta: number;
  delta_breakdown: {
    allow_to_deny: number;
    deny_to_allow: number;
    unchanged: number;
  };
  impacted_workflows: Array<Record<string, unknown>>;
  high_risk_clusters: Array<Record<string, unknown>>;
  deny_reasons_histogram: Array<{ reason: string; count: number }>;
}
