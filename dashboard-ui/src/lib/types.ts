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
  };
  snapshot_binding: {
    policy_hash?: string | null;
    snapshot_hash?: string | null;
    decision_hash?: string | null;
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

export interface SimulationResult {
  tenant_id: string;
  lookback_days: number;
  total_transitions: number;
  allowed: number;
  blocked: number;
  blocked_pct: number;
  override_required: number;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
  };
  ran_at: string | null;
  has_run: boolean;
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
