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
