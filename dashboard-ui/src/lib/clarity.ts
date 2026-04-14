import type { DashboardAlerts, DecisionExplainer, PolicyDiffResponse } from "@/lib/types";

function toStartCase(value: string): string {
  return String(value || "")
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

export function formatPercent(value: number, digits = 1): string {
  return `${(Number(value || 0) * 100).toFixed(digits)}%`;
}

export function humanizeReasonCode(reasonCode?: string | null): string {
  const normalized = String(reasonCode || "").trim().toUpperCase();
  const mapped: Record<string, string> = {
    RISK_TOO_HIGH: "The change exceeded the allowed risk threshold.",
    POLICY_BLOCKED: "A required release rule blocked the change.",
    RULE_BLOCKED: "A required release rule blocked the transition.",
    STRICT_FAIL_CLOSED: "Required governance evidence was missing, so the system failed closed.",
    OVERRIDE_EXPIRED: "A previous override expired, so protection re-locked the change.",
    APPROVALS_REQUIRED: "Required approvals were missing for this release.",
    APPROVAL_REQUIRED: "Required approvals were missing for this release.",
    APPROVALS_EXPIRED: "Previously granted approvals were too old to count for this release.",
    APPROVALS_UNAVAILABLE: "Approval evidence could not be loaded, so the system blocked the release.",
    SOD_VIOLATION: "A separation-of-duties control was violated.",
    SOD_POLICY_AUTHOR_APPROVER_CONFLICT: "The same person authored the active policy and approved this release.",
  };
  if (mapped[normalized]) return mapped[normalized];
  if (!normalized) return "A governance control blocked this release.";
  return `${toStartCase(normalized.toLowerCase())}.`;
}

export function governanceIntegrityLabel(score: number): {
  label: string;
  tone: "strong" | "watch" | "critical";
  explanation: string;
} {
  const numeric = Number(score || 0);
  if (numeric >= 95) {
    return {
      label: "Strong",
      tone: "strong",
      explanation: "Controls are operating as expected, with low evidence of bypass or process drift.",
    };
  }
  if (numeric >= 85) {
    return {
      label: "Watch",
      tone: "watch",
      explanation: "The control posture is still workable, but drift or exceptions are starting to climb.",
    };
  }
  return {
    label: "Needs Attention",
    tone: "critical",
    explanation: "Release controls are weakening and need intervention before confidence erodes further.",
  };
}

export function decisionRiskBand(score: number): {
  label: string;
  tone: "low" | "medium" | "high";
} {
  const numeric = Number(score || 0);
  if (numeric >= 0.85) return { label: "Critical", tone: "high" };
  if (numeric >= 0.6) return { label: "High", tone: "high" };
  if (numeric >= 0.3) return { label: "Moderate", tone: "medium" };
  return { label: "Low", tone: "low" };
}

export function describeDecisionOutcome({
  decision,
  riskScore,
  bindingVerified,
}: {
  decision: DecisionExplainer["decision"];
  riskScore: number;
  bindingVerified?: boolean | null;
}) {
  const risk = decisionRiskBand(riskScore);
  const environment = decision.environment ? ` for ${decision.environment}` : "";
  const workflow = decision.workflow_id ? ` in workflow ${decision.workflow_id}` : "";
  const blockedReason = decision.reason_code ? humanizeReasonCode(decision.reason_code) : decision.blocked_because || humanizeReasonCode(decision.reason_code);
  const normalizedReason = String(decision.reason_code || "").trim().toUpperCase();

  if (decision.outcome === "BLOCK") {
    return {
      headline: `Release protection stopped this change${environment} before deployment.`,
      plainLanguage: blockedReason,
      businessImpact:
        risk.tone === "high"
          ? `A high-risk change was prevented${workflow}, lowering the chance of a failed release or control breach.`
          : `A governance control stopped the change${workflow}, preserving review discipline before release.`,
      auditLens: bindingVerified
        ? "This decision is tied to immutable policy and decision hashes, which supports change-control evidence for SOX, SOC 2, and ISO reviews."
        : "Decision hashes are present, but snapshot verification should be confirmed before using this as audit evidence.",
      nextStep:
        normalizedReason === "RISK_TOO_HIGH"
          ? "Reduce the risk score below the production threshold or add the required approvals before retrying the release."
          : normalizedReason === "APPROVAL_REQUIRED" || normalizedReason === "APPROVALS_REQUIRED"
          ? "Add the required release approval before re-running the production transition."
          : normalizedReason === "RISK_SIGNAL_MISSING"
          ? "Restore the missing risk signal source, then re-run the release with fresh evidence."
          : "Fix the missing control evidence, then re-run the release once the protection requirement is satisfied.",
      riskLabel: risk.label,
    };
  }

  return {
    headline: `Release protection allowed this change${environment} because required controls were satisfied.`,
    plainLanguage: "The release met its configured risk and approval requirements.",
    businessImpact: `This release passed policy checks${workflow} without triggering an exception path.`,
    auditLens: bindingVerified
      ? "The approval can be traced back to a specific policy snapshot and decision hash for audit evidence."
      : "The decision was allowed, but snapshot verification should be confirmed before using it as audit evidence.",
    nextStep: "Proceed with confidence, then monitor for post-release drift or exception activity.",
    riskLabel: risk.label,
  };
}

export function describePolicyOverall(result: PolicyDiffResponse) {
  const highChanges = Number(result.summary.severity_counts.high || 0);
  const mediumChanges = Number(result.summary.severity_counts.medium || 0);

  if (result.overall === "WEAKENING") {
    return {
      headline: "The staged policy would loosen release controls.",
      businessImpact:
        highChanges > 0
          ? `There ${highChanges === 1 ? "is" : "are"} ${highChanges} high-impact change${highChanges === 1 ? "" : "s"} that would reduce release scrutiny.`
          : "The staged policy lowers control strength and should be reviewed carefully before rollout.",
      auditLens:
        "Treat this as a change-control review item. Approval thresholds, rule outcomes, or separation-of-duties requirements are becoming less strict.",
    };
  }
  if (result.overall === "STRENGTHENING") {
    return {
      headline: "The staged policy would tighten release controls.",
      businessImpact:
        mediumChanges > 0 || highChanges > 0
          ? "The staged policy increases release scrutiny and may raise approval or blocking rates."
          : "The staged policy adds protection without major structural change.",
      auditLens:
        "This usually improves change-control posture, but teams should still preview the operational impact before rollout.",
    };
  }
  return {
    headline: "The staged policy changes control logic without materially shifting overall strength.",
    businessImpact: "The change appears mostly neutral, but operators should still review the affected workflows and approval paths.",
    auditLens:
      "Document the intent of the change so buyers and auditors understand whether this is cleanup, coverage expansion, or wording-only drift.",
  };
}

export function describeAlert(alert: DashboardAlerts["alerts"][number]) {
  const code = String(alert.code || "").trim().toUpperCase();
  const details = alert.details || {};

  if (code === "OVERRIDE_SPIKE") {
    return {
      summary: `Policy exceptions jumped to ${formatPercent(Number(details.today || 0))} from a ${formatPercent(
        Number(details.baseline_7d || 0),
      )} 7-day baseline.`,
      auditLens: "A spike in overrides can signal weakening change-control discipline or rushed release behavior.",
    };
  }
  if (code === "DRIFT_SPIKE") {
    return {
      summary: `Change-control drift rose to ${Number(details.today || 0).toFixed(3)} from ${Number(
        details.baseline_7d || 0,
      ).toFixed(3)}.`,
      auditLens: "Drift spikes can mean workflow behavior is changing faster than policy owners expect.",
    };
  }
  if (code === "STRICT_MODE_DROP") {
    return {
      summary: `Strict protection dropped from ${details.yesterday ?? 0} covered scopes to ${details.today ?? 0} today.`,
      auditLens: "Fewer strict-mode scopes means fewer releases are receiving the strongest fail-closed protections.",
    };
  }
  if (code === "NO_DATA") {
    return {
      summary: "No governed release decisions were recorded in the current rollup window.",
      auditLens: "No data can hide release risk, so this should be treated as an observability gap until explained.",
    };
  }
  return {
    summary: alert.title,
    auditLens: "Review this governance signal in the context of release controls, approval coverage, and audit evidence.",
  };
}

export function severityLabel(severity: string): string {
  const normalized = String(severity || "").trim().toLowerCase();
  if (normalized === "high") return "High impact";
  if (normalized === "medium") return "Needs attention";
  if (normalized === "low") return "Monitor";
  return "Unknown";
}

export function severityToneClass(severity: string): string {
  const normalized = String(severity || "").trim().toLowerCase();
  if (normalized === "high") return "border-rose-200 bg-rose-50 text-rose-900";
  if (normalized === "medium") return "border-amber-200 bg-amber-50 text-amber-900";
  return "border-slate-200 bg-slate-50 text-slate-900";
}

export function plainEnglishRiskCardFromAlert(alert: DashboardAlerts["alerts"][number]): {
  title: string;
  severity: string;
  whatHappened: string;
  whyItMatters: string;
  consequence: string;
  whatToDo: string;
} {
  const code = String(alert.code || "").trim().toUpperCase();
  const details = alert.details || {};

  if (code === "OVERRIDE_SPIKE") {
    return {
      title: "Release protections are being bypassed more often",
      severity: String(alert.severity || "medium"),
      whatHappened: `Overrides rose to ${formatPercent(Number(details.today || 0))}, up from a ${formatPercent(
        Number(details.baseline_7d || 0),
      )} recent baseline.`,
      whyItMatters: "More exceptions usually mean riskier releases are moving without normal review discipline.",
      consequence: "Issues like this commonly lead to failed deployments, control drift, or audit findings.",
      whatToDo:
        "Require dual approval for overrides in the affected production workflows and review role assignments for the actors driving the spike.",
    };
  }
  if (code === "DRIFT_SPIKE") {
    return {
      title: "Unexpected workflow behavior is rising",
      severity: String(alert.severity || "medium"),
      whatHappened: `Change-control drift increased to ${Number(details.today || 0).toFixed(3)} from ${Number(
        details.baseline_7d || 0,
      ).toFixed(3)}.`,
      whyItMatters: "When workflow behavior drifts away from the expected path, releases become harder to predict and audit.",
      consequence: "Issues like this commonly lead to unexpected deployment paths and weaker audit evidence.",
      whatToDo:
        "Review recent workflow changes, then re-align the release rule on the affected production path before the next deployment.",
    };
  }
  if (code === "STRICT_MODE_DROP") {
    return {
      title: "Fewer releases are getting the strongest protection",
      severity: String(alert.severity || "medium"),
      whatHappened: `Strict fail-closed coverage dropped from ${details.yesterday ?? 0} protected scope${
        Number(details.yesterday || 0) === 1 ? "" : "s"
      } to ${details.today ?? 0}.`,
      whyItMatters: "This reduces the number of releases that automatically stop when required evidence is missing.",
      consequence: "Issues like this commonly let risky releases continue when approvals or evidence are missing.",
      whatToDo:
        "Re-enable strict fail-closed protection on the critical production workflow before the next deployment window.",
    };
  }
  if (code === "NO_DATA") {
    return {
      title: "Release decisions are not being recorded",
      severity: String(alert.severity || "medium"),
      whatHappened: "No governed release decisions were captured in this reporting window.",
      whyItMatters: "If the system cannot see decisions, it cannot prove release discipline or catch risky behavior.",
      consequence: "Issues like this commonly create blind spots that surface later as failed releases or missing audit proof.",
      whatToDo: "Verify instrumentation, event delivery, and workflow coverage before trusting the dashboard.",
    };
  }

  return {
    title: alert.title,
    severity: String(alert.severity || "medium"),
    whatHappened: alert.title,
    whyItMatters: "This signal indicates release controls may be weakening.",
    consequence: "Issues like this commonly increase the chance of risky releases reaching deployment without enough scrutiny.",
    whatToDo: "Review the related workflow and restore the intended protection path.",
  };
}

export function plainEnglishRiskCardFromRecommendation(recommendation: {
  title: string;
  severity: string;
  playbook?: string | null;
  message?: string | null;
}): {
  title: string;
  severity: string;
  whatHappened: string;
  whyItMatters: string;
  consequence: string;
  whatToDo: string;
} {
  return {
    title: recommendation.title,
    severity: String(recommendation.severity || "medium").toLowerCase(),
    whatHappened: String(recommendation.message || recommendation.title || "A release control needs attention."),
    whyItMatters: "If this stays unresolved, release controls are more likely to be bypassed or weakened.",
    consequence: "Issues like this commonly turn into preventable release failures or control exceptions.",
    whatToDo: String(recommendation.playbook || "Review the affected workflow and apply the recommended control change."),
  };
}

export function plainEnglishRiskCardFromBlocked(item: {
  subject_ref?: string | null;
  workflow?: string | null;
  transition?: string | null;
  reason_code?: string | null;
}): {
  title: string;
  severity: string;
  whatHappened: string;
  whyItMatters: string;
  consequence: string;
  whatToDo: string;
} {
  const subject = String(item.subject_ref || "A release");
  const workflow = item.workflow ? ` in ${item.workflow}` : "";
  const transition = item.transition ? ` during ${item.transition}` : "";
  return {
    title: `${subject} was stopped before release`,
    severity: "medium",
    whatHappened: `${subject} was blocked${workflow}${transition} because ${humanizeReasonCode(item.reason_code).replace(/\.$/, "").toLowerCase()}.`,
    whyItMatters: "A blocked release is evidence that the control layer is catching risk before deployment.",
    consequence: "Issues like this commonly would have become failed deployments or audit exceptions if the block had not fired.",
    whatToDo: "Open the blocked decision explainer, confirm the missing control, and fix it before retrying the release.",
  };
}

export function describePolicyDelta(
  row: Record<string, unknown> & { severity?: string },
  bucket: "thresholds" | "conditions" | "roles" | "sod",
): string {
  if (bucket === "thresholds") {
    const metric = toStartCase(String(row.metric || "threshold"));
    return `${metric} changed from ${String(row.from ?? "-")} to ${String(row.to ?? "-")}.`;
  }
  if (bucket === "conditions") {
    const op = String(row.op || "changed");
    const path = toStartCase(String(row.path || "rule"));
    if (op === "added") return `Added a new control rule at ${path}.`;
    if (op === "removed") return `Removed a control rule at ${path}.`;
    return `Changed enforcement behavior for ${path}.`;
  }
  if (bucket === "roles") {
    if (String(row.role || "") === "min_approvals") {
      const from = Number(row.from || 0);
      const to = Number(row.to || 0);
      return `${to < from ? "Reduced" : "Raised"} minimum required approvals from ${from} to ${to}.`;
    }
    if (String(row.to || "") === "removed") {
      return `Removed the required approver role ${toStartCase(String(row.role || "role"))}.`;
    }
    return `Added the required approver role ${toStartCase(String(row.role || "role"))}.`;
  }
  return `Changed separation-of-duties coverage for ${toStartCase(String(row.scope || "policy"))}.`;
}

export function formatDetailValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.length ? value.map((item) => String(item)).join(", ") : "none";
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  return String(value ?? "—");
}
