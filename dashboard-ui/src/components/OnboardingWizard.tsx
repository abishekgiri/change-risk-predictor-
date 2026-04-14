"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";

import type {
  JiraProject,
  JiraProjectsDiscoveryResponse,
  JiraTransitionsDiscoveryResponse,
  JiraWorkflow,
  JiraWorkflowsDiscoveryResponse,
  OnboardingActivation,
  OnboardingActivationHistory,
  OnboardingActivationRollback,
  OnboardingMode,
  OnboardingStatus,
  SimulationResult,
} from "@/lib/types";

const AUTOSAVE_DEBOUNCE_MS = 800;
const AUTO_SIMULATION_DEBOUNCE_MS = 900;
const SIMULATION_LOOKBACK_DAYS = 7;

type SaveState = "idle" | "saving" | "saved" | "error";

type SetupPayload = {
  tenant_id: string;
  jira_instance_id: string | null;
  project_keys: string[];
  workflow_ids: string[];
  transition_ids: string[];
  mode: OnboardingMode;
  canary_pct: number | null;
};

type Recommendation = {
  ids: string[];
  reason: string | null;
};

const POSITIVE_RELEASE_TERMS = [
  "release",
  "deploy",
  "production",
  "prod",
  "go live",
  "golive",
  "ship",
  "ready for production",
  "ready for release",
  "done",
  "complete",
  "closed",
  "resolved",
];

const NEGATIVE_RELEASE_TERMS = [
  "draft",
  "backlog",
  "selected",
  "analysis",
  "todo",
  "to do",
  "in progress",
  "review",
  "qa",
  "testing",
  "triage",
];

function toggleSelection(items: string[], value: string, checked: boolean): string[] {
  if (checked) {
    if (items.includes(value)) return items;
    return [...items, value];
  }
  return items.filter((item) => item !== value);
}

function buildSetupPayload(args: {
  tenantId: string;
  jiraInstanceId: string;
  projectKeys: string[];
  workflowIds: string[];
  transitionIds: string[];
  persistedMode: OnboardingMode;
  persistedCanaryPct: number | null;
}): SetupPayload {
  const {
    tenantId,
    jiraInstanceId,
    projectKeys,
    workflowIds,
    transitionIds,
    persistedMode,
    persistedCanaryPct,
  } = args;
  return {
    tenant_id: tenantId,
    jira_instance_id: jiraInstanceId.trim() || null,
    project_keys: projectKeys,
    workflow_ids: workflowIds,
    transition_ids: transitionIds,
    mode: persistedMode,
    canary_pct: persistedMode === "canary" ? persistedCanaryPct : null,
  };
}

function buildSetupSignature(payload: SetupPayload): string {
  return JSON.stringify(payload);
}

function normalizeText(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

function scoreByTerms(text: string, positiveTerms: string[], negativeTerms: string[]): number {
  const normalized = normalizeText(text);
  let score = 0;
  for (const term of positiveTerms) {
    if (normalized.includes(term)) score += 2;
  }
  for (const term of negativeTerms) {
    if (normalized.includes(term)) score -= 2;
  }
  return score;
}

function recommendWorkflowIds(workflows: JiraWorkflow[]): Recommendation {
  const ranked = workflows
    .map((workflow) => ({
      workflowId: workflow.workflow_id,
      workflowName: workflow.workflow_name,
      score: scoreByTerms(workflow.workflow_name, POSITIVE_RELEASE_TERMS, NEGATIVE_RELEASE_TERMS),
    }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || left.workflowName.localeCompare(right.workflowName));

  if (!ranked.length) {
    return { ids: [], reason: null };
  }

  const ids = ranked.slice(0, 3).map((item) => item.workflowId);
  return {
    ids,
    reason:
      ids.length === 1
        ? "We preselected the workflow most likely to represent a release path."
        : "We preselected the workflows most likely to represent release paths.",
  };
}

function recommendTransitionIds(
  transitions: JiraTransitionsDiscoveryResponse["items"],
  selectedWorkflowIds: string[],
): Recommendation {
  const selectedWorkflowSet = new Set(selectedWorkflowIds);
  const ranked = transitions
    .map((transition) => {
      const transitionScore = scoreByTerms(
        transition.transition_name,
        POSITIVE_RELEASE_TERMS,
        NEGATIVE_RELEASE_TERMS,
      );
      const workflowScore = scoreByTerms(
        transition.workflow_name,
        POSITIVE_RELEASE_TERMS,
        NEGATIVE_RELEASE_TERMS,
      );
      const selectedWorkflowBoost = selectedWorkflowSet.has(transition.workflow_id) ? 2 : 0;
      return {
        transitionId: transition.transition_id,
        transitionName: transition.transition_name,
        score: transitionScore + workflowScore + selectedWorkflowBoost,
      };
    })
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || left.transitionName.localeCompare(right.transitionName));

  if (!ranked.length) {
    return { ids: [], reason: null };
  }

  const ids = Array.from(new Set(ranked.slice(0, 3).map((item) => item.transitionId)));
  return {
    ids,
    reason:
      ids.length === 1
        ? "We preselected the transition most likely to represent a release or production path."
        : "We preselected the transitions most likely to represent release or production paths.",
  };
}

async function fetchJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, init);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof payload?.error === "string" ? payload.error : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload as T;
}

function formatModeLabel(mode: OnboardingMode, canaryPct: number | null): string {
  if (mode === "canary" && canaryPct) {
    return `Canary (${canaryPct}%)`;
  }
  if (mode === "strict") {
    return "Strict";
  }
  return "Simulation";
}

function modeActionLabel(mode: OnboardingMode, canaryPct: number | null): string {
  if (mode === "canary") {
    return `Protect the next release with ${canaryPct ?? 10}% canary`;
  }
  if (mode === "strict") {
    return "Protect every release with strict mode";
  }
  return "Stay in observe-only mode";
}

function historicalReleasesLabel(totalTransitions: number): string {
  return `${totalTransitions} historical ${totalTransitions === 1 ? "release" : "releases"}`;
}

function confidenceSignal(totalTransitions: number): {
  label: string;
  detail: string;
  panelClassName: string;
} {
  if (totalTransitions >= 75) {
    return {
      label: "High",
      detail: `based on ${historicalReleasesLabel(totalTransitions)}`,
      panelClassName: "border-emerald-200 bg-emerald-50 text-emerald-800",
    };
  }
  if (totalTransitions >= 25) {
    return {
      label: "Medium",
      detail: `based on ${historicalReleasesLabel(totalTransitions)}`,
      panelClassName: "border-sky-200 bg-sky-50 text-sky-800",
    };
  }
  return {
    label: "Growing",
    detail: `based on ${historicalReleasesLabel(totalTransitions)} so far`,
    panelClassName: "border-amber-200 bg-amber-50 text-amber-800",
  };
}

export function OnboardingWizard({ defaultTenantId }: { defaultTenantId: string }) {
  const searchParams = useSearchParams();
  const tenantId = useMemo(() => searchParams.get("tenant_id") || defaultTenantId, [defaultTenantId, searchParams]);

  const [loading, setLoading] = useState(true);
  const [busyWorkflows, setBusyWorkflows] = useState(false);
  const [busyTransitions, setBusyTransitions] = useState(false);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [activationLoading, setActivationLoading] = useState(false);
  const [rollbackLoading, setRollbackLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [activationError, setActivationError] = useState<string | null>(null);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [recommendationHint, setRecommendationHint] = useState<string | null>(null);

  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [activationStatus, setActivationStatus] = useState<OnboardingActivation | null>(null);
  const [activationHistory, setActivationHistory] = useState<OnboardingActivationHistory | null>(null);
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [projects, setProjects] = useState<JiraProject[]>([]);
  const [workflows, setWorkflows] = useState<JiraWorkflow[]>([]);
  const [transitions, setTransitions] = useState<JiraTransitionsDiscoveryResponse["items"]>([]);

  const [jiraInstanceId, setJiraInstanceId] = useState("");
  const [selectedProjects, setSelectedProjects] = useState<string[]>([]);
  const [selectedWorkflows, setSelectedWorkflows] = useState<string[]>([]);
  const [selectedTransitions, setSelectedTransitions] = useState<string[]>([]);
  const [mode, setMode] = useState<OnboardingMode>("simulation");
  const [canaryPct, setCanaryPct] = useState<number>(10);

  const hydratingRef = useRef(true);
  const autoWorkflowRecommendationAppliedRef = useRef(false);
  const autoTransitionRecommendationAppliedRef = useRef(false);
  const lastSnapshotTelemetryKeyRef = useRef("");
  const lastSavedSignatureRef = useRef("");
  const lastSaveAttemptSignatureRef = useRef("");
  const lastSimulatedSignatureRef = useRef("");
  const lastSimulationAttemptSignatureRef = useRef("");

  const persistedMode = (activationStatus?.mode || status?.config.mode || "simulation") as OnboardingMode;
  const persistedCanaryPct =
    persistedMode === "canary" ? (activationStatus?.canary_pct ?? status?.config.canary_pct ?? 10) : null;

  const setupPayload = useMemo(
    () =>
      buildSetupPayload({
        tenantId,
        jiraInstanceId,
        projectKeys: selectedProjects,
        workflowIds: selectedWorkflows,
        transitionIds: selectedTransitions,
        persistedMode,
        persistedCanaryPct,
      }),
    [jiraInstanceId, persistedCanaryPct, persistedMode, selectedProjects, selectedTransitions, selectedWorkflows, tenantId],
  );
  const setupSignature = useMemo(() => buildSetupSignature(setupPayload), [setupPayload]);

  const selectedProjectsKey = useMemo(() => selectedProjects.join("|"), [selectedProjects]);
  const selectedWorkflowsKey = useMemo(() => selectedWorkflows.join("|"), [selectedWorkflows]);
  const hasProtectedTransitions = selectedTransitions.length > 0;
  const jiraConnected = jiraInstanceId.trim().length > 0;
  const previewReady = Boolean(simulationResult?.has_run);
  const activationMatchesSelection =
    persistedMode === mode && (mode !== "canary" || (persistedCanaryPct ?? null) === (canaryPct ?? null));
  const discoveredProjectsCount = projects.length;
  const discoveredWorkflowsCount = workflows.length;
  const discoveredTransitionsCount = transitions.length;
  const hasSavedWorkflowScope = Boolean((status?.config.workflow_ids || []).length);
  const hasSavedTransitionScope = Boolean((status?.config.transition_ids || []).length);

  const loadProjects = async () => {
    const data = await fetchJson<JiraProjectsDiscoveryResponse>(
      `/api/dashboard/integrations/jira/projects?tenant_id=${encodeURIComponent(tenantId)}`,
    );
    setProjects(data.items || []);
  };

  const loadWorkflows = async (projectKeys: string[]) => {
    if (!projectKeys.length) {
      setWorkflows([]);
      setSelectedWorkflows([]);
      setTransitions([]);
      setSelectedTransitions([]);
      return;
    }

    setBusyWorkflows(true);
    try {
      const workflowMap = new Map<string, JiraWorkflow>();
      const responses = await Promise.all(
        projectKeys.map((projectKey) =>
          fetchJson<JiraWorkflowsDiscoveryResponse>(
            `/api/dashboard/integrations/jira/workflows?tenant_id=${encodeURIComponent(tenantId)}&project_key=${encodeURIComponent(projectKey)}`,
          ),
        ),
      );
      for (const data of responses) {
        for (const workflow of data.items || []) {
          workflowMap.set(workflow.workflow_id, workflow);
        }
      }
      setWorkflows(Array.from(workflowMap.values()));
      setSelectedWorkflows((current) => current.filter((workflowId) => workflowMap.has(workflowId)));
    } finally {
      setBusyWorkflows(false);
    }
  };

  const loadTransitions = async (workflowIds: string[]) => {
    if (!workflowIds.length) {
      setTransitions([]);
      setSelectedTransitions([]);
      return;
    }

    setBusyTransitions(true);
    try {
      const transitionMap = new Map<string, JiraTransitionsDiscoveryResponse["items"][number]>();
      for (const workflowId of workflowIds) {
        const data = await fetchJson<JiraTransitionsDiscoveryResponse>(
          `/api/dashboard/integrations/jira/workflows/${encodeURIComponent(workflowId)}/transitions?tenant_id=${encodeURIComponent(tenantId)}`,
        );
        for (const transition of data.items || []) {
          const key = `${transition.workflow_id}::${transition.transition_id}`;
          transitionMap.set(key, transition);
        }
      }
      const nextTransitions = Array.from(transitionMap.values());
      setTransitions(nextTransitions);
      const validIds = new Set(nextTransitions.map((item) => item.transition_id));
      setSelectedTransitions((current) => current.filter((transitionId) => validIds.has(transitionId)));
    } finally {
      setBusyTransitions(false);
    }
  };

  const loadActivationHistory = async () => {
    const payload = await fetchJson<OnboardingActivationHistory>(
      `/api/dashboard/onboarding/activation/history?tenant_id=${encodeURIComponent(tenantId)}&limit=10`,
    );
    setActivationHistory(payload);
  };

  const persistSetup = async (payload: SetupPayload, signature: string): Promise<boolean> => {
    lastSaveAttemptSignatureRef.current = signature;
    setSaveState("saving");
    setError(null);

    try {
      const nextStatus = await fetchJson<OnboardingStatus>("/api/dashboard/onboarding/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setStatus(nextStatus);
      lastSavedSignatureRef.current = signature;
      setSaveState("saved");
      return true;
    } catch (saveError) {
      setSaveState("error");
      setError(saveError instanceof Error ? saveError.message : "Failed to save onboarding setup");
      return false;
    }
  };

  const ensureLatestSetupSaved = async (): Promise<boolean> => {
    if (setupSignature === lastSavedSignatureRef.current) {
      return true;
    }
    return persistSetup(setupPayload, setupSignature);
  };

  const runSimulation = async ({
    announceSuccess,
    signature,
    ensureSaved,
  }: {
    announceSuccess: boolean;
    signature: string;
    ensureSaved: boolean;
  }): Promise<boolean> => {
    if (!hasProtectedTransitions) {
      setSimulationError("Select at least one protected transition to preview impact.");
      return false;
    }

    if (ensureSaved) {
      const saved = await ensureLatestSetupSaved();
      if (!saved) {
        return false;
      }
    }

    lastSimulationAttemptSignatureRef.current = signature;
    setSimulationLoading(true);
    setSimulationError(null);
    if (announceSuccess) {
      setSuccess(null);
    }

    try {
      const payload = await fetchJson<SimulationResult>("/api/dashboard/simulation/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          lookback_days: SIMULATION_LOOKBACK_DAYS,
        }),
      });
      setSimulationResult(payload);
      lastSimulatedSignatureRef.current = signature;
      if (announceSuccess) {
        setSuccess("Historical preview refreshed.");
      }
      return true;
    } catch (runError) {
      setSimulationError(runError instanceof Error ? runError.message : "Failed to run historical simulation");
      return false;
    } finally {
      setSimulationLoading(false);
    }
  };

  const loadStatusAndDiscovery = async () => {
    hydratingRef.current = true;
    setLoading(true);
    setError(null);
    setSuccess(null);
    setSaveState("idle");

    try {
      const [
        statusData,
        projectsData,
        simulationData,
        activationData,
        activationHistoryData,
      ] = await Promise.all([
        fetchJson<OnboardingStatus>(`/api/dashboard/onboarding/status?tenant_id=${encodeURIComponent(tenantId)}`),
        fetchJson<JiraProjectsDiscoveryResponse>(
          `/api/dashboard/integrations/jira/projects?tenant_id=${encodeURIComponent(tenantId)}`,
        ),
        fetchJson<SimulationResult>(
          `/api/dashboard/simulation/last?tenant_id=${encodeURIComponent(tenantId)}&lookback_days=${SIMULATION_LOOKBACK_DAYS}`,
        ),
        fetchJson<OnboardingActivation>(
          `/api/dashboard/onboarding/activation?tenant_id=${encodeURIComponent(tenantId)}`,
        ),
        fetchJson<OnboardingActivationHistory>(
          `/api/dashboard/onboarding/activation/history?tenant_id=${encodeURIComponent(tenantId)}&limit=10`,
        ),
      ]);

      setStatus(statusData);
      setActivationStatus(activationData);
      setActivationHistory(activationHistoryData);
      setSimulationResult(simulationData);
      setProjects(projectsData.items || []);
      setRecommendationHint(null);

      setJiraInstanceId(statusData.config.jira_instance_id || "");
      setSelectedProjects(statusData.config.project_keys || []);
      setSelectedWorkflows(statusData.config.workflow_ids || []);
      setSelectedTransitions(statusData.config.transition_ids || []);
      setMode((activationData.mode || statusData.config.mode || "simulation") as OnboardingMode);
      setCanaryPct(activationData.canary_pct || statusData.config.canary_pct || 10);

      const loadedSetupPayload = buildSetupPayload({
        tenantId,
        jiraInstanceId: statusData.config.jira_instance_id || "",
        projectKeys: statusData.config.project_keys || [],
        workflowIds: statusData.config.workflow_ids || [],
        transitionIds: statusData.config.transition_ids || [],
        persistedMode: (activationData.mode || statusData.config.mode || "simulation") as OnboardingMode,
        persistedCanaryPct: activationData.canary_pct ?? statusData.config.canary_pct ?? null,
      });
      const loadedSetupSignature = buildSetupSignature(loadedSetupPayload);
      lastSavedSignatureRef.current = loadedSetupSignature;
      lastSaveAttemptSignatureRef.current = loadedSetupSignature;
      if (simulationData.has_run) {
        lastSimulatedSignatureRef.current = loadedSetupSignature;
        lastSimulationAttemptSignatureRef.current = loadedSetupSignature;
      } else {
        lastSimulatedSignatureRef.current = "";
        lastSimulationAttemptSignatureRef.current = "";
      }
      autoWorkflowRecommendationAppliedRef.current = Boolean((statusData.config.workflow_ids || []).length);
      autoTransitionRecommendationAppliedRef.current = Boolean((statusData.config.transition_ids || []).length);
    } catch (loadError) {
      const message = loadError instanceof Error ? loadError.message : "Failed to load onboarding state";
      if (message.toLowerCase().includes("cannot access another tenant")) {
        setError(
          `Tenant access mismatch for "${tenantId}". Open this page with ?tenant_id matching your backend tenant configuration.`,
        );
      } else {
        setError(message);
      }
    } finally {
      hydratingRef.current = false;
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadStatusAndDiscovery();
  }, [tenantId]);

  useEffect(() => {
    if (loading || hydratingRef.current) {
      return;
    }
    void loadWorkflows(selectedProjects);
  }, [loading, selectedProjectsKey, tenantId]);

  useEffect(() => {
    if (loading || hydratingRef.current) {
      return;
    }
    void loadTransitions(selectedWorkflows);
  }, [loading, selectedWorkflowsKey, tenantId]);

  useEffect(() => {
    if (loading || hydratingRef.current || autoWorkflowRecommendationAppliedRef.current) {
      return;
    }
    if (hasSavedWorkflowScope || selectedWorkflows.length || !workflows.length) {
      return;
    }
    const recommendation = recommendWorkflowIds(workflows);
    autoWorkflowRecommendationAppliedRef.current = true;
    if (!recommendation.ids.length) {
      return;
    }
    setSelectedWorkflows(recommendation.ids);
    setRecommendationHint(recommendation.reason);
  }, [hasSavedWorkflowScope, loading, selectedWorkflows.length, workflows]);

  useEffect(() => {
    if (loading || hydratingRef.current || autoTransitionRecommendationAppliedRef.current) {
      return;
    }
    if (hasSavedTransitionScope || selectedTransitions.length || !transitions.length) {
      return;
    }
    const recommendation = recommendTransitionIds(transitions, selectedWorkflows);
    autoTransitionRecommendationAppliedRef.current = true;
    if (!recommendation.ids.length) {
      return;
    }
    setSelectedTransitions(recommendation.ids);
    setRecommendationHint(recommendation.reason);
  }, [hasSavedTransitionScope, loading, selectedTransitions.length, selectedWorkflows, transitions]);

  useEffect(() => {
    if (loading || hydratingRef.current) {
      return;
    }
    if (setupSignature === lastSavedSignatureRef.current || setupSignature === lastSaveAttemptSignatureRef.current) {
      return;
    }

    const handle = window.setTimeout(() => {
      void persistSetup(setupPayload, setupSignature);
    }, AUTOSAVE_DEBOUNCE_MS);

    return () => window.clearTimeout(handle);
  }, [loading, setupPayload, setupSignature]);

  useEffect(() => {
    if (loading || hydratingRef.current || !hasProtectedTransitions) {
      return;
    }
    if (setupSignature !== lastSavedSignatureRef.current) {
      return;
    }
    if (
      setupSignature === lastSimulatedSignatureRef.current ||
      setupSignature === lastSimulationAttemptSignatureRef.current
    ) {
      return;
    }

    const handle = window.setTimeout(() => {
      void runSimulation({
        announceSuccess: false,
        signature: setupSignature,
        ensureSaved: false,
      });
    }, AUTO_SIMULATION_DEBOUNCE_MS);

    return () => window.clearTimeout(handle);
  }, [hasProtectedTransitions, loading, setupSignature]);

  useEffect(() => {
    if (!simulationResult?.has_run) {
      return;
    }
    const snapshotKey = [
      tenantId,
      simulationResult.ran_at || "unknown",
      simulationResult.total_transitions,
      simulationResult.starter_pack,
    ].join("|");
    if (snapshotKey === lastSnapshotTelemetryKeyRef.current) {
      return;
    }
    lastSnapshotTelemetryKeyRef.current = snapshotKey;

    void fetch("/api/dashboard/onboarding/telemetry", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenant_id: tenantId,
        event_name: "snapshot_shown",
        metadata: {
          snapshot_ran_at: simulationResult.ran_at,
          total_transitions: simulationResult.total_transitions,
          starter_pack: simulationResult.starter_pack,
        },
      }),
    }).catch(() => undefined);
  }, [
    simulationResult?.has_run,
    simulationResult?.ran_at,
    simulationResult?.starter_pack,
    simulationResult?.total_transitions,
    tenantId,
  ]);

  const applyActivation = async (targetMode?: OnboardingMode, targetCanaryPct?: number) => {
    setActivationError(null);
    setRollbackError(null);
    setSuccess(null);

    const modeToApply = targetMode ?? mode;
    const canaryPctToApply = modeToApply === "canary" ? targetCanaryPct ?? canaryPct : null;

    if (!hasProtectedTransitions) {
      setActivationError("Select at least one protected transition before enabling canary or strict mode.");
      return;
    }

    if (
      modeToApply === "canary" &&
      (!Number.isFinite(canaryPctToApply) || (canaryPctToApply ?? 0) < 1 || (canaryPctToApply ?? 0) > 100)
    ) {
      setActivationError("Canary percentage must be between 1 and 100.");
      return;
    }

    const saved = await ensureLatestSetupSaved();
    if (!saved) {
      setActivationError("Finish saving onboarding changes before applying a protection level.");
      return;
    }

    if (typeof window !== "undefined" && modeToApply !== "simulation") {
      const confirmed = window.confirm(
        modeToApply === "strict"
          ? "Strict mode enforces 100% of protected transitions. Continue?"
          : `Canary mode enforces ${canaryPctToApply}% of protected transitions. Continue?`,
      );
      if (!confirmed) return;
    }

    setActivationLoading(true);
    try {
      const payload = await fetchJson<OnboardingActivation>("/api/dashboard/onboarding/activation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          mode: modeToApply,
          canary_pct: canaryPctToApply,
        }),
      });
      setActivationStatus(payload);
      setMode(payload.mode);
      setCanaryPct(payload.canary_pct || 10);
      setStatus((current) => {
        if (!current) return current;
        return {
          ...current,
          onboarding_completed: payload.applied,
          config: {
            ...current.config,
            mode: payload.mode,
            canary_pct: payload.canary_pct,
            updated_at: payload.updated_at || current.config.updated_at,
          },
        };
      });
      const nextSetupSignature = buildSetupSignature(
        buildSetupPayload({
          tenantId,
          jiraInstanceId,
          projectKeys: selectedProjects,
          workflowIds: selectedWorkflows,
          transitionIds: selectedTransitions,
          persistedMode: payload.mode,
          persistedCanaryPct: payload.canary_pct,
        }),
      );
      lastSavedSignatureRef.current = nextSetupSignature;
      lastSaveAttemptSignatureRef.current = nextSetupSignature;
      await loadActivationHistory();
      setSuccess("Protection level applied.");
    } catch (applyError) {
      setActivationError(applyError instanceof Error ? applyError.message : "Failed to apply activation mode");
    } finally {
      setActivationLoading(false);
    }
  };

  const rollbackActivation = async () => {
    setActivationError(null);
    setRollbackError(null);
    setSuccess(null);

    if (typeof window !== "undefined") {
      const confirmed = window.confirm(
        "Rollback will revert the activation mode to the previous state. Continue?",
      );
      if (!confirmed) return;
    }

    setRollbackLoading(true);
    try {
      const payload = await fetchJson<OnboardingActivationRollback>("/api/dashboard/onboarding/activation/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: tenantId }),
      });
      const nextActivation = payload.activation;
      setActivationStatus(nextActivation);
      setMode(nextActivation.mode);
      setCanaryPct(nextActivation.canary_pct || 10);
      setStatus((current) => {
        if (!current) return current;
        return {
          ...current,
          onboarding_completed: nextActivation.applied,
          config: {
            ...current.config,
            mode: nextActivation.mode,
            canary_pct: nextActivation.canary_pct,
            updated_at: nextActivation.updated_at || current.config.updated_at,
          },
        };
      });
      const nextSetupSignature = buildSetupSignature(
        buildSetupPayload({
          tenantId,
          jiraInstanceId,
          projectKeys: selectedProjects,
          workflowIds: selectedWorkflows,
          transitionIds: selectedTransitions,
          persistedMode: nextActivation.mode,
          persistedCanaryPct: nextActivation.canary_pct,
        }),
      );
      lastSavedSignatureRef.current = nextSetupSignature;
      lastSaveAttemptSignatureRef.current = nextSetupSignature;
      await loadActivationHistory();
      setSuccess("Activation rolled back to the previous state.");
    } catch (rollbackApplyError) {
      setRollbackError(
        rollbackApplyError instanceof Error ? rollbackApplyError.message : "Failed to rollback activation mode",
      );
    } finally {
      setRollbackLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold text-slate-900">Launch Release Governance</h1>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 text-sm text-slate-600 shadow-sm">
          Loading onboarding configuration...
        </div>
      </div>
    );
  }

  const setupChecks = [
    { label: "Jira workspace connected", ready: jiraConnected },
    { label: "Protected transitions selected", ready: hasProtectedTransitions },
    { label: "Historical preview ready", ready: previewReady },
  ];
  const snapshotConfidence = confidenceSignal(simulationResult?.total_transitions ?? 0);

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">Launch Release Governance</h1>
            <p className="mt-1 text-sm text-slate-600">Tenant: {tenantId}</p>
            <p className="mt-3 max-w-3xl text-sm text-slate-600">
              This flow is tuned for fast adoption: connect Jira, choose the transitions you want protected, review the
              preview, then move into canary when you are comfortable.
            </p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <p>
              Live mode: <span className="font-medium text-slate-900">{formatModeLabel(persistedMode, persistedCanaryPct)}</span>
            </p>
            <p className="mt-1">
              Autosave:{" "}
              <span className="font-medium text-slate-900">
                {saveState === "saving"
                  ? "Saving..."
                  : saveState === "saved"
                    ? "All changes saved"
                    : saveState === "error"
                      ? "Attention needed"
                      : "On"}
              </span>
            </p>
          </div>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-3">
          {setupChecks.map((item) => (
            <div
              key={item.label}
              className={`rounded-xl border px-4 py-3 text-sm ${
                item.ready ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-amber-200 bg-amber-50 text-amber-800"
              }`}
            >
              <p className="font-medium">{item.label}</p>
              <p className="mt-1 text-xs">{item.ready ? "Ready" : "Still needed"}</p>
            </div>
          ))}
        </div>

        {error ? <p className="mt-4 text-sm text-rose-700">{error}</p> : null}
        {success ? <p className="mt-4 text-sm text-emerald-700">{success}</p> : null}
      </div>

      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Step 1</p>
            <h2 className="mt-1 text-xl font-semibold text-slate-900">Connect Jira</h2>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">
              Add the Jira workspace you want this tenant to watch. ReleaseGate only reads workflow metadata here, then
              autosaves the connection so the rest of the flow can stay lightweight.
            </p>
          </div>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
            {jiraConnected ? "Connected" : "Required"}
          </div>
        </div>

        <label className="mt-4 block text-sm font-medium text-slate-700">
          Jira instance
          <input
            type="text"
            value={jiraInstanceId}
            onChange={(event) => setJiraInstanceId(event.target.value)}
            placeholder="https://your-domain.atlassian.net"
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
          />
        </label>
        {jiraConnected ? (
          <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
            We found {discoveredProjectsCount} projects and {discoveredWorkflowsCount} workflows so far.
          </div>
        ) : null}
        <p className="mt-3 text-xs text-slate-500">
          Safe start: nothing blocks your Jira users during onboarding. You stay in observe-only mode until you
          explicitly turn on canary or strict protection.
        </p>
      </section>

      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Step 2</p>
            <h2 className="mt-1 text-xl font-semibold text-slate-900">Choose What To Protect</h2>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">
              Pick the Jira projects, workflows, and transitions that matter. Workflows and transitions refresh
              automatically as you narrow the scope.
            </p>
          </div>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
            {discoveredTransitionsCount} transitions discovered
          </div>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">Projects</h3>
              <span className="text-xs text-slate-500">{selectedProjects.length} selected</span>
            </div>
            <div className="grid gap-2">
              {projects.map((project) => (
                <label key={project.project_key} className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={selectedProjects.includes(project.project_key)}
                    onChange={(event) => {
                      const next = toggleSelection(selectedProjects, project.project_key, event.target.checked);
                      setSelectedProjects(next);
                    }}
                  />
                  <span className="text-sm text-slate-800">
                    {project.project_key}
                    {project.name && project.name !== project.project_key ? ` - ${project.name}` : ""}
                  </span>
                </label>
              ))}
              {!projects.length ? <p className="text-sm text-slate-500">No projects discovered yet.</p> : null}
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">Workflows</h3>
              <span className="text-xs text-slate-500">
                {busyWorkflows ? "Loading..." : `${selectedWorkflows.length} selected`}
              </span>
            </div>
            <div className="grid gap-2">
              {workflows.map((workflow) => (
                <label key={workflow.workflow_id} className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={selectedWorkflows.includes(workflow.workflow_id)}
                    onChange={(event) => {
                      const next = toggleSelection(selectedWorkflows, workflow.workflow_id, event.target.checked);
                      setSelectedWorkflows(next);
                    }}
                  />
                  <span className="text-sm text-slate-800">{workflow.workflow_name}</span>
                </label>
              ))}
              {!workflows.length ? (
                <p className="text-sm text-slate-500">
                  {selectedProjects.length ? "No workflows discovered for the selected projects yet." : "Choose a project first."}
                </p>
              ) : null}
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">Protected transitions</h3>
              <span className="text-xs text-slate-500">
                {busyTransitions ? "Loading..." : `${selectedTransitions.length} selected`}
              </span>
            </div>
            <div className="grid gap-2">
              {transitions.map((transition) => (
                <label
                  key={`${transition.workflow_id}-${transition.transition_id}`}
                  className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2"
                >
                  <input
                    type="checkbox"
                    checked={selectedTransitions.includes(transition.transition_id)}
                    onChange={(event) => {
                      const next = toggleSelection(selectedTransitions, transition.transition_id, event.target.checked);
                      setSelectedTransitions(next);
                    }}
                  />
                  <span className="text-sm text-slate-800">
                    {transition.transition_name} ({transition.transition_id})
                  </span>
                </label>
              ))}
              {!transitions.length ? (
                <p className="text-sm text-slate-500">
                  {selectedWorkflows.length
                    ? "We couldn't detect release transitions for this workflow yet. Select one manually if you know the correct transition."
                    : "Choose a workflow first."}
                </p>
              ) : null}
            </div>
          </div>
        </div>
        {recommendationHint ? (
          <div className="mt-4 rounded-xl border border-sky-200 bg-sky-50 p-3 text-sm text-sky-800">
            {recommendationHint}
          </div>
        ) : null}
      </section>

      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Step 3</p>
            <h2 className="mt-1 text-xl font-semibold text-slate-900">Preview And Go Live</h2>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">
              Stay in simulation while you review the preview, then move into canary when you are comfortable. Rollback
              stays visible the whole time.
            </p>
          </div>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
            Target: {formatModeLabel(mode, canaryPct)}
          </div>
        </div>

        <div className="mt-5 grid gap-5 lg:grid-cols-[1.1fr,0.9fr]">
          <div className="space-y-5">
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Launch mode</h3>
                  <p className="mt-1 text-sm text-slate-600">
                    Mode selection stays local until you explicitly apply it. Coverage changes still autosave in the background.
                  </p>
                </div>
                <div className="rounded-full bg-white px-3 py-1 text-xs font-medium text-slate-700">
                  Current: {formatModeLabel(persistedMode, persistedCanaryPct)}
                </div>
              </div>

              <div className="mt-4 grid gap-2">
                <label className="flex items-center gap-2 text-sm text-slate-800">
                  <input type="radio" name="mode" checked={mode === "simulation"} onChange={() => setMode("simulation")} />
                  Simulation
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-800">
                  <input type="radio" name="mode" checked={mode === "canary"} onChange={() => setMode("canary")} />
                  Canary
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-800">
                  <input type="radio" name="mode" checked={mode === "strict"} onChange={() => setMode("strict")} />
                  Strict
                </label>
              </div>

              {mode === "canary" ? (
                <label className="mt-4 block text-sm font-medium text-slate-700">
                  Canary percentage
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={canaryPct}
                    onChange={(event) => setCanaryPct(Number(event.target.value || 10))}
                    className="mt-1 w-36 rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                  />
                </label>
              ) : null}
            </div>

            <div className="rounded-2xl border border-slate-200 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Historical preview</h3>
                  <p className="mt-1 text-sm text-slate-600">
                    A {SIMULATION_LOOKBACK_DAYS}-day preview runs automatically after your protected transitions are saved.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() =>
                    void runSimulation({
                      announceSuccess: true,
                      signature: setupSignature,
                      ensureSaved: true,
                    })
                  }
                  disabled={simulationLoading || !hasProtectedTransitions}
                  className="rounded-lg border border-slate-300 bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
                >
                  {simulationLoading ? "Running..." : "Run preview again"}
                </button>
              </div>
              {simulationError ? <p className="mt-3 text-sm text-rose-700">{simulationError}</p> : null}

              {simulationResult?.has_run ? (
                <div className="mt-4 space-y-3">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Your Release Risk Snapshot</p>
                        <h4 className="mt-1 text-lg font-semibold text-slate-900">Protect your next release with confidence</h4>
                        <p className="mt-2 max-w-2xl text-sm text-slate-600">
                          {simulationResult.summary || `We analyzed your last ${simulationResult.total_transitions} releases.`}
                        </p>
                        <p className="mt-2 text-xs text-slate-500">
                          Starter simulation pack: <span className="font-medium capitalize text-slate-700">{simulationResult.starter_pack}</span>
                        </p>
                        <div className={`mt-3 inline-flex rounded-full border px-3 py-1 text-sm ${snapshotConfidence.panelClassName}`}>
                          <span className="font-semibold">Confidence: {snapshotConfidence.label}</span>
                          <span className="ml-1">{snapshotConfidence.detail}</span>
                        </div>
                        <p className="mt-3 max-w-2xl text-xs text-slate-500">
                          Prevented issues like these are a common source of failed releases and audit findings.
                        </p>
                      </div>
                      {persistedMode === "simulation" ? (
                        <div className="max-w-xs text-right">
                          <button
                            type="button"
                            onClick={() => {
                              setMode("canary");
                              setCanaryPct(10);
                              void applyActivation("canary", 10);
                            }}
                            disabled={activationLoading || !hasProtectedTransitions}
                            className="rounded-lg border border-slate-300 bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
                          >
                            {activationLoading ? "Starting..." : "Start Canary Protection For The Next Release"}
                          </button>
                          <p className="mt-2 text-xs text-slate-500">
                            We will monitor your next release and flag risks before deployment.
                          </p>
                          <p className="mt-1 text-xs text-slate-500">You can disable protection anytime.</p>
                        </div>
                      ) : null}
                    </div>
                    <div className="mt-4 grid gap-3 md:grid-cols-3">
                      <div className="rounded-xl border border-rose-200 bg-white p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-500">High-risk releases</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-900">
                          {simulationResult.insights.high_risk_releases}
                        </p>
                        <p className="text-sm text-slate-600">Releases the starter pack would treat as highest concern</p>
                      </div>
                      <div className="rounded-xl border border-amber-200 bg-white p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Missing approvals</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-900">
                          {simulationResult.insights.missing_approvals}
                        </p>
                        <p className="text-sm text-slate-600">Historical transitions with approval gaps</p>
                      </div>
                      <div className="rounded-xl border border-sky-200 bg-white p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Unmapped transitions</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-900">
                          {simulationResult.insights.unmapped_transitions}
                        </p>
                        <p className="text-sm text-slate-600">Transitions with no active protection mapping yet</p>
                      </div>
                    </div>
                    <div className="mt-3 rounded-xl border border-slate-200 bg-white p-3 text-sm text-slate-700">
                      <p className="font-medium text-slate-900">Real example</p>
                      <p className="mt-1">
                        If a production-bound transition looks high risk and is missing required approvals, ReleaseGate
                        will surface it here in observe-only mode first, then catch the next one automatically once you
                        start canary protection.
                      </p>
                    </div>
                  </div>
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Would block</p>
                      <p className="mt-1 text-xl font-semibold text-slate-900">{simulationResult.blocked_pct.toFixed(2)}%</p>
                      <p className="text-sm text-slate-600">
                        {simulationResult.blocked} / {simulationResult.total_transitions}
                      </p>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Projected overrides</p>
                      <p className="mt-1 text-xl font-semibold text-slate-900">{simulationResult.override_required}</p>
                      <p className="text-sm text-slate-600">Transitions needing manual override</p>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Transitions analyzed</p>
                      <p className="mt-1 text-xl font-semibold text-slate-900">{simulationResult.total_transitions}</p>
                      <p className="text-sm text-slate-600">Historical decision data</p>
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                    <p className="font-medium text-slate-900">Risk distribution</p>
                    <div className="mt-2 grid gap-2 md:grid-cols-3">
                      <p>Low: {simulationResult.risk_distribution.low}</p>
                      <p>Medium: {simulationResult.risk_distribution.medium}</p>
                      <p>High: {simulationResult.risk_distribution.high}</p>
                    </div>
                  </div>
                  {simulationResult.ran_at ? (
                    <p className="text-xs text-slate-500">Last preview: {simulationResult.ran_at}</p>
                  ) : null}
                </div>
              ) : (
                <p className="mt-4 text-sm text-slate-500">
                  {hasProtectedTransitions
                    ? "Preview will appear automatically once autosave finishes."
                    : "Choose at least one protected transition to generate the preview."}
                </p>
              )}
            </div>
          </div>

          <div className="space-y-5">
            <div className="rounded-2xl border border-slate-200 p-4">
              <h3 className="text-sm font-semibold text-slate-900">Apply protection level</h3>
              <p className="mt-1 text-sm text-slate-600">
                Move from dry run to controlled enforcement when you are ready. Canary is the best first step for most teams.
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Trust note: canary starts as a controlled rollout, and you can disable protection at any time with the
                rollback button below.
              </p>

              <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                <p>
                  Current mode: <span className="font-medium text-slate-900">{formatModeLabel(persistedMode, persistedCanaryPct)}</span>
                </p>
                {activationStatus?.updated_at ? (
                  <p className="mt-1 text-xs text-slate-500">Last updated: {activationStatus.updated_at}</p>
                ) : null}
              </div>

              {!hasProtectedTransitions ? (
                <div className="mt-4 rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
                  Select at least one protected transition before enabling canary or strict mode.
                </div>
              ) : null}

              <div className="mt-4 flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => void applyActivation()}
                  disabled={activationLoading || activationMatchesSelection || !hasProtectedTransitions}
                  className="rounded-lg border border-slate-300 bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
                >
                  {activationLoading ? "Applying..." : modeActionLabel(mode, canaryPct)}
                </button>
                <button
                  type="button"
                  onClick={() => void rollbackActivation()}
                  disabled={rollbackLoading}
                  className="rounded-lg border border-rose-600 bg-rose-600 px-4 py-2 text-sm font-medium text-white hover:bg-rose-700 disabled:opacity-60"
                >
                  {rollbackLoading ? "Rolling back..." : "Rollback"}
                </button>
              </div>
              {mode === "canary" ? (
                <div className="mt-3 text-xs text-slate-500">
                  <p>We will monitor your next release and flag risks before deployment.</p>
                  <p className="mt-1">You can disable protection anytime.</p>
                </div>
              ) : null}

              {activationError ? <p className="mt-3 text-sm text-rose-700">{activationError}</p> : null}
              {rollbackError ? <p className="mt-3 text-sm text-rose-700">{rollbackError}</p> : null}
            </div>

            <div className="rounded-2xl border border-slate-200 p-4">
              <h3 className="text-sm font-semibold text-slate-900">Activation history</h3>
              <p className="mt-1 text-sm text-slate-600">Rollback stays available because the previous launch states are kept here.</p>
              {activationHistory?.items.length ? (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="text-left text-slate-500">
                        <th className="py-1 pr-4 font-medium">Recorded at</th>
                        <th className="py-1 pr-4 font-medium">Mode</th>
                        <th className="py-1 pr-4 font-medium">Canary %</th>
                        <th className="py-1 pr-0 font-medium">Previous updated at</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activationHistory.items.map((entry) => (
                        <tr key={entry.history_id} className="border-t border-slate-100 text-slate-700">
                          <td className="py-1 pr-4">{entry.recorded_at || "—"}</td>
                          <td className="py-1 pr-4">{entry.mode}</td>
                          <td className="py-1 pr-4">{entry.canary_pct ?? "—"}</td>
                          <td className="py-1 pr-0">{entry.updated_at || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="mt-3 text-sm text-slate-500">No activation history recorded yet.</p>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
