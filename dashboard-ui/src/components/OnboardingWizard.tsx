"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";

import type {
  JiraProject,
  JiraProjectsDiscoveryResponse,
  JiraTransitionsDiscoveryResponse,
  JiraWorkflow,
  JiraWorkflowsDiscoveryResponse,
  OnboardingMode,
  OnboardingStatus,
} from "@/lib/types";

function toggleSelection(items: string[], value: string, checked: boolean): string[] {
  if (checked) {
    if (items.includes(value)) return items;
    return [...items, value];
  }
  return items.filter((item) => item !== value);
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

export function OnboardingWizard() {
  const searchParams = useSearchParams();
  const tenantId = useMemo(() => searchParams.get("tenant_id") || "default", [searchParams]);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [busyWorkflows, setBusyWorkflows] = useState(false);
  const [busyTransitions, setBusyTransitions] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [projects, setProjects] = useState<JiraProject[]>([]);
  const [workflows, setWorkflows] = useState<JiraWorkflow[]>([]);
  const [transitions, setTransitions] = useState<JiraTransitionsDiscoveryResponse["items"]>([]);

  const [jiraInstanceId, setJiraInstanceId] = useState("");
  const [selectedProjects, setSelectedProjects] = useState<string[]>([]);
  const [selectedWorkflows, setSelectedWorkflows] = useState<string[]>([]);
  const [selectedTransitions, setSelectedTransitions] = useState<string[]>([]);
  const [mode, setMode] = useState<OnboardingMode>("simulation");
  const [canaryPct, setCanaryPct] = useState<number>(10);

  const onboardingCompleted = Boolean(status?.onboarding_completed);

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
      setSelectedWorkflows((current) =>
        current.filter((workflowId) => workflowMap.has(workflowId)),
      );
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

  const loadStatusAndDiscovery = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const statusData = await fetchJson<OnboardingStatus>(
        `/api/dashboard/onboarding/status?tenant_id=${encodeURIComponent(tenantId)}`,
      );
      setStatus(statusData);
      setJiraInstanceId(statusData.config.jira_instance_id || "");
      setSelectedProjects(statusData.config.project_keys || []);
      setSelectedWorkflows(statusData.config.workflow_ids || []);
      setSelectedTransitions(statusData.config.transition_ids || []);
      setMode(statusData.config.mode || "simulation");
      setCanaryPct(statusData.config.canary_pct || 10);
      await loadProjects();
      if ((statusData.config.project_keys || []).length) {
        await loadWorkflows(statusData.config.project_keys);
      }
      if ((statusData.config.workflow_ids || []).length) {
        await loadTransitions(statusData.config.workflow_ids);
      }
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load onboarding state");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadStatusAndDiscovery();
  }, [tenantId]);

  const saveSetup = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const payload = await fetchJson<OnboardingStatus>("/api/dashboard/onboarding/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          jira_instance_id: jiraInstanceId || null,
          project_keys: selectedProjects,
          workflow_ids: selectedWorkflows,
          transition_ids: selectedTransitions,
          mode,
          canary_pct: mode === "canary" ? canaryPct : null,
        }),
      });
      setStatus(payload);
      setSuccess("Onboarding configuration saved.");
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Failed to save onboarding setup");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold text-slate-900">Enterprise Onboarding</h1>
        <div className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-600">
          Loading onboarding configuration...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h1 className="text-2xl font-semibold text-slate-900">Enterprise Onboarding</h1>
        <p className="mt-1 text-sm text-slate-600">Tenant: {tenantId}</p>
        <p className="mt-2 text-sm">
          Status:{" "}
          <span
            className={
              onboardingCompleted
                ? "rounded-md bg-emerald-100 px-2 py-0.5 text-emerald-700"
                : "rounded-md bg-amber-100 px-2 py-0.5 text-amber-700"
            }
          >
            {onboardingCompleted ? "Configured" : "Not configured"}
          </span>
        </p>
        {error ? <p className="mt-3 text-sm text-rose-700">{error}</p> : null}
        {success ? <p className="mt-3 text-sm text-emerald-700">{success}</p> : null}
      </div>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">1. Connect Jira</h2>
        <label className="mt-3 block text-sm font-medium text-slate-700">
          Jira instance
          <input
            type="text"
            value={jiraInstanceId}
            onChange={(event) => setJiraInstanceId(event.target.value)}
            placeholder="https://your-domain.atlassian.net"
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
          />
        </label>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-lg font-semibold text-slate-900">2. Select Projects</h2>
          <button
            type="button"
            onClick={() => void loadProjects()}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
          >
            Refresh projects
          </button>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {projects.map((project) => (
            <label key={project.project_key} className="flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2">
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
        <div className="mt-3">
          <button
            type="button"
            onClick={() => void loadWorkflows(selectedProjects)}
            disabled={busyWorkflows || !selectedProjects.length}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          >
            {busyWorkflows ? "Loading workflows..." : "Load workflows"}
          </button>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">3. Select Workflows</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {workflows.map((workflow) => (
            <label key={workflow.workflow_id} className="flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2">
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
          {!workflows.length ? <p className="text-sm text-slate-500">Load workflows after selecting projects.</p> : null}
        </div>
        <div className="mt-3">
          <button
            type="button"
            onClick={() => void loadTransitions(selectedWorkflows)}
            disabled={busyTransitions || !selectedWorkflows.length}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          >
            {busyTransitions ? "Loading transitions..." : "Load transitions"}
          </button>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">4. Select Protected Transitions</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {transitions.map((transition) => (
            <label
              key={`${transition.workflow_id}-${transition.transition_id}`}
              className="flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2"
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
          {!transitions.length ? <p className="text-sm text-slate-500">Load transitions after selecting workflows.</p> : null}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">5. Enforcement Mode</h2>
        <div className="mt-3 grid gap-2">
          <label className="flex items-center gap-2 text-sm text-slate-800">
            <input type="radio" name="mode" checked={mode === "simulation"} onChange={() => setMode("simulation")} />
            Simulation (recommended default)
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
          <label className="mt-3 block text-sm font-medium text-slate-700">
            Canary percentage
            <input
              type="number"
              min={1}
              max={100}
              value={canaryPct}
              onChange={(event) => setCanaryPct(Number(event.target.value || 10))}
              className="mt-1 w-36 rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            />
          </label>
        ) : null}
        <p className="mt-3 text-xs text-slate-500">
          Simulation mode is safest for initial rollout. Move to Canary or Strict after reviewing historical simulation.
        </p>
      </section>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => void saveSetup()}
          disabled={saving}
          className="rounded-md border border-slate-300 bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {saving ? "Saving..." : "Save onboarding setup"}
        </button>
        {status?.config.updated_at ? (
          <p className="text-xs text-slate-500">Last saved: {status.config.updated_at}</p>
        ) : null}
      </div>
    </div>
  );
}
