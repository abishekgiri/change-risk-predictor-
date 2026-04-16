"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { callDashboardApi } from "@/lib/api";
import type { PolicyScopeType, RegistryPolicy } from "@/lib/types";

const SCOPE_OPTIONS: { value: PolicyScopeType; label: string; description: string }[] = [
  { value: "org", label: "Organization", description: "Applies to all projects in the org" },
  { value: "project", label: "Project", description: "Applies to all workflows in this project" },
  { value: "workflow", label: "Workflow", description: "Applies to all transitions in this workflow" },
  { value: "transition", label: "Transition", description: "Applies to a specific transition only" },
];

const STARTER_TEMPLATE: Record<string, unknown> = {
  rules: [
    {
      name: "require-approval",
      description: "Require at least one approval before release",
      conditions: {
        min_approvals: 1,
      },
      action: "BLOCK",
      reason: "APPROVAL_REQUIRED",
    },
  ],
  risk_thresholds: {
    high: 0.7,
    critical: 0.9,
  },
  sod: {
    enabled: false,
    min_distinct_actors: 2,
  },
};

export default function CreatePolicyPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "";

  const [scopeType, setScopeType] = useState<PolicyScopeType>("org");
  const [scopeId, setScopeId] = useState(tenantId || "default");
  const [policyJson, setPolicyJson] = useState(JSON.stringify(STARTER_TEMPLATE, null, 2));
  const [rolloutPct, setRolloutPct] = useState(100);
  const [status, setStatus] = useState<"DRAFT" | "STAGED">("DRAFT");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);

  const validateJson = (text: string): boolean => {
    try {
      JSON.parse(text);
      setJsonError(null);
      return true;
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : "Invalid JSON");
      return false;
    }
  };

  const handleCreate = async () => {
    if (!validateJson(policyJson)) return;
    setLoading(true);
    setError(null);
    try {
      const data = await callDashboardApi<RegistryPolicy>(
        "/api/dashboard/policies/create",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scope_type: scopeType,
            scope_id: scopeId,
            policy_json: JSON.parse(policyJson),
            status,
            rollout_percentage: rolloutPct,
            tenant_id: tenantId || undefined,
          }),
        },
      );
      const params = new URLSearchParams(searchParams.toString());
      router.push(`/policies/${data.policy_id}?${params.toString()}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create policy");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900">Create Policy</h1>
        <p className="text-sm text-slate-500">
          Define a new governance policy and assign it to a scope.
        </p>
      </div>

      {/* Scope selection */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-semibold text-slate-800">Scope</h3>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {SCOPE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setScopeType(opt.value)}
              className={`rounded-lg border p-3 text-left transition-colors ${
                scopeType === opt.value
                  ? "border-slate-900 bg-slate-50 ring-1 ring-slate-900"
                  : "border-slate-200 hover:border-slate-300"
              }`}
            >
              <p className="text-sm font-semibold text-slate-800">{opt.label}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">{opt.description}</p>
            </button>
          ))}
        </div>

        <label className="block">
          <span className="text-xs font-medium text-slate-600">Scope ID</span>
          <input
            type="text"
            value={scopeId}
            onChange={(e) => setScopeId(e.target.value)}
            placeholder={scopeType === "org" ? "my-org" : "e.g. PROJECT-123"}
            className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
      </div>

      {/* Policy definition */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-800">Policy Definition</h3>
          <button
            onClick={() => {
              setPolicyJson(JSON.stringify(STARTER_TEMPLATE, null, 2));
              setJsonError(null);
            }}
            className="text-xs text-indigo-600 hover:text-indigo-800"
          >
            Reset to template
          </button>
        </div>
        <textarea
          value={policyJson}
          onChange={(e) => {
            setPolicyJson(e.target.value);
            if (jsonError) validateJson(e.target.value);
          }}
          onBlur={() => validateJson(policyJson)}
          rows={16}
          spellCheck={false}
          className={`block w-full rounded-lg border px-4 py-3 font-mono text-xs ${
            jsonError
              ? "border-rose-300 bg-rose-50"
              : "border-slate-200 bg-slate-50"
          }`}
        />
        {jsonError && (
          <p className="text-xs text-rose-600">{jsonError}</p>
        )}
      </div>

      {/* Options */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-4">Options</h3>
        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Initial Status</span>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as "DRAFT" | "STAGED")}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="DRAFT">Draft</option>
              <option value="STAGED">Staged for Review</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">
              Rollout Percentage ({rolloutPct}%)
            </span>
            <input
              type="range"
              min={0}
              max={100}
              value={rolloutPct}
              onChange={(e) => setRolloutPct(Number(e.target.value))}
              className="mt-2 block w-full"
            />
          </label>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleCreate}
          disabled={loading || !!jsonError}
          className="rounded-lg bg-slate-900 px-6 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading ? "Creating..." : "Create Policy"}
        </button>
        <button
          onClick={() => router.back()}
          className="rounded-lg border border-slate-300 bg-white px-6 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
