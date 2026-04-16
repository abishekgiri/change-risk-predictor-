"use client";

import { useState } from "react";
import type { PolicyStatus } from "@/lib/types";
import { callDashboardApi } from "@/lib/api";

interface Props {
  policyId: string;
  tenantId: string;
  currentStatus: PolicyStatus;
  onStatusChange: (newPolicy: Record<string, unknown>) => void;
}

export function PolicyLifecycleActions({
  policyId,
  tenantId,
  currentStatus,
  onStatusChange,
}: Props) {
  const [loading, setLoading] = useState("");
  const [error, setError] = useState<string | null>(null);

  const doAction = async (action: string) => {
    setLoading(action);
    setError(null);
    try {
      const data = await callDashboardApi<Record<string, unknown>>(
        `/api/dashboard/policies/${policyId}/${action}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tenant_id: tenantId }),
        },
      );
      onStatusChange(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setLoading("");
    }
  };

  const actions: Array<{ key: string; label: string; from: PolicyStatus[]; style: string }> = [
    {
      key: "stage",
      label: "Stage for Review",
      from: ["DRAFT"],
      style: "bg-amber-600 text-white hover:bg-amber-700",
    },
    {
      key: "activate",
      label: "Activate",
      from: ["DRAFT", "STAGED"],
      style: "bg-emerald-600 text-white hover:bg-emerald-700",
    },
    {
      key: "rollback",
      label: "Rollback",
      from: ["ACTIVE", "STAGED"],
      style: "border border-rose-300 bg-white text-rose-700 hover:bg-rose-50",
    },
  ];

  const available = actions.filter((a) => a.from.includes(currentStatus));

  if (available.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        {available.map((action) => (
          <button
            key={action.key}
            onClick={() => doAction(action.key)}
            disabled={!!loading}
            className={`rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-60 ${action.style}`}
          >
            {loading === action.key ? "Processing..." : action.label}
          </button>
        ))}
      </div>
      {error && <p className="text-xs text-rose-600">{error}</p>}
    </div>
  );
}
