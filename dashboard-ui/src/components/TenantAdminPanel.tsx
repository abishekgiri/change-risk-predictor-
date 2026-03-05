"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";

import type { TenantInfo, TenantKeyRotationResult, TenantPlan, TenantRole, TenantStatus } from "@/lib/types";

const ROLE_OPTIONS: TenantRole[] = ["owner", "admin", "operator", "auditor", "viewer"];
const PLAN_OPTIONS: TenantPlan[] = ["starter", "growth", "enterprise"];

async function fetchJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, init);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof payload?.error === "string" ? payload.error : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload as T;
}

function asTenantStatus(value: string): TenantStatus {
  if (value === "locked" || value === "throttled") return value;
  return "active";
}

export function TenantAdminPanel() {
  const searchParams = useSearchParams();
  const tenantId = useMemo(() => searchParams.get("tenant_id") || "default", [searchParams]);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [name, setName] = useState(tenantId);
  const [plan, setPlan] = useState<TenantPlan>("enterprise");
  const [region, setRegion] = useState("us-east");

  const [actorId, setActorId] = useState("");
  const [role, setRole] = useState<TenantRole>("operator");
  const [roleAction, setRoleAction] = useState<"assign" | "remove">("assign");

  const [rotateSigningKey, setRotateSigningKey] = useState(true);
  const [rotateApiKey, setRotateApiKey] = useState(true);
  const [apiKeyId, setApiKeyId] = useState("");
  const [rotationResult, setRotationResult] = useState<TenantKeyRotationResult | null>(null);

  const loadTenant = async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await fetchJson<TenantInfo>(
        `/api/dashboard/tenant/info?tenant_id=${encodeURIComponent(tenantId)}`,
      );
      setTenant(payload);
      setName(payload.name || tenantId);
      setPlan(payload.plan || "enterprise");
      setRegion(payload.region || "us-east");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load tenant profile");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadTenant();
  }, [tenantId]);

  const saveTenant = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const payload = await fetchJson<TenantInfo>("/api/dashboard/tenant/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          name,
          plan,
          region,
        }),
      });
      setTenant(payload);
      setSuccess("Tenant profile updated.");
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Failed to save tenant profile");
    } finally {
      setSaving(false);
    }
  };

  const updateStatus = async (status: TenantStatus) => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const endpoint = status === "active" ? "/api/dashboard/tenant/unlock" : "/api/dashboard/tenant/lock";
      const payload = await fetchJson<TenantInfo>(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          status === "active"
            ? { tenant_id: tenantId, reason: "manual_unlock_from_dashboard" }
            : { tenant_id: tenantId, status, reason: `manual_${status}_from_dashboard` },
        ),
      });
      setTenant(payload);
      setSuccess(`Tenant status set to ${status}.`);
    } catch (statusError) {
      setError(statusError instanceof Error ? statusError.message : "Failed to update tenant status");
    } finally {
      setSaving(false);
    }
  };

  const applyRoleMutation = async () => {
    if (!actorId.trim()) {
      setError("Actor ID is required.");
      return;
    }
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const payload = await fetchJson<TenantInfo>("/api/dashboard/tenant/role_assign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          actor_id: actorId.trim(),
          role,
          action: roleAction,
        }),
      });
      setTenant(payload);
      setSuccess(`Role ${roleAction} applied for ${actorId.trim()}.`);
    } catch (roleError) {
      setError(roleError instanceof Error ? roleError.message : "Failed to update role assignment");
    } finally {
      setSaving(false);
    }
  };

  const rotateKeys = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const payload = await fetchJson<TenantKeyRotationResult>("/api/dashboard/tenant/key_rotate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          rotate_signing_key: rotateSigningKey,
          rotate_api_key: rotateApiKey,
          api_key_id: apiKeyId.trim() || null,
        }),
      });
      setRotationResult(payload);
      setSuccess("Tenant key rotation completed.");
      await loadTenant();
    } catch (rotateError) {
      setError(rotateError instanceof Error ? rotateError.message : "Failed to rotate tenant keys");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-600">
        Loading tenant admin profile...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h1 className="text-2xl font-semibold text-slate-900">Tenant Admin</h1>
        <p className="mt-1 text-sm text-slate-600">Tenant: {tenantId}</p>
        <p className="mt-2 text-sm text-slate-700">
          Status:{" "}
          <span className="font-medium text-slate-900">{tenant?.status || "active"}</span>
        </p>
        {error ? <p className="mt-3 text-sm text-rose-700">{error}</p> : null}
        {success ? <p className="mt-3 text-sm text-emerald-700">{success}</p> : null}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Organization</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <label className="text-sm font-medium text-slate-700">
            Name
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Plan
            <select
              value={plan}
              onChange={(event) => setPlan(event.target.value as TenantPlan)}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            >
              {PLAN_OPTIONS.map((planValue) => (
                <option key={planValue} value={planValue}>
                  {planValue}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium text-slate-700">
            Region
            <input
              value={region}
              onChange={(event) => setRegion(event.target.value)}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            />
          </label>
        </div>
        <button
          type="button"
          onClick={() => void saveTenant()}
          disabled={saving}
          className="mt-3 rounded-md border border-slate-300 bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {saving ? "Saving..." : "Save tenant profile"}
        </button>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Tenant Status</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          {["active", "locked", "throttled"].map((value) => {
            const status = asTenantStatus(value);
            const active = tenant?.status === status;
            return (
              <button
                key={status}
                type="button"
                onClick={() => void updateStatus(status)}
                disabled={saving}
                className={
                  active
                    ? "rounded-md border border-slate-900 bg-slate-900 px-3 py-1.5 text-sm font-medium text-white"
                    : "rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
                }
              >
                {status}
              </button>
            );
          })}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Role Assignment</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <label className="text-sm font-medium text-slate-700">
            Actor ID
            <input
              value={actorId}
              onChange={(event) => setActorId(event.target.value)}
              placeholder="user@example.com"
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Role
            <select
              value={role}
              onChange={(event) => setRole(event.target.value as TenantRole)}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            >
              {ROLE_OPTIONS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium text-slate-700">
            Action
            <select
              value={roleAction}
              onChange={(event) => setRoleAction(event.target.value as "assign" | "remove")}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            >
              <option value="assign">assign</option>
              <option value="remove">remove</option>
            </select>
          </label>
          <div className="flex items-end">
            <button
              type="button"
              onClick={() => void applyRoleMutation()}
              disabled={saving}
              className="w-full rounded-md border border-slate-300 bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
            >
              Apply role change
            </button>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-3">Actor</th>
                <th className="py-2 pr-3">Roles</th>
                <th className="py-2 pr-3">Assigned By</th>
                <th className="py-2">Last Assigned At</th>
              </tr>
            </thead>
            <tbody>
              {(tenant?.roles || []).map((entry) => (
                <tr key={entry.actor_id} className="border-b border-slate-100">
                  <td className="py-2 pr-3 font-mono text-xs text-slate-800">{entry.actor_id}</td>
                  <td className="py-2 pr-3 text-slate-700">{entry.roles.join(", ") || "-"}</td>
                  <td className="py-2 pr-3 text-slate-700">{entry.assigned_by || "-"}</td>
                  <td className="py-2 text-slate-700">{entry.last_assigned_at || "-"}</td>
                </tr>
              ))}
              {!tenant?.roles.length ? (
                <tr>
                  <td className="py-3 text-slate-500" colSpan={4}>
                    No explicit role assignments configured yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Key Rotation</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <label className="flex items-center gap-2 text-sm text-slate-800">
            <input
              type="checkbox"
              checked={rotateSigningKey}
              onChange={(event) => setRotateSigningKey(event.target.checked)}
            />
            Rotate signing key
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-800">
            <input
              type="checkbox"
              checked={rotateApiKey}
              onChange={(event) => setRotateApiKey(event.target.checked)}
            />
            Rotate API key
          </label>
          <label className="text-sm font-medium text-slate-700">
            API key id (optional)
            <input
              value={apiKeyId}
              onChange={(event) => setApiKeyId(event.target.value)}
              className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
            />
          </label>
        </div>
        <button
          type="button"
          onClick={() => void rotateKeys()}
          disabled={saving}
          className="mt-3 rounded-md border border-rose-600 bg-rose-600 px-4 py-2 text-sm font-medium text-white hover:bg-rose-700 disabled:opacity-60"
        >
          Rotate tenant keys
        </button>

        {rotationResult ? (
          <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
            <p>Signing key: {rotationResult.rotated_signing_key_id || "not rotated"}</p>
            <p>API key: {rotationResult.rotated_api_key_id || "not rotated"}</p>
            <p>API key created: {rotationResult.api_key_created ? "yes" : "no"}</p>
          </div>
        ) : null}
      </section>
    </div>
  );
}
