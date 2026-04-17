"use client";

import { useCallback, useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface Pilot {
  id: string;
  company_name: string;
  contact_name: string | null;
  contact_email: string | null;
  tenant_id: string | null;
  icp_band: "STRONG" | "MEDIUM" | "WEAK";
  status: string;
  pilot_start_date: string | null;
  pilot_end_date: string | null;
  monthly_value_usd: number | null;
  notes: string | null;
  before_metrics: Record<string, unknown> | null;
  after_metrics: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

interface Pipeline {
  by_status: Record<string, { count: number; mrr: number }>;
  total_active_mrr: number;
  total_arr: number;
  converted_count: number;
  active_pilots: number;
  prospects: number;
}

interface PilotsResponse {
  pilots: Pilot[];
  pipeline: Pipeline;
}

const STATUS_STYLE: Record<string, string> = {
  PROSPECT:   "bg-slate-100 text-slate-600",
  ONBOARDING: "bg-blue-50 text-blue-700",
  ACTIVE:     "bg-emerald-50 text-emerald-700",
  CONVERTED:  "bg-teal-50 text-teal-800 font-bold",
  CHURNED:    "bg-rose-50 text-rose-600",
  PAUSED:     "bg-amber-50 text-amber-700",
};

const ICP_STYLE: Record<string, string> = {
  STRONG: "bg-emerald-100 text-emerald-800",
  MEDIUM: "bg-amber-100 text-amber-800",
  WEAK:   "bg-slate-100 text-slate-500",
};

const fmt = (n: number) =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(n);

const STATUSES = ["PROSPECT", "ONBOARDING", "ACTIVE", "CONVERTED", "CHURNED", "PAUSED"];

export function PilotTrackerClient() {
  const [data, setData]         = useState<PilotsResponse | null>(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [showAdd, setShowAdd]   = useState(false);
  const [saving, setSaving]     = useState(false);
  const [form, setForm]         = useState({
    company_name: "",
    contact_name: "",
    contact_email: "",
    icp_band: "MEDIUM",
    status: "PROSPECT",
    monthly_value_usd: "",
    notes: "",
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const url = `/api/dashboard/commercial/pilots${statusFilter ? `?status=${statusFilter}` : ""}`;
      setData(await callDashboardApi<PilotsResponse>(url));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load pilots");
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  const addPilot = async () => {
    if (!form.company_name.trim()) return;
    setSaving(true);
    try {
      await callDashboardApi("/api/dashboard/commercial/pilots", {
        method: "POST",
        body: JSON.stringify({
          ...form,
          monthly_value_usd: form.monthly_value_usd ? Number(form.monthly_value_usd) : null,
        }),
      });
      setShowAdd(false);
      setForm({ company_name: "", contact_name: "", contact_email: "", icp_band: "MEDIUM", status: "PROSPECT", monthly_value_usd: "", notes: "" });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add pilot");
    } finally {
      setSaving(false);
    }
  };

  const pipeline = data?.pipeline;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Pilot Tracker</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Design partners and paid pilots — from prospect to conversion.
          </p>
        </div>
        <button onClick={() => setShowAdd(!showAdd)}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800">
          + Add pilot
        </button>
      </div>

      {error && <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>}

      {/* Add form */}
      {showAdd && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-800">New pilot / design partner</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {[
              { label: "Company *", key: "company_name", placeholder: "Acme Corp" },
              { label: "Contact name", key: "contact_name", placeholder: "Jane Smith" },
              { label: "Contact email", key: "contact_email", placeholder: "jane@acme.com" },
              { label: "Monthly value ($)", key: "monthly_value_usd", placeholder: "1500" },
            ].map(({ label, key, placeholder }) => (
              <label key={key} className="flex flex-col gap-1 text-xs font-medium text-slate-600">
                {label}
                <input
                  type="text"
                  placeholder={placeholder}
                  value={(form as Record<string, string>)[key]}
                  onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-900"
                />
              </label>
            ))}
            <label className="flex flex-col gap-1 text-xs font-medium text-slate-600">
              ICP Band
              <select value={form.icp_band} onChange={(e) => setForm({ ...form, icp_band: e.target.value })}
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-900">
                <option value="STRONG">STRONG</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="WEAK">WEAK</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs font-medium text-slate-600">
              Status
              <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-900">
                {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1 text-xs font-medium text-slate-600">
            Notes
            <textarea
              rows={2}
              placeholder="Pain points, ICP signals, next steps…"
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-900"
            />
          </label>
          <div className="flex gap-2">
            <button onClick={addPilot} disabled={saving || !form.company_name.trim()}
              className="rounded-md bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60">
              {saving ? "Saving…" : "Save"}
            </button>
            <button onClick={() => setShowAdd(false)}
              className="rounded-md border border-slate-200 px-4 py-1.5 text-sm text-slate-600 hover:bg-slate-50">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Pipeline summary */}
      {pipeline && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            { label: "ARR", value: fmt(pipeline.total_arr), sub: "active + converted", highlight: pipeline.total_arr > 0 },
            { label: "Converted", value: pipeline.converted_count, sub: "paying customers", highlight: pipeline.converted_count > 0 },
            { label: "Active pilots", value: pipeline.active_pilots, sub: "in workflow" },
            { label: "Prospects", value: pipeline.prospects, sub: "in funnel" },
          ].map(({ label, value, sub, highlight }) => (
            <div key={label} className={`rounded-xl border p-4 shadow-sm ${highlight ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white"}`}>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
              <p className={`mt-1 text-2xl font-bold ${highlight ? "text-emerald-800" : "text-slate-900"}`}>{value}</p>
              <p className="mt-0.5 text-xs text-slate-400">{sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* Status filter */}
      <div className="flex flex-wrap gap-2">
        {["", ...STATUSES].map((s) => (
          <button key={s}
            onClick={() => setStatusFilter(s)}
            className={`rounded-full border px-3 py-1 text-xs font-medium ${
              statusFilter === s
                ? "bg-slate-900 text-white border-slate-900"
                : "border-slate-200 text-slate-600 hover:bg-slate-50"
            }`}>
            {s || "All"}
          </button>
        ))}
      </div>

      {/* Pilot list */}
      {data && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          {data.pilots.length === 0 ? (
            <div className="px-8 py-16 text-center">
              <p className="text-sm font-medium text-slate-500">No pilots yet.</p>
              <p className="mt-1 text-xs text-slate-400">
                Add your first design partner — aim for regulated, Jira-heavy teams.
              </p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="px-4 py-3">Company</th>
                  <th className="px-4 py-3">Contact</th>
                  <th className="px-4 py-3">ICP</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">MRR</th>
                  <th className="px-4 py-3">Notes</th>
                  <th className="px-4 py-3">Since</th>
                </tr>
              </thead>
              <tbody>
                {data.pilots.map((p) => (
                  <tr key={p.id} className="border-b border-slate-50 hover:bg-slate-50">
                    <td className="px-4 py-3">
                      <p className="font-semibold text-slate-900">{p.company_name}</p>
                      {p.tenant_id && <p className="text-xs text-slate-400 font-mono">{p.tenant_id}</p>}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-600">
                      <p>{p.contact_name || "—"}</p>
                      {p.contact_email && <p className="text-slate-400">{p.contact_email}</p>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${ICP_STYLE[p.icp_band] ?? ""}`}>
                        {p.icp_band}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${STATUS_STYLE[p.status] ?? "bg-slate-100 text-slate-600"}`}>
                        {p.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-medium text-slate-900">
                      {p.monthly_value_usd ? fmt(p.monthly_value_usd) : "—"}
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <p className="truncate text-xs text-slate-500">{p.notes || "—"}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {new Date(p.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ICP reminder */}
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold text-slate-700 mb-1">Target ICP</p>
        <p className="text-xs text-slate-500">
          Engineering teams <strong>(10–100 devs)</strong> using <strong>Jira + GitHub</strong>,
          with <strong>compliance or audit pressure</strong>, deploying <strong>multiple times/week</strong>.
          Fintech, healthtech, enterprise SaaS.
        </p>
      </div>
    </div>
  );
}
