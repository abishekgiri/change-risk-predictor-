"use client";

import { useMemo, useState } from "react";

import { callDashboardApi } from "@/lib/api";
import type { BlockedDecisionItem } from "@/lib/types";

interface BlockedResponse {
  trace_id: string;
  items: BlockedDecisionItem[];
  next_cursor: string | null;
}

interface Props {
  tenantId: string;
  fromTs?: string | null;
  toTs?: string | null;
  initialItems: BlockedDecisionItem[];
  initialCursor?: string | null;
}

function scopedDecisionHref(decisionId: string, tenantId: string, fromTs?: string | null, toTs?: string | null): string {
  const params = new URLSearchParams();
  if (tenantId) params.set("tenant_id", tenantId);
  if (fromTs) params.set("from", fromTs);
  if (toTs) params.set("to", toTs);
  const query = params.toString();
  if (!query) return `/decisions/${decisionId}`;
  return `/decisions/${decisionId}?${query}`;
}

export function BlockedDecisionsTable({
  tenantId,
  fromTs = null,
  toTs = null,
  initialItems,
  initialCursor = null,
}: Props) {
  const [items, setItems] = useState<BlockedDecisionItem[]>(initialItems);
  const [cursor, setCursor] = useState<string | null>(initialCursor);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasMore = useMemo(() => Boolean(cursor), [cursor]);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm" data-testid="blocked-table">
      <h3 className="text-sm font-semibold text-slate-800">Recent Blocked Decisions</h3>
      <div className="mt-3 overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
              <th className="py-2 pr-3">Time</th>
              <th className="py-2 pr-3">Issue</th>
              <th className="py-2 pr-3">Workflow/Transition</th>
              <th className="py-2 pr-3">Reason</th>
              <th className="py-2">Link</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.decision_id} className="border-b border-slate-100">
                <td className="py-2 pr-3 text-slate-600">{new Date(item.created_at).toLocaleString()}</td>
                <td className="py-2 pr-3 text-slate-900">{item.subject_ref || "-"}</td>
                <td className="py-2 pr-3 text-slate-700">
                  {item.workflow || "-"} / {item.transition || "-"}
                </td>
                <td className="py-2 pr-3 text-slate-700">{item.reason_code || "-"}</td>
                <td className="py-2">
                  <a
                    className="text-indigo-600 hover:underline"
                    href={scopedDecisionHref(item.decision_id, tenantId, fromTs, toTs)}
                    data-testid="blocked-row-link"
                  >
                    View
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {error ? <p className="mt-3 text-xs text-rose-600">{error}</p> : null}

      {hasMore ? (
        <div className="mt-3">
          <button
            type="button"
            disabled={loading}
            onClick={async () => {
              if (!cursor) return;
              setLoading(true);
              setError(null);
              try {
                const params = new URLSearchParams({
                  tenant_id: tenantId,
                  limit: "25",
                  cursor,
                });
                if (fromTs) params.set("from", fromTs);
                if (toTs) params.set("to", toTs);
                const next = await callDashboardApi<BlockedResponse>(
                  `/api/dashboard/blocked?${params.toString()}`,
                );
                setItems((prev) => [...prev, ...(next.items ?? [])]);
                setCursor(next.next_cursor || null);
              } catch (err) {
                setError(err instanceof Error ? err.message : "Failed to load more blocked decisions.");
              } finally {
                setLoading(false);
              }
            }}
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          >
            {loading ? "Loading..." : "Load more"}
          </button>
        </div>
      ) : null}
    </div>
  );
}
