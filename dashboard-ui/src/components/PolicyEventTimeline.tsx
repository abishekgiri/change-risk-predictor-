"use client";

import { useEffect, useState } from "react";
import type { PolicyRegistryEvent } from "@/lib/types";
import { callDashboardApi } from "@/lib/api";

interface Props {
  policyId: string;
  tenantId: string;
}

const EVENT_STYLES: Record<string, { icon: string; color: string }> = {
  CREATED: { icon: "+", color: "bg-sky-100 text-sky-700" },
  STAGED: { icon: "S", color: "bg-amber-100 text-amber-700" },
  ACTIVATED: { icon: "✓", color: "bg-emerald-100 text-emerald-700" },
  ARCHIVED: { icon: "×", color: "bg-slate-100 text-slate-500" },
  ROLLED_BACK: { icon: "↩", color: "bg-rose-100 text-rose-700" },
  UPDATED: { icon: "~", color: "bg-violet-100 text-violet-700" },
};

function formatRelative(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

export function PolicyEventTimeline({ policyId, tenantId }: Props) {
  const [events, setEvents] = useState<PolicyRegistryEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    callDashboardApi<{ events: PolicyRegistryEvent[] }>(
      `/api/dashboard/policies/${policyId}/events?tenant_id=${encodeURIComponent(tenantId)}`,
    )
      .then((data) => setEvents(data.events || []))
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [policyId, tenantId]);

  if (loading) {
    return <div className="animate-pulse rounded-lg bg-slate-100 h-24" />;
  }

  if (events.length === 0) {
    return <p className="text-sm text-slate-500 italic">No events recorded.</p>;
  }

  return (
    <div className="space-y-0">
      {events.map((event, idx) => {
        const style = EVENT_STYLES[event.event_type] ?? {
          icon: "?",
          color: "bg-slate-100 text-slate-600",
        };
        const isLast = idx === events.length - 1;

        return (
          <div key={event.event_id ?? idx} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <div
                className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${style.color}`}
              >
                {style.icon}
              </div>
              {!isLast && <div className="w-0.5 h-5 bg-slate-200" />}
            </div>
            <div className="pt-1 min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-800">
                  {event.event_type.replace(/_/g, " ")}
                </span>
                <span className="text-xs text-slate-400">
                  {formatRelative(event.created_at)}
                </span>
              </div>
              {event.actor_id && (
                <p className="text-xs text-slate-500">by {event.actor_id}</p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
