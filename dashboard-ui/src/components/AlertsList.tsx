import React from "react";

import type { DashboardAlerts } from "@/lib/types";
import { SeverityBadge } from "@/components/SeverityBadge";

export function AlertsList({ alerts }: { alerts: DashboardAlerts["alerts"] }) {
  if (!alerts.length) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-500 shadow-sm">
        No governance alerts in this window.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-800">Governance Alerts</h3>
      <ul className="mt-3 space-y-3">
        {alerts.map((alert) => (
          <li key={`${alert.date_utc}-${alert.code}`} className="rounded-lg border border-slate-100 p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-medium text-slate-900">{alert.title}</p>
              <SeverityBadge severity={alert.severity} />
            </div>
            <p className="mt-1 text-xs text-slate-500">{alert.code} • {alert.date_utc}</p>
            <pre className="mt-2 overflow-x-auto rounded-md bg-slate-50 p-2 text-xs text-slate-700">
              {JSON.stringify(alert.details, null, 2)}
            </pre>
          </li>
        ))}
      </ul>
    </div>
  );
}
