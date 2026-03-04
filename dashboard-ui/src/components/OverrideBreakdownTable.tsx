import type { OverrideBreakdownRow, OverridesGroupBy } from "@/lib/types";

const groupLabel: Record<OverridesGroupBy, string> = {
  actor: "Actor",
  workflow: "Workflow",
  rule: "Rule",
};

interface Props {
  groupBy: OverridesGroupBy;
  rows: OverrideBreakdownRow[];
}

function formatLastSeen(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toISOString().replace("T", " ").replace("Z", " UTC");
}

export function OverrideBreakdownTable({ groupBy, rows }: Props) {
  if (!rows.length) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-base font-semibold text-slate-900">No override events in this range</h3>
        <p className="mt-2 text-sm text-slate-600">Try a broader window or a different tenant.</p>
      </div>
    );
  }

  const secondaryColumnLabel =
    groupBy === "actor" ? "Workflows" : "Actors";
  const tertiaryColumnLabel =
    groupBy === "rule" ? "Workflows" : "Rules";

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50">
          <tr>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">{groupLabel[groupBy]}</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Overrides</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">{secondaryColumnLabel}</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">{tertiaryColumnLabel}</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 bg-white">
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="px-4 py-3 font-medium text-slate-900">{row.key}</td>
              <td className="px-4 py-3 text-slate-700">{row.count}</td>
              <td className="px-4 py-3 text-slate-700">{groupBy === "actor" ? row.workflows : row.actors}</td>
              <td className="px-4 py-3 text-slate-700">{groupBy === "rule" ? row.workflows : row.rules}</td>
              <td className="px-4 py-3 text-slate-700">{formatLastSeen(row.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
