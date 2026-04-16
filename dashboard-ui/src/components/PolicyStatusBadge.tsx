import type { PolicyStatus } from "@/lib/types";

const STATUS_STYLES: Record<PolicyStatus, string> = {
  DRAFT: "bg-slate-100 text-slate-700 border-slate-300",
  STAGED: "bg-amber-50 text-amber-700 border-amber-300",
  ACTIVE: "bg-emerald-50 text-emerald-700 border-emerald-300",
  ARCHIVED: "bg-slate-50 text-slate-500 border-slate-200",
  DEPRECATED: "bg-rose-50 text-rose-600 border-rose-200",
};

export function PolicyStatusBadge({ status }: { status: PolicyStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${STATUS_STYLES[status] ?? STATUS_STYLES.DRAFT}`}
    >
      {status}
    </span>
  );
}
