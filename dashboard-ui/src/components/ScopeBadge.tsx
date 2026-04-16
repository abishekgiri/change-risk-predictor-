import type { PolicyScopeType } from "@/lib/types";

const SCOPE_STYLES: Record<PolicyScopeType, string> = {
  org: "bg-indigo-50 text-indigo-700 border-indigo-200",
  project: "bg-sky-50 text-sky-700 border-sky-200",
  workflow: "bg-violet-50 text-violet-700 border-violet-200",
  transition: "bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200",
};

const SCOPE_ICONS: Record<PolicyScopeType, string> = {
  org: "🏢",
  project: "📁",
  workflow: "🔄",
  transition: "➡️",
};

export function ScopeBadge({
  scopeType,
  scopeId,
}: {
  scopeType: PolicyScopeType;
  scopeId?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${SCOPE_STYLES[scopeType] ?? SCOPE_STYLES.org}`}
    >
      <span>{SCOPE_ICONS[scopeType]}</span>
      <span>{scopeType}</span>
      {scopeId && (
        <span className="font-mono text-[10px] opacity-75">{scopeId}</span>
      )}
    </span>
  );
}
