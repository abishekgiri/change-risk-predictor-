export default function OverridesLoading() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <div className="h-8 w-64 rounded bg-slate-200" />
          <div className="mt-2 h-4 w-40 rounded bg-slate-200" />
        </div>
        <div className="h-4 w-44 rounded bg-slate-200" />
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="h-4 w-24 rounded bg-slate-200" />
        <div className="mt-2 h-10 w-48 rounded bg-slate-200" />
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="h-4 w-56 rounded bg-slate-200" />
        <div className="mt-3 h-[280px] rounded bg-slate-100" />
      </div>
    </div>
  );
}
