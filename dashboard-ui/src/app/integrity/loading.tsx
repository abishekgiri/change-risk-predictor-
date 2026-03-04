export default function IntegrityLoading() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex items-end justify-between">
        <div>
          <div className="h-8 w-56 rounded bg-slate-200" />
          <div className="mt-2 h-4 w-40 rounded bg-slate-200" />
        </div>
        <div className="h-4 w-44 rounded bg-slate-200" />
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="h-4 w-28 rounded bg-slate-200" />
          <div className="mt-4 h-8 w-20 rounded bg-slate-200" />
          <div className="mt-3 h-4 w-32 rounded bg-slate-200" />
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="h-4 w-24 rounded bg-slate-200" />
          <div className="mt-4 h-8 w-20 rounded bg-slate-200" />
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="h-4 w-36 rounded bg-slate-200" />
          <div className="mt-4 h-8 w-20 rounded bg-slate-200" />
        </div>
      </section>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="h-4 w-52 rounded bg-slate-200" />
        <div className="mt-3 h-[320px] rounded bg-slate-100" />
      </div>
    </div>
  );
}
