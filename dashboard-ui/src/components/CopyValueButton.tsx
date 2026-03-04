"use client";

import { useState } from "react";

export function CopyValueButton({ value }: { value: string }) {
  const [done, setDone] = useState(false);

  return (
    <button
      type="button"
      className="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
      onClick={async () => {
        if (!value) return;
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          setDone(false);
        }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}
