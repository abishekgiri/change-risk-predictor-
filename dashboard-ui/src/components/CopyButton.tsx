"use client";

import { useState } from "react";

interface CopyButtonProps {
  value: string;
  label?: string;
  title?: string;
  compact?: boolean;
}

export function CopyButton({
  value,
  label = "Copy",
  title,
  compact = false,
}: CopyButtonProps) {
  const [done, setDone] = useState(false);

  return (
    <button
      type="button"
      title={title || label}
      aria-label={title || label}
      className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
      onClick={async () => {
        if (!value) return;
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          setDone(false);
        }
      }}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-3.5 w-3.5"
        aria-hidden="true"
      >
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      {!compact ? <span>{done ? "Copied!" : label}</span> : null}
      {compact && done ? <span>Copied!</span> : null}
    </button>
  );
}
