"use client";

import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useState } from "react";

export function AuditExportClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";

  const [repo, setRepo] = useState("");
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [contract, setContract] = useState<"soc2_v1" | "raw">("soc2_v1");
  const [limit, setLimit] = useState(200);
  const [verifyChain, setVerifyChain] = useState(true);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportResult, setExportResult] = useState<Record<string, unknown> | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);

  const buildParams = () => {
    const params = new URLSearchParams();
    params.set("tenant_id", tenantId);
    params.set("repo", repo.trim());
    params.set("format", format);
    params.set("contract", contract);
    params.set("limit", String(limit));
    params.set("verify_chain", String(verifyChain));
    if (status) params.set("status", status);
    return params;
  };

  const runExport = async () => {
    if (!repo.trim()) {
      setError("Repository is required");
      return;
    }
    setLoading(true);
    setError(null);
    setExportResult(null);
    setDownloadUrl(null);
    try {
      const params = buildParams();
      const res = await fetch(`/api/dashboard/audit/export?${params.toString()}`);
      if (!res.ok) {
        const body = await res.text();
        throw new Error(body || `Export failed (${res.status})`);
      }
      if (format === "csv") {
        const text = await res.text();
        const blob = new Blob([text], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        setDownloadUrl(url);
      } else {
        const data = await res.json();
        setExportResult(data);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        setDownloadUrl(url);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setLoading(false);
    }
  };

  const fileName = `releasegate-audit-${repo.replace("/", "-") || "export"}-${contract}.${format}`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href={`/audit?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          ← Back to Trust Overview
        </Link>
        <h1 className="mt-2 text-xl font-bold text-slate-900">Proof-of-History Export</h1>
        <p className="text-sm text-slate-500">
          Export a portable, verifiable audit bundle with decisions, hashes, override chain, and checkpoint references.
        </p>
      </div>

      {/* What's in the bundle */}
      <div className="rounded-xl border border-indigo-100 bg-indigo-50 p-5">
        <h3 className="text-sm font-semibold text-indigo-900 mb-3">SOC2 v1 bundle includes</h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-3">
          {[
            "Decision records with status",
            "Input / policy / replay hashes",
            "Override chain with verification",
            "Approval records",
            "Ledger tip hash",
            "Integrity aggregates",
          ].map((item) => (
            <div key={item} className="flex items-center gap-2 text-xs text-indigo-800">
              <span className="text-emerald-500 font-bold">✓</span>
              {item}
            </div>
          ))}
        </div>
        <p className="mt-3 text-xs text-indigo-600">
          All hashes are independently verifiable offline.{" "}
          <a
            href="/docs/compliance/proof_bundle_verification.md"
            className="underline"
          >
            Verification guide →
          </a>
        </p>
      </div>

      {/* Export config */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-semibold text-slate-800">Export Parameters</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <label className="block sm:col-span-2 lg:col-span-1">
            <span className="text-xs font-medium text-slate-600">
              Repository <span className="text-rose-500">*</span>
            </span>
            <input
              type="text"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              placeholder="org/repo"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Contract</span>
            <select
              value={contract}
              onChange={(e) => setContract(e.target.value as "soc2_v1" | "raw")}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="soc2_v1">SOC2 v1 (recommended)</option>
              <option value="raw">Raw decisions</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Format</span>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as "json" | "csv")}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="json">JSON (with hashes)</option>
              <option value="csv">CSV (tabular)</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Status filter</span>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="">All decisions</option>
              <option value="ALLOWED">Allowed only</option>
              <option value="BLOCKED">Blocked only</option>
              <option value="CONDITIONAL">Conditional only</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Record limit</span>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value={50}>50</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </label>
          <div className="flex items-end pb-0.5">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={verifyChain}
                onChange={(e) => setVerifyChain(e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-indigo-600"
              />
              <span className="text-xs font-medium text-slate-600">Verify override chain</span>
            </label>
          </div>
        </div>
        <button
          onClick={runExport}
          disabled={loading}
          className="rounded-lg bg-slate-900 px-5 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading ? "Generating…" : "Generate Export"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {/* Download + preview */}
      {downloadUrl && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-emerald-800">Export ready</p>
              <p className="text-xs text-emerald-600 font-mono">{fileName}</p>
            </div>
            <a
              href={downloadUrl}
              download={fileName}
              className="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-800"
            >
              Download
            </a>
          </div>
          {exportResult && (
            <IntegrityCard result={exportResult} />
          )}
        </div>
      )}

      {/* JSON preview */}
      {exportResult && format === "json" && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-800">Bundle Preview</h3>
            <p className="text-xs text-slate-500">
              {(exportResult.records as unknown[])?.length ?? 0} record(s) — showing integrity section
            </p>
          </div>
          <div className="overflow-x-auto p-4">
            <pre className="text-[11px] text-slate-700 font-mono leading-relaxed whitespace-pre-wrap">
              {JSON.stringify(
                {
                  contract: exportResult.contract,
                  schema_version: exportResult.schema_version,
                  generated_at: exportResult.generated_at,
                  tenant_id: exportResult.tenant_id,
                  repo: exportResult.repo,
                  integrity: exportResult.integrity,
                  record_count: (exportResult.records as unknown[])?.length ?? 0,
                },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      )}

      {/* CLI verification snippet */}
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-5 space-y-2">
        <h3 className="text-sm font-semibold text-slate-800">Offline Verification</h3>
        <p className="text-xs text-slate-500">
          Auditors can independently verify the exported bundle without access to the ReleaseGate system.
        </p>
        <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-900 p-4 text-xs text-slate-200 font-mono leading-relaxed">
{`# Verify proof pack integrity
python -m releasegate.cli verify-pack \\
  --pack ${fileName} \\
  --format json \\
  --key-file public-keys.json

# Optional: verify against RFC3161 TSA
python -m releasegate.cli verify-pack \\
  --pack ${fileName} \\
  --tsa-ca-bundle tsa-ca.pem`}
        </pre>
      </div>
    </div>
  );
}

function IntegrityCard({ result }: { result: Record<string, unknown> }) {
  const integrity = result.integrity as Record<string, unknown> | undefined;
  if (!integrity) return null;
  return (
    <div className="rounded-lg border border-emerald-200 bg-white p-3 space-y-1">
      <p className="text-xs font-semibold text-slate-700 mb-2">Integrity hashes</p>
      {["decision_hash", "input_hash", "policy_hash", "replay_hash"].map((key) => {
        const val = integrity[key] as string | undefined;
        return val ? (
          <div key={key} className="flex items-center gap-2">
            <span className="w-24 text-[10px] font-medium text-slate-500 shrink-0">{key.replace("_hash", "")}</span>
            <span className="font-mono text-[10px] text-slate-700 truncate">{String(val).slice(0, 40)}…</span>
          </div>
        ) : null;
      })}
    </div>
  );
}
