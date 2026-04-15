"use client";

import { useState } from "react";

export function BillingActions({
  tenantId,
  currentPlan,
}: {
  tenantId: string;
  currentPlan: string;
}) {
  const [loading, setLoading] = useState("");

  const handleUpgrade = async (plan: string) => {
    setLoading(plan);
    try {
      const res = await fetch(`/api/billing/checkout?tenant_id=${tenantId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan }),
      });
      const data = await res.json();
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
      }
    } catch {
      // Stripe not configured — no-op
    } finally {
      setLoading("");
    }
  };

  const handleManage = async () => {
    setLoading("portal");
    try {
      const res = await fetch(`/api/billing/portal?tenant_id=${tenantId}`, {
        method: "POST",
      });
      const data = await res.json();
      if (data.portal_url) {
        window.location.href = data.portal_url;
      }
    } catch {
      // Stripe not configured — no-op
    } finally {
      setLoading("");
    }
  };

  return (
    <div className="flex flex-wrap gap-3">
      {currentPlan !== "growth" && (
        <button
          onClick={() => handleUpgrade("growth")}
          disabled={!!loading}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading === "growth" ? "Redirecting..." : "Upgrade to Growth"}
        </button>
      )}
      {currentPlan !== "enterprise" && (
        <button
          onClick={() => handleUpgrade("enterprise")}
          disabled={!!loading}
          className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 hover:bg-slate-50 disabled:opacity-60"
        >
          {loading === "enterprise" ? "Redirecting..." : "Upgrade to Enterprise"}
        </button>
      )}
      <button
        onClick={handleManage}
        disabled={!!loading}
        className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-60"
      >
        {loading === "portal" ? "Redirecting..." : "Manage Subscription"}
      </button>
    </div>
  );
}
