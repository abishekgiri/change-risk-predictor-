"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

const plans = [
  {
    id: "starter",
    name: "Starter",
    price: "Free",
    description: "For teams getting started with release governance",
    features: ["5,000 decisions/mo", "200 overrides/mo", "7-day history", "512 MB storage"],
  },
  {
    id: "growth",
    name: "Growth",
    price: "$299/mo",
    description: "For growing teams that need deeper compliance",
    features: ["50,000 decisions/mo", "2,000 overrides/mo", "30-day history", "2 GB storage"],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Custom",
    description: "For regulated orgs with audit and compliance needs",
    features: ["Unlimited decisions", "Unlimited overrides", "365-day history", "Unlimited storage"],
  },
];

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [selectedPlan, setSelectedPlan] = useState("starter");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, org_name: orgName, plan: selectedPlan }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || data.detail || "Signup failed");
        return;
      }
      if (data.token) {
        document.cookie = `rg_token=${data.token}; path=/; max-age=${60 * 60 * 24}; SameSite=Lax`;
      }
      router.push(data.redirect_url || `/onboarding?tenant_id=${data.tenant_id}`);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-[80vh] flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-slate-900">Get Started with ReleaseGate</h1>
          <p className="mt-2 text-slate-600">
            Set up your organization and start monitoring release risk in minutes.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              {error}
            </div>
          )}

          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold text-slate-900">Account Details</h2>
            <div className="space-y-4">
              <div>
                <label htmlFor="org" className="block text-sm font-medium text-slate-700">
                  Organization Name
                </label>
                <input
                  id="org"
                  type="text"
                  required
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="Acme Corp"
                  className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
                />
              </div>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-slate-700">
                  Work Email
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-slate-700">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
                />
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold text-slate-900">Choose a Plan</h2>
            <div className="grid gap-3 md:grid-cols-3">
              {plans.map((plan) => (
                <button
                  key={plan.id}
                  type="button"
                  onClick={() => setSelectedPlan(plan.id)}
                  className={`rounded-lg border-2 p-4 text-left transition ${
                    selectedPlan === plan.id
                      ? "border-slate-900 bg-slate-50"
                      : "border-slate-200 hover:border-slate-300"
                  }`}
                >
                  <div className="flex items-baseline justify-between">
                    <span className="font-semibold text-slate-900">{plan.name}</span>
                    <span className="text-sm font-medium text-slate-600">{plan.price}</span>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">{plan.description}</p>
                  <ul className="mt-3 space-y-1">
                    {plan.features.map((f) => (
                      <li key={f} className="text-xs text-slate-600">
                        {f}
                      </li>
                    ))}
                  </ul>
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm hover:bg-slate-800 disabled:opacity-60"
          >
            {loading ? "Creating your account..." : "Create Account"}
          </button>

          <p className="text-center text-sm text-slate-500">
            Already have an account?{" "}
            <Link href="/login" className="font-medium text-slate-900 hover:underline">
              Sign in
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
