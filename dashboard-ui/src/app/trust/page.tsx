import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Trust — ReleaseGate",
  description:
    "How ReleaseGate handles your data and where we are on our compliance journey.",
};

// Public, unauthenticated page.  Linked from cold emails and demo
// decks, not from the authenticated AppNav.  Content is intentionally
// calibrated to what the codebase ships today — no aspirational
// control numbers, no marketing superlatives.  See PR rationale.
export default function TrustPage() {
  return (
    <div className="bg-white">
      {/* Minimal public header — no tenant scope, no date picker. */}
      <header className="border-b border-slate-200">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-6 py-4">
          <Link
            href="/"
            className="text-sm font-semibold text-slate-900 hover:text-slate-700"
          >
            ReleaseGate
          </Link>
          <Link
            href="/"
            className="text-sm text-slate-500 hover:text-slate-900"
          >
            ← Back to home
          </Link>
        </div>
      </header>

      <article className="mx-auto max-w-3xl px-6 py-10 text-slate-800 leading-relaxed">
        <h1 className="text-3xl font-bold text-slate-900">Trust at ReleaseGate</h1>

        <p className="mt-6">
          ReleaseGate is evidence infrastructure for software changes.
          We are in our design-partner phase — small, hand-picked
          customers running ReleaseGate against real production deploys.
          This page describes how we handle your data and where we are
          on our compliance journey. It is intentionally short. If a
          claim you need isn&apos;t on this page, email us and we will tell
          you the truth.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Where your data lives</h2>

        <p className="mt-4">
          ReleaseGate stores governance metadata (decision records,
          signed attestations, policy snapshots, evidence graphs).
          We do not store source code, diffs, secrets, or access tokens.
        </p>

        <p className="mt-4">Active subprocessors:</p>

        <div className="mt-3 overflow-x-auto rounded-xl border border-slate-200">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2">Provider</th>
                <th className="px-4 py-2">Purpose</th>
                <th className="px-4 py-2">Region</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              <tr>
                <td className="px-4 py-2 font-medium text-slate-900">Render</td>
                <td className="px-4 py-2">Primary application hosting and Postgres database</td>
                <td className="px-4 py-2">US — Oregon</td>
              </tr>
              <tr>
                <td className="px-4 py-2 font-medium text-slate-900">GitHub</td>
                <td className="px-4 py-2">Source code hosting, CI execution, OAuth identity</td>
                <td className="px-4 py-2">US</td>
              </tr>
              <tr>
                <td className="px-4 py-2 font-medium text-slate-900">Neon</td>
                <td className="px-4 py-2">Cold backup Postgres instance (no live writes today)</td>
                <td className="px-4 py-2">US</td>
              </tr>
            </tbody>
          </table>
        </div>

        <p className="mt-4">
          We will notify customers 30 days before adding a new
          subprocessor that handles customer data.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Encryption</h2>

        <ul className="mt-4 list-disc space-y-2 pl-6">
          <li>
            <strong>In transit.</strong> All connections use TLS 1.2 or higher.
            Render and GitHub enforce this at the platform level.
          </li>
          <li>
            <strong>At rest.</strong> Render Postgres encrypts the database volume
            at rest using AES-256.
          </li>
          <li>
            <strong>Signing.</strong> Decision attestations and daily checkpoints are
            signed with Ed25519. Signing keys are rotated under a
            versioned key identifier (<code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">rg-ci-2026-02</code> is the current
            production key).
          </li>
        </ul>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Compliance status</h2>

        <p className="mt-4">We are honest about where we are. Today:</p>

        <ul className="mt-4 list-disc space-y-2 pl-6">
          <li>
            <strong>SOC 2 Type I</strong> — planned, kickoff in H2 2026 with Drata or
            Vanta. Not yet in audit.
          </li>
          <li>
            <strong>SOC 2 Type II</strong> — planned for 2027.
          </li>
          <li>
            <strong>ISO 27001</strong> — on the roadmap, not yet scoped.
          </li>
          <li>
            <strong>GDPR / DPA</strong> — a data processing addendum is available on
            request for design partners; ask us.
          </li>
        </ul>

        <p className="mt-4">
          We will update this page the day we move from &ldquo;planned&rdquo; to
          &ldquo;in audit&rdquo; and again the day a report is issued. Anything
          stronger than what&apos;s on this page today is not something we
          are claiming.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Security contact</h2>

        <p className="mt-4">
          Security reports go to{" "}
          <a
            href="mailto:security@releasegate.io"
            className="font-medium text-slate-900 underline underline-offset-2 hover:text-slate-700"
          >
            <strong>security@releasegate.io</strong>
          </a>
          .
        </p>

        <p className="mt-4">
          We aim to acknowledge a credible security report within 48
          business hours during the design-partner phase. If you
          believe you have found a vulnerability that puts customer
          data at risk, please email rather than open a public issue.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Incident response</h2>

        <p className="mt-4">
          In the event of a confirmed incident affecting customer data,
          we will notify affected customers by email within 72 hours of
          confirmation, and follow up with a written postmortem within
          14 days. We do not have a paying-customer SLA yet because we
          are pre-revenue; these commitments are what design partners
          should expect.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">What we do not do</h2>

        <ul className="mt-4 list-disc space-y-2 pl-6">
          <li>
            We do not sell, share, or use customer data for model
            training.
          </li>
          <li>
            We do not store source code, diffs, or access tokens.
          </li>
          <li>
            We do not have a third-party telemetry vendor on the
            dashboard.
          </li>
        </ul>

        <hr className="my-10 border-slate-200" />

        <p className="text-sm text-slate-500">Last updated: 2026-05-19.</p>
      </article>
    </div>
  );
}
