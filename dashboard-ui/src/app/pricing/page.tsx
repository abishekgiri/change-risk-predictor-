import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Pricing — ReleaseGate",
  description:
    "Design Partner, Team, Platform, Enterprise — how to start a ReleaseGate pilot.",
};

// Public, unauthenticated page.  Linked from cold emails and demo
// decks, not from the authenticated AppNav.  Tier content is
// calibrated to what ReleaseGate ships today — aspirational
// features (SSO / on-prem / BYOK) are marked "Coming" with a date
// window, never inside a "What you get" list.
export default function PricingPage() {
  return (
    <div className="bg-white">
      {/* Minimal public header — same shape as /trust. */}
      <header className="border-b border-slate-200">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
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

      <article className="mx-auto max-w-5xl px-6 py-10 text-slate-800 leading-relaxed">
        <h1 className="text-3xl font-bold text-slate-900">Pricing</h1>

        <p className="mt-6">
          We are in our design-partner phase. Active design partners use
          ReleaseGate free of charge for 90 days in exchange for a written
          case study and a 30-minute call with future prospects. The tiers
          below describe what subscription pricing will look like as we
          exit design-partner phase in 2026. Until then, the path in is a
          conversation, not a credit card.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">Tiers</h2>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-4">
          {/* Design Partner */}
          <div className="rounded-xl border border-slate-200 p-6">
            <h3 className="text-base font-bold text-slate-900">Design Partner</h3>
            <p className="mt-1 text-sm font-semibold text-slate-700">Free (90-day pilot)</p>
            <p className="mt-3 text-sm text-slate-600">
              For the first wave of customers. Run ReleaseGate against real
              production deploys for 90 days at no cost. We help you install,
              write your first policy bundle, and produce your first evidence
              pack.
            </p>

            <p className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-500">
              What you get
            </p>
            <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-700">
              <li>1 org, 1 tenant</li>
              <li>Unlimited policies, decisions, and evidence packs</li>
              <li>Direct Slack channel with the founder</li>
              <li>Migration help and weekly check-ins</li>
              <li>Co-authored case study at the end of the 90 days</li>
            </ul>

            <p className="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">
              What we ask in return
            </p>
            <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-700">
              <li>A written case study and a logo for the marketing site</li>
              <li>A 30-minute reference call when future prospects ask</li>
              <li>Honest feedback as we close gaps</li>
            </ul>
          </div>

          {/* Team */}
          <div className="rounded-xl border border-slate-200 p-6">
            <h3 className="text-base font-bold text-slate-900">Team</h3>
            <p className="mt-1 text-sm font-semibold text-slate-700">$24,000 / year</p>
            <p className="mt-3 text-sm text-slate-600">
              For engineering organizations adopting evidence-grade change
              governance as a standard practice.
            </p>

            <p className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-500">
              What you get
            </p>
            <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-700">
              <li>1 org, up to 3 tenants</li>
              <li>Unlimited policies, decisions, and evidence packs</li>
              <li>Email support, 2-business-day response window</li>
              <li>Quarterly compliance-pack export (SOC 2 CC8.1 mapped)</li>
              <li>12-month commitment</li>
            </ul>
          </div>

          {/* Platform */}
          <div className="rounded-xl border border-slate-200 p-6">
            <h3 className="text-base font-bold text-slate-900">Platform</h3>
            <p className="mt-1 text-sm font-semibold text-slate-700">$75,000 / year</p>
            <p className="mt-3 text-sm text-slate-600">
              For platform-engineering teams owning change governance across
              multiple business units.
            </p>

            <p className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-500">
              What you get
            </p>
            <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-700">
              <li>Up to 5 tenants, multi-team policy authoring</li>
              <li>Dedicated Slack with the founding team</li>
              <li>99.5% uptime target (target, not contractual SLA)</li>
              <li>SOC 2 Type I report shared on request once delivered</li>
              <li>Quarterly governance review with a ReleaseGate engineer</li>
              <li>12-month commitment</li>
            </ul>
          </div>

          {/* Enterprise */}
          <div className="rounded-xl border border-slate-200 p-6">
            <h3 className="text-base font-bold text-slate-900">Enterprise</h3>
            <p className="mt-1 text-sm font-semibold text-slate-700">Custom</p>
            <p className="mt-3 text-sm text-slate-600">
              For regulated organizations with procurement, legal review, and
              custom deployment constraints.
            </p>

            <p className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-500">
              What we&apos;ll build with you
            </p>
            <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-700">
              <li>Unlimited tenants, custom data residency</li>
              <li>Custom contract, DPA, and SLA</li>
              <li>SSO via SAML / OIDC (Coming — Q3 2026, WorkOS-backed)</li>
              <li>On-prem / VPC deployment via Helm (Coming — 2027)</li>
              <li>Bring-your-own-key (BYOK) signing (Coming — 2027)</li>
              <li>Named account engineer</li>
            </ul>
          </div>
        </div>

        <h2 className="mt-12 text-xl font-bold text-slate-900">How to start</h2>

        <p className="mt-4">
          Every tier above starts the same way: a 30-minute call to confirm
          fit and to walk through a real evidence pack from your own repo.
          Email{" "}
          <a
            href="mailto:hello@releasegate.io"
            className="font-medium text-slate-900 underline underline-offset-2 hover:text-slate-700"
          >
            <strong>hello@releasegate.io</strong>
          </a>{" "}
          with one sentence about your team size, your CI stack, and your
          audit timeline.
        </p>

        <h2 className="mt-10 text-xl font-bold text-slate-900">What is not on this page</h2>

        <p className="mt-4">
          We do not list per-seat pricing, per-deploy pricing, or
          pay-as-you-go tiers. Change governance is a platform purchase,
          not a metered service. If you need a unit-priced model for
          procurement reasons, ask us — we will build something that
          maps to your buying motion.
        </p>

        <p className="mt-4">We do not have:</p>

        <ul className="mt-3 list-disc pl-6 space-y-1.5 text-sm text-slate-700">
          <li>Free-forever self-serve sign-up</li>
          <li>A credit-card checkout</li>
          <li>A 14-day free trial separate from the design-partner program</li>
        </ul>

        <p className="mt-4">
          These are deliberate omissions, not roadmap items. Self-serve
          makes sense for tools. ReleaseGate is infrastructure; it goes
          through procurement.
        </p>

        <hr className="my-10 border-slate-200" />

        <p className="text-sm text-slate-500">Last updated: 2026-05-20.</p>

        <p className="mt-4 text-sm text-slate-500">
          See the{" "}
          <Link href="/trust" className="text-slate-700 underline">
            trust page
          </Link>{" "}
          for our security posture and compliance status.
        </p>
      </article>
    </div>
  );
}
