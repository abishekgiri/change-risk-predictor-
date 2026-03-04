import Link from "next/link";

const links = [
  { href: "/overview", label: "Overview" },
  { href: "/integrity", label: "Integrity" },
  { href: "/policies/diff", label: "Policy Diff" },
];

export function AppNav() {
  return (
    <nav className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl items-center gap-3 px-6 py-3">
        <p className="mr-4 text-sm font-semibold text-slate-900">Governance Dashboard</p>
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-md px-2 py-1 text-sm text-slate-700 hover:bg-slate-100"
          >
            {link.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
