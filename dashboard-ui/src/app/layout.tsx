import type { Metadata } from "next";
import { Suspense } from "react";

import "@/app/globals.css";
import { AppNav } from "@/components/AppNav";

export const metadata: Metadata = {
  title: "Governance Dashboard",
  description: "Executive governance control plane",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <Suspense fallback={<div className="border-b border-slate-200 bg-white px-6 py-3 text-sm font-semibold text-slate-900">Governance Dashboard</div>}>
          <AppNav />
        </Suspense>
        <main className="mx-auto max-w-7xl px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
