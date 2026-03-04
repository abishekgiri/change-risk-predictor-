import type { Metadata } from "next";

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
        <AppNav />
        <main className="mx-auto max-w-7xl px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
