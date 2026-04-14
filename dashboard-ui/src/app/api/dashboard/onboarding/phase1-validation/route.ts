import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/internal/onboarding/phase1/validation", [
    "days",
    "tenant_id",
    "tenant_prefix",
    "limit",
  ]);
}
