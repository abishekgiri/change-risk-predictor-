import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/audit/export", [
    "tenant_id",
    "repo",
    "format",
    "limit",
    "status",
    "include_overrides",
    "verify_chain",
    "contract",
  ]);
}
