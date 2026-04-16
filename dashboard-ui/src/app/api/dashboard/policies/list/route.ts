import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/policies", [
    "tenant_id",
    "scope_type",
    "scope_id",
    "status",
    "limit",
  ]);
}
