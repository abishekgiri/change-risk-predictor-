import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/dashboard/metrics/summary", [
    "tenant_id",
    "from",
    "to",
    "window_days",
  ]);
}
