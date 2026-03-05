import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/dashboard/customer_success/override_analysis", [
    "tenant_id",
    "from",
    "to",
    "window_days",
    "top_users_limit",
  ]);
}
