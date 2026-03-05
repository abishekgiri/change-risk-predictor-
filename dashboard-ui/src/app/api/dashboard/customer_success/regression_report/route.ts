import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/dashboard/customer_success/regression_report", [
    "tenant_id",
    "from",
    "to",
    "window_days",
    "correlation_window_hours",
    "drop_threshold",
  ]);
}
