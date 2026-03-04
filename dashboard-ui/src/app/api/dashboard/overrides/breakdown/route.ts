import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/dashboard/overrides/breakdown", ["tenant_id", "from", "to", "group_by", "limit"]);
}
