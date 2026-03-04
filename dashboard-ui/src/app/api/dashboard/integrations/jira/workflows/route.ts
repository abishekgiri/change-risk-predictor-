import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/integrations/jira/workflows", ["tenant_id", "project_key"]);
}
