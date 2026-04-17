import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/fabric/changes/query", ["tenant_id", "filter_type", "limit"]);
}
