import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/audit/authority-report", ["tenant_id", "days"]);
}
