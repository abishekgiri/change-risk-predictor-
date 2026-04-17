import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/commercial/icp-score", ["tenant_id", "team_size", "deploys_per_week"]);
}
