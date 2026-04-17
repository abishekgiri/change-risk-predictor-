import { NextRequest } from "next/server";
import { proxyGet, proxyPost } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/fabric/changes", ["tenant_id", "lifecycle_state", "environment", "limit"]);
}
export async function POST(request: NextRequest) {
  return proxyPost(request, "/fabric/changes");
}
