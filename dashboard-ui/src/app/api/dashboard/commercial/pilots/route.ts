import { NextRequest } from "next/server";
import { proxyGet, proxyPost } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/commercial/pilots", ["status", "icp_band", "limit"]);
}

export async function POST(request: NextRequest) {
  return proxyPost(request, "/commercial/pilots");
}
