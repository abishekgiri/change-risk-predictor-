import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyGet(request, `/fabric/changes/${encodeURIComponent(id)}`, ["tenant_id"]);
}
