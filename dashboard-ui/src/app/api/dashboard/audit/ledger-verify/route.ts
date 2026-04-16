import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/audit/ledger/verify", [
    "tenant_id",
    "repo",
    "ledger",
    "chain_id",
  ]);
}
