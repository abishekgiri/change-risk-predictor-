import { NextRequest } from "next/server";
import { proxyPost } from "@/lib/proxy";

export async function POST(request: NextRequest) {
  return proxyPost(request, "/decisions/declare");
}
