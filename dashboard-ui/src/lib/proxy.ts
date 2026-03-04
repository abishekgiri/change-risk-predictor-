import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/backend";

function firstParam(value: string | string[] | null): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value ?? undefined;
}

export async function proxyGet<T>(
  request: NextRequest,
  backendPath: string,
  queryKeys: string[] = [],
): Promise<NextResponse> {
  try {
    const query: Record<string, string> = {};
    for (const key of queryKeys) {
      const value = firstParam(request.nextUrl.searchParams.getAll(key));
      if (value) query[key] = value;
    }
    const { data } = await backendFetch<T>(backendPath, { method: "GET", query });
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Request failed" },
      { status: 500 },
    );
  }
}

export async function proxyPost<T>(
  request: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
  try {
    const body = await request.json();
    const { data } = await backendFetch<T>(backendPath, {
      method: "POST",
      body: JSON.stringify(body),
    });
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Request failed" },
      { status: 500 },
    );
  }
}
